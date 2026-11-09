// The @polkadot/api backend's pure edges, checked against the real spec-330 runtime.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Keyring } from "@polkadot/keyring";
import { Metadata, TypeRegistry } from "@polkadot/types";
import { decorateExtrinsics } from "@polkadot/types/metadata/decorate";
import type { SignerPayloadJSON } from "@polkadot/types/types";
import { u8aToHex } from "@polkadot/util";
import { blake2AsU8a, cryptoWaitReady, sr25519Verify } from "@polkadot/util-crypto";
import type { KeySigner } from "@openmatter-network/matter-sdk-core";
import { Aad, aadBytes } from "@openmatter-network/matter-sdk-core";
import { describe, expect, it } from "vitest";

import { requireEvent } from "../src/backend.js";
import { ClientError } from "../src/errors.js";
import { secretIdFromReceipt } from "../src/facade.js";
import {
  MAX_UNHASHED_SIGNING_PAYLOAD_BYTES,
  extrinsicSigningBytes,
  keySignerAdapter,
  palletNamesByIndex,
  receiptEvents,
  storedValue,
  toChainArgs,
} from "../src/polkadot.js";

const vectorsDir = resolve(import.meta.dirname, "../../../testvectors");

function spec330(): { registry: TypeRegistry; metadata: Metadata } {
  const registry = new TypeRegistry();
  const metadata = new Metadata(
    registry,
    new Uint8Array(readFileSync(resolve(vectorsDir, "spec330_metadata.scale"))),
  );
  registry.setMetadata(metadata);
  return { registry, metadata };
}

/** `api.tx` as @polkadot builds it from metadata, without a socket. */
function extrinsicsOf(registry: TypeRegistry, metadata: Metadata) {
  return decorateExtrinsics(registry, metadata.asLatest, metadata.version);
}

function filled(length: number, byte: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

/** Bytes whose first byte is `first`: the byte @polkadot would misread as a compact length. */
function startingWith(first: number, length: number): Uint8Array {
  const bytes = filled(length, 0x55);
  bytes[0] = first;
  return bytes;
}

/** A sealed envelope as `SecretsFacade.store` shapes it: raw bytes under the runtime's field names. */
function envelope(bindingFirstByte: number) {
  return {
    binding_id: startingWith(bindingFirstByte, 32),
    capsule: filled(300, 0x01),
    proof: filled(200, 0x02),
    ct: filled(40, 0x03),
  };
}

describe("argument normalization", () => {
  it("turns every Uint8Array into hex, at any depth, and leaves the rest alone", () => {
    const account = filled(32, 0xab);
    const out = toChainArgs([
      7n,
      42,
      "0x00",
      null,
      true,
      account,
      { User: account },
      { Staked: null },
      [account, { Id: account }],
      { binding_id: account, nested: { ct: account } },
    ]);
    const hex = u8aToHex(account);
    expect(out).toEqual([
      7n,
      42,
      "0x00",
      null,
      true,
      hex,
      { User: hex },
      { Staked: null },
      [hex, { Id: hex }],
      { binding_id: hex, nested: { ct: hex } },
    ]);
  });

  it("does not descend into values that are not plain data", () => {
    const { registry } = spec330();
    const codec = registry.createType("u128", 5);
    expect(toChainArgs([codec])[0]).toBe(codec);
    // A byte-backed codec is a Uint8Array subclass; hex of it is the same value.
    const account = registry.createType("AccountId32", filled(32, 1));
    expect(toChainArgs([account])[0]).toBe(account.toHex());
  });

  it("encodes store_secret exactly as the caller's bytes, whatever the first byte", () => {
    const { registry, metadata } = spec330();
    const tx = extrinsicsOf(registry, metadata);
    const label = new TextEncoder().encode("db-url");
    const aad = aadBytes(Aad.EnvV1);

    for (const first of [0x00, 0x04, 0x6d, 0xff, 0x07]) {
      const payload = envelope(first);
      const call = tx["secrets"]!["storeSecret"]!(...toChainArgs([payload, 1, label, aad]));
      const encoded = call.args[0] as unknown as Record<string, { toU8a(bare: boolean): Uint8Array }>;
      expect(encoded["bindingId"]!.toU8a(true)).toEqual(payload.binding_id);
      expect(encoded["capsule"]!.toU8a(true)).toEqual(payload.capsule);
      expect(encoded["proof"]!.toU8a(true)).toEqual(payload.proof);
      expect(encoded["ct"]!.toU8a(true)).toEqual(payload.ct);
      expect(call.args[2]!.toU8a(true)).toEqual(label);
      expect(call.args[3]!.toU8a(true)).toEqual(aad);
    }
  });

  it("round-trips every variable-length byte argument the façades send", () => {
    const { registry, metadata } = spec330();
    const tx = extrinsicsOf(registry, metadata);
    const cases: Array<[string, string, unknown[], Array<[number, Uint8Array]>]> = [
      [
        "secrets",
        "rotateSecret",
        [1n, envelope(0x6d), 2, aadBytes(Aad.TlsV1)],
        [[3, aadBytes(Aad.TlsV1)]],
      ],
      [
        "jobs",
        "registerWgPeer",
        [1n, filled(32, 0x09), filled(1088, 0x09)],
        [[1, filled(32, 0x09)], [2, filled(1088, 0x09)]],
      ],
      [
        "resources",
        "registerResource",
        [filled(32, 0x01), filled(70, 0x11), "node-1"],
        [[0, filled(32, 0x01)], [1, filled(70, 0x11)]],
      ],
    ];
    for (const [pallet, method, args, expected] of cases) {
      const call = tx[pallet]![method]!(...toChainArgs(args));
      for (const [index, bytes] of expected) {
        expect(call.args[index]!.toU8a(true), `${pallet}.${method} arg ${index}`).toEqual(bytes);
      }
    }
  });

  it("pins why: @polkadot reads a raw Uint8Array as length-prefixed SCALE", () => {
    const { registry, metadata } = spec330();
    const tx = extrinsicsOf(registry, metadata);
    // Every AAD tag starts with `m` or `q`, whose compact prefix claims 64+ bytes.
    expect(() =>
      tx["secrets"]!["storeSecret"]!(envelope(0x07), 1, "0x", aadBytes(Aad.EnvV1)),
    ).toThrow(/Bytes/);
    // A first byte that decodes as a small length truncates instead, with no error.
    const truncated = tx["jobs"]!["registerWgPeer"]!(1n, filled(32, 9), filled(1088, 0x09));
    expect(truncated.args[2]!.toU8a(true).length).not.toBe(1088);
  });
});

describe("extrinsic signing bytes", () => {
  it("passes a payload of up to 256 bytes through unchanged", () => {
    const payload = filled(MAX_UNHASHED_SIGNING_PAYLOAD_BYTES, 0xab);
    expect(extrinsicSigningBytes(payload)).toBe(payload);
  });

  it("hands over the blake2b-256 digest of anything longer, as the runtime verifies", () => {
    const payload = filled(MAX_UNHASHED_SIGNING_PAYLOAD_BYTES + 1, 0xab);
    const signed = extrinsicSigningBytes(payload);
    expect(signed).toHaveLength(32);
    expect(signed).toEqual(blake2AsU8a(payload));
  });
});

describe("the KeySigner adapter", () => {
  function signerPayloadFor(
    registry: TypeRegistry,
    metadata: Metadata,
    pallet: string,
    method: string,
    args: unknown[],
  ): SignerPayloadJSON {
    const tx = extrinsicsOf(registry, metadata);
    const call = tx[pallet]![method]!(...toChainArgs(args));
    return registry
      .createType("SignerPayload", {
        address: registry.createType("AccountId32", filled(32, 0xee)).toString(),
        blockHash: u8aToHex(filled(32, 0x01)),
        blockNumber: 0,
        era: "0x00",
        genesisHash: u8aToHex(filled(32, 0x02)),
        method: call.toHex(),
        nonce: 0,
        specVersion: 330,
        tip: 0,
        transactionVersion: 1,
        signedExtensions: registry.signedExtensions,
        version: 4,
      })
      .toPayload();
  }

  function recording(): { signer: KeySigner; received: Uint8Array[] } {
    const received: Uint8Array[] = [];
    return {
      received,
      signer: {
        accountId: filled(32, 0xee),
        sign(message) {
          received.push(message);
          return filled(64, 0x5a);
        },
      },
    };
  }

  it("hashes a store_secret payload before the signer sees it, and frames the result", async () => {
    const { registry, metadata } = spec330();
    const json = signerPayloadFor(registry, metadata, "secrets", "storeSecret", [
      envelope(0x07),
      1,
      "0x",
      aadBytes(Aad.EnvV1),
    ]);
    const raw = registry.createType("ExtrinsicPayload", json, { version: json.version }).toU8a({ method: true });
    expect(raw.length).toBeGreaterThan(MAX_UNHASHED_SIGNING_PAYLOAD_BYTES);

    const { signer, received } = recording();
    const result = await keySignerAdapter(registry, signer).signPayload!(json);

    expect(received).toHaveLength(1);
    expect(received[0]).toEqual(blake2AsU8a(raw));
    expect(result.signature).toBe(u8aToHex(new Uint8Array([0x01, ...filled(64, 0x5a)])));
  });

  it("hands a short payload over unhashed", async () => {
    const { registry, metadata } = spec330();
    const json = signerPayloadFor(registry, metadata, "staking", "chill", []);
    const raw = registry.createType("ExtrinsicPayload", json, { version: json.version }).toU8a({ method: true });
    expect(raw.length).toBeLessThanOrEqual(MAX_UNHASHED_SIGNING_PAYLOAD_BYTES);

    const { signer, received } = recording();
    await keySignerAdapter(registry, signer).signPayload!(json);
    expect(received[0]).toEqual(raw);
  });

  it("produces a signature the runtime would accept from a raw sr25519 signer", async () => {
    await cryptoWaitReady();
    const pair = new Keyring({ type: "sr25519" }).addFromUri("//Alice");
    const { registry, metadata } = spec330();
    const json = signerPayloadFor(registry, metadata, "secrets", "storeSecret", [
      envelope(0x07),
      1,
      "0x",
      aadBytes(Aad.EnvV1),
    ]);
    const raw = registry.createType("ExtrinsicPayload", json, { version: json.version }).toU8a({ method: true });

    const hsmLike: KeySigner = { accountId: pair.publicKey, sign: (message) => pair.sign(message) };
    const result = await keySignerAdapter(registry, hsmLike).signPayload!(json);
    const framed = registry.createType("MultiSignature", result.signature);
    expect(framed.isSr25519).toBe(true);
    // The runtime checks the signature over blake2b-256(payload) once the payload exceeds 256 bytes.
    expect(sr25519Verify(blake2AsU8a(raw), framed.asSr25519.toU8a(), pair.publicKey)).toBe(true);
  });
});

describe("receipt events", () => {
  function secretStored(registry: TypeRegistry, metadata: Metadata, secretId: bigint, owner: Uint8Array) {
    const secrets = metadata.asLatest.pallets.find((p) => p.name.toString() === "Secrets");
    expect(secrets, "spec 330 has a Secrets pallet").toBeDefined();
    const variant = registry.lookup
      .getSiType(secrets!.events.unwrap().type)
      .def.asVariant.variants.find((v) => v.name.toString() === "SecretStored");
    expect(variant, "Secrets emits SecretStored").toBeDefined();

    // SecretStored { secret_id: u128, owner: AccountId32 }
    const encoded = new Uint8Array([
      secrets!.index.toNumber(),
      variant!.index.toNumber(),
      ...registry.createType("u128", secretId).toU8a(),
      ...owner,
    ]);
    return registry.createType("Event", encoded);
  }

  it("names the pallet as metadata spells it, not as @polkadot camelCases it", () => {
    const { registry, metadata } = spec330();
    const event = secretStored(registry, metadata, 0n, filled(32, 0));
    expect(event.section).toBe("secrets"); // what the receipt used to carry

    const [[pallet, name]] = receiptEvents([{ event }], palletNamesByIndex(metadata));
    expect([pallet, name]).toEqual(["Secrets", "SecretStored"]);
  });

  it("carries each event's fields under the runtime's own field names", () => {
    const { registry, metadata } = spec330();
    const owner = filled(32, 0x11);
    const event = secretStored(registry, metadata, 7n, owner);

    const events = receiptEvents([{ event }], palletNamesByIndex(metadata));
    expect(events).toEqual([
      ["Secrets", "SecretStored", { secret_id: 7, owner: registry.createType("AccountId32", owner).toString() }],
    ]);
  });

  it("renders an id beyond 2^53 losslessly", () => {
    const { registry, metadata } = spec330();
    const big = (1n << 100n) + 3n;
    const [[, , data]] = receiptEvents(
      [{ event: secretStored(registry, metadata, big, filled(32, 0)) }],
      palletNamesByIndex(metadata),
    );
    expect(BigInt(data!["secret_id"] as string)).toBe(big);
  });

  it("reads the secret id from a store receipt", () => {
    const { registry, metadata } = spec330();
    const events = receiptEvents(
      [
        { event: registry.createType("Event", new Uint8Array([0, 0, ...filled(40, 0)])) },
        { event: secretStored(registry, metadata, 9n, filled(32, 0)) },
      ],
      palletNamesByIndex(metadata),
    );
    const receipt = { txHash: "0x", blockHash: "0x", events };
    expect(secretIdFromReceipt(receipt)).toBe(9n);
    expect(requireEvent(receipt, "Secrets", "SecretStored")).toEqual(events[1]![2]);
  });

  it("refuses a receipt without the event, naming what it saw", () => {
    const receipt = { txHash: "0x", blockHash: "0x", events: [["System", "ExtrinsicSuccess", {}] as const] };
    let caught: unknown;
    try {
      requireEvent(receipt, "Secrets", "SecretStored");
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ClientError);
    expect((caught as ClientError).kind).toBe("chain");
    expect((caught as ClientError).message).toMatch(/System\.ExtrinsicSuccess/);
  });

  it("maps every pallet index to its metadata name", () => {
    const { metadata } = spec330();
    const names = palletNamesByIndex(metadata);
    expect(names.size).toBe(metadata.asLatest.pallets.length);
    for (const pallet of metadata.asLatest.pallets) {
      expect(names.get(pallet.index.toNumber())).toBe(pallet.name.toString());
    }
    expect([...names.values()]).toContain("NominationPools");
  });
});

describe("query results", () => {
  it("returns a stored zero, not undefined", () => {
    const { registry } = spec330();
    const zero = registry.createType("u128", 0);
    expect(storedValue(zero)).toBe(zero);
  });

  it("reads an absent entry with a storage default as undefined", () => {
    const { registry } = spec330();
    const fallback = registry.createType("u128", 0);
    (fallback as { isStorageFallback?: boolean }).isStorageFallback = true;
    expect(storedValue(fallback)).toBeUndefined();
  });

  it("reads an absent optional entry as undefined", () => {
    const { registry } = spec330();
    expect(storedValue(registry.createType("Option<u128>", null))).toBeUndefined();
    const some = registry.createType("Option<u128>", 0);
    expect(storedValue(some)).toBe(some);
  });
});
