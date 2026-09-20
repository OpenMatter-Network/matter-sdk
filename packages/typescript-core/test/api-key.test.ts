// API-key ingestion conformance.
//
// Replays the Rust-emitted fixture (testvectors/api_keys.json) so this binding
// agrees with every other on what parses, what is rejected, and which account
// each key derives. Derivation happens in the shared wasm core, so a divergence
// here means the core changed — not that TypeScript drifted.
//
// The redaction cases are TypeScript-specific: `toString`/`toJSON`/`inspect` are
// the paths by which a key reaches a log line in this runtime.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { ApiKey, keySigner, partialDecryptAuth } from "../src/index.js";
import { toHex } from "../src/util.js";

const vectorsDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../../testvectors");
const vectors = JSON.parse(readFileSync(resolve(vectorsDir, "api_keys.json"), "utf8"));

interface ValidCase {
  name: string;
  key: string;
  account_id_hex: string;
}
interface InvalidCase {
  name: string;
  key: string;
  error: string;
}

const MNEMONIC = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
const SEED_HEX = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";

describe("api key conformance", () => {
  it.each(vectors.valid as ValidCase[])("parses $name", (c) => {
    const key = new ApiKey(c.key);
    expect(toHex(key.accountId)).toBe(`0x${c.account_id_hex}`);
    expect(key.accountIdHex).toBe(`0x${c.account_id_hex}`);
    expect(key.scheme).toBe("sr25519");
    key.free();
  });

  it.each(vectors.invalid as InvalidCase[])("rejects $name", (c) => {
    expect(() => new ApiKey(c.key)).toThrow();
  });

  it("derives a different account once junctions are applied", () => {
    // The failure this guards: dropping the derivation path and silently
    // returning the root account.
    const root = new ApiKey(SEED_HEX);
    const hard = new ApiKey(`${SEED_HEX}//hard`);
    expect(hard.accountIdHex).not.toBe(root.accountIdHex);

    // The mnemonic form of the same secret must land on the same account.
    const fromMnemonic = new ApiKey(`${MNEMONIC}//hard`);
    expect(fromMnemonic.accountIdHex).toBe(hard.accountIdHex);
  });
});

describe("api key redaction", () => {
  const secretBody = SEED_HEX.slice(2);

  it("never renders key material through any string path", () => {
    const key = new ApiKey(SEED_HEX);
    const renderings = [
      key.toString(),
      `${key}`,
      JSON.stringify(key),
      JSON.stringify({ nested: key }),
      inspect(key),
      inspect({ nested: key }),
    ];
    for (const rendered of renderings) {
      expect(rendered.toLowerCase()).not.toContain(secretBody);
      expect(rendered.toLowerCase()).not.toContain("bottom drive");
      expect(rendered).toContain("<redacted>");
    }
  });

  it("exposes no property carrying the secret", () => {
    const key = new ApiKey(MNEMONIC);
    const reachable = [
      ...Object.keys(key),
      ...Object.getOwnPropertyNames(key),
      ...Object.getOwnPropertyNames(Object.getPrototypeOf(key)),
    ];
    // `accountId`/`accountIdHex`/`scheme` are public; nothing else may return a
    // value containing key material.
    for (const name of reachable) {
      const value = (key as unknown as Record<string, unknown>)[name];
      if (typeof value !== "string") continue;
      expect(value.toLowerCase()).not.toContain(secretBody);
      expect(value.toLowerCase()).not.toContain("bottom drive");
    }
  });

  it("throws without echoing the key when parsing fails", () => {
    // A thrown message is the most likely thing to be logged verbatim.
    for (const bad of [`${SEED_HEX}00`, `secp256k1:${SEED_HEX}`, `${MNEMONIC} zoo`]) {
      let message = "";
      try {
        new ApiKey(bad);
      } catch (e) {
        message = String(e).toLowerCase();
      }
      expect(message).not.toBe("");
      expect(message).not.toContain(secretBody);
      expect(message).not.toContain("bottom drive");
    }
  });
});

describe("api key as a signer", () => {
  const request = {
    secretId: 42n,
    subset: [1, 2, 3],
    recipientIndex: 2,
    blockHash: new Uint8Array(32).fill(0x11),
  };

  it("frames a SCALE MultiSignature over the canonical payload", async () => {
    const key = new ApiKey(SEED_HEX);
    const auth = await partialDecryptAuth(key, request);

    expect(auth.auth).toBe("substrate");
    expect(auth.requester).toBe(key.accountIdHex);
    // 0x + 1-byte variant (Sr25519 = 1) + 64-byte signature.
    expect(auth.signature).toHaveLength(2 + 2 * 65);
    expect(auth.signature.slice(0, 4)).toBe("0x01");
  });

  it("is usable directly as a committee Signer", async () => {
    const key = new ApiKey(MNEMONIC);
    const signer = keySigner(key);
    expect(signer.authScheme()).toBe("substrate");
    const auth = await signer.authorize(request);
    expect(auth.requester).toBe(key.accountIdHex);
  });

  it("signs a distinct payload per recipient (MV-C1)", async () => {
    // The same request addressed to two nodes must not produce interchangeable
    // signatures. sr25519 is non-deterministic, so assert on the payload the
    // signer is handed rather than the signature bytes.
    const seen: string[] = [];
    const spy = {
      accountId: new Uint8Array(32),
      sign(payload: Uint8Array) {
        seen.push(toHex(payload));
        return new Uint8Array(64);
      },
    };
    await partialDecryptAuth(spy, { ...request, recipientIndex: 2 });
    await partialDecryptAuth(spy, { ...request, recipientIndex: 4 });
    expect(seen[0]).not.toBe(seen[1]);
  });
});
