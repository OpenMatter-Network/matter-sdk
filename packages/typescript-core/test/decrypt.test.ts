// A fake committee replays the open_secret fixture's partials, exercising the
// whole `decrypt` flow without a socket.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  cryptoProtocolVersion,
  decrypt,
  DecryptError,
  type CommitteeNode,
  type Health,
  type PartialDecryptRequest,
  type PartialDecryptResponse,
  type Signer,
  type Transport,
} from "../src/index.js";
import { fromHex, toHex } from "../src/util.js";

const vectorsDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../../testvectors");
const fixture = JSON.parse(readFileSync(resolve(vectorsDir, "open_secret.json"), "utf8"));

const byIndex = new Map<number, any>(
  (fixture.subset as number[]).map((idx, i) => [idx, fixture.partials[i]]),
);

class FixtureCommittee implements Transport {
  /** Endpoints whose `/health` rejects, as an unreachable node does. */
  constructor(
    private readonly unreachableHealth: ReadonlySet<string> = new Set(),
    /** Endpoints that pass `/health` and then refuse the real request. */
    private readonly refusePartial: ReadonlySet<string> = new Set(),
    /** Crypto protocol version `/health` reports per endpoint (absent = not reported). */
    private readonly versions: ReadonlyMap<string, number> = new Map(),
  ) {}

  asked: string[] = [];

  async health(endpoint: string): Promise<Health> {
    if (this.unreachableHealth.has(endpoint)) {
      throw new DecryptError("transport", `health failed: connection refused (${endpoint})`);
    }
    return { status: "active", epoch: fixture.epoch, crypto_protocol_version: this.versions.get(endpoint) };
  }
  async partialDecrypt(endpoint: string, _req: PartialDecryptRequest): Promise<PartialDecryptResponse> {
    if (this.refusePartial.has(endpoint)) {
      throw new DecryptError("transport", `partial-decrypt 503 from ${endpoint}`);
    }
    this.asked.push(endpoint);
    const index = Number(endpoint.split("-").at(-1));
    const p = byIndex.get(index);
    return {
      node_index: index,
      partial: "0x" + p.partial_hex,
      proof: "0x" + p.proof_hex,
      served_epoch: fixture.epoch,
    };
  }
}

// The fake committee ignores auth.
const fakeSigner: Signer = {
  authScheme: () => "substrate",
  async authorize() {
    return { auth: "substrate", requester: "0x00", signature: "0x00" };
  },
};

function nodes(): CommitteeNode[] {
  return (fixture.subset as number[]).map((index) => ({
    index,
    endpoint: `http://node-${index}`,
    shareCommitment: fromHex(byIndex.get(index).commitment_hex),
  }));
}

function baseParams() {
  return {
    secretId: BigInt(fixture.secret_id),
    epoch: fixture.epoch,
    bindingId: fromHex(fixture.binding_id_hex),
    aad: fromHex(fixture.aad_hex),
    capsule: fromHex(fixture.capsule_hex),
    ct: fromHex(fixture.ct_hex),
    sharedA: fromHex(fixture.shared_a_hex),
    blockHash: new Uint8Array(32),
    threshold: Number(fixture.meta.t),
    nodes: nodes(),
  };
}

describe("decrypt orchestration", () => {
  it("recovers the secret from a quorum", async () => {
    const plaintext = await decrypt(new FixtureCommittee(), fakeSigner, {
      secretId: BigInt(fixture.secret_id),
      epoch: fixture.epoch,
      bindingId: fromHex(fixture.binding_id_hex),
      aad: fromHex(fixture.aad_hex),
      capsule: fromHex(fixture.capsule_hex),
      ct: fromHex(fixture.ct_hex),
      sharedA: fromHex(fixture.shared_a_hex),
      blockHash: new Uint8Array(32),
      threshold: Number(fixture.meta.t),
      nodes: nodes(),
    });
    expect(toHex(plaintext)).toBe("0x" + fixture.expected_plaintext_hex);
  });

  it("rejects when too few nodes are healthy", async () => {
    const oneNode = nodes().slice(0, 1);
    await expect(
      decrypt(new FixtureCommittee(), fakeSigner, {
        secretId: BigInt(fixture.secret_id),
        epoch: fixture.epoch,
        bindingId: fromHex(fixture.binding_id_hex),
        aad: fromHex(fixture.aad_hex),
        capsule: fromHex(fixture.capsule_hex),
        ct: fromHex(fixture.ct_hex),
        sharedA: fromHex(fixture.shared_a_hex),
        blockHash: new Uint8Array(32),
        threshold: Number(fixture.meta.t),
        nodes: oneNode,
      }),
    ).rejects.toMatchObject({ kind: "quorum" } satisfies Partial<DecryptError>);
  });

  it("reports no faults when the caller simply supplied too few nodes", async () => {
    const err = await decrypt(new FixtureCommittee(), fakeSigner, {
      ...baseParams(),
      nodes: nodes().slice(0, 1),
    }).catch((e: unknown) => e as DecryptError);
    expect(err.faults).toEqual([]);
  });

  it("names a node that never answered /health", async () => {
    const all = nodes();
    const err = await decrypt(
      new FixtureCommittee(new Set([all[0]!.endpoint])),
      fakeSigner,
      baseParams(),
    ).catch((e: unknown) => e as DecryptError);

    expect(err.kind).toBe("quorum");
    const fault = err.faults.find((f) => f.index === all[0]!.index);
    expect(fault?.stage).toBe("health");
    expect(err.message).toContain(all[0]!.endpoint);
    expect(err.message).toContain("connection refused");
  });

  // The fixture is t = 3 of 3, so dropping one still fails, but as `quorum`
  // naming the node, not as `transport`.
  it("drops a node that refuses the real request instead of aborting on it", async () => {
    const all = nodes();
    const err = await decrypt(
      new FixtureCommittee(new Set(), new Set([all[1]!.endpoint])),
      fakeSigner,
      baseParams(),
    ).catch((e: unknown) => e as DecryptError);

    expect(err.kind).toBe("quorum");
    const fault = err.faults.find((f) => f.index === all[1]!.index);
    expect(fault?.stage).toBe("partial-decrypt");
    expect(fault?.detail).toContain("503");
    expect(err.message).toContain("503");
  });
});

describe("protocol version", () => {
  it("drops a node that speaks another crypto protocol version, before asking it", async () => {
    const bad = `http://node-${fixture.subset[0]}`;
    const committee = new FixtureCommittee(
      new Set(),
      new Set(),
      new Map([[bad, cryptoProtocolVersion() + 1]]),
    );
    const err = await decrypt(committee, fakeSigner, baseParams()).catch((e) => e);
    expect(err).toBeInstanceOf(DecryptError);
    expect(err.kind).toBe("quorum");
    expect(err.faults).toEqual([
      expect.objectContaining({ endpoint: bad, stage: "protocol-version" }),
    ]);
    expect(committee.asked).not.toContain(bad);
  });

  it("accepts a node that does not report a version", async () => {
    const got = await decrypt(new FixtureCommittee(), fakeSigner, baseParams());
    expect(toHex(got)).toBe("0x" + fixture.expected_plaintext_hex);
  });
});
