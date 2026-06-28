// Orchestration tracer for the TS `decrypt` flow. A fake committee replays the
// real partials from the open_secret fixture, so quorum selection, request
// building, the per-node Lagrange computation, fan-out, and aggregation are all
// exercised without a socket — the TS analogue of the Rust SDK's fake-committee test.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
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

// Map each subset node index → the fixture partial produced for it (subset order).
const byIndex = new Map<number, any>(
  (fixture.subset as number[]).map((idx, i) => [idx, fixture.partials[i]]),
);

class FixtureCommittee implements Transport {
  async health(_endpoint: string): Promise<Health> {
    return { status: "active", epoch: fixture.epoch };
  }
  async partialDecrypt(endpoint: string, _req: PartialDecryptRequest): Promise<PartialDecryptResponse> {
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

// The fake committee ignores auth; the signer just needs to return well-formed fields.
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
});
