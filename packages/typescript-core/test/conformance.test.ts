// Replays the Rust-generated testvectors/*.json through the wasm path; byte-equal.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  bindingCommitsTo,
  bindingIdFor,
  lagrangeFor,
  openSecret,
  signingPayload,
} from "../src/index.js";
import { fromHex, toHex } from "../src/util.js";

const vectorsDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../../testvectors");
const load = (name: string) => JSON.parse(readFileSync(resolve(vectorsDir, name), "utf8"));

describe("signing payload conformance", () => {
  const { cases } = load("signing_payload.json");
  it.each(cases)("secret_id=$secret_id subset=$subset", (c: any) => {
    const got = signingPayload(BigInt(c.secret_id), c.subset, fromHex(c.block_hash_hex), c.recipient_index);
    expect(toHex(got)).toBe("0x" + c.payload_hex);
  });
});

describe("lagrange coefficient conformance", () => {
  const { cases } = load("lagrange.json");
  it.each(cases)("point=$point subset=$subset", (c: any) => {
    const got = lagrangeFor(c.point, c.subset);
    expect(toHex(got)).toBe("0x" + c.lambda_hex);
  });
});

describe("open_secret conformance", () => {
  it("recovers the expected plaintext from the fixture quorum", () => {
    const v = load("open_secret.json");
    const partials = v.partials.map((p: any) => ({
      point: p.point,
      partial: fromHex(p.partial_hex),
      proof: fromHex(p.proof_hex),
      commitment: fromHex(p.commitment_hex),
    }));
    const plaintext = openSecret({
      sharedA: fromHex(v.shared_a_hex),
      capsule: fromHex(v.capsule_hex),
      secretId: BigInt(v.secret_id),
      epoch: v.epoch,
      bindingId: fromHex(v.binding_id_hex),
      aad: fromHex(v.aad_hex),
      ct: fromHex(v.ct_hex),
      partials,
    });
    expect(toHex(plaintext)).toBe("0x" + v.expected_plaintext_hex);
  });
});

// The owner-bound binding id is a wire contract with the chain, which checks it
// on every stored secret. matter-node pins the first row as a literal too.
describe("owner-bound binding id conformance", () => {
  const v = load("binding_ids.json");
  it.each(v.commits)("derives $binding_id_hex", (c: any) => {
    const [owner, salt] = [fromHex("0x" + c.owner_hex), fromHex("0x" + c.salt_hex)];
    const id = bindingIdFor(owner, salt);
    expect(toHex(id)).toBe("0x" + c.binding_id_hex);
    expect(bindingCommitsTo(owner, id)).toBe(true);
  });
  it.each(v.does_not_commit)("refuses $why", (c: any) => {
    expect(bindingCommitsTo(fromHex("0x" + c.owner_hex), fromHex("0x" + c.binding_id_hex))).toBe(false);
  });
});
