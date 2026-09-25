// Consumer smoke test for matter-sdk-core, run by scripts/smoke-npm.sh against the
// installed package: golden-vector recovery, a seal (wasm RNG), and a sign (key core).
//
//   usage: node npm-core.mjs <path/to/testvectors/open_secret.json>
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Aad, ApiKey, encrypt, openSecret } from "@openmatter-network/matter-sdk-core";

const fail = (message) => {
  console.error(`npm-core smoke: ${message}`);
  process.exit(1);
};
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const hex = (u8) => Buffer.from(u8).toString("hex");

// Must test the installed tarball, not monorepo sources.
const resolved = fileURLToPath(import.meta.resolve("@openmatter-network/matter-sdk-core"));
if (!resolved.includes("node_modules")) fail(`resolved outside node_modules: ${resolved}`);

const v = JSON.parse(readFileSync(process.argv[2], "utf8"));

const plaintext = openSecret({
  sharedA: bytes(v.shared_a_hex),
  capsule: bytes(v.capsule_hex),
  secretId: BigInt(v.secret_id),
  epoch: v.epoch,
  bindingId: bytes(v.binding_id_hex),
  aad: bytes(v.aad_hex),
  ct: bytes(v.ct_hex),
  partials: v.partials.map((p) => ({
    point: p.point,
    partial: bytes(p.partial_hex),
    proof: bytes(p.proof_hex),
    commitment: bytes(p.commitment_hex),
  })),
});
if (hex(plaintext) !== v.expected_plaintext_hex) fail("openSecret did not recover the golden plaintext");

const sealed = encrypt(bytes(v.joint_pk_hex), v.epoch, new TextEncoder().encode("smoke"), Aad.EnvV1);
if (sealed.capsule.length !== bytes(v.capsule_hex).length) fail("encrypt produced a capsule of the wrong size");

// Fixed, non-secret seed.
const SR25519_ACCOUNT_ID_LEN = 32;
const SR25519_SIGNATURE_LEN = 64;
const key = new ApiKey(`0x${"11".repeat(32)}`);
if (key.accountId.length !== SR25519_ACCOUNT_ID_LEN) fail("ApiKey did not derive a 32-byte account id");
if (key.sign(new Uint8Array([1])).length !== SR25519_SIGNATURE_LEN) fail("ApiKey did not produce a 64-byte signature");
