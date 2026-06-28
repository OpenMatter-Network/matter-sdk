// MatterVault TypeScript SDK — runnable end-to-end demo.
//
//   cd examples/typescript && npm install && npm run demo
//
// It seals a fresh secret (real encryption), then recovers a pre-sealed secret
// from a committee (real threshold decryption). The committee here is backed by
// the cross-language test fixture so the demo runs with no live network; in
// production you'd use `FetchTransport` and fetch the committee state from chain.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Aad,
  decrypt,
  encrypt,
  storeSecret,
  type CommitteeNode,
  type Health,
  type PartialDecryptRequest,
  type PartialDecryptResponse,
  type Signer,
  type Transport,
} from "../../packages/typescript/src/index.js";
import { fromHex } from "../../packages/typescript/src/util.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(resolve(here, "../../testvectors/open_secret.json"), "utf8"));

// === 1. SEAL (pure, no network) ============================================
const jointPk = fromHex(fx.joint_pk_hex);
const epoch = fx.epoch as number;
const secret = new TextEncoder().encode("DATABASE_URL=postgres://prod\nAPI_KEY=swordfish");
const env = encrypt(jointPk, epoch, secret, Aad.EnvV1);
console.log(
  `Sealed ${secret.length} bytes -> capsule ${env.capsule.length}B, ` +
    `proof ${env.proof.length}B, ct ${env.ct.length}B`,
);

// === 2. STORE (submit with your own @polkadot/api client) ==================
const call = storeSecret(env, epoch, "prod-env", Aad.EnvV1);
console.log(
  `Would submit secrets.storeSecret(payload, epoch=${call.epoch}, ` +
    `label="${new TextDecoder().decode(call.label)}", aad="${new TextDecoder().decode(call.aad)}")`,
);

// === 3. DECRYPT a committee-sealed secret ==================================
const byIndex = new Map<number, any>((fx.subset as number[]).map((i, k) => [i, fx.partials[k]]));

const committee: Transport = {
  async health(): Promise<Health> {
    return { status: "active", epoch };
  },
  async partialDecrypt(endpoint: string, _req: PartialDecryptRequest): Promise<PartialDecryptResponse> {
    const index = Number(endpoint.split("-").at(-1));
    const p = byIndex.get(index);
    return { node_index: index, partial: "0x" + p.partial_hex, proof: "0x" + p.proof_hex, served_epoch: epoch };
  },
};

// Demo signer — the committee fixture ignores auth. In production, pass a
// `substrateSigner(accountId, sign)` whose `sign` callback holds your key.
const signer: Signer = {
  authScheme: () => "substrate",
  async authorize() {
    return { auth: "substrate", requester: "0x00", signature: "0x00" };
  },
};

const nodes: CommitteeNode[] = (fx.subset as number[]).map((index) => ({
  index,
  endpoint: `http://node-${index}`,
  shareCommitment: fromHex(byIndex.get(index).commitment_hex),
}));

const recovered = await decrypt(committee, signer, {
  secretId: BigInt(fx.secret_id),
  epoch,
  bindingId: fromHex(fx.binding_id_hex),
  aad: fromHex(fx.aad_hex),
  capsule: fromHex(fx.capsule_hex),
  ct: fromHex(fx.ct_hex),
  sharedA: fromHex(fx.shared_a_hex),
  blockHash: new Uint8Array(32),
  threshold: Number(fx.meta.t),
  nodes,
});

console.log(`\nRecovered secret: ${new TextDecoder().decode(recovered)}`);
console.log("Done ✔");
