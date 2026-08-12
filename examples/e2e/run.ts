// MatterVault end-to-end test against a LIVE chain + committee.
//
// Flow: connect → fetch committee context → encrypt → secrets.storeSecret →
// read the secret back from chain → threshold-decrypt → assert round trip.
//
// You provide a FUNDED account: the storeSecret extrinsic pays a fee, and the
// same key signs the partial-decrypt requests. The key never leaves this
// process — it stays in the @polkadot keyring pair; the SDK only gets a sign
// callback.
//
// Config (env, so keys never land in shell history / argv):
//   MATTER_RPC_URL     ws(s):// endpoint of the chain node (default: testnet)
//   MATTER_SIGNER_SEED sr25519 SURI: mnemonic or 0x-seed; falls back to TEST_KEY
//   MATTER_NETWORK     "testnet" (default) | "mainnet"
//   MATTER_SECRET      plaintext to seal (default: a sample env line)
//   MATTER_SECRET_ID   decrypt this existing secret instead of storing a new one
//   MATTER_AAD         env (default) | tls | storage | dek | dataset
//   MATTER_CONFIRM     "yes" — required to act against mainnet
//
// Run:  cd examples/e2e && npm install && npm start

import { ApiPromise, WsProvider } from "@polkadot/api";
import { Keyring } from "@polkadot/keyring";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { u8aConcat, u8aToHex } from "@polkadot/util";

import {
  Aad,
  aadBytes,
  decrypt,
  encrypt,
  FetchTransport,
  storeSecret,
  substrateSigner,
  type CommitteeNode,
  type EncryptedSecret,
} from "../../packages/typescript/src/index.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const AAD_TAGS: Record<string, Aad> = {
  env: Aad.EnvV1,
  tls: Aad.TlsV1,
  storage: Aad.StorageCredsV1,
  dek: Aad.VolumeDekV1,
  dataset: Aad.DatasetSourceCredsV1,
};

/** Same default as the Rust/Python/Go harnesses. */
const DEFAULT_RPC_URL = "wss://node2.testnet.openmatter.network";

interface Config {
  rpcUrl: string;
  seed: string;
  network: string;
  secret: string;
  secretId?: string;
  aad: Aad;
}

function readConfig(): Config | null {
  const rpcUrl = process.env.MATTER_RPC_URL ?? DEFAULT_RPC_URL;
  const seed = process.env.MATTER_SIGNER_SEED ?? process.env.TEST_KEY;
  if (!seed) return null;

  const network = (process.env.MATTER_NETWORK ?? "testnet").toLowerCase();
  if (network === "mainnet" && process.env.MATTER_CONFIRM !== "yes") {
    throw new Error(
      "Refusing to run against mainnet without MATTER_CONFIRM=yes (this posts on-chain and spends fees).",
    );
  }
  const aadTag = (process.env.MATTER_AAD ?? "env").toLowerCase();
  const aad = AAD_TAGS[aadTag];
  if (!aad) throw new Error(`unknown MATTER_AAD "${aadTag}"; use one of ${Object.keys(AAD_TAGS).join(", ")}`);

  return {
    rpcUrl,
    seed,
    network,
    secret: process.env.MATTER_SECRET ?? "API_KEY=swordfish\nDATABASE_URL=postgres://prod",
    secretId: process.env.MATTER_SECRET_ID,
    aad,
  };
}

function usage(): void {
  console.error(
    [
      "MatterVault e2e test — set these env vars and re-run:",
      "  MATTER_SIGNER_SEED=<sr25519 SURI>  (required; a FUNDED account. TEST_KEY also accepted)",
      "  MATTER_RPC_URL=wss://<node>        (default: testnet)",
      "  MATTER_NETWORK=testnet|mainnet     (default testnet)",
      "  MATTER_SECRET='KEY=VALUE'          (optional)",
      "  MATTER_SECRET_ID=<u128>            (optional: decrypt existing, skip store)",
      "  MATTER_AAD=env|tls|storage|dek|dataset  (default env)",
      "  MATTER_CONFIRM=yes                 (required for mainnet)",
    ].join("\n"),
  );
}

// ---------------------------------------------------------------------------
// Chain reads (exact runtime-API names the committee/pallets expose)
// ---------------------------------------------------------------------------

const STATE_CALL_TYPES = {
  KgcNodeInfoJs: { endpoint: "Bytes", dkg_index: "u64" },
  EncryptedSecretJs: { binding_id: "Bytes", capsule: "Bytes", proof: "Bytes", ct: "Bytes" },
};
let typesRegistered = false;
function ensureTypes(api: ApiPromise): void {
  if (typesRegistered) return;
  api.registry.register(STATE_CALL_TYPES);
  typesRegistered = true;
}

async function stateCall(api: ApiPromise, method: string, argsHex = "0x"): Promise<Uint8Array> {
  const res = await (api.rpc as any).state.call(method, argsHex);
  return res.toU8a(true);
}

function decodeOptionBytes(api: ApiPromise, bytes: Uint8Array): Uint8Array | null {
  const opt = api.registry.createType("Option<Bytes>", bytes) as any;
  return opt.isSome ? opt.unwrap().toU8a(true) : null;
}

async function fetchEncryptionContext(api: ApiPromise): Promise<{ jointPk: Uint8Array; epoch: number }> {
  const jointPk = decodeOptionBytes(api, await stateCall(api, "KgcApi_joint_pk"));
  if (!jointPk || jointPk.length === 0) throw new Error("KGC DKG not finalised on chain (joint_pk is None).");
  const epoch = (api.registry.createType("u32", await stateCall(api, "KgcApi_dkg_epoch")) as any).toNumber();
  return { jointPk, epoch };
}

interface KgcNodeRow {
  account: string;
  dkgIndex: number;
  endpoint: string;
}

async function readNodes(api: ApiPromise): Promise<KgcNodeRow[]> {
  ensureTypes(api);
  const vec = api.registry.createType(
    "Vec<(AccountId, KgcNodeInfoJs)>",
    await stateCall(api, "KgcApi_kgc_nodes"),
  ) as any[];
  return vec.map((pair) => ({
    account: pair[0].toString(),
    dkgIndex: pair[1].dkg_index.toNumber(),
    endpoint: normalizeEndpoint(new TextDecoder().decode(pair[1].endpoint.toU8a(true))),
  }));
}

async function readSharedA(api: ApiPromise): Promise<Uint8Array> {
  const v = decodeOptionBytes(api, await stateCall(api, "KgcApi_shared_a"));
  if (!v) throw new Error("KGC shared_a unavailable (DKG not finalised).");
  return v;
}

async function readThresholdAtEpoch(api: ApiPromise, epoch: number): Promise<number> {
  const argsHex = u8aToHex(api.createType("u32", epoch).toU8a());
  const tuple = api.registry.createType("(u64,u64)", await stateCall(api, "KgcApi_threshold_params_at_epoch", argsHex)) as any;
  return tuple[1].toNumber();
}

async function readShareCommitment(api: ApiPromise, epoch: number, account: string): Promise<Uint8Array> {
  const argsHex = u8aToHex(
    u8aConcat(api.createType("u32", epoch).toU8a(), api.createType("AccountId", account).toU8a()),
  );
  const v = decodeOptionBytes(api, await stateCall(api, "KgcApi_share_commitment", argsHex));
  if (!v) throw new Error(`no share commitment for node ${account} at epoch ${epoch}`);
  return v;
}

function secretIdArgHex(api: ApiPromise, secretId: string): string {
  // state.call wants the SCALE (little-endian) u128.
  return u8aToHex(api.createType("u128", BigInt(secretId)).toU8a());
}

async function readSecretPayload(api: ApiPromise, secretId: string): Promise<EncryptedSecret> {
  ensureTypes(api);
  const opt = api.registry.createType(
    "Option<EncryptedSecretJs>",
    await stateCall(api, "SecretsApi_secret_payload", secretIdArgHex(api, secretId)),
  ) as any;
  if (!opt.isSome) throw new Error(`secret ${secretId} not found on chain`);
  const s = opt.unwrap();
  return {
    bindingId: s.binding_id.toU8a(true),
    capsule: s.capsule.toU8a(true),
    proof: s.proof.toU8a(true),
    ct: s.ct.toU8a(true),
  };
}

async function readSecretEpoch(api: ApiPromise, secretId: string): Promise<number> {
  const opt = api.registry.createType(
    "Option<u32>",
    await stateCall(api, "SecretsApi_secret_epoch", secretIdArgHex(api, secretId)),
  ) as any;
  if (!opt.isSome) throw new Error(`secret ${secretId} has no epoch`);
  return opt.unwrap().toNumber();
}

function normalizeEndpoint(raw: string): string {
  const s = raw.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
  return withScheme.replace(/\/+$/, "");
}

// ---------------------------------------------------------------------------
// storeSecret extrinsic (submit + read back the assigned secret_id)
// ---------------------------------------------------------------------------

async function storeOnChain(
  api: ApiPromise,
  pair: any,
  env: EncryptedSecret,
  epoch: number,
  aad: Aad,
): Promise<string> {
  const payload = {
    binding_id: u8aToHex(env.bindingId),
    capsule: u8aToHex(env.capsule),
    proof: u8aToHex(env.proof),
    ct: u8aToHex(env.ct),
  };
  const tx = (api.tx as any).secrets.storeSecret(payload, epoch, "0x", u8aToHex(aadBytes(aad)));

  return await new Promise<string>((resolve, reject) => {
    tx.signAndSend(pair, ({ status, events, dispatchError }: any) => {
      if (dispatchError) {
        reject(new Error(decodeDispatchError(api, dispatchError)));
        return;
      }
      // Wait for FINALIZATION, not just in-block: the committee authorizes a
      // partial-decrypt against a finalized block_hash, so a secret decrypted
      // before its storing block is finalized is not yet visible to the nodes
      // (they return 403). Resolving on isInBlock here raced the finalized head.
      if (status.isFinalized) {
        for (const { event } of events) {
          if (event.section === "secrets" && event.method === "SecretStored") {
            resolve(event.data[0].toString());
            return;
          }
        }
        reject(new Error("storeSecret landed but emitted no secrets.SecretStored event"));
      }
    }).catch(reject);
  });
}

function decodeDispatchError(api: ApiPromise, dispatchError: any): string {
  if (dispatchError.isModule) {
    const meta = api.registry.findMetaError(dispatchError.asModule);
    return `storeSecret failed: ${meta.section}.${meta.name} — ${meta.docs.join(" ")}`;
  }
  return `storeSecret failed: ${dispatchError.toString()}`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const cfg = readConfig();
  if (!cfg) {
    usage();
    process.exit(2);
  }

  await cryptoWaitReady();
  const pair = new Keyring({ type: "sr25519" }).addFromUri(cfg.seed);
  console.log(`Network: ${cfg.network}   Signer: ${pair.address}`);

  const api = await ApiPromise.create({ provider: new WsProvider(cfg.rpcUrl) });
  try {
    const { jointPk, epoch } = await fetchEncryptionContext(api);
    console.log(`Connected. Committee epoch=${epoch}, joint_pk=${jointPk.length}B`);

    // 1. Determine the secret to decrypt: either store a new one, or use an existing id.
    let secretId: string;
    let env: EncryptedSecret;
    let secretEpoch: number;
    const plaintext = new TextEncoder().encode(cfg.secret);

    if (cfg.secretId) {
      secretId = cfg.secretId;
      env = await readSecretPayload(api, secretId);
      secretEpoch = await readSecretEpoch(api, secretId);
      console.log(`Using existing secret ${secretId} (epoch ${secretEpoch}).`);
    } else {
      env = encrypt(jointPk, epoch, plaintext, cfg.aad);
      console.log(
        `Sealed ${plaintext.length}B -> capsule ${env.capsule.length}B, proof ${env.proof.length}B, ct ${env.ct.length}B`,
      );
      console.log("Submitting secrets.storeSecret ...");
      secretId = await storeOnChain(api, pair, env, epoch, cfg.aad);
      secretEpoch = await readSecretEpoch(api, secretId);
      console.log(`Stored on chain: secret_id=${secretId} (epoch ${secretEpoch}).`);
      // Read the envelope back from chain so the decrypt uses the persisted bytes.
      env = await readSecretPayload(api, secretId);
    }

    // 2. Gather committee state for the secret's epoch.
    const [nodes, sharedA, threshold] = await Promise.all([
      readNodes(api),
      readSharedA(api),
      readThresholdAtEpoch(api, secretEpoch),
    ]);
    console.log(`Committee: ${nodes.length} nodes, threshold t=${threshold}.`);

    const committeeNodes: CommitteeNode[] = await Promise.all(
      nodes.map(async (n) => ({
        index: n.dkgIndex,
        endpoint: n.endpoint,
        shareCommitment: await readShareCommitment(api, secretEpoch, n.account),
      })),
    );

    // 3. Threshold-decrypt. The signer wraps the keyring pair — the key stays here.
    const blockHash = (await api.rpc.chain.getFinalizedHead()).toU8a();
    const signer = substrateSigner(pair.publicKey, (p) => pair.sign(p));

    console.log("Collecting partial decryptions ...");
    const recovered = await decrypt(new FetchTransport(), signer, {
      secretId: BigInt(secretId),
      epoch: secretEpoch,
      bindingId: env.bindingId,
      aad: cfg.aad,
      capsule: env.capsule,
      ct: env.ct,
      sharedA,
      blockHash,
      threshold,
      nodes: committeeNodes,
    });

    const recoveredText = new TextDecoder().decode(recovered);
    console.log(`\nRecovered: ${recoveredText}`);
    if (!cfg.secretId) {
      if (recoveredText !== cfg.secret) {
        throw new Error("MISMATCH: recovered plaintext != original");
      }
      console.log("Round trip verified ✔");
    }
  } finally {
    await api.disconnect();
  }
}

main().catch((e) => {
  console.error(`\nFAILED: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
