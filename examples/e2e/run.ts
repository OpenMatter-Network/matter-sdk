// Live Secrets round trip against a chain + committee, through MatterClient: the
// store is encoded, signed and followed to finality by the SDK, and the committee
// requests are authorized by the same KeySigner. Needs a FUNDED account; the key
// stays in the @polkadot keyring pair and the SDK only gets a sign callback.
// See README.md.

import { Keyring } from "@polkadot/keyring";
import { TypeRegistry } from "@polkadot/types";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { hexToU8a, u8aConcat, u8aToHex } from "@polkadot/util";

import {
  Aad,
  decrypt,
  encrypt,
  FetchTransport,
  keySigner,
  storeSecret,
  wipe,
  type CommitteeNode,
  type EncryptedSecret,
  type KeySigner,
} from "../../packages/typescript-core/src/index.js";
import { MatterClient, secretIdFromReceipt } from "../../packages/typescript/src/index.js";
import { defaultRpcUrl, Network } from "../../packages/typescript/src/network.js";

/** The label the stored secret carries on chain. */
const SECRET_LABEL = "ts-e2e";

const AAD_TAGS: Record<string, Aad> = {
  env: Aad.EnvV1,
  tls: Aad.TlsV1,
  storage: Aad.StorageCredsV1,
  dek: Aad.VolumeDekV1,
  dataset: Aad.DatasetSourceCredsV1,
};

interface Config {
  rpcUrl: string;
  seed: string;
  network: Network;
  secret: string;
  secretId?: string;
  aad: Aad;
}

function readConfig(): Config | null {
  const seed = process.env.MATTER_SIGNER_SEED ?? process.env.TEST_KEY;
  if (!seed) return null;

  // Default endpoint per network: testvectors/networks.json.
  const network = (process.env.MATTER_NETWORK ?? "testnet").toLowerCase();
  if (network !== Network.Testnet && network !== Network.Mainnet) {
    throw new Error(`MATTER_NETWORK must be testnet or mainnet, got ${network}`);
  }
  const rpcUrl = process.env.MATTER_RPC_URL ?? defaultRpcUrl(network)!;
  // The URL counts too, so MATTER_NETWORK=testnet pointed at a mainnet node is caught.
  const looksLikeMainnet = network === Network.Mainnet || rpcUrl.includes("mainnet");
  if (looksLikeMainnet && process.env.MATTER_CONFIRM !== "yes") {
    throw new Error(
      `Refusing to run against mainnet (${rpcUrl}) without MATTER_CONFIRM=yes ` +
        "(this posts on-chain and spends fees).",
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
      "Secrets e2e test — set these env vars and re-run:",
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

const STATE_CALL_TYPES = {
  KgcNodeInfoJs: { endpoint: "Bytes", dkg_index: "u64" },
  EncryptedSecretJs: { binding_id: "Bytes", capsule: "Bytes", proof: "Bytes", ct: "Bytes" },
};
/** Decodes SCALE runtime-API results; needs no metadata for these base types. */
function registryForStateCalls(): TypeRegistry {
  const registry = new TypeRegistry();
  registry.register(STATE_CALL_TYPES);
  return registry;
}

/** A runtime API read through the SDK; the result is SCALE, decoded by the caller. */
async function stateCall(client: MatterClient, method: string, argsHex = "0x"): Promise<Uint8Array> {
  return hexToU8a(await client.runtimeApi(method, argsHex));
}

function decodeOptionBytes(api: TypeRegistry, bytes: Uint8Array): Uint8Array | null {
  const opt = api.createType("Option<Bytes>", bytes) as any;
  return opt.isSome ? opt.unwrap().toU8a(true) : null;
}

async function fetchEncryptionContext(
  client: MatterClient,
  api: TypeRegistry,
): Promise<{ jointPk: Uint8Array; epoch: number }> {
  const jointPk = decodeOptionBytes(api, await stateCall(client, "KgcApi_joint_pk"));
  if (!jointPk || jointPk.length === 0) throw new Error("KGC DKG not finalised on chain (joint_pk is None).");
  const epoch = (api.createType("u32", await stateCall(client, "KgcApi_dkg_epoch")) as any).toNumber();
  return { jointPk, epoch };
}

interface KgcNodeRow {
  account: string;
  dkgIndex: number;
  endpoint: string;
}

async function readNodes(client: MatterClient, api: TypeRegistry): Promise<KgcNodeRow[]> {
  const vec = api.createType(
    "Vec<(AccountId, KgcNodeInfoJs)>",
    await stateCall(client, "KgcApi_kgc_nodes"),
  ) as any[];
  return vec.map((pair) => ({
    account: pair[0].toString(),
    dkgIndex: pair[1].dkg_index.toNumber(),
    endpoint: normalizeEndpoint(new TextDecoder().decode(pair[1].endpoint.toU8a(true))),
  }));
}

async function readSharedA(client: MatterClient, api: TypeRegistry): Promise<Uint8Array> {
  const v = decodeOptionBytes(api, await stateCall(client, "KgcApi_shared_a"));
  if (!v) throw new Error("KGC shared_a unavailable (DKG not finalised).");
  return v;
}

async function readThresholdAtEpoch(client: MatterClient, api: TypeRegistry, epoch: number): Promise<number> {
  const argsHex = u8aToHex(api.createType("u32", epoch).toU8a());
  const tuple = api.createType("(u64,u64)", await stateCall(client, "KgcApi_threshold_params_at_epoch", argsHex)) as any;
  return tuple[1].toNumber();
}

async function readShareCommitment(
  client: MatterClient,
  api: TypeRegistry,
  epoch: number,
  account: string,
): Promise<Uint8Array> {
  const argsHex = u8aToHex(
    u8aConcat(api.createType("u32", epoch).toU8a(), api.createType("AccountId", account).toU8a()),
  );
  const v = decodeOptionBytes(api, await stateCall(client, "KgcApi_share_commitment", argsHex));
  if (!v) throw new Error(`no share commitment for node ${account} at epoch ${epoch}`);
  return v;
}

function secretIdArgHex(api: TypeRegistry, secretId: bigint): string {
  // SCALE u128 (little-endian).
  return u8aToHex(api.createType("u128", secretId).toU8a());
}

async function readSecretPayload(client: MatterClient, api: TypeRegistry, secretId: bigint): Promise<EncryptedSecret> {
  const opt = api.createType(
    "Option<EncryptedSecretJs>",
    await stateCall(client, "SecretsApi_secret_payload", secretIdArgHex(api, secretId)),
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

async function readSecretEpoch(client: MatterClient, api: TypeRegistry, secretId: bigint): Promise<number> {
  const opt = api.createType(
    "Option<u32>",
    await stateCall(client, "SecretsApi_secret_epoch", secretIdArgHex(api, secretId)),
  ) as any;
  if (!opt.isSome) throw new Error(`secret ${secretId} has no epoch`);
  return opt.unwrap().toNumber();
}

function normalizeEndpoint(raw: string): string {
  const s = raw.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
  return withScheme.replace(/\/+$/, "");
}

/**
 * Store through the SDK: `SecretsFacade` shapes the call, `PolkadotBackend`
 * encodes it against live metadata, hashes the (far over 256 bytes) signing
 * payload before the KeySigner sees it, and resolves once finalized. The id
 * comes from the receipt's `Secrets.SecretStored` event.
 */
async function storeOnChain(client: MatterClient, env: EncryptedSecret, epoch: number, aad: Aad): Promise<bigint> {
  const receipt = await client.secrets.store(storeSecret(env, epoch, SECRET_LABEL, aad));
  return secretIdFromReceipt(receipt);
}

async function main(): Promise<void> {
  const cfg = readConfig();
  if (!cfg) {
    usage();
    process.exit(2);
  }

  await cryptoWaitReady();
  const pair = new Keyring({ type: "sr25519" }).addFromUri(cfg.seed);
  console.log(`Network: ${cfg.network}   Signer: ${pair.address}`);

  // The custom-signer seam, as an HSM or KMS would implement it: the SDK hands
  // over bytes to sign and gets a raw 64-byte sr25519 signature back.
  const hsmLike: KeySigner = { accountId: pair.publicKey, sign: (message) => pair.sign(message) };
  const client = await MatterClient.connectWithSigner(hsmLike, {
    network: cfg.network,
    rpcUrl: cfg.rpcUrl,
    confirmMainnet: process.env.MATTER_CONFIRM === "yes",
  });
  // No second connection: every read and write goes through the client. The
  // registry only decodes the SCALE that `client.runtimeApi` returns.
  const api = registryForStateCalls();
  try {
    const { jointPk, epoch } = await fetchEncryptionContext(client, api);
    console.log(`Connected. Committee epoch=${epoch}, joint_pk=${jointPk.length}B`);

    // 1. Store a new secret, or use MATTER_SECRET_ID.
    let secretId: bigint;
    let env: EncryptedSecret;
    let secretEpoch: number;
    const plaintext = new TextEncoder().encode(cfg.secret);

    if (cfg.secretId) {
      secretId = BigInt(cfg.secretId);
      env = await readSecretPayload(client, api, secretId);
      secretEpoch = await readSecretEpoch(client, api, secretId);
      console.log(`Using existing secret ${secretId} (epoch ${secretEpoch}).`);
    } else {
      env = encrypt(jointPk, epoch, plaintext, cfg.aad);
      console.log(
        `Sealed ${plaintext.length}B -> capsule ${env.capsule.length}B, proof ${env.proof.length}B, ct ${env.ct.length}B`,
      );
      console.log("Submitting Secrets.store_secret through MatterClient ...");
      secretId = await storeOnChain(client, env, epoch, cfg.aad);
      secretEpoch = await readSecretEpoch(client, api, secretId);
      console.log(`Stored on chain: secret_id=${secretId} (epoch ${secretEpoch}).`);
      // Decrypt the persisted bytes, not the local envelope.
      env = await readSecretPayload(client, api, secretId);
    }

    // 2. Gather committee state for the secret's epoch.
    const [nodes, sharedA, threshold] = await Promise.all([
      readNodes(client, api),
      readSharedA(client, api),
      readThresholdAtEpoch(client, api, secretEpoch),
    ]);
    console.log(`Committee: ${nodes.length} nodes, threshold t=${threshold}.`);

    const committeeNodes: CommitteeNode[] = await Promise.all(
      nodes.map(async (n) => ({
        index: n.dkgIndex,
        endpoint: n.endpoint,
        shareCommitment: await readShareCommitment(client, api, secretEpoch, n.account),
      })),
    );

    // 3. Threshold-decrypt with the same KeySigner that signed the store.
    const blockHash = await client.finalizedHead();
    const signer = keySigner(client.signer!);

    console.log("Collecting partial decryptions ...");
    const recovered = await decrypt(new FetchTransport(), signer, {
      secretId,
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

    // Recovered plaintext is compared in process, never printed.
    console.log(`\nRecovered ${recovered.length} bytes`);
    const matches = new TextDecoder().decode(recovered) === cfg.secret;
    wipe(recovered);
    if (!cfg.secretId) {
      if (!matches) {
        throw new Error("MISMATCH: recovered plaintext != original");
      }
      console.log("Round trip verified ✔");
    }
  } finally {
    await client.disconnect();
  }
}

main().catch((e) => {
  console.error(`\nFAILED: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
