// Read-only preflight for run.ts (no gas, no extrinsics): checks the account can
// pay a fee, DKG is finalised, and how many committee nodes report /health
// "active". Every chain read goes through a read-only MatterClient; the key only
// names the account and never signs.
//
// Env: MATTER_RPC_URL (default testnet), MATTER_SIGNER_SEED or TEST_KEY.
//   cd examples/e2e && npx tsx preflight.ts

import { Keyring } from "@polkadot/keyring";
import { TypeRegistry } from "@polkadot/types";
import { hexToU8a } from "@polkadot/util";
import { cryptoWaitReady } from "@polkadot/util-crypto";

import { MatterClient } from "../../packages/typescript/src/index.js";

const HEALTH_TIMEOUT_MS = 8000;
/** What a committee node that can serve a decrypt reports as its status. */
const ACTIVE = "active";

enum Exit {
  Ok = 0,
  Failed = 1,
  Usage = 2,
}

interface NodeHealth {
  line: string;
  active: boolean;
}

/** Decodes SCALE runtime-API results; needs no metadata for these base types. */
function registryForStateCalls(): TypeRegistry {
  const registry = new TypeRegistry();
  registry.register({ KgcNodeInfoJs: { endpoint: "Bytes", dkg_index: "u64" } });
  return registry;
}

/** A runtime API read through the SDK; the result is SCALE, decoded by the caller. */
async function stateCall(client: MatterClient, method: string): Promise<Uint8Array> {
  return hexToU8a(await client.runtimeApi(method));
}

function normalizeEndpoint(raw: string): string {
  const s = raw.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
  return withScheme.replace(/\/+$/, "");
}

async function probe(index: number, endpoint: string): Promise<NodeHealth> {
  try {
    const res = await fetch(`${endpoint}/health`, { signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS) });
    const body: any = res.ok ? await res.json() : {};
    const epoch = body.epoch != null ? ` epoch=${body.epoch}` : "";
    return {
      line: `  [${index}] ${endpoint}  ${res.status} ${body.status ?? "?"}${epoch}`,
      active: body.status === ACTIVE,
    };
  } catch (e) {
    return {
      line: `  [${index}] ${endpoint}  UNREACHABLE (${e instanceof Error ? e.message : e})`,
      active: false,
    };
  }
}

async function main(): Promise<Exit> {
  const seed = process.env.MATTER_SIGNER_SEED ?? process.env.TEST_KEY;
  if (!seed) {
    console.error("Set MATTER_SIGNER_SEED or TEST_KEY (sr25519 SURI / 0x-seed).");
    return Exit.Usage;
  }

  await cryptoWaitReady();
  const pair = new Keyring({ type: "sr25519" }).addFromUri(seed);

  const rpcUrl = process.env.MATTER_RPC_URL;
  const client = await MatterClient.connect(rpcUrl ? { rpcUrl } : {});
  try {
    const chain = client.properties;
    console.log(
      `Chain:   ${chain.chainName}  (ss58=${chain.ss58Prefix}, ${chain.tokenSymbol}, ${chain.tokenDecimalsEffective}dp)`,
    );

    // A fee may not take the account below the existential deposit, so what
    // counts is what it can spend while staying alive, not its free balance.
    const balance = await client.accounts.balance(pair.publicKey);
    const spendable = balance.transferableKeepAlive;
    console.log(`Account: ${balance.account}`);
    console.log(`Balance: ${spendable} planck spendable  (${client.formatAmount(spendable)} ${chain.tokenSymbol})`);
    if (spendable === 0n) {
      console.error(`\nFAIL: account ${balance.account} has nothing to pay fees with — fund it before the live e2e.`);
      return Exit.Failed;
    }

    const registry = registryForStateCalls();
    const jointPk = registry.createType("Option<Bytes>", await stateCall(client, "KgcApi_joint_pk")) as any;
    if (jointPk.isNone || jointPk.unwrap().length === 0) {
      console.error("\nFAIL: KgcApi_joint_pk is None — DKG not finalised on this chain.");
      return Exit.Failed;
    }
    const epoch = (registry.createType("u32", await stateCall(client, "KgcApi_dkg_epoch")) as any).toNumber();
    console.log(`DKG:     epoch=${epoch}, joint_pk=${jointPk.unwrap().length}B`);

    const nodes = registry.createType(
      "Vec<(AccountId, KgcNodeInfoJs)>",
      await stateCall(client, "KgcApi_kgc_nodes"),
    ) as any[];
    console.log(`Nodes:   ${nodes.length} registered`);

    const health = await Promise.all(
      nodes.map(([, info]) =>
        probe(info.dkg_index.toNumber(), normalizeEndpoint(new TextDecoder().decode(info.endpoint.toU8a(true)))),
      ),
    );
    health.forEach(({ line }) => console.log(line));
    const active = health.filter((node) => node.active).length;

    console.log(`\nCommittee: ${active}/${nodes.length} active.`);
    console.log(
      active >= 1
        ? "Preflight OK — funded account, DKG finalised, committee reachable."
        : "WARN: no active committee nodes — decrypt half will fail.",
    );
    return Exit.Ok;
  } finally {
    await client.disconnect();
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(`\nFAILED: ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
    process.exitCode = Exit.Failed;
  },
);
