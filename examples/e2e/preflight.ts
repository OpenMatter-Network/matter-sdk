// Read-only testnet preflight — NO gas, NO extrinsics.
//
// Confirms the three things the live e2e depends on before we spend anything:
//   1. the key derives an account, and that account is FUNDED,
//   2. the chain is reachable over ws and DKG is finalised (joint_pk present),
//   3. the committee is live (how many nodes report /health "active").
//
// Env: MATTER_RPC_URL (default testnet), MATTER_SIGNER_SEED or TEST_KEY (sr25519 SURI/0x-seed).
//   cd examples/e2e && npx tsx preflight.ts

import { ApiPromise, WsProvider } from "@polkadot/api";
import { Keyring } from "@polkadot/keyring";
import { cryptoWaitReady } from "@polkadot/util-crypto";

const DEFAULT_RPC = "wss://node2.testnet.openmatter.network";

async function stateCall(api: ApiPromise, method: string, argsHex = "0x"): Promise<Uint8Array> {
  const res = await (api.rpc as any).state.call(method, argsHex);
  return res.toU8a(true);
}

function decodeOptionBytes(api: ApiPromise, bytes: Uint8Array): Uint8Array | null {
  const opt = api.registry.createType("Option<Bytes>", bytes) as any;
  return opt.isSome ? opt.unwrap().toU8a(true) : null;
}

function normalizeEndpoint(raw: string): string {
  const s = raw.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
  return withScheme.replace(/\/+$/, "");
}

async function main(): Promise<void> {
  const rpcUrl = process.env.MATTER_RPC_URL ?? DEFAULT_RPC;
  const seed = process.env.MATTER_SIGNER_SEED ?? process.env.TEST_KEY;
  if (!seed) {
    console.error("Set MATTER_SIGNER_SEED or TEST_KEY (sr25519 SURI / 0x-seed).");
    process.exit(2);
  }

  await cryptoWaitReady();
  const pair = new Keyring({ type: "sr25519" }).addFromUri(seed);

  const api = await ApiPromise.create({ provider: new WsProvider(rpcUrl) });
  try {
    const [chain, decimals, tokens] = [
      (await api.rpc.system.chain()).toString(),
      api.registry.chainDecimals[0] ?? 18,
      api.registry.chainTokens[0] ?? "UNIT",
    ];
    console.log(`Chain:   ${chain}  (ss58=${api.registry.chainSS58}, ${tokens}, ${decimals}dp)`);
    console.log(`Account: ${pair.address}`);

    // 1. Balance.
    const acct = (await api.query.system.account(pair.address)) as any;
    const free: bigint = acct.data.free.toBigInt();
    const human = Number(free) / 10 ** Number(decimals);
    console.log(`Balance: ${free} planck  (~${human} ${tokens})`);
    if (free === 0n) {
      console.error(`\nFAIL: account ${pair.address} has zero balance — fund it before the live e2e.`);
      process.exit(1);
    }

    // 2. DKG context.
    api.registry.register({ KgcNodeInfoJs: { endpoint: "Bytes", dkg_index: "u64" } });
    const jointPk = decodeOptionBytes(api, await stateCall(api, "KgcApi_joint_pk"));
    if (!jointPk || jointPk.length === 0) {
      console.error("\nFAIL: KgcApi_joint_pk is None — DKG not finalised on this chain.");
      process.exit(1);
    }
    const epoch = (api.registry.createType("u32", await stateCall(api, "KgcApi_dkg_epoch")) as any).toNumber();
    console.log(`DKG:     epoch=${epoch}, joint_pk=${jointPk.length}B`);

    // 3. Committee health.
    const vec = api.registry.createType(
      "Vec<(AccountId, KgcNodeInfoJs)>",
      await stateCall(api, "KgcApi_kgc_nodes"),
    ) as any[];
    const nodes = vec.map((pair) => ({
      index: pair[1].dkg_index.toNumber(),
      endpoint: normalizeEndpoint(new TextDecoder().decode(pair[1].endpoint.toU8a(true))),
    }));
    console.log(`Nodes:   ${nodes.length} registered`);

    let active = 0;
    for (const n of nodes) {
      try {
        const res = await fetch(`${n.endpoint}/health`, { signal: AbortSignal.timeout(8000) });
        const body: any = res.ok ? await res.json() : {};
        const ok = body.status === "active";
        if (ok) active++;
        console.log(`  [${n.index}] ${n.endpoint}  ${res.status} ${body.status ?? "?"}${body.epoch != null ? ` epoch=${body.epoch}` : ""}`);
      } catch (e) {
        console.log(`  [${n.index}] ${n.endpoint}  UNREACHABLE (${e instanceof Error ? e.message : e})`);
      }
    }
    console.log(`\nCommittee: ${active}/${nodes.length} active.`);
    console.log(active >= 1 ? "Preflight OK — funded account, DKG finalised, committee reachable." : "WARN: no active committee nodes — decrypt half will fail.");
  } finally {
    await api.disconnect();
  }
}

main().catch((e) => {
  console.error(`\nFAILED: ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
  process.exit(1);
});
