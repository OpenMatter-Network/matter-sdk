// Connect to OpenMatter from an apiKey and exercise the whole client surface.
//
// Read-only by default. Every call here is a read unless you opt into submission
// with MATTER_SUBMIT=yes, so running it costs nothing and cannot change chain
// state by accident.
//
//   MATTER_API_KEY=$TEST_KEY npm start
//   MATTER_API_KEY=$TEST_KEY MATTER_SUBMIT=yes npm start   # actually submits
//
//   MATTER_API_KEY   the key; falls back to MATTER_SIGNER_SEED, then TEST_KEY
//   MATTER_RPC_URL   endpoint override (default: testnet)
//   MATTER_NETWORK   testnet (default) or mainnet
//   MATTER_CONFIRM   must be "yes" for a signing client on mainnet
//   MATTER_SUBMIT    must be "yes" to submit anything

import {
  ApiKey,
  MatterClient,
  Network,
  decimalsDisagree,
  type MatterConfig,
} from "@openmatter-network/matter-client";

/** Opt-in gate for anything that costs gas. */
const SUBMIT_ENV = "MATTER_SUBMIT";
const SUBMIT_VALUE = "yes";

/** The key is read from the environment, never from argv — argv lands in shell
 * history and `ps` output. */
function readKey(): ApiKey | undefined {
  for (const name of ["MATTER_API_KEY", "MATTER_SIGNER_SEED", "TEST_KEY"]) {
    const value = process.env[name];
    if (value !== undefined && value.trim() !== "") {
      const key = new ApiKey(value);
      // Note what this prints: the account, never the key. `toString` is redacted,
      // so even a careless log is safe.
      console.log(`${name} -> ${key}`);
      return key;
    }
  }
  return undefined;
}

async function main(): Promise<void> {
  const network = process.env["MATTER_NETWORK"] === "mainnet" ? Network.Mainnet : Network.Testnet;
  const config: MatterConfig = { network };
  const rpcUrl = process.env["MATTER_RPC_URL"];
  if (rpcUrl !== undefined) config.rpcUrl = rpcUrl;

  const key = readKey();
  const client =
    key === undefined
      ? (console.log("No key set — connecting read-only."),
        await MatterClient.connect(config))
      : (console.log("Connecting with an api key ..."),
        await MatterClient.connectWithApiKey(key, config));

  try {
    describeChain(client);
    await readState(client);
    demonstrateAmounts(client);
    await maybeSubmit(client);
    console.log("\nDone.");
  } finally {
    await client.disconnect();
  }
}

function describeChain(client: MatterClient): void {
  const p = client.properties;
  console.log("\n--- chain ---");
  console.log(`  name            : ${p.chainName}`);
  console.log(`  spec_version    : ${p.specVersion}`);
  console.log(`  token           : ${p.tokenSymbol}`);
  console.log(`  ss58 prefix     : ${p.ss58Prefix}`);
  console.log(`  decimals (spec) : ${p.tokenDecimalsDeclared}`);
  console.log(`  decimals (live) : ${p.tokenDecimalsEffective}`);
  if (decimalsDisagree(p)) {
    console.log("  ^ the node's chain spec disagrees with its runtime; the live value wins");
  }
  console.log(`  signing as      : ${client.address ?? "(read-only)"}`);
}

/** The generic surface: every pallet the runtime exposes, resolved by name. */
async function readState(client: MatterClient): Promise<void> {
  console.log("\n--- reads (the generic surface) ---");

  const nextSecret = await client.query("Secrets", "NextSecretId");
  console.log(`  Secrets.NextSecretId        = ${nextSecret}`);

  // Absence is normal control flow, not an error: an unfunded account has no row.
  if (client.accountId !== undefined) {
    const entry = await client.query("System", "Account", [client.accountId]);
    console.log(`  System.Account(me)          = ${entry ?? "absent (unfunded account)"}`);
  }

  const epoch = await client.runtimeApi("KgcApi_dkg_epoch");
  console.log(`  KgcApi_dkg_epoch            = ${epoch}`);
  console.log(`  Balances.ExistentialDeposit = ${client.constant("Balances", "ExistentialDeposit")}`);
}

/** Amounts are always bigint plancks; conversion is explicit. */
function demonstrateAmounts(client: MatterClient): void {
  console.log("\n--- amounts (always plancks, never numbers) ---");
  const one = client.oneToken();
  console.log(`  1 ${client.properties.tokenSymbol} = ${one} plancks`);
  console.log(`  "1.5" = ${client.parseAmount("1.5")} plancks`);
  console.log(`  ${one} plancks reads back as ${client.formatAmount(one)}`);

  // Excess precision is rejected rather than rounded: losing someone's funds to a
  // silent truncation is not a trade worth making for convenience.
  try {
    client.parseAmount(`0.${"0".repeat(40)}1`);
    console.log("  unexpectedly parsed an over-precise amount");
  } catch (e) {
    console.log(`  over-precise amount rejected: ${(e as Error).message}`);
  }
}

/** What submission looks like. Gated, because it costs gas. */
async function maybeSubmit(client: MatterClient): Promise<void> {
  console.log("\n--- writes ---");

  if (client.accountId === undefined) {
    console.log("  read-only client: nothing to submit.");
    return;
  }
  if (process.env[SUBMIT_ENV] !== SUBMIT_VALUE) {
    console.log("  would submit Staking.chill() via the curated staking façade:");
    console.log("      await client.staking.chill()");
    console.log("  and the same call through the generic surface:");
    console.log('      await client.tx("Staking", "chill", [])');
    console.log(`  set ${SUBMIT_ENV}=${SUBMIT_VALUE} to actually send it (costs a fee).`);
    return;
  }

  // `chill` is the demo call because it is idempotent, self-targeted, and a no-op
  // for an account that is not nominating — the cheapest way to prove the signing
  // path end-to-end without moving funds.
  console.log("  submitting Staking.chill() ...");
  const receipt = await client.staking.chill();
  console.log(`  finalized in block ${receipt.blockHash}`);
  console.log(`  events: ${receipt.events.map(([p, e]) => `${p}.${e}`).join(", ")}`);
}

main().catch((error: unknown) => {
  console.error(`\nFAILED: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
