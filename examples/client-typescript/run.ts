// Connect from an apiKey and exercise the client surface. Read-only unless
// MATTER_SUBMIT=yes. Environment variables: examples/README.md.
//
//   MATTER_API_KEY=$TEST_KEY npm start

import {
  ApiKey,
  MatterClient,
  Network,
  decimalsDisagree,
  type MatterConfig,
} from "@openmatter-network/matter-sdk";

/** Opt-in gate for anything that costs gas. */
const SUBMIT_ENV = "MATTER_SUBMIT";
const SUBMIT_VALUE = "yes";

/** Read the key from the environment, never argv (shell history, `ps`). */
function readKey(): ApiKey | undefined {
  for (const name of ["MATTER_API_KEY", "MATTER_SIGNER_SEED", "TEST_KEY"]) {
    const value = process.env[name];
    if (value !== undefined && value.trim() !== "") {
      const key = new ApiKey(value);
      // Prints the account only: `toString` is redacted.
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

async function readState(client: MatterClient): Promise<void> {
  console.log("\n--- reads (the generic surface) ---");

  const nextSecret = await client.query("Secrets", "NextSecretId");
  console.log(`  Secrets.NextSecretId        = ${nextSecret}`);

  // Absence is not an error: an unfunded account has no row.
  if (client.accountId !== undefined) {
    const entry = await client.query("System", "Account", [client.accountId]);
    console.log(`  System.Account(me)          = ${entry ?? "absent (unfunded account)"}`);
  }

  const epoch = await client.runtimeApi("KgcApi_dkg_epoch");
  console.log(`  KgcApi_dkg_epoch            = ${epoch}`);
  console.log(`  Balances.ExistentialDeposit = ${client.constant("Balances", "ExistentialDeposit")}`);
}

function demonstrateAmounts(client: MatterClient): void {
  console.log("\n--- amounts (always plancks, never numbers) ---");
  const one = client.oneToken();
  console.log(`  1 ${client.properties.tokenSymbol} = ${one} plancks`);
  console.log(`  "1.5" = ${client.parseAmount("1.5")} plancks`);
  console.log(`  ${one} plancks reads back as ${client.formatAmount(one)}`);

  try {
    client.parseAmount(`0.${"0".repeat(40)}1`);
    console.log("  unexpectedly parsed an over-precise amount");
  } catch (e) {
    console.log(`  over-precise amount rejected: ${(e as Error).message}`);
  }
}

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

  // `chill` is idempotent, self-targeted, and a no-op for a non-nominator: the
  // cheapest signed call that moves no funds.
  console.log("  submitting Staking.chill() ...");
  const receipt = await client.staking.chill();
  console.log(`  finalized in block ${receipt.blockHash}`);
  console.log(`  events: ${receipt.events.map(([p, e]) => `${p}.${e}`).join(", ")}`);
}

main().catch((error: unknown) => {
  console.error(`\nFAILED: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
