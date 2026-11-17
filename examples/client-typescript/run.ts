// Connect from an apiKey and exercise the client surface. Read-only unless
// MATTER_SUBMIT=yes. Environment variables: examples/README.md.
//
//   MATTER_API_KEY=$TEST_KEY npm start

import {
  ApiKey,
  MatterClient,
  Network,
  decimalsDisagree,
  type FeeEstimate,
  type MatterConfig,
} from "@openmatter-network/matter-sdk";

/** Opt-in gate for anything that costs gas. */
const SUBMIT_ENV = "MATTER_SUBMIT";
const SUBMIT_VALUE = "yes";

/**
 * The well-known development account, read when no key is set so a read-only
 * run still shows a real balance.
 */
const SAMPLE_ACCOUNT = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

/** The call this tour submits behind the gate, and so the one it prices. */
const WRITE_PALLET = "Staking";
const WRITE_CALL = "chill";

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
    await readBalance(client);
    await preflight(client);
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

/** Façade reads: one question, one call, no pallet or encoding knowledge. */
async function readBalance(client: MatterClient): Promise<void> {
  console.log("\n--- reads (friendly helpers) ---");

  // Two reads, one block: the balance is pinned to the head just read.
  const head = await client.network.head();
  const balance = await client.accounts.at(head.hash).balance(client.accountId ?? SAMPLE_ACCOUNT);
  const amount = (plancks: bigint): string => tokens(client, plancks);

  console.log(`  at block        : ${head.number}`);
  console.log(`  account         : ${balance.account}`);
  console.log(`  exists          : ${balance.exists}`);
  console.log(`  total           : ${amount(balance.total)}`);
  // Not `free`: freezes and the existential deposit hold some of it back.
  console.log(`  transferable    : ${amount(balance.transferable)}`);
  for (const hold of balance.holds) {
    console.log(`  on hold         : ${amount(hold.amount)} for ${hold.reason}`);
  }
  for (const freeze of balance.freezes) {
    console.log(`  frozen          : ${amount(freeze.amount)} for ${freeze.reason}`);
  }
}

/** An amount of plancks as the chain's token, for printing. */
function tokens(client: MatterClient, plancks: bigint): string {
  return `${client.formatAmount(plancks)} ${client.properties.tokenSymbol}`;
}

/**
 * Whose balance a fee comes out of, and how the tour knows. The runtime's answer
 * comes first; where it has none, the signer is the working assumption; a
 * read-only client charges nobody, so the sample account stands in.
 */
function chargedTo(estimate: FeeEstimate): { payer: string; how: string } {
  if (estimate.payer !== undefined) {
    const how = estimate.billedTo === undefined ? "per the runtime" : "an organization's treasury";
    return { payer: estimate.payer, how };
  }
  if (estimate.signer !== undefined) {
    return { payer: estimate.signer, how: "the signer; the runtime did not say" };
  }
  return { payer: SAMPLE_ACCOUNT, how: "a sample account; this client is read-only" };
}

/** Three reads put together: can whoever pays for this tour's write afford it? */
async function preflight(client: MatterClient): Promise<void> {
  console.log("\n--- pre-flight (three reads, one block) ---");

  // Every read is pinned to one block, so the fee and the balance agree.
  const head = await client.network.head();
  const estimate = await client.fees.at(head.hash).estimate(WRITE_PALLET, WRITE_CALL, []);
  const { payer, how } = chargedTo(estimate);
  const balance = await client.accounts.at(head.hash).balance(payer);
  // A fee may not take the payer below the existential deposit.
  const spendable = balance.transferableKeepAlive;
  const deposit = client.network.info().existentialDeposit;

  console.log(`  call            : ${estimate.pallet}.${estimate.call}`);
  console.log(`  at block        : ${head.number}`);
  console.log(`  fee             : ${tokens(client, estimate.partialFee)} for ${estimate.encodedLen} bytes`);
  console.log(`  charged to      : ${balance.account} (${how})`);
  console.log(
    `  can spend       : ${tokens(client, spendable)}, keeping the existential deposit of ${tokens(client, deposit)}`,
  );
  console.log(
    spendable >= estimate.partialFee
      ? `  verdict         : affordable, leaving ${tokens(client, spendable - estimate.partialFee)}`
      : `  verdict         : short by ${tokens(client, estimate.partialFee - spendable)}`,
  );
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
