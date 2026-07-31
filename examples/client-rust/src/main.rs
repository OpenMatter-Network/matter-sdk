//! Connect to OpenMatter from an `apiKey` and exercise the whole client surface.
//!
//! **Read-only by default.** Every call here is a read unless you opt into
//! submission with `MATTER_SUBMIT=yes`, so running it costs nothing and cannot
//! change chain state by accident.
//!
//! ```bash
//! # Read-only: connects, reads state, and dry-describes what it would submit.
//! MATTER_API_KEY=$TEST_KEY cargo run -p matter-client-example
//!
//! # Actually submit the (cheap, self-targeted) demo extrinsic.
//! MATTER_API_KEY=$TEST_KEY MATTER_SUBMIT=yes cargo run -p matter-client-example
//! ```
//!
//! | Variable | Meaning |
//! |---|---|
//! | `MATTER_API_KEY` | the key; falls back to `MATTER_SIGNER_SEED`, then `TEST_KEY` |
//! | `MATTER_RPC_URL` | endpoint override (default: testnet) |
//! | `MATTER_NETWORK` | `testnet` (default) or `mainnet` |
//! | `MATTER_CONFIRM` | must be `yes` for a signing client on mainnet |
//! | `MATTER_SUBMIT` | must be `yes` to submit anything |

use anyhow::{Context, Result};
use matter_vault::chain::{MatterClient, MatterConfig, Network, Value};
use matter_vault::ApiKey;

/// Opt-in gate for anything that costs gas.
const SUBMIT_ENV: &str = "MATTER_SUBMIT";
const SUBMIT_VALUE: &str = "yes";

#[tokio::main]
async fn main() -> Result<()> {
    let network = match std::env::var("MATTER_NETWORK").ok().as_deref() {
        Some("mainnet") => Network::Mainnet,
        _ => Network::Testnet,
    };
    let mut config = MatterConfig::for_network(network);
    if let Ok(url) = std::env::var("MATTER_RPC_URL") {
        config.rpc_url = Some(url);
    }

    // The key is read from the environment, never from argv — argv lands in shell
    // history and `ps` output.
    let client = match read_key()? {
        Some(key) => {
            println!("Connecting with an api key ...");
            MatterClient::connect_with_api_key(config, key).await?
        }
        None => {
            println!(
                "No MATTER_API_KEY / MATTER_SIGNER_SEED / TEST_KEY set — connecting read-only."
            );
            MatterClient::connect(config).await?
        }
    };

    describe_chain(&client);
    read_state(&client).await?;
    demonstrate_amounts(&client);
    maybe_submit(&client).await?;

    println!("\nDone.");
    Ok(())
}

/// `MATTER_API_KEY`, then `MATTER_SIGNER_SEED`, then `TEST_KEY`.
fn read_key() -> Result<Option<ApiKey>> {
    for var in ["MATTER_API_KEY", "MATTER_SIGNER_SEED", "TEST_KEY"] {
        match std::env::var(var) {
            Ok(value) if !value.trim().is_empty() => {
                let key =
                    ApiKey::parse(&value).with_context(|| format!("parsing the key from {var}"))?;
                // Note what this prints: the account, never the key. `ApiKey`'s
                // Debug is redacted, so even a careless log is safe.
                println!("{var} -> {key:?}");
                return Ok(Some(key));
            }
            _ => continue,
        }
    }
    Ok(None)
}

fn describe_chain(client: &MatterClient) {
    let props = client.properties();
    println!("\n--- chain ---");
    println!("  name             : {}", props.chain_name);
    println!("  spec_version     : {}", props.spec_version);
    println!("  token            : {}", props.token_symbol);
    println!("  ss58 prefix      : {}", props.ss58_prefix);
    println!("  decimals (spec)  : {}", props.token_decimals_declared);
    println!("  decimals (live)  : {}", props.token_decimals_effective);
    if props.decimals_disagree() {
        println!("  ^ the node's chain spec disagrees with its runtime; the live value wins");
    }
    match client.address() {
        Some(address) => println!("  signing as       : {address}"),
        None => println!("  signing as       : (read-only)"),
    }
}

/// The generic surface: every pallet the runtime exposes, resolved by name.
async fn read_state(client: &MatterClient) -> Result<()> {
    println!("\n--- reads (the generic surface) ---");

    // Storage: a plain value.
    let next_secret = client.query("Secrets", "NextSecretId", vec![]).await?;
    println!("  Secrets.NextSecretId      = {next_secret:?}");

    // Storage: a map lookup. Absence is normal control flow, not an error — an
    // unfunded account simply has no row.
    if let Some(account) = client.account_id() {
        let entry = client
            .query("System", "Account", vec![Value::from_bytes(account)])
            .await?;
        match entry {
            Some(value) => println!("  System.Account(me)        = {value:?}"),
            None => println!("  System.Account(me)        = absent (unfunded account)"),
        }
    }

    // A runtime API.
    let epoch = client.runtime_api("KgcApi", "dkg_epoch", vec![]).await?;
    println!("  KgcApi.dkg_epoch          = {epoch:?}");

    // A pallet constant.
    let ed = client.constant("Balances", "ExistentialDeposit")?;
    println!("  Balances.ExistentialDeposit = {ed:?}");

    Ok(())
}

/// Amounts are always integer plancks; conversion is explicit.
fn demonstrate_amounts(client: &MatterClient) {
    println!("\n--- amounts (always plancks, never floats) ---");
    let one = client.one_token();
    println!(
        "  1 {}  = {} plancks",
        client.properties().token_symbol,
        one
    );
    println!(
        "  \"1.5\" = {} plancks",
        client.parse_amount("1.5").unwrap()
    );
    println!(
        "  {} plancks reads back as {}",
        one,
        client.format_amount(one)
    );

    // Excess precision is rejected rather than rounded: losing someone's funds to
    // a silent truncation is not a trade worth making for convenience.
    let too_precise = "0.".to_owned() + &"0".repeat(40) + "1";
    match client.parse_amount(&too_precise) {
        Ok(v) => println!("  unexpectedly parsed an over-precise amount as {v}"),
        Err(e) => println!("  over-precise amount rejected: {e}"),
    }
}

/// What submission looks like. Gated, because it costs gas.
async fn maybe_submit(client: &MatterClient) -> Result<()> {
    println!("\n--- writes ---");

    if client.account_id().is_none() {
        println!("  read-only client: nothing to submit.");
        return Ok(());
    }

    let submit = std::env::var(SUBMIT_ENV).is_ok_and(|v| v == SUBMIT_VALUE);
    if !submit {
        println!("  would submit Staking.chill() via the curated staking façade:");
        println!("      client.staking().chill().await?");
        println!("  and the same call through the generic surface:");
        println!("      client.tx(\"Staking\", \"chill\", vec![]).await?");
        println!("  set {SUBMIT_ENV}={SUBMIT_VALUE} to actually send it (costs a fee).");
        return Ok(());
    }

    // `chill` is the demo call because it is idempotent, self-targeted, and a
    // no-op for an account that is not nominating — the cheapest way to prove the
    // signing path end-to-end without moving funds.
    println!("  submitting Staking.chill() ...");
    let receipt = client.staking().chill().await?;
    println!("  finalized in block {}", receipt.block_hash_hex());
    println!("  events: {:?}", receipt.events);
    Ok(())
}
