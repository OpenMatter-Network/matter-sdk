//! Connect from an `apiKey` and exercise the client surface.
//!
//! Read-only unless `MATTER_SUBMIT=yes`. Environment variables: `examples/README.md`.
//!
//! ```bash
//! MATTER_API_KEY=$TEST_KEY cargo run -p matter-sdk-client-example
//! MATTER_API_KEY=$TEST_KEY MATTER_SUBMIT=yes cargo run -p matter-sdk-client-example
//! ```

use anyhow::{Context, Result};
use matter_sdk::chain::{parse_account, FeeEstimate, MatterClient, MatterConfig, Network, Value};
use matter_sdk::ApiKey;

/// Opt-in gate for anything that costs gas.
const SUBMIT_ENV: &str = "MATTER_SUBMIT";
const SUBMIT_VALUE: &str = "yes";

/// The well-known development account, read when no key is set so a read-only
/// run still shows a real balance.
const SAMPLE_ACCOUNT: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

/// The call this tour submits behind the gate, and so the one it prices.
const WRITE_PALLET: &str = "Staking";
const WRITE_CALL: &str = "chill";

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

    // From the environment, never argv (shell history, `ps`).
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
    read_balance(&client).await?;
    preflight(&client).await?;
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
                // Prints the account only: `ApiKey`'s Debug is redacted.
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

/// Generic surface: any pallet the runtime exposes, resolved by name.
async fn read_state(client: &MatterClient) -> Result<()> {
    println!("\n--- reads (the generic surface) ---");

    let next_secret = client.query("Secrets", "NextSecretId", vec![]).await?;
    println!("  Secrets.NextSecretId      = {next_secret:?}");

    // Absence is not an error: an unfunded account has no row.
    if let Some(account) = client.account_id() {
        let entry = client
            .query("System", "Account", vec![Value::from_bytes(account)])
            .await?;
        match entry {
            Some(value) => println!("  System.Account(me)        = {value:?}"),
            None => println!("  System.Account(me)        = absent (unfunded account)"),
        }
    }

    let epoch = client.runtime_api("KgcApi", "dkg_epoch", vec![]).await?;
    println!("  KgcApi.dkg_epoch          = {epoch:?}");

    let ed = client.constant("Balances", "ExistentialDeposit")?;
    println!("  Balances.ExistentialDeposit = {ed:?}");

    Ok(())
}

/// Façade reads: one question, one call, no pallet or encoding knowledge.
async fn read_balance(client: &MatterClient) -> Result<()> {
    println!("\n--- reads (friendly helpers) ---");

    let who = match client.account() {
        Some(me) => me,
        None => parse_account(SAMPLE_ACCOUNT)?,
    };
    // Two reads, one block: the balance is pinned to the head just read.
    let head = client.network().head().await?;
    let balance = client.accounts().at(head.hash).balance(who).await?;
    let amount = |plancks: u128| tokens(client, plancks);

    println!("  at block         : {}", head.number);
    println!("  account          : {}", balance.account);
    println!("  exists           : {}", balance.exists);
    println!("  total            : {}", amount(balance.total));
    // Not `free`: freezes and the existential deposit hold some of it back.
    println!("  transferable     : {}", amount(balance.transferable));
    for hold in &balance.holds {
        println!(
            "  on hold          : {} for {}",
            amount(hold.amount),
            hold.reason
        );
    }
    for freeze in &balance.freezes {
        println!(
            "  frozen           : {} for {}",
            amount(freeze.amount),
            freeze.reason
        );
    }
    Ok(())
}

/// An amount of plancks as the chain's token, for printing.
fn tokens(client: &MatterClient, plancks: u128) -> String {
    format!(
        "{} {}",
        client.format_amount(plancks),
        client.properties().token_symbol
    )
}

/// Whose balance a fee comes out of, and how the tour knows. The runtime's
/// answer comes first; where it has none, the signer is the working assumption;
/// a read-only client charges nobody, so the sample account stands in.
fn charged_to(estimate: &FeeEstimate) -> Result<(matter_sdk::AccountId, &'static str)> {
    Ok(match (&estimate.payer, &estimate.signer) {
        (Some(payer), _) if estimate.billed_to.is_some() => {
            (payer.account_id(), "an organization's treasury")
        }
        (Some(payer), _) => (payer.account_id(), "per the runtime"),
        (None, Some(signer)) => (signer.account_id(), "the signer; the runtime did not say"),
        (None, None) => (
            parse_account(SAMPLE_ACCOUNT)?,
            "a sample account; this client is read-only",
        ),
    })
}

/// Three reads put together: can whoever pays for this tour's write afford it?
async fn preflight(client: &MatterClient) -> Result<()> {
    println!("\n--- pre-flight (three reads, one block) ---");

    // Every read is pinned to one block, so the fee and the balance agree.
    let head = client.network().head().await?;
    let estimate = client
        .fees()
        .at(head.hash)
        .estimate(WRITE_PALLET, WRITE_CALL, vec![])
        .await?;
    let (payer, how) = charged_to(&estimate)?;
    let balance = client.accounts().at(head.hash).balance(payer).await?;
    // A fee may not take the payer below the existential deposit.
    let spendable = balance.transferable_keep_alive;
    let deposit = client.network().info().existential_deposit;

    println!("  call             : {}.{}", estimate.pallet, estimate.call);
    println!("  at block         : {}", head.number);
    println!(
        "  fee              : {} for {} bytes",
        tokens(client, estimate.partial_fee),
        estimate.encoded_len
    );
    println!("  charged to       : {} ({how})", balance.account);
    println!(
        "  can spend        : {}, keeping the existential deposit of {}",
        tokens(client, spendable),
        tokens(client, deposit)
    );
    match spendable.checked_sub(estimate.partial_fee) {
        Some(left) => println!(
            "  verdict          : affordable, leaving {}",
            tokens(client, left)
        ),
        None => println!(
            "  verdict          : short by {}",
            tokens(client, estimate.partial_fee - spendable)
        ),
    }
    Ok(())
}

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

    let too_precise = "0.".to_owned() + &"0".repeat(40) + "1";
    match client.parse_amount(&too_precise) {
        Ok(v) => println!("  unexpectedly parsed an over-precise amount as {v}"),
        Err(e) => println!("  over-precise amount rejected: {e}"),
    }
}

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

    // `chill` is idempotent, self-targeted, and a no-op for a non-nominator: the
    // cheapest signed call that moves no funds.
    println!("  submitting Staking.chill() ...");
    let receipt = client.staking().chill().await?;
    println!("  finalized in block {}", receipt.block_hash_hex());
    println!("  events: {:?}", receipt.events);
    Ok(())
}
