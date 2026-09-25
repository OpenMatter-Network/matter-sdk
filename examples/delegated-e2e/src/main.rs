//! What a member-tied scoped API key can and cannot do, end to end.
//!
//! A plain run prints the grant the chain reports. `MATTER_SUBMIT=yes` adds two
//! local refusals and one wrapped write that fails on chain. Environment variables:
//! `examples/README.md`.
//!
//! ```bash
//! MATTER_API_KEY=$MATTER_DELEGATED_KEY cargo run -p matter-delegated-e2e
//! MATTER_API_KEY=$MATTER_DELEGATED_KEY MATTER_SUBMIT=yes cargo run -p matter-delegated-e2e
//! ```
//!
//! Dev-node counterpart, including mint and revoke: `crates/matter-sdk/tests/scoped_keys_dev.rs`.

use anyhow::{bail, Context, Result};
use matter_sdk::chain::{MatterClient, MatterConfig, Mode, Network, Value};
use matter_sdk::{Access, ApiKey, Scope, SdkError};

/// Opt-in gate for anything that costs gas.
const SUBMIT_ENV: &str = "MATTER_SUBMIT";
const SUBMIT_VALUE: &str = "yes";

/// A deployment id that does not exist, so the wrapped call fails on chain.
const ABSENT_DEPLOYMENT: u128 = u128::MAX;

#[tokio::main]
async fn main() -> Result<()> {
    // The SDK logs through `tracing` and is silent without a subscriber.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "matter_sdk=info".into()),
        )
        .with_target(false)
        .init();

    // A URL overrides the network name, e.g. to target a dev node.
    let network = match std::env::var("MATTER_NETWORK").ok().as_deref() {
        Some("mainnet") => Network::Mainnet,
        _ => Network::Testnet,
    };
    let mut config = match std::env::var("MATTER_RPC_URL") {
        Ok(url) => MatterConfig::for_url(url),
        Err(_) => MatterConfig::for_network(network),
    };
    // A dev chain shares mainnet's token symbol, so the mainnet guard also needs
    // MATTER_CONFIRM=yes there.
    config.confirm_mainnet = std::env::var("MATTER_CONFIRM").is_ok_and(|v| v == "yes");

    // From the environment, never argv (shell history, `ps`).
    let raw = std::env::var("MATTER_API_KEY")
        .context("set MATTER_API_KEY to a scoped key minted in the dashboard")?;
    let key = ApiKey::parse(&raw).context("MATTER_API_KEY did not parse as an sr25519 key")?;

    let client = MatterClient::connect_with_api_key(config, key).await?;
    let grant = describe_grant(&client)?;
    if !submitting() {
        println!("\nRead-only. Set {SUBMIT_ENV}={SUBMIT_VALUE} to exercise the write paths.");
        return Ok(());
    }

    refusals_that_never_reach_the_chain(&client).await?;
    a_wrapped_write(&client, &grant).await?;
    println!("\nDone.");
    Ok(())
}

/// Print who the key acts for: the first thing to check when a scoped key misbehaves.
fn describe_grant(client: &MatterClient) -> Result<Grant> {
    println!("--- the key ---");
    println!("  signing as   : {}", client.address().unwrap_or_default());

    match client.mode() {
        Mode::Direct => {
            bail!(
                "this key resolved Direct: the chain grants it no scoped proxy. It was \
                 revoked, minted against a different network, or is a plain human seed. \
                 Check the key in the dashboard against {}",
                client.properties().chain_name
            )
        }
        Mode::Delegated { principal, scopes } => {
            // SS58, as the dashboard displays it.
            println!(
                "  acts for     : {}",
                client.principal_address().unwrap_or_default()
            );
            println!("  scopes       : {scopes}");
            println!("  every write is wrapped in proxy.proxy and paid for by that member.");
            Ok(Grant {
                _principal: principal,
                can_write_deployments: scopes.contains(Scope::Deployments, Access::Write),
            })
        }
        // `Mode` is non-exhaustive: stop on an unknown variant rather than guess.
        other => bail!("this build does not know how to act in mode {other:?}"),
    }
}

struct Grant {
    _principal: matter_sdk::AccountId,
    can_write_deployments: bool,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn submitting() -> bool {
    std::env::var(SUBMIT_ENV).is_ok_and(|v| v == SUBMIT_VALUE)
}

/// The two refusals the SDK raises locally, before spending anything.
///
/// A delegated key holds no balance, so without the local check an inadmissible
/// call is refused in the *pool* as "cannot pay fees", which says nothing about scopes.
async fn refusals_that_never_reach_the_chain(client: &MatterClient) -> Result<()> {
    println!("\n--- refused locally, so nothing is spent ---");

    match client
        .tx("Balances", "transfer_all", vec![Value::bool(false)])
        .await
    {
        Err(SdkError::NeverAdmitted { pallet, call }) => {
            println!("  {pallet}.{call}: never admitted to any api key");
        }
        other => bail!("expected NeverAdmitted for Balances.transfer_all, got {other:?}"),
    }

    // Needs a scope this key probably lacks; holding it is not an SDK failure.
    match client
        .tx("Volumes", "retire_volume", vec![Value::u128(1)])
        .await
    {
        Err(SdkError::NotPermitted {
            pallet,
            call,
            required,
            held,
        }) => {
            println!("  {pallet}.{call}: needs {required}, key holds {held}");
        }
        Err(other) => println!("  Volumes.retire_volume: {other}"),
        Ok(_) => println!("  Volumes.retire_volume: submitted (this key holds volumes:w)"),
    }
    Ok(())
}

/// One wrapped write that fails *on chain*.
///
/// `proxy.proxy` succeeds as an extrinsic even when the inner call fails; getting
/// `SdkError::Dispatch` here proves the SDK surfaces the inner failure.
async fn a_wrapped_write(client: &MatterClient, grant: &Grant) -> Result<()> {
    println!("\n--- a wrapped write ---");
    if !grant.can_write_deployments {
        println!("  skipped: this key holds no deployments:w, so the call would be refused");
        return Ok(());
    }

    println!("  submitting Jobs.cancel_deployment({ABSENT_DEPLOYMENT}) as the member ...");
    match client
        .tx(
            "Jobs",
            "cancel_deployment",
            vec![Value::u128(ABSENT_DEPLOYMENT)],
        )
        .await
    {
        Err(SdkError::Dispatch {
            pallet,
            call,
            detail,
        }) => {
            println!("  {pallet}.{call} ran as the member and failed on chain: {detail}");
            println!("  the member paid the fee; the key holds no funds and never did.");
        }
        Err(SdkError::KeyRevoked) => {
            bail!("the key was revoked between connect and submit")
        }
        Err(SdkError::Unsponsored { principal, .. }) => {
            bail!("nobody would pay for this call: {principal} needs gas coverage")
        }
        Err(other) => bail!("unexpected failure: {other}"),
        Ok(receipt) => {
            // Only reachable if the deployment somehow exists.
            println!("  submitted in block 0x{}", to_hex(&receipt.block_hash));
        }
    }
    Ok(())
}
