//! What a member-tied scoped API key can and cannot do, end to end.
//!
//! **Read-only by default.** Everything that costs gas is behind
//! `MATTER_SUBMIT=yes`, so a plain run connects, prints the grant the chain
//! reports, and stops.
//!
//! ```bash
//! # Read-only: resolve the key and print who it acts for.
//! MATTER_API_KEY=$MATTER_DELEGATED_KEY cargo run -p matter-delegated-e2e
//!
//! # Spend: one wrapped write that is expected to fail on chain, plus the two
//! # refusals that never reach the chain at all.
//! MATTER_API_KEY=$MATTER_DELEGATED_KEY MATTER_SUBMIT=yes cargo run -p matter-delegated-e2e
//! ```
//!
//! | Variable | Meaning |
//! |---|---|
//! | `MATTER_API_KEY` | the scoped key: a `0x` mini-secret or a mnemonic, as the dashboard shows it |
//! | `MATTER_RPC_URL` | endpoint override (default: testnet) |
//! | `MATTER_NETWORK` | `testnet` (default) or `mainnet` |
//! | `MATTER_CONFIRM` | must be `yes` for a signing client on mainnet |
//! | `MATTER_SUBMIT` | must be `yes` to submit anything |
//!
//! This is the reference for the scoped-key path; `crates/matter-vault/tests/
//! scoped_keys_dev.rs` covers the same ground against a dev node, including the
//! mint and revoke a key cannot perform for itself.

use anyhow::{bail, Context, Result};
use matter_vault::chain::{MatterClient, MatterConfig, Mode, Network, Value};
use matter_vault::{Access, ApiKey, Scope, SdkError};

/// Opt-in gate for anything that costs gas.
const SUBMIT_ENV: &str = "MATTER_SUBMIT";
const SUBMIT_VALUE: &str = "yes";

/// A deployment id that will not exist, so the wrapped call is guaranteed to
/// fail *on chain* rather than do something. The point is the error's shape:
/// proving the failure of a wrapped call surfaces at all is the whole reason
/// this example exists.
const ABSENT_DEPLOYMENT: u128 = u128::MAX;

#[tokio::main]
async fn main() -> Result<()> {
    // The client logs through `tracing` and says nothing without a subscriber.
    // An application installs one; this is what that looks like.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "matter_vault=info".into()),
        )
        .with_target(false)
        .init();

    // A URL wins over the network name, so this also drives a dev node — where
    // you can mint and revoke the key yourself, which no testnet key lets you do.
    let network = match std::env::var("MATTER_NETWORK").ok().as_deref() {
        Some("mainnet") => Network::Mainnet,
        _ => Network::Testnet,
    };
    let mut config = match std::env::var("MATTER_RPC_URL") {
        Ok(url) => MatterConfig::for_url(url),
        Err(_) => MatterConfig::for_network(network),
    };
    // A dev chain reports the same token symbol as mainnet, so the mainnet guard
    // treats it the same way. The guard is doing its job; say yes deliberately.
    config.confirm_mainnet = std::env::var("MATTER_CONFIRM").is_ok_and(|v| v == "yes");

    // From the environment, never from argv: argv lands in shell history and in
    // `ps` output.
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

/// Print who the key acts for, which is the first thing to check when anything
/// about a scoped key looks wrong.
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
            // SS58, so it can be compared against what the dashboard displayed.
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
        // `Mode` is non-exhaustive so a new variant is additive on chain; a
        // client that guessed at one would be worse than one that stops.
        other => bail!("this build does not know how to act in mode {other:?}"),
    }
}

struct Grant {
    _principal: matter_vault::AccountId,
    can_write_deployments: bool,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn submitting() -> bool {
    std::env::var(SUBMIT_ENV).is_ok_and(|v| v == SUBMIT_VALUE)
}

/// The two refusals a caller should get locally, before spending anything.
///
/// Both matter for a reason that is easy to miss: a delegated key holds no
/// balance, so a call the runtime will not admit is refused in the *pool* for
/// want of fees. Without the local check the caller reads "cannot pay some
/// fees" and learns nothing about scopes.
async fn refusals_that_never_reach_the_chain(client: &MatterClient) -> Result<()> {
    println!("\n--- refused locally, so nothing is spent ---");

    // A call no key may ever make, whatever its scopes.
    match client
        .tx("Balances", "transfer_all", vec![Value::bool(false)])
        .await
    {
        Err(SdkError::NeverAdmitted { pallet, call }) => {
            println!("  {pallet}.{call}: never admitted to any api key");
        }
        other => bail!("expected NeverAdmitted for Balances.transfer_all, got {other:?}"),
    }

    // A call that needs a scope this key is unlikely to hold. If it does hold
    // Volumes:Write this is not a failure of the SDK, so say so rather than
    // asserting something about someone else's key.
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

/// One wrapped write, chosen so it fails *on chain* rather than doing anything.
///
/// `proxy.proxy` succeeds as an extrinsic even when the call inside it failed,
/// so a client that stopped at "the extrinsic landed" would report this as a
/// success. Seeing a `Dispatch` error here is the proof that it does not.
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
