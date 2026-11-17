//! Read-only checks against the live testnet (no key, no gas, no submission).
//!
//! `#[ignore]`d because they need a network and the chain upgrades independently.
//!
//! ```bash
//! cargo test -p matter-sdk --features chain --test live_chain -- --ignored --nocapture
//! ```

#![cfg(feature = "chain")]

mod common;

use std::collections::BTreeSet;

use matter_sdk::chain::{parse_account, MatterClient, MatterConfig, Network, Value};
use serde_json::{json, Value as Json};

async fn testnet() -> MatterClient {
    MatterClient::connect(MatterConfig::for_network(Network::Testnet))
        .await
        .expect("connect to the public testnet")
}

#[tokio::test]
#[ignore = "needs the live testnet"]
async fn connects_and_reads_consistent_properties() {
    let client = testnet().await;
    let props = client.properties();

    println!("chain           : {}", props.chain_name);
    println!("spec_version    : {}", props.spec_version);
    println!("token           : {}", props.token_symbol);
    println!("ss58 prefix     : {}", props.ss58_prefix);
    println!("decimals (spec) : {}", props.token_decimals_declared);
    println!("decimals (live) : {}", props.token_decimals_effective);
    println!("existential dep : {}", props.existential_deposit);
    println!("genesis         : 0x{}", hex::encode(props.genesis_hash));

    assert!(
        props.chain_name.contains("MatterChain"),
        "{}",
        props.chain_name
    );
    assert_eq!(props.token_symbol, "MTR-Test");
    assert_eq!(props.ss58_prefix, 42);

    // ED must be the documented `10^(d-3)`.
    assert!(props.token_decimals_effective >= 3);
    assert_eq!(
        props.existential_deposit,
        10u128.pow(props.token_decimals_effective as u32 - 3),
        "ExistentialDeposit should be UNIT/1000"
    );

    // Chain-spec file disagrees with the running wasm; report upstream, SDK unaffected.
    if props.decimals_disagree() {
        println!(
            "NOTE: chain spec says {} decimals, runtime implies {}",
            props.token_decimals_declared, props.token_decimals_effective
        );
    }
}

#[tokio::test]
#[ignore = "needs the live testnet"]
async fn the_generic_surface_reaches_every_layer() {
    let client = testnet().await;

    let next = client
        .query("Secrets", "NextSecretId", vec![])
        .await
        .expect("read Secrets.NextSecretId");
    println!("Secrets.NextSecretId = {next:?}");

    // Absence is `None`, not an error.
    let missing = client
        .query("System", "Account", vec![Value::from_bytes([0xff; 32])])
        .await
        .expect("query an unfunded account");
    assert!(
        missing.is_none(),
        "an unfunded account should have no entry"
    );

    let epoch = client
        .runtime_api("KgcApi", "dkg_epoch", vec![])
        .await
        .expect("call KgcApi_dkg_epoch");
    println!("KgcApi.dkg_epoch = {epoch:?}");

    let ed = client
        .constant("Balances", "ExistentialDeposit")
        .expect("read Balances.ExistentialDeposit");
    println!("Balances.ExistentialDeposit = {ed:?}");
}

#[tokio::test]
#[ignore = "needs the live testnet"]
async fn the_curated_pallets_all_exist_in_live_metadata() {
    // Façades resolve calls by name, so a forkless-upgrade rename breaks them.
    let client = testnet().await;
    let metadata = client.subxt().metadata();

    for (pallet, calls) in [
        (
            "Secrets",
            &[
                "store_secret",
                "rotate_secret",
                "grant_access",
                "revoke_access",
                "delete_secret",
            ][..],
        ),
        (
            "Jobs",
            &[
                "request_deployment",
                "cancel_deployment",
                "set_deployment_env",
                "set_deployment_secret_ref",
            ][..],
        ),
        (
            "Resources",
            &[
                "register_resource",
                "update_sku",
                "report_capacity",
                "set_resource_privacy",
                "add_to_whitelist",
                "remove_from_whitelist",
            ][..],
        ),
        (
            "Staking",
            &[
                "bond",
                "bond_extra",
                "unbond",
                "withdraw_unbonded",
                "nominate",
                "chill",
            ][..],
        ),
        ("NominationPools", &["join", "claim_payout"][..]),
        (
            "Organizations",
            &["create_org", "add_member", "remove_member"][..],
        ),
        (
            "Budgets",
            &[
                "allot",
                "authorize_project_secrets_agent",
                "revoke_project_secrets_agent",
            ][..],
        ),
    ] {
        let found = metadata
            .pallet_by_name(pallet)
            .unwrap_or_else(|| panic!("runtime has no pallet {pallet}"));
        for call in calls {
            assert!(
                found.call_variant_by_name(call).is_some(),
                "{pallet} has no call {call} in the live runtime"
            );
        }
        println!("{pallet}: {} curated calls present", calls.len());
    }
}

#[tokio::test]
#[ignore = "needs the live testnet"]
async fn a_read_only_client_refuses_to_submit() {
    let client = testnet().await;
    assert!(client.account_id().is_none());

    let err = client
        .tx("Staking", "chill", vec![])
        .await
        .expect_err("a read-only client must not submit");
    assert!(
        matches!(err, matter_sdk::SdkError::ReadOnly),
        "expected ReadOnly, got {err:?}"
    );
}

#[tokio::test]
#[ignore = "needs the live testnet"]
async fn pointing_testnet_config_at_mainnet_is_caught() {
    // Skips if the mainnet endpoint is unreachable.
    let mut config = MatterConfig::for_network(Network::Testnet);
    config.rpc_url = Some("wss://node2.mainnet.openmatter.network".to_string());

    match MatterClient::connect(config).await {
        Err(matter_sdk::SdkError::WrongNetwork { expected, actual }) => {
            println!("guard fired: expected {expected}, endpoint serves {actual}");
        }
        Err(other) => println!("mainnet endpoint unreachable, skipping: {other}"),
        Ok(_) => panic!("a testnet config accepted a mainnet endpoint"),
    }
}

/// The chain the read check runs against: `MATTER_RPC_URL` when set, as the
/// nightly drift job sets it per network, otherwise the public testnet. `None`
/// when a named endpoint cannot be reached, which this file treats as a skip.
async fn read_target() -> Option<MatterClient> {
    let Ok(url) = std::env::var("MATTER_RPC_URL") else {
        return Some(testnet().await);
    };
    match MatterClient::connect(MatterConfig::for_url(url.clone())).await {
        Ok(client) => Some(client),
        Err(e) => {
            println!("{url} unreachable, skipping: {e}");
            None
        }
    }
}

/// The block to read at: `MATTER_AT_BLOCK` (hex) when set, so every binding can
/// be pointed at the same one; otherwise the latest finalized block.
async fn read_block(client: &MatterClient) -> [u8; 32] {
    match std::env::var("MATTER_AT_BLOCK") {
        Ok(text) => {
            let mut block = [0u8; 32];
            hex::decode_to_slice(text.trim().trim_start_matches("0x"), &mut block)
                .expect("MATTER_AT_BLOCK is a 32-byte block hash in hex");
            block
        }
        Err(_) => {
            client
                .rpc()
                .chain_get_finalized_head()
                .await
                .expect("read the finalized head")
                .0
        }
    }
}

/// One catalogue read by name, as its canonical JSON text. Rust has no
/// reflection, so a read added to the catalogue needs an arm here.
async fn live_read(
    client: &MatterClient,
    at: [u8; 32],
    facade: &str,
    method: &str,
    args: &Json,
) -> String {
    let text = |name: &str| args[name].as_str().expect("a live argument is text");
    let account =
        |name: &str| parse_account(text(name)).expect("live_reads.json holds valid accounts");
    // Wide integers travel as decimal strings: JSON numbers cannot carry 64 bits.
    let number = |name: &str| {
        text(name)
            .parse::<u64>()
            .expect("a u64 argument is decimal")
    };
    // A call's arguments, as `tx` takes them here: values in declared order.
    let call_args = |name: &str| -> Vec<Value> {
        let list = args[name].as_array().expect("call arguments are a list");
        list.iter()
            .map(|arg| match arg["type"].as_str() {
                Some("u128") => Value::u128(
                    arg["value"]
                        .as_str()
                        .and_then(|value| value.parse().ok())
                        .expect("a u128 call argument is decimal"),
                ),
                other => panic!("live_reads.json names a call argument type this test does not convert: {other:?}"),
            })
            .collect()
    };
    fn canonical<T: serde::Serialize>(read: &str, result: matter_sdk::Result<T>) -> String {
        let value = result.unwrap_or_else(|e| panic!("{read}: {e}"));
        serde_json::to_string(&value).expect("a read result serializes")
    }
    let read = format!("{facade}.{method}({args}) at 0x{}", hex::encode(at));

    match (facade, method) {
        ("accounts", "balance") => canonical(
            &read,
            client.accounts().at(at).balance(account("who")).await,
        ),
        ("fees", "estimate") => canonical(
            &read,
            client
                .fees()
                .at(at)
                .estimate(text("pallet"), text("call"), call_args("args"))
                .await,
        ),
        ("network", "info") => canonical(&read, Ok(client.network().info())),
        ("network", "head") => canonical(&read, client.network().at(at).head().await),
        ("network", "block") => canonical(&read, client.network().block(number("number")).await),
        ("network", "node") => canonical(&read, client.network().node().await),
        ("network", "timing") => canonical(&read, client.network().timing()),
        other => panic!("live_reads.json names a read this test does not dispatch: {other:?}"),
    }
}

/// Strict decoders fail when a forkless upgrade changes a layout. This runs every
/// catalogue read against the live runtime, so that shows up here first.
///
/// With `MATTER_LIVE_READS_OUT` set it also writes the results there, for
/// `scripts/compare-live-reads.sh` to hold the four bindings to the same bytes.
#[tokio::test]
#[ignore = "needs the live testnet"]
async fn every_catalogue_read_decodes_against_the_live_runtime() {
    let catalogue: Json =
        serde_json::from_str(include_str!("../../../testvectors/facade_reads.json")).unwrap();
    let live: Json =
        serde_json::from_str(include_str!("../../../testvectors/live_reads.json")).unwrap();
    let name = |row: &Json| {
        (
            row["facade"].as_str().unwrap().to_string(),
            row["method"].as_str().unwrap().to_string(),
        )
    };
    let pinned: BTreeSet<_> = catalogue["reads"]
        .as_array()
        .unwrap()
        .iter()
        .map(name)
        .collect();
    let exercised: BTreeSet<_> = live["reads"].as_array().unwrap().iter().map(name).collect();
    assert_eq!(
        pinned, exercised,
        "testvectors/live_reads.json must exercise exactly the reads the catalogue pins"
    );

    let Some(client) = read_target().await else {
        return;
    };
    let at = read_block(&client).await;
    let mut reads = Vec::new();
    for row in live["reads"].as_array().unwrap() {
        let (facade, method) = name(row);
        let result_json = live_read(&client, at, &facade, &method, &row["args"]).await;
        println!("{facade}.{method}({}) = {result_json}", row["args"]);
        // The canonical text itself: the comparison is of bytes, not parsed values.
        reads.push(json!({
            "facade": facade,
            "method": method,
            "args": row["args"],
            "result_json": result_json,
        }));
    }

    if let Ok(path) = std::env::var("MATTER_LIVE_READS_OUT") {
        let out = json!({ "at": format!("0x{}", hex::encode(at)), "reads": reads });
        std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap())
            .unwrap_or_else(|e| panic!("write {path}: {e}"));
    }
}

/// Decoders fail on a layout they were not written for, but only once a value
/// with that layout is read: a new hold reason breaks nobody until an account
/// holds funds under it. This compares every source's layout itself, so the
/// drift job reports the change before a user meets it.
#[tokio::test]
#[ignore = "needs the live testnet"]
async fn catalogue_sources_have_the_layout_the_decoders_were_written_for() {
    let Some(client) = read_target().await else {
        return;
    };
    let live = common::source_shapes(&client.subxt().metadata());
    let drifted: Vec<String> = common::pinned_shapes()
        .into_iter()
        .filter(|(source, pinned)| live.get(source) != Some(pinned))
        .map(|(source, pinned)| {
            let now = live.get(&source).map_or("<absent>", String::as_str);
            format!("{source}\n    decoders expect: {pinned}\n    runtime has:     {now}")
        })
        .collect();
    assert!(
        drifted.is_empty(),
        "the live runtime (spec {}) lays out {} source(s) differently from what the read \
         decoders were written for:\n  {}",
        client.properties().spec_version,
        drifted.len(),
        drifted.join("\n  ")
    );
}

/// A forkless upgrade that adds a call to a scoped pallet leaves the scope table
/// incomplete, and the local pre-flight would refuse a call the chain admits.
#[tokio::test]
#[ignore = "needs the live testnet"]
async fn the_scoped_key_surface_matches_the_live_runtime() {
    use matter_sdk::chain::scopes_table::{required_scopes, SCOPED_PALLETS};

    let client = testnet().await;
    let metadata = client.subxt().metadata();

    assert!(
        metadata
            .runtime_api_trait_by_name("BudgetsApi")
            .and_then(|t| t.method_by_name("agent_key"))
            .is_some(),
        "the live runtime no longer declares BudgetsApi_agent_key, so no key can \
         discover who it acts for"
    );

    assert!(
        metadata
            .pallet_by_name("Budgets")
            .and_then(|p| p.call_variant_by_name("authorize_agent_key"))
            .is_some(),
        "Budgets.authorize_agent_key is gone, and the Python and Go bindings gate \
         their whole delegated path on it"
    );

    // Every delegated write dispatches through `Proxy.proxy`.
    let proxy = metadata
        .pallet_by_name("Proxy")
        .expect("the live runtime has a Proxy pallet");
    assert!(proxy.call_variant_by_name("proxy").is_some());
    // subxt indexes events by index, not name.
    assert!(
        proxy
            .event_variants()
            .is_some_and(|variants| variants.iter().any(|v| v.name == "ProxyExecuted")),
        "without ProxyExecuted a failed wrapped call cannot be told from a successful one"
    );

    let mut unclassified = Vec::new();
    for pallet in SCOPED_PALLETS {
        let variants = metadata
            .pallet_by_name(pallet)
            .and_then(|p| p.call_variants())
            .unwrap_or_else(|| {
                panic!("{pallet} is a scoped pallet but the live runtime has no such pallet")
            });
        for variant in variants {
            // Argument-sensitive rows still return `Some` for empty args.
            if required_scopes(pallet, variant.name.as_str(), &[]).is_none()
                && !is_known_never_admitted(pallet, variant.name.as_str())
            {
                unclassified.push(format!("{pallet}.{}", variant.name));
            }
        }
    }
    assert!(
        unclassified.is_empty(),
        "the live runtime has calls this SDK's scope table does not classify: {unclassified:?}. \
         See the regeneration recipe in crates/matter-sdk/src/chain/scopes_table.rs."
    );
}

/// Whether the table deliberately admits nothing for this call. `required_scopes`
/// returns `None` for both "never admitted" and "unclassified"; this tells them apart.
fn is_known_never_admitted(pallet: &str, call: &str) -> bool {
    matter_sdk::chain::scopes_table::NEVER_ADMITTED
        .iter()
        .any(|(p, denied)| *p == pallet && denied.contains(&call))
}
