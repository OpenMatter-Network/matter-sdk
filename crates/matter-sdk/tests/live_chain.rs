//! Read-only checks against the live testnet (no key, no gas, no submission).
//!
//! `#[ignore]`d because they need a network and the chain upgrades independently.
//!
//! ```bash
//! cargo test -p matter-sdk --features chain --test live_chain -- --ignored --nocapture
//! ```

#![cfg(feature = "chain")]

use matter_sdk::chain::{MatterClient, MatterConfig, Network, Value};

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
