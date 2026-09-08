//! Read-only checks against the live OpenMatter testnet.
//!
//! `#[ignore]`d, so they never run in PR CI: they need a network and they assert
//! against a chain that upgrades independently of this repo. Everything here is
//! read-only — no key, no gas, no submission.
//!
//! ```bash
//! cargo test -p matter-vault --features chain --test live_chain -- --ignored --nocapture
//! ```
//!
//! What they prove that no fake can: that the metadata we resolve calls against
//! is really there, that the runtime APIs return shapes we can decode, and that
//! the decimals we compute from `ExistentialDeposit` match the live runtime.

#![cfg(feature = "chain")]

use matter_vault::chain::{MatterClient, MatterConfig, Network, Value};

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

    // The consensus-backed decimals must be derivable, and ED must be the
    // documented `10^(d-3)`.
    assert!(props.token_decimals_effective >= 3);
    assert_eq!(
        props.existential_deposit,
        10u128.pow(props.token_decimals_effective as u32 - 3),
        "ExistentialDeposit should be UNIT/1000"
    );

    // If this fires, the deployed node's chain-spec file disagrees with the wasm
    // it is executing — worth reporting to matter-node, but the SDK still works.
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

    // A plain storage value.
    let next = client
        .query("Secrets", "NextSecretId", vec![])
        .await
        .expect("read Secrets.NextSecretId");
    println!("Secrets.NextSecretId = {next:?}");

    // A map lookup for an account that does not exist — absence is normal
    // control flow, not an error.
    let missing = client
        .query("System", "Account", vec![Value::from_bytes([0xff; 32])])
        .await
        .expect("query an unfunded account");
    assert!(
        missing.is_none(),
        "an unfunded account should have no entry"
    );

    // A runtime API the committee flow depends on.
    let epoch = client
        .runtime_api("KgcApi", "dkg_epoch", vec![])
        .await
        .expect("call KgcApi_dkg_epoch");
    println!("KgcApi.dkg_epoch = {epoch:?}");

    // A pallet constant.
    let ed = client
        .constant("Balances", "ExistentialDeposit")
        .expect("read Balances.ExistentialDeposit");
    println!("Balances.ExistentialDeposit = {ed:?}");
}

#[tokio::test]
#[ignore = "needs the live testnet"]
async fn the_curated_pallets_all_exist_in_live_metadata() {
    // The façades resolve calls by name, so a rename in a forkless upgrade would
    // break them at call time. This is the cheap tripwire for that.
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
    // The contract for a client built without a key: reads work, writes are a
    // typed error rather than a panic or a confusing chain rejection.
    let client = testnet().await;
    assert!(client.account_id().is_none());

    let err = client
        .tx("Staking", "chill", vec![])
        .await
        .expect_err("a read-only client must not submit");
    assert!(
        matches!(err, matter_vault::SdkError::ReadOnly),
        "expected ReadOnly, got {err:?}"
    );
}

#[tokio::test]
#[ignore = "needs the live testnet"]
async fn pointing_testnet_config_at_mainnet_is_caught() {
    // A typo'd RPC URL must fail before it costs anything. Skips cleanly if the
    // mainnet endpoint is unreachable, since that is not what is under test.
    let mut config = MatterConfig::for_network(Network::Testnet);
    config.rpc_url = Some("wss://node1.mainnet.openmatter.network".to_string());

    match MatterClient::connect(config).await {
        Err(matter_vault::SdkError::WrongNetwork { expected, actual }) => {
            println!("guard fired: expected {expected}, endpoint serves {actual}");
        }
        Err(other) => println!("mainnet endpoint unreachable, skipping: {other}"),
        Ok(_) => panic!("a testnet config accepted a mainnet endpoint"),
    }
}

/// The scoped-key surface, checked against the runtime that is actually live.
///
/// The unit tests pin this against a checked-in spec-322 blob, which proves the
/// table was right when it was written. This proves it is right now. A forkless
/// upgrade that adds a call to a scoped pallet makes the table incomplete
/// without changing a line of this repo, and the local pre-flight check would
/// then refuse a call the chain would have admitted.
#[tokio::test]
#[ignore = "needs the live testnet"]
async fn the_scoped_key_surface_matches_the_live_runtime() {
    use matter_vault::chain::scopes_table::{required_scopes, SCOPED_PALLETS};

    let client = testnet().await;
    let metadata = client.subxt().metadata();

    // The runtime API the client resolves a key's principal from.
    assert!(
        metadata
            .runtime_api_trait_by_name("BudgetsApi")
            .and_then(|t| t.method_by_name("agent_key"))
            .is_some(),
        "the live runtime no longer declares BudgetsApi_agent_key, so no key can \
         discover who it acts for"
    );

    // The call Python and Go gate on, which must ship with that runtime API.
    assert!(
        metadata
            .pallet_by_name("Budgets")
            .and_then(|p| p.call_variant_by_name("authorize_agent_key"))
            .is_some(),
        "Budgets.authorize_agent_key is gone, and the Python and Go bindings gate \
         their whole delegated path on it"
    );

    // The dispatch shape every delegated write takes.
    let proxy = metadata
        .pallet_by_name("Proxy")
        .expect("the live runtime has a Proxy pallet");
    assert!(proxy.call_variant_by_name("proxy").is_some());
    // Events are resolved by walking the pallet's event variants: subxt indexes
    // them by index, not by name.
    assert!(
        proxy
            .event_variants()
            .is_some_and(|variants| variants.iter().any(|v| v.name == "ProxyExecuted")),
        "without ProxyExecuted a failed wrapped call cannot be told from a successful one"
    );

    // Every call of every scoped pallet must be classified one way or the other.
    let mut unclassified = Vec::new();
    for pallet in SCOPED_PALLETS {
        let variants = metadata
            .pallet_by_name(pallet)
            .and_then(|p| p.call_variants())
            .unwrap_or_else(|| {
                panic!("{pallet} is a scoped pallet but the live runtime has no such pallet")
            });
        for variant in variants {
            // Args only matter for the two argument-sensitive rows, which are
            // covered by unit tests; an empty slice still yields a `Some`.
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
         See the regeneration recipe in crates/matter-vault/src/chain/scopes_table.rs."
    );
}

/// Whether the table deliberately admits nothing for this call.
///
/// `required_scopes` returns `None` both for "no key may make this" and for
/// "this call is new and nobody has classified it", so the live test needs the
/// never-list to tell them apart. It reads the same one the unit test does:
/// a second copy here drifted from the first within an hour of being written.
fn is_known_never_admitted(pallet: &str, call: &str) -> bool {
    matter_vault::chain::scopes_table::NEVER_ADMITTED
        .iter()
        .any(|(p, denied)| *p == pallet && denied.contains(&call))
}
