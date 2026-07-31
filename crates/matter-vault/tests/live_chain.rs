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
