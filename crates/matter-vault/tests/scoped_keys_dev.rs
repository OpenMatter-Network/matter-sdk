//! The scoped-API-key lifecycle, end to end, against a local dev node.
//!
//! `#[ignore]`d: it needs a `matter-node` at spec >= 322 and it submits
//! extrinsics. Run it explicitly.
//!
//! ```bash
//! matter-node --dev --tmp --rpc-port 9955 &
//! MATTER_RPC_URL=ws://127.0.0.1:9955 \
//!   cargo test -p matter-vault --features chain --test scoped_keys_dev -- --ignored --nocapture
//! ```
//!
//! # Why this needs `confirm_mainnet`
//!
//! A `--dev` chain reports `tokenSymbol: "MTR"`, and with the mainnet genesis
//! hash still unpinned that is exactly the signal the mainnet guard falls back
//! to. So a *signing* client against a local node is refused unless it confirms,
//! the same as one against mainnet. The guard is doing its job; the dev chain is
//! simply indistinguishable from mainnet by the only evidence available.

#![cfg(feature = "chain")]

use matter_vault::chain::{MatterClient, MatterConfig, Mode, Value};
use matter_vault::{Access, ApiKey, Scope, ScopeSet, SdkError};

/// The public development phrase. `ApiKey::parse` rejects a phrase-less SURI
/// like a bare `//Alice`, because an unset environment variable would otherwise
/// silently mint a globally known key — so the phrase is spelled out.
const DEV_PHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

fn suri(junction: &str) -> String {
    format!("{DEV_PHRASE}{junction}")
}

fn config() -> MatterConfig {
    let mut config = MatterConfig::for_url(
        std::env::var("MATTER_RPC_URL").unwrap_or_else(|_| "ws://127.0.0.1:9955".to_string()),
    );
    // See the module docs: a dev chain looks like mainnet to the guard.
    config.confirm_mainnet = true;
    config
}

async fn client(junction: &str) -> MatterClient {
    let key = ApiKey::parse(&suri(junction)).expect("dev suri parses");
    MatterClient::connect_with_api_key(config(), key)
        .await
        .expect("connects to the dev node")
}

/// Mint, act, and revoke — the whole lifecycle, in the order an operator lives it.
///
/// One test rather than five because every step depends on the previous one's
/// on-chain effect, and splitting them would either serialise through shared
/// mutable chain state or re-mint the key four times.
#[tokio::test]
#[ignore = "needs a local matter-node at spec >= 322"]
async fn a_scoped_key_acts_for_its_member_and_stops_when_revoked() {
    let member = client("//Alice").await;
    assert_eq!(
        member.mode(),
        Mode::Direct,
        "a human seed holds no scoped proxy"
    );

    // An account with no funds of its own, so anything that lands proves the
    // member paid for it.
    let agent_key = ApiKey::parse(&suri("//ScopedKeyTest")).expect("agent suri parses");
    let agent_account = agent_key.account_id();
    let scopes = ScopeSet::single(Scope::Deployments, Access::Write);

    member
        .keys()
        .authorize(agent_account, scopes)
        .await
        .expect("Alice authorizes the key");

    let looked_up = member
        .keys()
        .lookup(agent_account)
        .await
        .expect("lookup succeeds");
    assert_eq!(
        looked_up,
        Some((member.account().unwrap(), scopes)),
        "the key points at Alice with the scopes she granted"
    );

    // A client built on the key must discover all of that for itself.
    let agent = client("//ScopedKeyTest").await;
    assert_eq!(
        agent.mode(),
        Mode::Delegated {
            principal: member.account().unwrap(),
            scopes
        }
    );
    assert_eq!(agent.principal(), member.account());
    assert_eq!(agent.scopes(), Some(scopes));

    // In scope, and genuinely dispatched: the deployment does not exist, so the
    // wrapped call fails — and that failure must surface as an error rather
    // than as the success `proxy.proxy` reports for itself.
    let err = agent
        .tx("Jobs", "cancel_deployment", vec![Value::u128(u128::MAX)])
        .await
        .expect_err("cancelling a deployment that does not exist fails");
    match &err {
        SdkError::Dispatch {
            pallet,
            call,
            detail,
        } => {
            assert_eq!(pallet, "Jobs");
            assert_eq!(call, "cancel_deployment");
            assert!(
                detail.contains("DeploymentNotFound"),
                "expected the wrapped call's own error, got {detail:?}"
            );
        }
        other => panic!("expected a wrapped dispatch error, got {other:?}"),
    }

    // Out of scope, and refused locally — before submission, and naming the
    // scope rather than complaining about fees.
    let err = agent
        .tx("Volumes", "retire_volume", vec![Value::u128(1)])
        .await
        .expect_err("the key holds no volumes:w");
    match &err {
        SdkError::NotPermitted { required, held, .. } => {
            assert_eq!(*required, ScopeSet::single(Scope::Volumes, Access::Write));
            assert_eq!(*held, scopes);
        }
        other => panic!("expected NotPermitted, got {other:?}"),
    }

    // Never admitted to any key, whatever its scopes.
    for (pallet, call) in [("Balances", "transfer_all"), ("Staking", "chill")] {
        let err = agent
            .tx(pallet, call, vec![])
            .await
            .expect_err("{pallet}.{call} is never admitted");
        assert!(
            matches!(err, SdkError::NeverAdmitted { .. }),
            "expected NeverAdmitted for {pallet}.{call}, got {err:?}"
        );
    }

    // Revoked: the same in-scope call now fails because the delegation is gone.
    member
        .keys()
        .revoke(agent_account)
        .await
        .expect("Alice revokes the key");
    assert_eq!(
        member.keys().lookup(agent_account).await.unwrap(),
        None,
        "the pointer is gone"
    );

    let err = agent
        .tx("Jobs", "cancel_deployment", vec![Value::u128(u128::MAX)])
        .await
        .expect_err("a revoked key cannot act");
    assert!(
        matches!(err, SdkError::KeyRevoked),
        "expected KeyRevoked, got {err:?}"
    );
}

/// Widening a key is the same call as minting it, and the client must see the
/// new set — including a Read bit, which is what the committee decrypt path
/// checks and what no `Write` bit implies.
#[tokio::test]
#[ignore = "needs a local matter-node at spec >= 322"]
async fn re_scoping_a_key_is_an_upsert() {
    // A different member from the lifecycle test above: `cargo test` runs the two
    // in parallel, and two clients signing as one account race for the same nonce
    // — the loser is rejected with "Priority is too low", which reads like a
    // product failure and is not one.
    let member = client("//Bob").await;
    let agent_key = ApiKey::parse(&suri("//ReScopeTest")).expect("agent suri parses");
    let agent_account = agent_key.account_id();

    let narrow = ScopeSet::single(Scope::Deployments, Access::Write);
    member
        .keys()
        .authorize(agent_account, narrow)
        .await
        .unwrap();
    assert_eq!(client("//ReScopeTest").await.scopes(), Some(narrow));

    let wider = narrow.with(Scope::Secrets, Access::Read);
    member.keys().authorize(agent_account, wider).await.unwrap();
    assert_eq!(
        client("//ReScopeTest").await.scopes(),
        Some(wider),
        "the upsert replaced the definition rather than adding a second"
    );

    // `Secrets:Read` is not `Secrets:Write`: storing is still refused.
    let agent = client("//ReScopeTest").await;
    let err = agent
        .tx("Secrets", "delete_secret", vec![Value::u128(1)])
        .await
        .expect_err("read does not imply write");
    assert!(matches!(err, SdkError::NotPermitted { .. }), "got {err:?}");

    member.keys().revoke(agent_account).await.unwrap();
}
