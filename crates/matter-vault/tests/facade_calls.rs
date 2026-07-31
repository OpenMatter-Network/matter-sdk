//! The curated façade surface, pinned as a fixture every language replays.
//!
//! The façades are hand-written per language, so the risk is that they drift:
//! TypeScript grows a `secrets.purge` that Rust does not have, or two languages
//! disagree about which pallet call a method maps to. Code generation was
//! considered and rejected for now — only two languages have a client, and a
//! generated four-line wrapper is less reviewable than the wrapper itself. So
//! instead of generating, **pin**: one fixture, emitted from Rust, replayed by
//! every binding, exactly the mechanism `testvectors/` already uses for crypto.
//!
//! The fixture is checked both ways. A row without an implementation fails, and
//! an implementation without a row fails — otherwise it would only catch half the
//! drift.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-vault --features chain --test facade_calls -- --ignored
//! ```

#![cfg(feature = "chain")]

use std::collections::BTreeSet;

use serde_json::json;

/// The curated surface: `(façade, method, pallet, call, ordered arg names)`.
///
/// This list is the contract. Adding a façade method means adding a row here and
/// regenerating; the live-metadata test in `tests/live_chain.rs` separately
/// proves each `(pallet, call)` actually exists on chain.
const FACADE_CALLS: &[(&str, &str, &str, &str, &[&str])] = &[
    // --- secrets ---
    (
        "secrets",
        "store",
        "Secrets",
        "store_secret",
        &["payload", "epoch", "label", "aad"],
    ),
    (
        "secrets",
        "rotate",
        "Secrets",
        "rotate_secret",
        &["secret_id", "payload", "epoch", "aad"],
    ),
    (
        "secrets",
        "grant",
        "Secrets",
        "grant_access",
        &["secret_id", "target"],
    ),
    (
        "secrets",
        "revoke",
        "Secrets",
        "revoke_access",
        &["secret_id", "target"],
    ),
    (
        "secrets",
        "delete",
        "Secrets",
        "delete_secret",
        &["secret_id"],
    ),
    // --- deployments (pallet-jobs) ---
    (
        "deployments",
        "request",
        "Jobs",
        "request_deployment",
        &["request"],
    ),
    (
        "deployments",
        "cancel",
        "Jobs",
        "cancel_deployment",
        &["deployment"],
    ),
    (
        "deployments",
        "set_secret_ref",
        "Jobs",
        "set_deployment_secret_ref",
        &["deployment", "secret_ref"],
    ),
    (
        "deployments",
        "set_env",
        "Jobs",
        "set_deployment_env",
        &["deployment", "env_vars"],
    ),
    (
        "deployments",
        "register_wg_peer",
        "Jobs",
        "register_wg_peer",
        &["deployment", "user_wg_pubkey"],
    ),
    // --- resources ---
    (
        "resources",
        "register",
        "Resources",
        "register_resource",
        &["resource_id", "ownership_proof", "name"],
    ),
    (
        "resources",
        "update_sku",
        "Resources",
        "update_sku",
        &["uuid", "sku"],
    ),
    (
        "resources",
        "report_capacity",
        "Resources",
        "report_capacity",
        &["capacity"],
    ),
    (
        "resources",
        "set_privacy",
        "Resources",
        "set_resource_privacy",
        &["resource_id", "is_private"],
    ),
    (
        "resources",
        "allow",
        "Resources",
        "add_to_whitelist",
        &["resource_id", "user"],
    ),
    (
        "resources",
        "disallow",
        "Resources",
        "remove_from_whitelist",
        &["resource_id", "user"],
    ),
    // --- staking ---
    ("staking", "bond", "Staking", "bond", &["value", "payee"]),
    (
        "staking",
        "bond_extra",
        "Staking",
        "bond_extra",
        &["additional"],
    ),
    ("staking", "unbond", "Staking", "unbond", &["value"]),
    (
        "staking",
        "withdraw_unbonded",
        "Staking",
        "withdraw_unbonded",
        &["num_slashing_spans"],
    ),
    ("staking", "nominate", "Staking", "nominate", &["targets"]),
    ("staking", "chill", "Staking", "chill", &[]),
    (
        "staking",
        "join_pool",
        "NominationPools",
        "join",
        &["amount", "pool_id"],
    ),
    (
        "staking",
        "claim_pool_payout",
        "NominationPools",
        "claim_payout",
        &[],
    ),
    // --- organizations & budgets ---
    (
        "orgs",
        "create",
        "Organizations",
        "create_org",
        &["metadata"],
    ),
    (
        "orgs",
        "add_member",
        "Organizations",
        "add_member",
        &["org", "who", "role"],
    ),
    (
        "orgs",
        "remove_member",
        "Organizations",
        "remove_member",
        &["org", "who"],
    ),
    (
        "orgs",
        "allot",
        "Budgets",
        "allot",
        &["org", "project", "amount"],
    ),
    (
        "orgs",
        "authorize_secrets_agent",
        "Budgets",
        "authorize_project_secrets_agent",
        &["org", "project", "who"],
    ),
    (
        "orgs",
        "revoke_secrets_agent",
        "Budgets",
        "revoke_project_secrets_agent",
        &["org", "project", "who"],
    ),
];

#[test]
fn every_row_is_unique() {
    // A duplicated (façade, method) row would let two rows disagree about the
    // same method and still pass.
    let mut seen = BTreeSet::new();
    for (facade, method, ..) in FACADE_CALLS {
        assert!(
            seen.insert((*facade, *method)),
            "duplicate row for {facade}.{method}"
        );
    }
}

#[test]
fn pallet_and_call_names_are_runtime_shaped() {
    // Pallets are PascalCase and calls are snake_case in metadata. A camelCase
    // call here would resolve in @polkadot but not in subxt, which is exactly the
    // cross-language drift this fixture exists to prevent.
    for (facade, method, pallet, call, _) in FACADE_CALLS {
        let first = pallet.chars().next().expect("pallet name is not empty");
        assert!(
            first.is_ascii_uppercase(),
            "{facade}.{method}: pallet {pallet:?} should be PascalCase as metadata spells it"
        );
        assert!(
            call.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "{facade}.{method}: call {call:?} should be snake_case as metadata spells it"
        );
    }
}

#[test]
fn the_curated_facades_are_the_five_documented_ones() {
    // The set of façades is a documented promise (README, docs/parity.md). Adding
    // a sixth should be a deliberate act that updates those too, not a silent
    // consequence of adding a row.
    let facades: BTreeSet<&str> = FACADE_CALLS.iter().map(|(f, ..)| *f).collect();
    assert_eq!(
        facades,
        BTreeSet::from(["secrets", "deployments", "orgs", "resources", "staking"]),
    );
}

#[test]
fn secrets_covers_every_pallet_secrets_call() {
    // pallet-secrets has exactly five extrinsics and the SDK previously built
    // three of them, leaving `revoke_access` — the call that contains a leaked
    // signer — with no builder at all. All five must stay covered.
    let covered: BTreeSet<&str> = FACADE_CALLS
        .iter()
        .filter(|(_, _, pallet, ..)| *pallet == "Secrets")
        .map(|(_, _, _, call, _)| *call)
        .collect();
    assert_eq!(
        covered,
        BTreeSet::from([
            "store_secret",
            "rotate_secret",
            "grant_access",
            "revoke_access",
            "delete_secret",
        ]),
    );
}

#[test]
#[ignore = "writes testvectors/facade_calls.json; run explicitly to regenerate"]
fn emit_facade_call_vectors() {
    let calls: Vec<_> = FACADE_CALLS
        .iter()
        .map(|(facade, method, pallet, call, args)| {
            json!({
                "facade": facade,
                "method": method,
                "pallet": pallet,
                "call": call,
                "args": args,
            })
        })
        .collect();

    let vectors = json!({
        "comment": "The curated typed façade surface. Every binding with a chain \
                    client must expose exactly these (facade, method) pairs, each \
                    mapping to the named (pallet, call) with these ordered args. \
                    Method names are snake_case here; bindings apply their own \
                    convention (TypeScript camelCases them).",
        "calls": calls,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testvectors/facade_calls.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap()).unwrap();
    println!("wrote {path}");
}
