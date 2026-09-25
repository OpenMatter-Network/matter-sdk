//! The curated façade surface, pinned as `testvectors/facade_calls.json`.
//!
//! Façades are hand-written per language. TypeScript, Python, and Go check the fixture
//! both ways by reflection (missing row or missing method both fail); Rust pins it here.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-sdk --features chain --test facade_calls -- --ignored
//! ```

#![cfg(feature = "chain")]

use std::collections::BTreeSet;

use serde_json::json;

/// `(façade, method, pallet, call, ordered arg names)`. Adding a façade method means
/// adding a row here and regenerating.
const FACADE_CALLS: &[(&str, &str, &str, &str, &[&str])] = &[
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
        &["deployment", "user_wg_pubkey", "pq_ciphertext"],
    ),
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
    ("staking", "bond", "Staking", "bond", &["value", "payee"]),
    (
        "staking",
        "bond_extra",
        "Staking",
        "bond_extra",
        &["max_additional"],
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
    // No args: the org id is derived from the signer and a sequence number.
    ("orgs", "create", "Organizations", "create_org", &[]),
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
    // Member-signed only: the runtime never admits these under a key, so a key
    // cannot widen itself.
    (
        "keys",
        "authorize",
        "Budgets",
        "authorize_agent_key",
        &["key", "scopes"],
    ),
    ("keys", "revoke", "Budgets", "revoke_agent_key", &["key"]),
];

/// Façade reads routed through a runtime API: `(façade, method, state_call, ordered arg
/// names)`.
const FACADE_RUNTIME_API_CALLS: &[(&str, &str, &str, &[&str])] =
    &[("keys", "lookup", "BudgetsApi_agent_key", &["key"])];

#[test]
fn every_row_is_unique() {
    // Across both tables: a method cannot be both an extrinsic and a read.
    let mut seen = BTreeSet::new();
    for (facade, method, ..) in FACADE_CALLS {
        assert!(
            seen.insert((*facade, *method)),
            "duplicate row for {facade}.{method}"
        );
    }
    for (facade, method, ..) in FACADE_RUNTIME_API_CALLS {
        assert!(
            seen.insert((*facade, *method)),
            "{facade}.{method} is pinned as both an extrinsic and a read"
        );
    }
}

/// Bindings replay the fixture against fakes, so only this check against real metadata
/// catches a wrong argument name offline.
#[test]
fn fixture_args_match_the_runtime_fields() {
    use parity_scale_codec::Decode;
    let bytes: &[u8] = include_bytes!("../../../testvectors/spec330_metadata.scale");
    let metadata = subxt::Metadata::decode(&mut &bytes[..]).expect("fixture decodes");

    let mut problems: Vec<String> = Vec::new();
    for (facade, method, pallet, call, args) in FACADE_CALLS {
        let Some(variant) = metadata
            .pallet_by_name(pallet)
            .and_then(|p| p.call_variants())
            .and_then(|v| v.iter().find(|v| v.name == *call))
        else {
            problems.push(format!(
                "{facade}.{method}: {pallet}.{call} is not on chain"
            ));
            continue;
        };
        let actual: Vec<&str> = variant
            .fields
            .iter()
            .filter_map(|f| f.name.as_deref())
            .collect();
        if actual != *args {
            problems.push(format!(
                "{facade}.{method} ({pallet}.{call}): fixture says {args:?}, runtime says {actual:?}"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{} façade row(s) disagree with the runtime:\n  {}",
        problems.len(),
        problems.join("\n  ")
    );
}

#[test]
fn pallet_and_call_names_are_runtime_shaped() {
    // A camelCase call resolves in @polkadot but not in subxt.
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
fn runtime_api_rows_name_a_state_call() {
    // `state_call` takes `Trait_method`, not `pallet.call`.
    for (facade, method, state_call, _) in FACADE_RUNTIME_API_CALLS {
        let (trait_name, method_name) = state_call
            .split_once('_')
            .unwrap_or_else(|| panic!("{facade}.{method}: {state_call:?} is not Trait_method"));
        assert!(
            trait_name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase()),
            "{facade}.{method}: {trait_name:?} should be the PascalCase runtime-API trait"
        );
        assert!(
            method_name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "{facade}.{method}: {method_name:?} should be snake_case"
        );
    }
}

#[test]
fn the_curated_facades_are_the_six_documented_ones() {
    // Documented in README and docs/parity.md; a new façade must update those too.
    let facades: BTreeSet<&str> = FACADE_CALLS
        .iter()
        .map(|(f, ..)| *f)
        .chain(FACADE_RUNTIME_API_CALLS.iter().map(|(f, ..)| *f))
        .collect();
    assert_eq!(
        facades,
        BTreeSet::from([
            "secrets",
            "deployments",
            "orgs",
            "resources",
            "staking",
            "keys",
        ]),
    );
}

#[test]
fn secrets_covers_every_pallet_secrets_call() {
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

    let runtime_api_calls: Vec<_> = FACADE_RUNTIME_API_CALLS
        .iter()
        .map(|(facade, method, state_call, args)| {
            json!({
                "facade": facade,
                "method": method,
                "state_call": state_call,
                "args": args,
            })
        })
        .collect();

    let vectors = json!({
        "comment": "The curated typed façade surface. Every binding with a chain \
                    client must expose exactly these (facade, method) pairs — the \
                    union of both arrays, and no more. `calls` are extrinsics, each \
                    mapping to the named (pallet, call) with these ordered args; \
                    `runtime_api_calls` are reads routed through a `state_call` \
                    instead, which is why they cannot share the same table. Method \
                    names are snake_case here; bindings apply their own convention \
                    (TypeScript camelCases them).",
        "calls": calls,
        "runtime_api_calls": runtime_api_calls,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testvectors/facade_calls.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap()).unwrap();
    println!("wrote {path}");
}
