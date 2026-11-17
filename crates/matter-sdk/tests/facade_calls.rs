//! The curated façade surface, pinned as `testvectors/facade_calls.json` (writes) and
//! `testvectors/facade_reads.json` (reads; emitted by `chain::read::vectors`).
//!
//! Façades are hand-written per language. TypeScript, Python, and Go check the fixtures
//! both ways by reflection (missing row or missing method both fail); Rust pins them here.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-sdk --features chain --test facade_calls -- --ignored
//! ```

#![cfg(feature = "chain")]

mod common;

use std::collections::BTreeSet;

use common::{pinned_shapes, read_catalogue, source_shapes, SHAPES_FIXTURE};
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

/// The spec-330 runtime every offline check here is made against.
fn fixture_metadata() -> subxt::Metadata {
    use parity_scale_codec::Decode;
    let bytes: &[u8] = include_bytes!("../../../testvectors/spec330_metadata.scale");
    subxt::Metadata::decode(&mut &bytes[..]).expect("fixture decodes")
}

/// `(façade, method)` of every catalogue read. The catalogue's emitter is a lib
/// test (it runs the real façades), so this crate reads the file.
fn catalogue_reads() -> Vec<(String, String)> {
    let text = |row: &serde_json::Value, key: &str| {
        row[key]
            .as_str()
            .unwrap_or_else(|| panic!("a catalogue row has no {key}"))
            .to_string()
    };
    read_catalogue()["reads"]
        .as_array()
        .expect("the catalogue lists reads")
        .iter()
        .map(|row| (text(row, "facade"), text(row, "method")))
        .collect()
}

#[test]
fn every_row_is_unique() {
    // Across every table: a method cannot be both an extrinsic and a read.
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
    let reads = catalogue_reads();
    for (facade, method) in &reads {
        assert!(
            seen.insert((facade.as_str(), method.as_str())),
            "{facade}.{method} is pinned twice"
        );
    }
}

/// Bindings replay the fixture against fakes, so only this check against real metadata
/// catches a wrong argument name offline.
#[test]
fn fixture_args_match_the_runtime_fields() {
    let metadata = fixture_metadata();

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

/// Runtime-API rows are replayed against fakes everywhere else, so only this check
/// against real metadata catches a method the runtime does not declare.
#[test]
fn runtime_api_rows_exist_in_the_metadata() {
    let metadata = fixture_metadata();

    for (facade, method, state_call, args) in FACADE_RUNTIME_API_CALLS {
        let (trait_name, method_name) = state_call.split_once('_').expect("Trait_method");
        let declared = metadata
            .runtime_api_trait_by_name(trait_name)
            .and_then(|api| api.method_by_name(method_name))
            .unwrap_or_else(|| panic!("{facade}.{method}: {state_call} is not on chain"));
        let actual: Vec<&str> = declared.inputs().map(|input| input.name.as_str()).collect();
        assert_eq!(
            actual, *args,
            "{facade}.{method} ({state_call}): fixture and runtime disagree on arguments"
        );
    }
}

/// Every source a catalogue read names must exist in the runtime. Storage values are
/// also encoded against their type when the vectors are emitted; this covers the
/// kinds that are not, and a row added by hand.
#[test]
fn catalogue_sources_exist_in_the_metadata() {
    let metadata = fixture_metadata();

    let catalogue = read_catalogue();
    for row in catalogue["reads"].as_array().expect("reads") {
        let read = format!("{}.{}", row["facade"], row["method"]);
        for source in row["sources"].as_array().expect("sources") {
            let name = source["name"].as_str().expect("a source has a name");
            let exists = match source["kind"].as_str().expect("a source has a kind") {
                "storage" => name.split_once('.').is_some_and(|(pallet, entry)| {
                    metadata
                        .pallet_by_name(pallet)
                        .and_then(|p| p.storage())
                        .is_some_and(|s| s.entry_by_name(entry).is_some())
                }),
                "constant" => name.split_once('.').is_some_and(|(pallet, constant)| {
                    metadata
                        .pallet_by_name(pallet)
                        .is_some_and(|p| p.constant_by_name(constant).is_some())
                }),
                "runtime_api" => name.split_once('_').is_some_and(|(api, method)| {
                    metadata
                        .runtime_api_trait_by_name(api)
                        .is_some_and(|t| t.method_by_name(method).is_some())
                }),
                // JSON-RPC methods are the node's, not the runtime's: no metadata.
                "rpc" => true,
                other => panic!("{read}: unknown source kind {other:?}"),
            };
            assert!(
                exists,
                "{read}: source {name} is not in the spec-330 runtime"
            );
        }
    }
}

#[test]
fn the_curated_facades_are_the_documented_ones() {
    // Documented in README and docs/parity.md (asserted below); a new façade needs a guide.
    let reads = catalogue_reads();
    let facades: BTreeSet<&str> = FACADE_CALLS
        .iter()
        .map(|(f, ..)| *f)
        .chain(FACADE_RUNTIME_API_CALLS.iter().map(|(f, ..)| *f))
        .chain(reads.iter().map(|(f, _)| f.as_str()))
        .collect();
    assert_eq!(
        facades,
        BTreeSet::from([
            "accounts",
            "network",
            "fees",
            "secrets",
            "deployments",
            "orgs",
            "resources",
            "staking",
            "keys",
        ]),
    );
}

/// The guide that documents each façade, as `(façade, doc)`.
const FACADE_GUIDES: &[(&str, &str)] = &[
    ("accounts", include_str!("../../../docs/reading-state.md")),
    ("network", include_str!("../../../docs/reading-state.md")),
    ("fees", include_str!("../../../docs/reading-state.md")),
    ("secrets", include_str!("../../../docs/secrets.md")),
    ("deployments", include_str!("../../../docs/deployments.md")),
    ("orgs", include_str!("../../../docs/organizations.md")),
    ("resources", include_str!("../../../docs/resources.md")),
    ("staking", include_str!("../../../docs/staking.md")),
    ("keys", include_str!("../../../docs/keys-and-scopes.md")),
];

#[test]
fn every_facade_method_is_documented_in_its_guide() {
    let reads = catalogue_reads();
    let pin = read_catalogue()["pin_method"]
        .as_str()
        .expect("the catalogue names the pin method")
        .to_string();
    let rows = FACADE_CALLS
        .iter()
        .map(|(f, m, ..)| (*f, *m))
        .chain(FACADE_RUNTIME_API_CALLS.iter().map(|(f, m, ..)| (*f, *m)))
        .chain(reads.iter().map(|(f, m)| (f.as_str(), m.as_str())))
        // Any façade that reads can be pinned to a block.
        .chain(reads.iter().map(|(f, _)| (f.as_str(), pin.as_str())));
    for (facade, method) in rows {
        let (_, guide) = FACADE_GUIDES
            .iter()
            .find(|(f, _)| *f == facade)
            .unwrap_or_else(|| panic!("façade {facade:?} has no guide in FACADE_GUIDES"));
        assert!(
            guide.contains(&format!("`{method}`")),
            "the {facade} guide must document `{method}`"
        );
    }
}

#[test]
fn the_readme_and_parity_name_every_facade() {
    let docs = [
        ("README.md", include_str!("../../../README.md")),
        ("docs/parity.md", include_str!("../../../docs/parity.md")),
    ];
    for (facade, _) in FACADE_GUIDES {
        for (path, doc) in docs {
            assert!(
                doc.contains(&format!("`{facade}`")),
                "{path} must name the `{facade}` façade"
            );
        }
    }
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

/// Decoders are written for one layout. This pins it, so a metadata refresh that
/// changes a source's bytes shows up as a diff to review before a read breaks.
#[test]
fn the_checked_in_source_shapes_are_current() {
    assert_eq!(
        pinned_shapes(),
        source_shapes(&fixture_metadata()),
        "testvectors/read_source_shapes.json is stale; regenerate it with \
         `cargo test -p matter-sdk --features chain --test facade_calls -- --ignored`"
    );
}

#[test]
#[ignore = "writes testvectors/read_source_shapes.json; run explicitly to regenerate"]
fn emit_read_source_shapes() {
    let fixture = json!({
        "comment": "The layout of every runtime source a catalogue read decodes \
                    (facade_reads.json), rendered from spec330_metadata.scale: field \
                    names, widths and enum variants with their indices. Read decoders \
                    are strict and positional, so this is what they were written for. \
                    The nightly runtime-drift job recomputes it from the live runtime \
                    and fails on any difference.",
        "spec_version": 330,
        "shapes": source_shapes(&fixture_metadata()),
    });
    let text = serde_json::to_string_pretty(&fixture).unwrap();
    std::fs::write(SHAPES_FIXTURE, format!("{text}\n")).unwrap();
    println!("wrote {SHAPES_FIXTURE}");
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
