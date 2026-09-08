//! The scope contract, pinned as fixtures every language replays.
//!
//! Two things have to agree across four languages and one runtime: the bit
//! layout of a `ScopeSet`, and which set each call requires. Neither is
//! cryptography, so neither goes through the FFI — `matter-vault-ffi` is
//! deliberately crypto-only, and the two argument-sensitive rows could not cross
//! that boundary anyway without shipping the whole dynamic argument tree across
//! it. So they are ported per language and pinned here instead, exactly as
//! `facade_calls.json` pins the façade surface.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-vault --features chain --test scope_vectors -- --ignored
//! ```

#![cfg(feature = "chain")]

use matter_vault::chain::scopes_table::required_scopes;
use matter_vault::chain::Value;
use matter_vault::{Access, Scope, ScopeSet};
use serde_json::json;

/// Every pallet the runtime scopes, in `Scope` discriminant order.
const SCOPED_PALLETS: &[(&str, Scope)] = &[
    ("Jobs", Scope::Deployments),
    ("Collaborations", Scope::Collaborations),
    ("Secrets", Scope::Secrets),
    ("Volumes", Scope::Volumes),
    ("Datasets", Scope::Datasets),
    ("OverlayNetworks", Scope::Networking),
    ("Resources", Scope::Resources),
    ("Organizations", Scope::Organization),
    ("Budgets", Scope::Billing),
    ("Communities", Scope::Communities),
];

/// Calls whose required set depends on their arguments, not just their name.
/// A binding that replays the table must cover these separately, because the
/// fixture can only pin the name-derived half.
const ARG_SENSITIVE: &[(&str, &str)] = &[
    ("Jobs", "request_deployment"),
    ("Jobs", "set_deployment_secret_ref"),
];

fn none_value() -> Value {
    Value::unnamed_variant("None", [])
}

#[test]
fn the_bit_layout_matches_the_runtime_contract() {
    // Restated from matter-node/docs/api-keys.md's table, so a binding that
    // replays scope_bits.json is replaying something checked here first.
    for (index, scope) in Scope::ALL.iter().enumerate() {
        assert_eq!(*scope as usize, index);
        assert_eq!(
            ScopeSet::single(*scope, Access::Read).bits(),
            1 << (index * 2)
        );
        assert_eq!(
            ScopeSet::single(*scope, Access::Write).bits(),
            1 << (index * 2 + 1)
        );
    }
    assert_eq!(ScopeSet::ALL.bits(), (1 << 20) - 1);
}

#[test]
fn the_arg_sensitive_rows_differ_by_argument() {
    // The whole reason those two rows cannot be pinned by name alone.
    let cleared = vec![Value::u128(1), none_value()];
    let set = vec![
        Value::u128(1),
        Value::unnamed_variant("Some", [Value::u128(9)]),
    ];
    assert_ne!(
        required_scopes("Jobs", "set_deployment_secret_ref", &cleared),
        required_scopes("Jobs", "set_deployment_secret_ref", &set),
    );
}

#[test]
#[ignore = "writes testvectors/scope_bits.json and required_scopes.json; run explicitly to regenerate"]
fn emit_scope_vectors() {
    let scopes: Vec<_> = Scope::ALL
        .iter()
        .enumerate()
        .map(|(index, scope)| {
            json!({
                "scope": scope.name(),
                "index": index,
                "read_bit": ScopeSet::single(*scope, Access::Read).bits(),
                "write_bit": ScopeSet::single(*scope, Access::Write).bits(),
            })
        })
        .collect();

    // A truth table for the set algebra, so a binding cannot pass by
    // implementing `contains` as `bits != 0`.
    let deployments_w = ScopeSet::single(Scope::Deployments, Access::Write);
    let secrets_rw = ScopeSet::covering(&[Scope::Secrets]);
    let secrets_r = ScopeSet::single(Scope::Secrets, Access::Read);
    let algebra: Vec<_> = [
        (deployments_w, deployments_w, true),
        (deployments_w, secrets_r, false),
        (secrets_rw, secrets_r, true),
        // Read never implies Write, nor Write Read.
        (
            secrets_r,
            ScopeSet::single(Scope::Secrets, Access::Write),
            false,
        ),
        (ScopeSet::ALL, secrets_rw, true),
        (ScopeSet::EMPTY, deployments_w, false),
        (deployments_w, ScopeSet::EMPTY, true),
    ]
    .iter()
    .map(|(held, required, expected)| {
        assert_eq!(held.is_superset(*required), *expected);
        json!({
            "held": held.bits(),
            "required": required.bits(),
            "held_text": held.to_string(),
            "is_superset": expected,
        })
    })
    .collect();

    write_vector(
        "scope_bits.json",
        json!({
            "comment": "ScopeSet wire contract: bit = scope * 2 + access, encoded as a bare u32. \
                        Mirrors matter-node's common/src/scopes.rs; both enums are append-only. \
                        `algebra` pins is_superset, where Read and Write are independent bits.",
            "scopes": scopes,
            "all_bits": ScopeSet::ALL.bits(),
            "algebra": algebra,
        }),
    );

    // The name-derived half of the table, over every call the fixture metadata
    // knows about. `arg_sensitive` rows carry the requirement for arguments the
    // SDK cannot read, which is the fail-safe (wider) answer.
    let mut rows = Vec::new();
    for (pallet, _) in SCOPED_PALLETS {
        for call in calls_of(pallet) {
            let required = required_scopes(pallet, &call, &[]);
            rows.push(json!({
                "pallet": pallet,
                "call": call,
                "required": required.map(|s| s.bits()),
                "required_text": required.map(|s| s.to_string()),
                "arg_sensitive": ARG_SENSITIVE.contains(&(pallet, call.as_str())),
            }));
        }
    }

    write_vector(
        "required_scopes.json",
        json!({
            "comment": "What each call requires of a delegated key, mirroring matter-node's \
                        runtime/src/configs/budgets.rs::required_scopes. `required: null` means no \
                        scope set admits the call at all. Rows with `arg_sensitive: true` depend on \
                        the call's arguments too: the value here is the one the SDK uses when it \
                        cannot read the arguments, which is deliberately the wider set. Replay this \
                        BOTH ways — a row with no local classification and a local classification \
                        with no row are both drift.",
            "calls": rows,
        }),
    );
}

/// Call names for `pallet`, from the checked-in spec-322 metadata.
fn calls_of(pallet: &str) -> Vec<String> {
    use parity_scale_codec::Decode;
    let bytes: &[u8] = include_bytes!("../../../testvectors/spec322_metadata.scale");
    let metadata = subxt::Metadata::decode(&mut &bytes[..]).expect("fixture decodes");
    metadata
        .pallet_by_name(pallet)
        .and_then(|p| p.call_variants())
        .unwrap_or_else(|| panic!("{pallet} has calls"))
        .iter()
        .map(|v| v.name.to_string())
        .collect()
}

fn write_vector(name: &str, value: serde_json::Value) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testvectors/").to_string() + name;
    std::fs::write(&path, serde_json::to_string_pretty(&value).unwrap() + "\n")
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
    println!("wrote {path}");
}
