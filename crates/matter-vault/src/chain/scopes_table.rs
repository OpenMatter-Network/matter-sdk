//! The SDK's mirror of the runtime's `required_scopes` call table.
//!
//! Source of truth is `matter-node`'s `runtime/src/configs/budgets.rs`. This is
//! a copy, and [`tests::the_table_classifies_every_call_of_the_scoped_pallets`]
//! is what keeps the copy honest against a checked-in spec-322 metadata blob.
//!
//! # This check is a courtesy, not a boundary
//!
//! The runtime's `ProxyType::Scoped` filter is the only thing that actually
//! enforces scopes. Everything here exists so a caller reads
//! "your key lacks `volumes:w`" instead of a pool rejection that says
//! `Inability to pay some fees` — which is what a balance-less delegated key
//! gets when the chain refuses its call.
//!
//! It follows that this table **may be wrong in the safe direction** without
//! being a vulnerability, and that shapes one real decision below: the SDK
//! cannot always see whether a deployment request references a secret, because
//! the request arrives as an opaque caller-supplied `Value`. Where the shape
//! cannot be read, we demand the *wider* set. A false positive costs a caller a
//! local rejection they can work around; the opposite default would let a call
//! through the local check that the chain then refuses, which is the failure
//! this module exists to prevent.
//!
//! # Why this is stringly-typed where the runtime is not
//!
//! The runtime matches on a typed `RuntimeCall` and gets exhaustiveness from
//! the compiler. The SDK resolves calls by name against live metadata and has
//! no generated types, so it matches on `(pallet, call)` strings. The drift test
//! is the only substitute for that lost exhaustiveness, which is why it asserts
//! over every call name in the metadata rather than over a hand-written list.

use matter_vault_key::{Access, Scope, ScopeSet};
use subxt::dynamic::Value;
use subxt::ext::scale_value::{Composite, ValueDef};

/// The set holding only `scope:w`.
const fn write(scope: Scope) -> ScopeSet {
    ScopeSet::single(scope, Access::Write)
}

/// Shipping a secret into a container the key controls is a read of that
/// secret, so those rows want `Secrets:Read` on top of `Deployments:Write`.
const DEPLOY_WITH_SECRET: ScopeSet = write(Scope::Deployments).with(Scope::Secrets, Access::Read);

/// The ten pallets a scoped key can reach at all.
///
/// Public so the live-chain tripwire can walk the same list this table claims to
/// cover: a runtime that adds a call to one of these and is not reflected here
/// would otherwise be found by a user rather than by CI.
pub const SCOPED_PALLETS: &[&str] = &[
    "Jobs",
    "Collaborations",
    "Secrets",
    "Volumes",
    "Datasets",
    "OverlayNetworks",
    "Resources",
    "Organizations",
    "Budgets",
    "Communities",
];

/// The calls of the scoped pallets that no key may ever make, per pallet.
///
/// Copied verbatim from matter-node's
/// `required_scopes_table_classifies_every_call_of_the_scoped_pallets`. The
/// duplication across repos is deliberate: the two share no crate, so this list
/// *is* the contract. Within this repo it has exactly one home, because both the
/// fixture drift test and the live tripwire need to tell "deliberately admits
/// nothing" from "nobody has classified this yet", and two copies of that
/// distinction would eventually disagree.
pub const NEVER_ADMITTED: &[(&str, &[&str])] = &[
    (
        "Jobs",
        &[
            "update_deployment_status",
            "set_deployment_network",
            "report_tls_status",
        ],
    ),
    (
        "Resources",
        &[
            "report_consumption",
            "request_consumption_report",
            "report_capacity",
            "update_sku",
            "remove_sku",
            "set_provider_min_stake",
        ],
    ),
    (
        "Collaborations",
        &["set_compute_node_image", "set_compute_node_sku_id"],
    ),
    ("OverlayNetworks", &[]),
    ("Volumes", &[]),
    ("Secrets", &[]),
    (
        "Datasets",
        &[
            "force_delist_dataset",
            "force_restore_dataset",
            "force_delete_dataset",
        ],
    ),
    ("Organizations", &["create_org", "delete_org"]),
    (
        "Budgets",
        &[
            "fund_org_treasury",
            "withdraw_org_treasury",
            "authorize_project_deployer",
            "revoke_project_deployer",
            "claim_sponsorship",
            "transfer_sponsorship",
            "authorize_project_secrets_agent",
            "revoke_project_secrets_agent",
            "authorize_org_resource_operator",
            "revoke_org_resource_operator",
            "bond_org_stake",
            "unbond_org_stake",
            "withdraw_org_stake",
            "approve_sponsor",
            "authorize_agent_key",
            "revoke_agent_key",
        ],
    ),
    (
        "Communities",
        &[
            "force_delist_community",
            "force_restore_community",
            "force_delete_community",
        ],
    ),
];

/// What `pallet.call(args)` requires of a delegated key's [`ScopeSet`], or
/// `None` if no set admits it at all (provider-signed, root-only, org
/// lifecycle, the roster calls, and every treasury value mover).
///
/// `args` is inspected only for the two rows whose requirement genuinely
/// depends on it; every other row is decided by name alone.
pub fn required_scopes(pallet: &str, call: &str, args: &[Value]) -> Option<ScopeSet> {
    match (pallet, call) {
        ("Jobs", "request_deployment") => Some(if request_references_secret(args.first()) {
            DEPLOY_WITH_SECRET
        } else {
            write(Scope::Deployments)
        }),
        ("Jobs", "set_deployment_secret_ref") => Some(if is_none(args.get(1)) {
            write(Scope::Deployments)
        } else {
            DEPLOY_WITH_SECRET
        }),
        (
            "Jobs",
            "cancel_deployment"
            | "set_deployment_env"
            | "set_deployment_image"
            | "set_deployment_launch",
        ) => Some(write(Scope::Deployments)),
        ("Jobs", "register_wg_peer" | "remove_wg_peer") => Some(write(Scope::Networking)),
        // `update_deployment_status`, `set_deployment_network`,
        // `report_tls_status`: provider-signed.
        ("Jobs", _) => None,

        // Every call but the two root-only setters — the permissionless cranks
        // included, which a key may legitimately drive.
        ("Collaborations", "set_compute_node_image" | "set_compute_node_sku_id") => None,
        ("Collaborations", _) => Some(write(Scope::Collaborations)),

        ("Secrets", _) => Some(write(Scope::Secrets)),
        ("Volumes", _) => Some(write(Scope::Volumes)),
        ("OverlayNetworks", _) => Some(write(Scope::Networking)),

        ("Datasets", "force_delist_dataset" | "force_restore_dataset" | "force_delete_dataset") => {
            None
        }
        ("Datasets", _) => Some(write(Scope::Datasets)),

        (
            "Resources",
            "register_resource"
            | "register_private_resource"
            | "register_org_resource"
            | "reactivate_resource"
            | "set_resource_privacy"
            | "add_to_whitelist"
            | "remove_from_whitelist"
            | "update_resource_name"
            | "remove_resource",
        ) => Some(write(Scope::Resources)),
        // `report_consumption`, `report_capacity`, `request_consumption_report`:
        // provider-signed; the SKU and stake setters: root.
        ("Resources", _) => None,

        (
            "Organizations",
            "add_member"
            | "set_member_role"
            | "remove_member"
            | "create_project"
            | "assign_to_project"
            | "unassign_from_project"
            | "delete_project"
            | "add_project_deployment_peer",
        ) => Some(write(Scope::Organization)),
        // `create_org` / `delete_org`: org lifecycle stays human-signed.
        ("Organizations", _) => None,

        (
            "Budgets",
            "allot"
            | "defund_project"
            | "set_plan_allotment"
            | "add_purchased_allotment"
            | "set_purchased_allotment"
            | "set_member_billing"
            | "clear_member_billing"
            | "set_member_gas_limit",
        ) => Some(write(Scope::Billing)),
        // Every other budgets call — the roster calls, so a key never mints
        // authority, and the treasury value movers.
        ("Budgets", _) => None,

        (
            "Communities",
            "force_delist_community" | "force_restore_community" | "force_delete_community",
        ) => None,
        ("Communities", _) => Some(write(Scope::Communities)),

        _ => None,
    }
}

/// Whether `value` is definitely the `None` variant of an `Option`.
///
/// Absent or unreadable counts as "not None", which is the wider requirement.
fn is_none(value: Option<&Value>) -> bool {
    matches!(value, Some(v) if matches!(&v.value, ValueDef::Variant(var) if var.name == "None"))
}

/// Whether a `ResourceRequest` sets either secret reference.
///
/// The request is whatever the caller passed — `Deployments::request`
/// deliberately does not mirror `ResourceRequest`'s shape, so this reads the
/// fields by name and gives up safely. Anything it cannot read — a positional
/// composite, a missing field, no argument at all — is treated as referencing a
/// secret, per this module's fail-safe direction.
fn request_references_secret(request: Option<&Value>) -> bool {
    let Some(request) = request else {
        return true;
    };
    let ValueDef::Composite(Composite::Named(fields)) = &request.value else {
        return true;
    };
    ["secret_ref", "tls_secret_ref"].iter().any(|name| {
        match fields.iter().find(|(field, _)| field == name) {
            Some((_, value)) => !is_none(Some(value)),
            // A request without the field is one this SDK cannot reason about.
            None => true,
        }
    })
}

#[cfg(test)]
mod tests {
    /// The checked-in spec-322 metadata. Regenerate against a `matter-node` at
    /// spec >= 322 running `--dev`:
    ///
    /// ```text
    /// curl -s -H 'Content-Type: application/json' \
    ///   -d '{"jsonrpc":"2.0","id":1,"method":"state_call",
    ///        "params":["Metadata_metadata_at_version","0x0f000000"]}' \
    ///   http://127.0.0.1:9944
    /// ```
    ///
    /// then strip the `Option` byte and the SCALE compact length prefix and
    /// keep the rest, which begins `meta\x0f`. It must be **V15**, not the V14
    /// that `state_getMetadata` returns: V14 carries no runtime-API definitions,
    /// and the client resolves `BudgetsApi_agent_key` from these same bytes.
    ///
    /// Go and Python read V14 — GSRPC and substrate-interface have no V15
    /// decoder — so `testvectors/spec322_metadata_v14.scale` is its sibling,
    /// taken from `state_getMetadata` on the same runtime.
    ///
    /// # When the runtime moves past 322
    ///
    /// The live tripwire in `tests/live_chain.rs` fails first, naming the call
    /// the table does not classify. Spec 323 is known to add
    /// `Budgets.set_project_spend_cap` to the `Billing:Write` row. The recipe:
    /// regenerate both blobs against the new runtime, add the row here and in
    /// the TypeScript, Python and Go tables, then re-emit
    /// `testvectors/required_scopes.json` (see `testvectors/README.md`).
    use super::super::test_metadata as metadata;
    use super::*;

    /// The fixture must be the runtime this table was written against;
    /// otherwise the drift test below is checking the wrong contract.
    #[test]
    fn the_fixture_is_a_scoped_key_runtime() {
        let meta = metadata();
        let budgets = meta.pallet_by_name("Budgets").expect("Budgets pallet");
        let calls: Vec<_> = budgets
            .call_variants()
            .expect("Budgets has calls")
            .iter()
            .map(|v| v.name.as_str())
            .collect();
        assert!(calls.contains(&"authorize_agent_key"));
        assert!(calls.contains(&"revoke_agent_key"));

        // The client resolves the key's principal through this runtime API, and
        // resolving it from metadata is how it detects a pre-322 chain.
        assert!(
            meta.runtime_api_trait_by_name("BudgetsApi")
                .and_then(|t| t.method_by_name("agent_key"))
                .is_some(),
            "fixture must carry runtime-API definitions (V15, not V14)"
        );
    }

    /// Every call of the ten scoped pallets is classified — a call added to any
    /// of them fails here until it is given a row or put on the never list.
    /// This is the SDK's stand-in for the exhaustiveness the runtime's typed
    /// match gets for free.
    #[test]
    fn the_table_classifies_every_call_of_the_scoped_pallets() {
        let meta = metadata();
        for (pallet, denied) in NEVER_ADMITTED {
            let variants = meta
                .pallet_by_name(pallet)
                .and_then(|p| p.call_variants())
                .unwrap_or_else(|| panic!("{pallet} has calls in the fixture"));
            assert!(!variants.is_empty(), "{pallet} has calls");

            for variant in variants {
                let name = variant.name.as_str();
                // Args only matter for the two rows tested separately below;
                // an empty slice takes each of them down its widest branch,
                // which is still a `Some`, so classification is unaffected.
                let got = required_scopes(pallet, name, &[]);
                if denied.contains(&name) {
                    assert!(
                        got.is_none(),
                        "{pallet}.{name} is on the never list but the table admits it as {got:?}"
                    );
                } else {
                    assert!(
                        got.is_some(),
                        "{pallet}.{name} exists on chain but the table admits no set for it"
                    );
                }
            }

            for name in *denied {
                assert!(
                    variants.iter().any(|v| v.name == *name),
                    "{pallet}.{name} names a real call"
                );
            }
        }
    }

    /// Calls outside the ten scoped pallets are never admitted, whatever the
    /// key's set — token movement and staking most of all.
    #[test]
    fn unscoped_pallets_are_never_admitted() {
        for (pallet, call) in [
            ("Balances", "transfer_all"),
            ("Balances", "transfer_keep_alive"),
            ("Staking", "bond"),
            ("Sudo", "sudo"),
            ("Proxy", "proxy"),
            ("Utility", "batch_all"),
            ("EthSigning", "dispatch_eth_signed"),
            ("NotAPallet", "nope"),
        ] {
            assert_eq!(required_scopes(pallet, call, &[]), None, "{pallet}.{call}");
        }
    }

    #[test]
    fn wholesale_pallets_map_to_their_group() {
        assert_eq!(
            required_scopes("Secrets", "store_secret", &[]),
            Some(write(Scope::Secrets))
        );
        assert_eq!(
            required_scopes("Volumes", "create_volume", &[]),
            Some(write(Scope::Volumes))
        );
        assert_eq!(
            required_scopes("OverlayNetworks", "create_network", &[]),
            Some(write(Scope::Networking))
        );
        assert_eq!(
            required_scopes("Datasets", "register_dataset", &[]),
            Some(write(Scope::Datasets))
        );
        assert_eq!(
            required_scopes("Communities", "create_community", &[]),
            Some(write(Scope::Communities))
        );
        assert_eq!(
            required_scopes("Collaborations", "expire_attestation", &[]),
            Some(write(Scope::Collaborations))
        );
    }

    /// `set_deployment_secret_ref(_, None)` clears a reference and needs no
    /// read; `Some` ships a secret into the container.
    #[test]
    fn clearing_a_secret_ref_does_not_need_secrets_read() {
        let clear = vec![Value::u128(1), Value::unnamed_variant("None", [])];
        assert_eq!(
            required_scopes("Jobs", "set_deployment_secret_ref", &clear),
            Some(write(Scope::Deployments))
        );

        let set = vec![
            Value::u128(1),
            Value::unnamed_variant("Some", [Value::u128(7)]),
        ];
        assert_eq!(
            required_scopes("Jobs", "set_deployment_secret_ref", &set),
            Some(DEPLOY_WITH_SECRET)
        );
    }

    /// A request whose shape cannot be read takes the wider set. This is the
    /// module's fail-safe direction, asserted rather than assumed.
    #[test]
    fn an_unreadable_deployment_request_takes_the_wider_set() {
        let named = |secret: Value, tls: Value| {
            vec![Value::named_composite([
                ("secret_ref", secret),
                ("tls_secret_ref", tls),
            ])]
        };
        let none = || Value::unnamed_variant("None", []);
        let some = || Value::unnamed_variant("Some", [Value::u128(7)]);

        // Both cleared, and readable: the narrow set is enough.
        assert_eq!(
            required_scopes("Jobs", "request_deployment", &named(none(), none())),
            Some(write(Scope::Deployments))
        );
        // Either one set: wider.
        for args in [named(some(), none()), named(none(), some())] {
            assert_eq!(
                required_scopes("Jobs", "request_deployment", &args),
                Some(DEPLOY_WITH_SECRET)
            );
        }
        // Unreadable shapes, all of which must fail safe.
        for args in [
            vec![],
            vec![Value::u128(1)],
            vec![Value::unnamed_composite([none(), none()])],
            vec![Value::named_composite([("secret_ref", none())])],
        ] {
            assert_eq!(
                required_scopes("Jobs", "request_deployment", &args),
                Some(DEPLOY_WITH_SECRET),
                "unreadable request must take the wider set"
            );
        }
    }

    /// The two `Jobs` networking calls belong to `Networking`, not
    /// `Deployments` — an easy row to mis-copy, since they live in `pallet-jobs`.
    #[test]
    fn wireguard_peers_are_networking_not_deployments() {
        for call in ["register_wg_peer", "remove_wg_peer"] {
            assert_eq!(
                required_scopes("Jobs", call, &[]),
                Some(write(Scope::Networking))
            );
        }
    }
}
