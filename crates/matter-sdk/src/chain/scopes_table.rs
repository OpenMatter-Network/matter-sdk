//! Mirror of the runtime's `required_scopes` table (source of truth:
//! `matter-node` `runtime/src/configs/budgets.rs`), kept in sync by
//! `the_table_classifies_every_call_of_the_scoped_pallets` against a
//! checked-in spec-330 metadata blob.
//!
//! This is a courtesy check, not a security boundary: only the runtime's
//! `ProxyType::Scoped` filter enforces scopes. It turns a pool
//! `Inability to pay some fees` into "your key lacks `volumes:w`". Where a
//! caller-supplied `Value` cannot be read, it demands the wider set.
//!
//! Calls match on `(pallet, call)` strings, so the drift test over every call in
//! the metadata stands in for compiler exhaustiveness.

use matter_sdk_key::{Access, Scope, ScopeSet};
use subxt::dynamic::Value;
use subxt::ext::scale_value::{Composite, ValueDef};

const fn write(scope: Scope) -> ScopeSet {
    ScopeSet::single(scope, Access::Write)
}

/// Shipping a secret into a container is a read of it.
const DEPLOY_WITH_SECRET: ScopeSet = write(Scope::Deployments).with(Scope::Secrets, Access::Read);

/// The pallets a scoped key can reach at all. Public for the live-chain tripwire.
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

/// Per scoped pallet, the calls no key may ever make. Copied verbatim from
/// matter-node's `required_scopes_table_classifies_every_call_of_the_scoped_pallets`;
/// the only copy in this repo, shared by the drift test and the live tripwire.
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
            "fund_non_revolving_treasury",
            "withdraw_non_revolving_treasury",
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
/// `None` if no set admits it (provider-signed, root-only, org lifecycle,
/// roster calls, treasury value movers).
///
/// `args` matters only for `request_deployment` and `set_deployment_secret_ref`.
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
            | "set_deployment_launch"
            | "set_deployment_policy_root"
            | "set_deployment_volumes"
            | "set_deployment_restart_policy",
        ) => Some(write(Scope::Deployments)),
        ("Jobs", "register_wg_peer" | "remove_wg_peer") => Some(write(Scope::Networking)),
        // `update_deployment_status`, `set_deployment_network`,
        // `report_tls_status`: provider-signed.
        ("Jobs", _) => None,

        // All but the root-only setters, permissionless cranks included.
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
            | "suspend_resource"
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
            | "set_member_gas_limit"
            | "set_project_spend_cap",
        ) => Some(write(Scope::Billing)),
        // Roster calls (a key never mints authority) and treasury value movers.
        ("Budgets", _) => None,

        (
            "Communities",
            "force_delist_community" | "force_restore_community" | "force_delete_community",
        ) => None,
        ("Communities", _) => Some(write(Scope::Communities)),

        _ => None,
    }
}

/// Whether `value` is definitely `None`. Absent or unreadable counts as not
/// `None` (the wider requirement).
fn is_none(value: Option<&Value>) -> bool {
    matches!(value, Some(v) if matches!(&v.value, ValueDef::Variant(var) if var.name == "None"))
}

/// Whether a caller-supplied `ResourceRequest` sets either secret reference.
/// Anything unreadable (positional composite, missing field, no argument)
/// counts as referencing a secret.
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
            None => true,
        }
    })
}

#[cfg(test)]
mod tests {
    /// The checked-in spec-330 metadata. Regenerate against a `matter-node` at
    /// spec >= 330 running `--dev`:
    ///
    /// ```text
    /// curl -s -H 'Content-Type: application/json' \
    ///   -d '{"jsonrpc":"2.0","id":1,"method":"state_call",
    ///        "params":["Metadata_metadata_at_version","0x0f000000"]}' \
    ///   http://127.0.0.1:9944
    /// ```
    ///
    /// then strip the `Option` byte and SCALE compact length prefix, keeping
    /// bytes that begin `meta\x0f`. It must be V15: V14 (`state_getMetadata`)
    /// has no runtime-API definitions. Go and Python read the V14 sibling
    /// `testvectors/spec330_metadata_v14.scale` from the same runtime.
    ///
    /// When the runtime adds calls (`tests/live_chain.rs` fails first):
    /// regenerate both blobs, add the row here and in the TypeScript, Python and
    /// Go tables, then re-emit `testvectors/required_scopes.json` (see
    /// `testvectors/README.md`).
    use super::super::test_metadata as metadata;
    use super::*;

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

        assert!(
            meta.runtime_api_trait_by_name("BudgetsApi")
                .and_then(|t| t.method_by_name("agent_key"))
                .is_some(),
            "fixture must carry runtime-API definitions (V15, not V14)"
        );
    }

    /// A new call fails here until it gets a row or goes on the never list.
    #[test]
    fn the_table_classifies_every_call_of_the_scoped_pallets() {
        let meta = metadata();
        // Report every disagreement at once; upgrades add several calls.
        let mut problems: Vec<String> = Vec::new();
        for (pallet, denied) in NEVER_ADMITTED {
            let variants = meta
                .pallet_by_name(pallet)
                .and_then(|p| p.call_variants())
                .unwrap_or_else(|| panic!("{pallet} has calls in the fixture"));
            assert!(!variants.is_empty(), "{pallet} has calls");

            for variant in variants {
                let name = variant.name.as_str();
                // Empty args take the widest branch, still `Some`.
                let got = required_scopes(pallet, name, &[]);
                if denied.contains(&name) {
                    if got.is_some() {
                        problems.push(format!(
                            "{pallet}.{name} is on the never list but the table admits it as {got:?}"
                        ));
                    }
                } else if got.is_none() {
                    problems.push(format!(
                        "{pallet}.{name} exists on chain but the table admits no set for it"
                    ));
                }
            }

            for name in *denied {
                assert!(
                    variants.iter().any(|v| v.name == *name),
                    "{pallet}.{name} names a real call"
                );
            }
        }

        assert!(
            problems.is_empty(),
            "the table disagrees with the runtime on {} call(s):\n  {}",
            problems.len(),
            problems.join("\n  ")
        );
    }

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

        assert_eq!(
            required_scopes("Jobs", "request_deployment", &named(none(), none())),
            Some(write(Scope::Deployments))
        );
        for args in [named(some(), none()), named(none(), some())] {
            assert_eq!(
                required_scopes("Jobs", "request_deployment", &args),
                Some(DEPLOY_WITH_SECRET)
            );
        }
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
