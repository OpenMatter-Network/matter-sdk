//! Whether this client signs for itself or acts for a member.
//!
//! From runtime spec 322, a member-tied API key holds a
//! `ProxyType::Scoped(ScopeSet)` proxy on the minting member's account and acts
//! only via `proxy.proxy(member, None, call)`. Its own account has no balance,
//! so a direct call is refused with `Inability to pay some fees`. A key with no
//! grant is [`Mode::Direct`].

use matter_sdk_key::{AccountId, ScopeSet};
use subxt::dynamic::Value;
use subxt::utils::AccountId32;
use subxt::{OnlineClient, PolkadotConfig};

use crate::error::{Result, SdkError};

/// Runtime API mapping a key to its principal; absent before spec 322.
const AGENT_KEY_TRAIT: &str = "BudgetsApi";
const AGENT_KEY_METHOD: &str = "agent_key";

/// Names the principal a key acts for when the chain's own pointer is stale.
const PRINCIPAL_ENV: &str = "MATTER_PRINCIPAL";

/// Who this client's signature speaks for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// The signer acts as itself: a human seed, an HSM key, a legacy
    /// project-tied key, or any key on a pre-322 chain.
    Direct,
    /// The signer is a member-tied API key acting for `principal`, and may make
    /// only the calls `scopes` covers.
    Delegated {
        /// The member every call runs as, and who pays for it.
        principal: AccountId,
        /// What the chain says this key may do.
        scopes: ScopeSet,
    },
}

impl Mode {
    /// The member this client acts for, if any.
    pub fn principal(&self) -> Option<AccountId> {
        match self {
            Mode::Direct => None,
            Mode::Delegated { principal, .. } => Some(*principal),
        }
    }

    /// What this client's key is permitted to do, if the chain knows.
    pub fn scopes(&self) -> Option<ScopeSet> {
        match self {
            Mode::Direct => None,
            Mode::Delegated { scopes, .. } => Some(*scopes),
        }
    }

    /// Whether writes must be wrapped in `proxy.proxy`.
    pub fn is_delegated(&self) -> bool {
        matches!(self, Mode::Delegated { .. })
    }
}

/// Ask the chain who `account` acts for.
///
/// 1. `MATTER_PRINCIPAL`, if set, for a key whose pointer is gone while its
///    proxy stands. Assumes [`ScopeSet::ALL`]: local pre-flight is off and the
///    runtime filter alone enforces.
/// 2. Otherwise [`lookup`]; no grant means [`Mode::Direct`].
pub(super) async fn resolve(
    api: &OnlineClient<PolkadotConfig>,
    account: AccountId,
) -> Result<Mode> {
    if let Some(principal) = principal_override()? {
        tracing::warn!(
            %principal,
            env = PRINCIPAL_ENV,
            "acting for an overridden principal without asking the chain; local scope \
             checking is disabled and the runtime alone enforces"
        );
        return Ok(decide(None, Some(principal)));
    }

    Ok(decide(lookup(api, account).await?, None))
}

/// Pure core of [`resolve`]: an override wins; no grant means [`Mode::Direct`].
pub(super) fn decide(
    lookup: Option<(AccountId, ScopeSet)>,
    override_principal: Option<AccountId>,
) -> Mode {
    if let Some(principal) = override_principal {
        return Mode::Delegated {
            principal,
            scopes: ScopeSet::ALL,
        };
    }
    match lookup {
        Some((principal, scopes)) => Mode::Delegated { principal, scopes },
        None => Mode::Direct,
    }
}

/// Whether this runtime has scoped API keys, read from metadata rather than
/// inferred from a failed call.
pub(super) fn supports_agent_keys(metadata: &subxt::Metadata) -> bool {
    has_runtime_api(metadata, AGENT_KEY_TRAIT, AGENT_KEY_METHOD)
}

fn has_runtime_api(metadata: &subxt::Metadata, trait_name: &str, method: &str) -> bool {
    metadata
        .runtime_api_trait_by_name(trait_name)
        .and_then(|t| t.method_by_name(method))
        .is_some()
}

/// `BudgetsApi_agent_key(key)`: who `key` acts for and what it may do. `None`
/// if the runtime lacks the API or the key is not registered.
pub(super) async fn lookup(
    api: &OnlineClient<PolkadotConfig>,
    key: AccountId,
) -> Result<Option<(AccountId, ScopeSet)>> {
    if !supports_agent_keys(&api.metadata()) {
        return Ok(None);
    }

    let payload = subxt::dynamic::runtime_api_call(
        AGENT_KEY_TRAIT,
        AGENT_KEY_METHOD,
        vec![Value::from_bytes(key.as_bytes())],
    );
    let thunk = api
        .runtime_api()
        .at_latest()
        .await
        .map_err(runtime_api_error)?
        .call(payload)
        .await
        .map_err(runtime_api_error)?;

    // Decode typed rather than walking the `Value` tree by hand.
    let resolved: Option<(AccountId32, u32)> = thunk.as_type().map_err(|e| SdkError::Chain {
        target: format!("{AGENT_KEY_TRAIT}_{AGENT_KEY_METHOD}"),
        detail: format!("could not decode Option<(AccountId, ScopeSet)>: {e}"),
    })?;

    Ok(resolved.map(|(principal, bits)| (AccountId::from(principal.0), ScopeSet::from_bits(bits))))
}

/// What a re-read of the chain's grant says about the one a client holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refresh {
    /// The same principal with the same scopes.
    Unchanged,
    /// Still this member, but the scopes moved.
    Rescoped { held: ScopeSet },
    /// Revoked, or rebound to a different member.
    Gone,
}

/// Compare a fresh grant against the one resolved at connect.
///
/// `Gone` must not fall back to [`Mode::Direct`]: the caller would see "cannot
/// pay fees" instead of "key revoked".
pub(super) fn after_refresh(previous: &Mode, fresh: Option<(AccountId, ScopeSet)>) -> Refresh {
    let Mode::Delegated { principal, scopes } = previous else {
        return Refresh::Unchanged;
    };
    match fresh {
        Some((fresh_principal, fresh_scopes)) if fresh_principal == *principal => {
            if fresh_scopes == *scopes {
                Refresh::Unchanged
            } else {
                Refresh::Rescoped { held: fresh_scopes }
            }
        }
        _ => Refresh::Gone,
    }
}

/// Parse `MATTER_PRINCIPAL`, which may be `0x`-hex or SS58.
fn principal_override() -> Result<Option<AccountId>> {
    let raw = match std::env::var(PRINCIPAL_ENV) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    let text = raw.trim();

    let bad = |detail: &str| SdkError::Config {
        detail: format!("{PRINCIPAL_ENV} {detail}"),
    };

    if let Some(hex_body) = text.strip_prefix("0x") {
        let bytes = hex::decode(hex_body).map_err(|_| bad("is not valid hex"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| bad("must be 32 bytes of hex"))?;
        return Ok(Some(AccountId::from(bytes)));
    }

    let account: AccountId32 = text
        .parse()
        .map_err(|_| bad("is neither 0x-prefixed hex nor a valid SS58 address"))?;
    Ok(Some(AccountId::from(account.0)))
}

fn runtime_api_error(e: subxt::Error) -> SdkError {
    SdkError::Chain {
        target: format!("{AGENT_KEY_TRAIT}_{AGENT_KEY_METHOD}"),
        detail: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use matter_sdk_key::{Access, Scope};

    use super::*;

    #[test]
    fn direct_mode_exposes_no_principal_and_no_scopes() {
        assert_eq!(Mode::Direct.principal(), None);
        assert_eq!(Mode::Direct.scopes(), None);
        assert!(!Mode::Direct.is_delegated());
    }

    #[test]
    fn delegated_mode_carries_the_principal_and_scopes() {
        let principal = AccountId::from([7u8; 32]);
        let scopes = ScopeSet::single(Scope::Deployments, Access::Write);
        let mode = Mode::Delegated { principal, scopes };
        assert_eq!(mode.principal(), Some(principal));
        assert_eq!(mode.scopes(), Some(scopes));
        assert!(mode.is_delegated());
    }

    #[test]
    fn no_grant_resolves_direct() {
        assert_eq!(decide(None, None), Mode::Direct);
    }

    #[test]
    fn a_grant_resolves_delegated() {
        let principal = AccountId::from([3u8; 32]);
        let scopes = ScopeSet::single(Scope::Secrets, Access::Read);
        assert_eq!(
            decide(Some((principal, scopes)), None),
            Mode::Delegated { principal, scopes }
        );
    }

    #[test]
    fn the_override_wins_and_assumes_every_scope() {
        // The empty set would refuse every call locally.
        let forced = AccountId::from([9u8; 32]);
        let chain_said = (AccountId::from([1u8; 32]), ScopeSet::EMPTY);
        for lookup in [None, Some(chain_said)] {
            assert_eq!(
                decide(lookup, Some(forced)),
                Mode::Delegated {
                    principal: forced,
                    scopes: ScopeSet::ALL,
                }
            );
        }
    }

    #[test]
    fn the_spec330_fixture_declares_the_agent_key_runtime_api() {
        assert!(supports_agent_keys(&super::super::test_metadata()));
    }

    #[test]
    fn an_undeclared_runtime_api_reads_as_pre_322() {
        let metadata = super::super::test_metadata();
        assert!(!has_runtime_api(
            &metadata,
            AGENT_KEY_TRAIT,
            "no_such_method"
        ));
        assert!(!has_runtime_api(&metadata, "NoSuchApi", AGENT_KEY_METHOD));
    }

    #[test]
    fn the_call_and_the_runtime_api_ship_together() {
        // Python and Go cannot see runtime APIs in V14 metadata and gate on
        // Budgets.authorize_agent_key instead.
        let metadata = super::super::test_metadata();
        assert!(supports_agent_keys(&metadata));
        assert!(
            metadata
                .pallet_by_name("Budgets")
                .and_then(|p| p.call_variant_by_name("authorize_agent_key"))
                .is_some(),
            "the call the other bindings gate on is missing from the same metadata"
        );
    }

    #[test]
    fn a_revoked_or_rebound_grant_is_gone_and_a_rescope_reports_the_fresh_set() {
        let principal = AccountId::from([4u8; 32]);
        let narrow = ScopeSet::single(Scope::Deployments, Access::Write);
        let wider = narrow.with(Scope::Secrets, Access::Read);
        let held = Mode::Delegated {
            principal,
            scopes: narrow,
        };

        assert_eq!(after_refresh(&held, None), Refresh::Gone);
        assert_eq!(
            after_refresh(&held, Some((AccountId::from([5u8; 32]), narrow))),
            Refresh::Gone
        );
        assert_eq!(
            after_refresh(&held, Some((principal, wider))),
            Refresh::Rescoped { held: wider }
        );
        assert_eq!(
            after_refresh(&held, Some((principal, narrow))),
            Refresh::Unchanged
        );
    }

    #[test]
    fn a_direct_client_has_no_grant_to_lose() {
        assert_eq!(after_refresh(&Mode::Direct, None), Refresh::Unchanged);
    }
}
