//! Whether this client signs for itself or acts for a member.
//!
//! Under runtime spec 322 an OpenMatter API key is not an account with
//! authority of its own. It is a delegate holding a `ProxyType::Scoped(ScopeSet)`
//! proxy on the account of the **member** who minted it, and everything it does
//! it does as that member, through `proxy.proxy(member, None, call)`.
//!
//! The key's own account has no authority and no balance, so a directly signed
//! call from a member-tied key is refused in the pool with
//! `Inability to pay some fees`. Resolving the mode at connect is what lets the
//! client wrap correctly instead of submitting that doomed call.
//!
//! A key that resolves to nothing is [`Mode::Direct`] — today's behaviour, and
//! what legacy project-tied keys and plain human seeds still want.

use matter_vault_key::{AccountId, ScopeSet};
use subxt::dynamic::Value;
use subxt::utils::AccountId32;
use subxt::{OnlineClient, PolkadotConfig};

use crate::error::{Result, SdkError};

/// The runtime API that maps a key to its principal, and the trait it lives on.
/// Its absence from metadata is how a pre-322 chain is detected.
const AGENT_KEY_TRAIT: &str = "BudgetsApi";
const AGENT_KEY_METHOD: &str = "agent_key";

/// Names the principal a key acts for when the chain's own pointer is stale.
const PRINCIPAL_ENV: &str = "MATTER_PRINCIPAL";

/// Who this client's signature speaks for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// The signer acts as itself. A human seed, an HSM key, a legacy
    /// project-tied key, or any key on a pre-322 chain.
    Direct,
    /// The signer is a member-tied API key acting for `principal`, and may make
    /// only the calls `scopes` covers.
    Delegated {
        /// The member every call actually runs as, and who pays for it.
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
/// Resolution order, and why:
///
/// 1. `MATTER_PRINCIPAL`, if set — the escape hatch for a key whose pointer is
///    gone while its proxy still stands. The chain cannot then tell us the
///    scopes either, so this assumes [`ScopeSet::ALL`]: the local pre-flight
///    check is turned off and the runtime's filter decides alone. Assuming the
///    empty set instead would refuse every call locally and make the override
///    useless, so the override is loud rather than narrow.
/// 2. The runtime API's presence in metadata. A pre-322 chain does not define
///    it, and asking metadata is free — no RPC, and no guessing from the shape
///    of an error.
/// 3. The call itself. `None` means the key is not registered, or was revoked.
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

/// The decision [`resolve`] makes once the chain and the environment have both
/// been consulted.
///
/// Pure, so the rule that matters — no grant means [`Mode::Direct`], and an
/// override wins over whatever the chain said — is pinned without a node.
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

/// Whether this runtime has scoped API keys at all.
///
/// Read from metadata, which already holds the answer: a pre-322 chain does not
/// declare the runtime API. Matching on the text of a failed call to discover it
/// would be guesswork, and would mistake a dropped connection for an old chain.
pub(super) fn supports_agent_keys(metadata: &subxt::Metadata) -> bool {
    has_runtime_api(metadata, AGENT_KEY_TRAIT, AGENT_KEY_METHOD)
}

/// Whether `metadata` declares `trait_name::method` as a runtime API.
fn has_runtime_api(metadata: &subxt::Metadata, trait_name: &str, method: &str) -> bool {
    metadata
        .runtime_api_trait_by_name(trait_name)
        .and_then(|t| t.method_by_name(method))
        .is_some()
}

/// `BudgetsApi_agent_key(key)` — who `key` acts for and what it may do.
///
/// `None` covers both "this chain has no such runtime API" (pre-322) and "the
/// chain has it and says this key is not registered". Both mean the same thing
/// to a caller: there is no scoped proxy here.
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

    // Typed rather than walked: `AccountId32` is a composite over `[u8; 32]`
    // and `ScopeSet` a newtype over `u32`, and hand-matching either shape is
    // how a decoder quietly starts reading the wrong field.
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

/// Compare a fresh grant against the one a client resolved at connect.
///
/// Note what this does *not* do: `Gone` is not a licence to fall back to
/// [`Mode::Direct`]. A revoked key that started signing directly would spend the
/// next call failing for want of funds it was never meant to have, and the
/// caller would read "cannot pay fees" instead of "your key was revoked".
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
    use matter_vault_key::{Access, Scope};

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
        // The common case, and the one that keeps every pre-322 user working.
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
        // The override exists for a stale pointer, so it cannot ask the chain
        // what the key may do. Assuming the empty set would refuse every call
        // locally and make the escape hatch useless.
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
    fn the_spec322_fixture_declares_the_agent_key_runtime_api() {
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
        // Python and Go cannot see runtime-API declarations in V14 metadata, so
        // they gate on Budgets.authorize_agent_key instead. That substitution is
        // only sound if the two really do arrive in the same runtime.
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
