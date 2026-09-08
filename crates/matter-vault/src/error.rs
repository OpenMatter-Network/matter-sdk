//! The SDK error type.

use matter_vault_core::CoreError;
use matter_vault_key::KeyError;
use thiserror::Error;

/// Why an SDK operation failed.
///
/// Cryptographic failures surface through [`SdkError::Core`]; everything else is
/// orchestration- or transport-level. Each variant is a distinct cause so a
/// caller can decide what to do (retry, refetch chain state, surface to the user)
/// without parsing a message.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SdkError {
    /// A cryptographic step failed (decode, proof rejected, AEAD). See [`CoreError`].
    #[error(transparent)]
    Core(#[from] CoreError),

    /// An API key could not be ingested, or a key-backed signer refused to sign.
    /// See [`KeyError`] — its variants never echo any part of the key.
    #[error(transparent)]
    Key(#[from] KeyError),

    /// An HTTP call to a committee node failed (connection, status, body).
    #[error("committee transport error for {endpoint}: {detail}")]
    Transport {
        /// The node endpoint involved.
        endpoint: String,
        /// A human-readable detail.
        detail: String,
    },

    /// Fewer than `threshold` committee nodes were reachable and healthy, so no
    /// quorum could be formed. Retry later or widen the node set.
    #[error("quorum unavailable: need {needed} healthy nodes, found {active}")]
    QuorumUnavailable {
        /// The threshold `t` required.
        needed: usize,
        /// How many nodes were healthy.
        active: usize,
    },

    /// The committee served the secret under a *different* epoch than the one the
    /// caller supplied state for — a key rotation happened. The caller must
    /// refetch the served epoch's `shared_a` and per-node share commitments and
    /// retry. Carries both epochs so the caller knows what to fetch.
    #[error("secret served under epoch {served}, but state was supplied for {provided}; refetch the served epoch's committee state")]
    EpochRotated {
        /// The epoch the committee actually served under.
        served: u32,
        /// The epoch the caller supplied `shared_a`/commitments for.
        provided: u32,
    },

    /// The signer could not authorize the request.
    #[error("signer error: {0}")]
    Signer(String),

    /// A node returned a syntactically valid but unusable response (e.g. a
    /// missing field the protocol requires for this path).
    #[error("unusable response from {endpoint}: {detail}")]
    BadResponse {
        /// The node endpoint involved.
        endpoint: String,
        /// What was wrong.
        detail: String,
    },

    /// A secret is sealed under a different AAD tag than the one requested, so
    /// it belongs to a different consumer and the open would fail anyway.
    #[error("secret {secret_id} is sealed under AAD {sealed_under:?}, not {requested:?}")]
    AadMismatch {
        /// The secret asked for.
        secret_id: u128,
        /// The AAD the chain records for it, as UTF-8 where it is text.
        sealed_under: String,
        /// The tag the caller presented.
        requested: String,
    },

    /// The client was built without a signer, so it cannot submit extrinsics or
    /// authorize decryption. Build it with an API key or a signer.
    #[error("this client is read-only: build it with an api key or a signer to submit")]
    ReadOnly,

    /// The connection configuration is inconsistent.
    #[error("configuration error: {detail}")]
    Config {
        /// What is wrong with it.
        detail: String,
    },

    /// A chain read or submission failed. `target` is the `pallet.item` involved.
    #[error("chain error at {target}: {detail}")]
    Chain {
        /// The `pallet.call`, `pallet.storage`, or RPC method involved.
        target: String,
        /// A human-readable detail.
        detail: String,
    },

    /// A member-tied API key was asked for a call its scopes do not cover.
    ///
    /// Caught before submission. The runtime would refuse it too, but a
    /// balance-less delegated key gets refused in the *pool* — for having no
    /// funds — so the chain's own answer to this is `Inability to pay some
    /// fees`, which names neither the call nor the missing scope.
    #[error("key lacks {required} for {pallet}.{call}; it holds {held}")]
    NotPermitted {
        /// The pallet involved.
        pallet: String,
        /// The call involved.
        call: String,
        /// What the call needs.
        required: matter_vault_key::ScopeSet,
        /// What the key actually has.
        held: matter_vault_key::ScopeSet,
    },

    /// The call is not admitted to *any* API key, whatever its scopes: token
    /// movement, staking, governance, `sudo`, root-only and provider-signed
    /// calls, org lifecycle, and the roster calls a key would otherwise use to
    /// widen itself.
    #[error("{pallet}.{call} is never admitted to an api key; sign it with the member's own key")]
    NeverAdmitted {
        /// The pallet involved.
        pallet: String,
        /// The call involved.
        call: String,
    },

    /// A delegated call landed and the outer `proxy.proxy` succeeded, but the
    /// call it wrapped failed. This is the error a direct dispatch would have
    /// returned; `proxy.proxy` reports it as an event rather than a dispatch
    /// error, which is why it needs a variant of its own.
    #[error("{pallet}.{call} failed under delegation: {detail}")]
    Dispatch {
        /// The pallet involved.
        pallet: String,
        /// The call involved.
        call: String,
        /// The wrapped call's own error, decoded through metadata.
        detail: String,
    },

    /// The key's proxy is gone — revoked, or removed by the member directly.
    /// Re-resolving confirmed it, so this is not transient.
    #[error("this api key is no longer registered; it was revoked or re-scoped")]
    KeyRevoked,

    /// A delegated call was refused in the pool for want of gas. The key never
    /// pays; the member does, or their billing org. So this means neither could
    /// cover it, not that the key is broke.
    #[error("{pallet}.{call} was not sponsored: neither {principal} nor their billing org could cover the fee")]
    Unsponsored {
        /// The member the call would have run as.
        principal: String,
        /// The pallet involved.
        pallet: String,
        /// The call involved.
        call: String,
    },

    /// A signing client was pointed at mainnet without explicit confirmation.
    /// Set `MATTER_CONFIRM=yes` or `MatterConfig::confirm_mainnet`.
    #[error("refusing to build a signing client against mainnet {chain_name:?} (detected via {detected_via}) without explicit confirmation: set MATTER_CONFIRM=yes or MatterConfig::confirm_mainnet. This client can spend real funds")]
    MainnetNotConfirmed {
        /// The chain the endpoint actually serves.
        chain_name: String,
        /// How mainnet was detected: `"genesis-hash"` or `"token-symbol"`.
        detected_via: &'static str,
    },

    /// The endpoint serves a different network than the config selected —
    /// usually a typo'd RPC URL, caught before it costs anything.
    #[error("expected the {expected} network but the endpoint serves {actual:?}")]
    WrongNetwork {
        /// The network the config asked for.
        expected: String,
        /// The chain the endpoint actually serves.
        actual: String,
    },

    /// A submitted extrinsic did not finalize within the configured budget. It
    /// may still finalize later — check the chain before resubmitting, or the
    /// call may be applied twice.
    #[error("{pallet}.{call} did not finalize within {waited:?}; it may still land, so check the chain before resubmitting")]
    FinalityTimeout {
        /// The pallet submitted to.
        pallet: String,
        /// The call submitted.
        call: String,
        /// How long the client waited.
        waited: std::time::Duration,
    },

    /// An amount string could not be converted to plancks.
    #[error("invalid amount: {detail}")]
    BadAmount {
        /// What was wrong with it.
        detail: String,
    },
}

/// Convenience alias for results in this crate.
pub type Result<T> = core::result::Result<T, SdkError>;
