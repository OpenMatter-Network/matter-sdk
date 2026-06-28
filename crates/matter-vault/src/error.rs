//! The SDK error type.

use matter_vault_core::CoreError;
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
}

/// Convenience alias for results in this crate.
pub type Result<T> = core::result::Result<T, SdkError>;
