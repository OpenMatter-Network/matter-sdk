//! The core error type.
//!
//! Every fallible core function returns [`CoreError`]. Each variant names a
//! distinct failure *bucket* so callers (and the language bindings above them)
//! can branch on cause instead of string-matching a message — the cure for the
//! regex-classified errors the reference dashboard carries today.

use thiserror::Error;

/// Why a [`crate`] operation failed.
///
/// The variants separate caller-bug input (`InvalidLength`, `Hex`, `Decode`)
/// from cryptographic outcomes (`ProofRejected`, `Aead`) so a quorum loop can
/// react correctly: retry a different subset on `ProofRejected`, but give up on
/// `Aead` (every valid quorum recovers the same key, so no other subset helps).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A fixed-width input had the wrong length (e.g. a `secret_id` that wasn't
    /// 16 bytes, or a `block_hash` that wasn't 32). Names the field and the
    /// expected width so the boundary violation is unambiguous.
    #[error("{field} must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// The offending field.
        field: &'static str,
        /// The required byte length.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },

    /// A value exceeded the on-chain `BoundedVec` limit it must fit (capsule,
    /// proof, ciphertext, or binding id). Rejecting here keeps an un-storable
    /// envelope from being produced in the first place.
    #[error("{field} is {actual} bytes; on-chain max is {max}")]
    TooLarge {
        /// The offending field.
        field: &'static str,
        /// The maximum allowed byte length.
        max: usize,
        /// The length actually produced.
        actual: usize,
    },

    /// An input that must be non-empty was empty (e.g. the plaintext to seal).
    #[error("{0} must not be empty")]
    Empty(&'static str),

    /// A `0x`-hex string failed to decode.
    #[error("hex decode of {field}: {source}")]
    Hex {
        /// The field being decoded.
        field: &'static str,
        /// The underlying hex error.
        source: hex::FromHexError,
    },

    /// A bincode/SCALE/tagged blob failed to decode into the expected type.
    #[error("decode of {field}: {detail}")]
    Decode {
        /// The field being decoded.
        field: &'static str,
        /// A human-readable detail from the underlying decoder.
        detail: String,
    },

    /// Aggregation rejected the quorum's proofs (a malformed or dishonest
    /// partial), or no partials were supplied. The detail carries the offending
    /// node's point where the underlying error identified one, so a caller can
    /// exclude it and retry a different subset.
    #[error("partial-decryption aggregate rejected: {0}")]
    Aggregate(String),

    /// Partials aggregated, but AEAD authentication failed: the recovered key,
    /// epoch, or AAD doesn't match the sealed payload. Terminal — no other
    /// quorum can open it.
    #[error("AEAD authentication failed (wrong key, epoch, or aad)")]
    Aead,
}

/// Convenience alias for results in this crate.
pub type Result<T> = core::result::Result<T, CoreError>;
