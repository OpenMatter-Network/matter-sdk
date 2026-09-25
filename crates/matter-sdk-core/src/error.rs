//! The core error type. Variants are distinct causes so callers branch on the
//! variant, never on the message.

use thiserror::Error;

/// Why a [`crate`] operation failed.
///
/// A quorum loop retries a different subset on `Aggregate` and gives up on
/// `Aead` (every valid quorum recovers the same key). The other variants
/// mean malformed or oversized input.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A fixed-width input had the wrong length.
    #[error("{field} must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// The offending field.
        field: &'static str,
        /// The required byte length.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },

    /// A value exceeded its on-chain `BoundedVec` bound (envelope fields) or
    /// the decode ceiling (everything else). Opening checks this before
    /// decoding untrusted bytes.
    #[error("{field} is {actual} bytes; max is {max}")]
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

    /// The partials are empty, or a point is zero or repeated. Reported before
    /// anything is decoded.
    #[error("invalid decrypt subset: {0}")]
    InvalidSubset(String),

    /// Aggregation rejected a malformed or dishonest partial. The detail names
    /// the offending node's point when known; exclude it and retry.
    #[error("partial-decryption aggregate rejected: {0}")]
    Aggregate(String),

    /// AEAD authentication failed: wrong key, epoch, or AAD. Terminal; no
    /// other quorum can open it.
    #[error("AEAD authentication failed (wrong key, epoch, or aad)")]
    Aead,
}

/// Convenience alias for results in this crate.
pub type Result<T> = core::result::Result<T, CoreError>;
