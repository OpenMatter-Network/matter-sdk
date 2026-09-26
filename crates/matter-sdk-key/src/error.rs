//! Key-ingestion errors.

use thiserror::Error;

/// Why an API key could not be ingested.
///
/// **No variant embeds any part of the input**: no prefix, character, position,
/// or length of the secret. Errors get logged, so upstream errors (which can
/// echo characters and offsets) are never forwarded; details are static
/// strings. Pinned by `tests/parse.rs::errors_never_echo_the_input`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The key was empty, or only whitespace.
    #[error("api key is empty")]
    Empty,

    /// The `scheme:` prefix named a scheme this build cannot use, including
    /// reserved-but-unimplemented ones such as `secp256k1`.
    #[error("unsupported api key scheme {scheme:?}: this build supports {supported}")]
    UnsupportedScheme {
        /// The reserved scheme's name, from this crate's own list; never text
        /// taken from the input.
        scheme: String,
        /// The schemes this build does support, comma-separated.
        supported: &'static str,
    },

    /// Not a recognised encoding.
    #[error("malformed api key: {detail}")]
    Malformed {
        /// Static description; never derived from the input.
        detail: &'static str,
    },

    /// Recognised encoding, rejected during derivation (bad BIP39 checksum,
    /// invalid seed).
    #[error("api key rejected during derivation: {detail}")]
    Derivation {
        /// Static description; never derived from the input.
        detail: &'static str,
    },

    /// A signer with no private key was asked to sign.
    #[error("signer holds no key material and cannot sign")]
    NoKey,
}

/// Convenience alias for results in this crate.
pub type Result<T> = core::result::Result<T, KeyError>;
