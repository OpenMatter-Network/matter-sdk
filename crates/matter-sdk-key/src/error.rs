//! Key-ingestion errors.

use thiserror::Error;

/// Why an API key could not be ingested.
///
/// # Redaction contract
///
/// **No variant embeds any part of the input.** Not a prefix, not a character
/// position, not a length of the secret portion. This is deliberate and is
/// asserted by `tests/parse.rs::errors_never_echo_the_input`: a `KeyError` is
/// routinely logged, and upstream errors are not careful here — `subxt_signer`'s
/// `Error::Hex` renders as `Cannot parse hex string: Invalid character 'g' at
/// position 5`, which discloses one character and its offset. We therefore never
/// forward an upstream source; [`KeyError::Derivation`] carries a static
/// description instead.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The key was empty, or only whitespace.
    #[error("api key is empty")]
    Empty,

    /// The `scheme:` prefix named a scheme this build cannot use.
    ///
    /// `secp256k1` (the Ethereum/EIP-712 path backing `pallet-eth-signing` and
    /// `pallet-staking-gateway`) is recognised and reserved, but unimplemented;
    /// it reports here rather than as a parse failure so the distinction between
    /// "not yet supported" and "malformed" survives to the caller.
    #[error("unsupported api key scheme {scheme:?}: this build supports {supported}")]
    UnsupportedScheme {
        /// The scheme token that was requested. Never contains key material —
        /// it is the text before the first `:`, which is a scheme name.
        scheme: String,
        /// The schemes this build does support, comma-separated.
        supported: &'static str,
    },

    /// The key was structurally wrong: not a recognised encoding at all.
    #[error("malformed api key: {detail}")]
    Malformed {
        /// A static description of the defect. Never derived from the input.
        detail: &'static str,
    },

    /// The encoding was recognised but the key material was rejected during
    /// derivation (bad BIP39 checksum, seed outside the valid range).
    #[error("api key rejected during derivation: {detail}")]
    Derivation {
        /// A static description of the defect. Never derived from the input.
        detail: &'static str,
    },

    /// A signer with no private key was asked to sign.
    #[error("signer holds no key material and cannot sign")]
    NoKey,
}

/// Convenience alias for results in this crate.
pub type Result<T> = core::result::Result<T, KeyError>;
