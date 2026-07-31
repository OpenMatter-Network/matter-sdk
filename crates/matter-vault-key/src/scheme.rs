//! Signature schemes and the on-chain account identifier.

use core::fmt;

use crate::error::{KeyError, Result};

/// Which signature scheme a key's material belongs to.
///
/// `#[non_exhaustive]` so that adding `Secp256k1` — the Ethereum/EIP-712 path
/// the wire types already carry fields for — cannot break a downstream `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyScheme {
    /// sr25519 (Schnorrkel/Ristretto). Framed on chain as `MultiSignature::Sr25519`.
    Sr25519,
}

/// Scheme tokens this build recognises but cannot yet use. Naming them lets
/// [`KeyError::UnsupportedScheme`] distinguish "reserved, not implemented" from
/// "that is not a scheme", which is the difference between a roadmap question
/// and a typo.
pub(crate) const RESERVED_SCHEMES: &[&str] = &["secp256k1", "ecdsa", "ed25519"];

/// The schemes this build supports, for error messages.
pub(crate) const SUPPORTED_SCHEMES: &str = "sr25519";

impl KeyScheme {
    /// The lowercase wire token used in a prefixed API key (`"sr25519:…"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyScheme::Sr25519 => "sr25519",
        }
    }

    /// Resolve a scheme token. Case-insensitive.
    pub(crate) fn from_token(token: &str) -> Result<Self> {
        // Compare lowercased so `SR25519:` works; the token is a scheme name,
        // never key material, so it is safe to echo in the error.
        if token.eq_ignore_ascii_case(KeyScheme::Sr25519.as_str()) {
            return Ok(KeyScheme::Sr25519);
        }
        Err(KeyError::UnsupportedScheme {
            scheme: token.to_ascii_lowercase(),
            supported: SUPPORTED_SCHEMES,
        })
    }
}

impl fmt::Display for KeyScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A 32-byte on-chain account identifier (`AccountId32`).
///
/// Rendered as `0x`-prefixed lowercase hex, **not** SS58. SS58 needs base58 plus
/// blake2b, and this crate must stay light enough to compile into
/// `bindings/wasm`; SS58 rendering belongs in the chain layer, where the
/// dependency is already paid for.
///
/// This is public information — it is the address the committee and the chain
/// both see — so unlike [`crate::ApiKey`] it is `Clone`, `Display`, and freely
/// loggable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountId(pub [u8; 32]);

impl AccountId {
    /// Borrow the raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `0x` + 64 lowercase hex characters.
    pub fn to_hex(self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Parse `0x`-prefixed or bare 64-character hex.
    pub fn from_hex(text: &str) -> Result<Self> {
        let body = text.strip_prefix("0x").unwrap_or(text);
        let mut out = [0u8; 32];
        hex::decode_to_slice(body, &mut out).map_err(|_| KeyError::Malformed {
            detail: "account id must be 32 bytes of hex",
        })?;
        Ok(AccountId(out))
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for AccountId {
    fn from(bytes: [u8; 32]) -> Self {
        AccountId(bytes)
    }
}

impl From<AccountId> for [u8; 32] {
    fn from(id: AccountId) -> Self {
        id.0
    }
}
