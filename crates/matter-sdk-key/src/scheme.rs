//! Signature schemes and the on-chain account identifier.

use core::fmt;

use crate::error::{KeyError, Result};

/// Which signature scheme a key's material belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyScheme {
    /// sr25519 (Schnorrkel/Ristretto). Framed on chain as `MultiSignature::Sr25519`.
    Sr25519,
}

/// Scheme tokens recognised but not yet implemented.
pub(crate) const RESERVED_SCHEMES: &[&str] = &["secp256k1", "ecdsa", "ed25519"];

/// Supported schemes, comma-separated, for error messages.
pub(crate) const SUPPORTED_SCHEMES: &str = "sr25519";

impl KeyScheme {
    /// The lowercase wire token used in a prefixed API key (`"sr25519:…"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyScheme::Sr25519 => "sr25519",
        }
    }

    /// Resolve a scheme token, case-insensitively. An unknown token is never
    /// echoed: an unprefixed hex seed followed by `:` has the same shape.
    pub(crate) fn from_token(token: &str) -> Result<Self> {
        if token.eq_ignore_ascii_case(KeyScheme::Sr25519.as_str()) {
            return Ok(KeyScheme::Sr25519);
        }
        Err(KeyError::Malformed {
            detail: "unrecognised api key scheme prefix; this build supports sr25519",
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
/// Renders as `0x`-prefixed lowercase hex, not SS58 (that lives in the chain
/// layer to keep this crate small). Public information: freely loggable.
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
