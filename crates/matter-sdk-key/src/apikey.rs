//! The [`ApiKey`] container: parse once, hold safely, sign.

use core::fmt;
use core::str::FromStr;

use subxt_signer::bip39::Mnemonic;
use subxt_signer::sr25519::Keypair;
use zeroize::Zeroizing;

use crate::error::{KeyError, Result};
use crate::scheme::{AccountId, KeyScheme, RESERVED_SCHEMES, SUPPORTED_SCHEMES};
use crate::suri;

const MINI_SECRET_HEX_LEN: usize = 64;

/// An OpenMatter API key: secret signing material plus the scheme it belongs to.
///
/// # Guarantees
///
/// * **Zeroized.** The keypair wipes on drop and every intermediate lives in a
///   [`Zeroizing`] buffer; no hex copy of the seed is left on the heap.
/// * **Redacted.** `Debug` shows only the scheme and account id. No `Display`.
/// * **Non-serializable.** No `Serialize`, `Clone`, `AsRef<[u8]>`, or secret
///   accessor. Share one with `Arc<ApiKey>`.
///
/// These guard against accidents, not attackers: anything that can read the
/// process can read the key. See `docs/secure-signing.md` for HSM/KMS-backed
/// [`crate::KeySigner`]s.
///
/// # Accepted encodings
///
/// With an optional `"<scheme>:"` prefix; bare keys default to `sr25519`:
///
/// | Form | Example |
/// |---|---|
/// | 32-byte mini-secret | `0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e` |
/// | BIP39 mnemonic | `bottom drive obey lake curtain smoke basket hold race lonely fit walk` |
/// | SURI with junctions | `bottom drive …//hard/soft` |
/// | Scheme-prefixed | `sr25519:0xfac7…479e` |
pub struct ApiKey {
    scheme: KeyScheme,
    account: AccountId,
    material: Material,
}

enum Material {
    Sr25519(Keypair),
}

impl ApiKey {
    /// Parse an OpenMatter API key.
    ///
    /// Surrounding whitespace is trimmed; the rest must be one of the encodings
    /// listed on [`ApiKey`].
    ///
    /// # Errors
    ///
    /// * [`KeyError::Empty`] — empty or whitespace-only.
    /// * [`KeyError::UnsupportedScheme`] — a reserved `scheme:` prefix this
    ///   build cannot use (`secp256k1`, `ecdsa`, `ed25519`).
    /// * [`KeyError::Malformed`] — not a recognised encoding, or an unknown
    ///   `scheme:` prefix.
    /// * [`KeyError::Derivation`] — recognised, but rejected while deriving.
    ///
    /// No error carries any part of the input.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(KeyError::Empty);
        }

        let (scheme, body) = split_scheme(trimmed)?;
        if body.trim().is_empty() {
            return Err(KeyError::Empty);
        }

        match scheme {
            KeyScheme::Sr25519 => Self::parse_sr25519(body),
        }
    }

    /// Build a key from a raw 32-byte sr25519 mini-secret. Prefer this over
    /// hex-encoding bytes for [`ApiKey::parse`], which leaves a heap copy.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        // `from_secret_key` takes the array by value; keep our copy zeroizing.
        let seed = Zeroizing::new(*seed);
        let keypair = Keypair::from_secret_key(*seed).map_err(|_| KeyError::Derivation {
            detail: "seed is not a valid sr25519 mini-secret",
        })?;
        Ok(Self::from_keypair(keypair))
    }

    /// Which scheme this key signs with.
    pub fn scheme(&self) -> KeyScheme {
        self.scheme
    }

    /// The 32-byte on-chain account id this key controls.
    pub fn account_id(&self) -> AccountId {
        self.account
    }

    /// Sign raw bytes, returning an unframed 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        match &self.material {
            Material::Sr25519(keypair) => Ok(keypair.sign(message).0),
        }
    }

    fn parse_sr25519(body: &str) -> Result<Self> {
        let uri = suri::split(body)?;

        // Upstream parsers fill a missing phrase (`//Alice`) with the public dev
        // phrase; reject it so an unset variable never yields a known keypair.
        if uri.phrase.is_empty() {
            return Err(KeyError::Malformed {
                detail: "api key has no phrase; this would derive from the public \
                         well-known development phrase",
            });
        }

        // A hex mini-secret ignores the password, matching `Keypair::from_uri`.
        let root = match uri.phrase.strip_prefix("0x") {
            Some(hex_body) => Self::keypair_from_hex(hex_body)?,
            None => Self::keypair_from_mnemonic(uri.phrase, uri.password)?,
        };

        Ok(Self::from_keypair(root.derive(uri.junctions)))
    }

    fn keypair_from_hex(hex_body: &str) -> Result<Keypair> {
        // Validate first so no error can disclose a character or offset of the key.
        if hex_body.len() != MINI_SECRET_HEX_LEN {
            return Err(KeyError::Malformed {
                detail: "hex mini-secret must be exactly 32 bytes (64 hex characters)",
            });
        }
        if !hex_body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(KeyError::Malformed {
                detail: "hex mini-secret contains a non-hex character",
            });
        }

        // Decode into a zeroizing stack buffer; no heap copy of the secret.
        let mut seed = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(hex_body, seed.as_mut()).map_err(|_| KeyError::Malformed {
            detail: "hex mini-secret contains a non-hex character",
        })?;

        Keypair::from_secret_key(*seed).map_err(|_| KeyError::Derivation {
            detail: "seed is not a valid sr25519 mini-secret",
        })
    }

    fn keypair_from_mnemonic(phrase: &str, password: Option<&str>) -> Result<Keypair> {
        // `FromStr`, not `Mnemonic::parse`, to normalize exactly as `Keypair::from_uri`.
        let mnemonic = Mnemonic::from_str(phrase).map_err(|_| KeyError::Malformed {
            detail: "not a 0x mini-secret, BIP39 mnemonic, or sr25519 SURI",
        })?;
        Keypair::from_phrase(&mnemonic, password).map_err(|_| KeyError::Derivation {
            detail: "sr25519 derivation failed (check the BIP39 checksum or word count)",
        })
    }

    fn from_keypair(keypair: Keypair) -> Self {
        Self {
            scheme: KeyScheme::Sr25519,
            account: AccountId(keypair.public_key().0),
            material: Material::Sr25519(keypair),
        }
    }
}

/// Split an optional `"<scheme>:"` prefix off the key.
///
/// Only a bare identifier before the first `:` is a scheme: a password or
/// junction may itself contain `:`, and a phrase or hex seed is never a bare
/// identifier with `0x`. Anything else is the key, whole.
fn split_scheme(input: &str) -> Result<(KeyScheme, &str)> {
    let Some((token, body)) = input
        .split_once(':')
        .filter(|(token, _)| is_scheme_token(token))
    else {
        return Ok((KeyScheme::Sr25519, input));
    };

    if let Some(reserved) = RESERVED_SCHEMES
        .iter()
        .find(|r| token.eq_ignore_ascii_case(r))
    {
        return Err(KeyError::UnsupportedScheme {
            scheme: (*reserved).to_owned(),
            supported: SUPPORTED_SCHEMES,
        });
    }

    Ok((KeyScheme::from_token(token)?, body))
}

/// Whether `token` has the shape of a scheme name: ASCII alphanumerics, `_` or
/// `-`, not starting `0x`. Shape only; the token may still be unknown.
fn is_scheme_token(token: &str) -> bool {
    !token.is_empty()
        && !token.starts_with("0x")
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Redacted: scheme and public account id only, never the key.
impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("scheme", &self.scheme.as_str())
            .field("account", &self.account.to_hex())
            .field("material", &"<redacted>")
            .finish()
    }
}
