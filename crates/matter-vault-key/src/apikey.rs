//! The [`ApiKey`] container: parse once, hold safely, sign.

use core::fmt;
use core::str::FromStr;

use subxt_signer::bip39::Mnemonic;
use subxt_signer::sr25519::Keypair;
use zeroize::Zeroizing;

use crate::error::{KeyError, Result};
use crate::scheme::{AccountId, KeyScheme, RESERVED_SCHEMES, SUPPORTED_SCHEMES};
use crate::suri;

/// Length of an sr25519 mini-secret in hex characters.
const MINI_SECRET_HEX_LEN: usize = 64;

/// An OpenMatter API key: secret signing material plus the scheme it belongs to.
///
/// # Guarantees, all enforced by construction
///
/// * **Zeroized.** The secret half wipes on drop (`schnorrkel::Keypair`
///   implements `Drop`), and every intermediate this crate creates lives in a
///   [`Zeroizing`] buffer. No `0x{hex}` copy of the seed is left on the heap —
///   that was audit finding MV-M3.
/// * **Redacted.** `Debug` renders the scheme and the *account id* only. There is
///   deliberately no `Display`.
/// * **Non-serializable.** No `Serialize`, no `Clone`, no `AsRef<[u8]>`, and no
///   accessor that returns the secret bytes. It cannot reach a config dump, a
///   structured-log field, or an error report by accident. Share one with
///   `Arc<ApiKey>`.
///
/// Guardrails constrain accidents, not attackers: anything that can read the
/// process can read the key. See `docs/secure-signing.md` for the trade against
/// an HSM/KMS-backed [`crate::KeySigner`].
///
/// # Accepted encodings
///
/// With an optional `"<scheme>:"` prefix, or bare (defaulting to `sr25519`, which
/// preserves the encodings pinned by `testvectors/seed_formats.json`):
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
    /// Private, so adding a variant for a new scheme is not a breaking change.
    material: Material,
}

enum Material {
    Sr25519(Keypair),
}

impl ApiKey {
    /// Parse an OpenMatter API key.
    ///
    /// Surrounding whitespace is tolerated (keys arrive via environment
    /// variables and files, which pick up newlines); everything else must be one
    /// of the encodings in the type documentation.
    ///
    /// # Errors
    ///
    /// * [`KeyError::Empty`] — empty or whitespace-only.
    /// * [`KeyError::UnsupportedScheme`] — a `scheme:` prefix this build cannot
    ///   use. `secp256k1` is recognised and reserved but unimplemented, so an
    ///   Ethereum key reports as unsupported rather than as malformed.
    /// * [`KeyError::Malformed`] — not a recognised encoding.
    /// * [`KeyError::Derivation`] — recognised, but rejected while deriving (bad
    ///   BIP39 checksum, seed out of range).
    ///
    /// No error carries any part of the input; see [`KeyError`].
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

    /// Build a key directly from a raw 32-byte sr25519 mini-secret.
    ///
    /// For callers that already hold bytes (a KMS unwrap, a decrypted secret) and
    /// would otherwise hex-encode them just to call [`ApiKey::parse`] — which is
    /// exactly the heap copy MV-M3 flagged.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        // Copy into a zeroizing buffer: `from_secret_key` takes the array by
        // value, so without this the temporary would outlive our control.
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

    /// Sign a message. The signature framing (SCALE `MultiSignature`, extrinsic
    /// payload) is the caller's concern — see `matter-vault`'s signer module.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        match &self.material {
            Material::Sr25519(keypair) => Ok(keypair.sign(message).0),
        }
    }

    fn parse_sr25519(body: &str) -> Result<Self> {
        let uri = suri::split(body)?;

        // A URI with no phrase (`//Alice`, `/soft`) makes every ecosystem parser
        // fall back to the *public* well-known development phrase. Silently
        // minting a globally-known keypair from an unset environment variable is
        // the worst failure this type can have, so a phrase-less key is rejected
        // outright. Callers who genuinely want a dev account spell the dev
        // phrase out in full.
        if uri.phrase.is_empty() {
            return Err(KeyError::Malformed {
                detail: "api key has no phrase; this would derive from the public \
                         well-known development phrase",
            });
        }

        // A hex phrase is a raw mini-secret; the password does not apply to it.
        // Matches `Keypair::from_uri`, which strips `0x` before consulting the
        // password at all.
        let root = match uri.phrase.strip_prefix("0x") {
            Some(hex_body) => Self::keypair_from_hex(hex_body)?,
            None => Self::keypair_from_mnemonic(uri.phrase, uri.password)?,
        };

        Ok(Self::from_keypair(root.derive(uri.junctions)))
    }

    fn keypair_from_hex(hex_body: &str) -> Result<Keypair> {
        // Validate before decoding. `hex::decode` would allocate a heap `Vec`
        // holding the secret (the MV-M3 pattern), and `subxt_signer` would
        // report `Invalid character 'g' at position 5` — disclosing a character
        // of the key and its offset into any log that captures the error.
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

        // Decode straight into a zeroizing fixed buffer — no intermediate
        // allocation, nothing left on the heap after this returns.
        let mut seed = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(hex_body, seed.as_mut()).map_err(|_| KeyError::Malformed {
            detail: "hex mini-secret contains a non-hex character",
        })?;

        Keypair::from_secret_key(*seed).map_err(|_| KeyError::Derivation {
            detail: "seed is not a valid sr25519 mini-secret",
        })
    }

    fn keypair_from_mnemonic(phrase: &str, password: Option<&str>) -> Result<Keypair> {
        // `FromStr`, not `Mnemonic::parse`: this is the exact call
        // `Keypair::from_uri` makes, and matching it keeps normalization
        // behaviour identical across the bip39 feature set.
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
/// Safe to split on the first `:` because no accepted sr25519 encoding contains
/// one: hex is `[0-9a-f]`, BIP39 words are alphabetic, and SURI separators are
/// `/` and `//`.
fn split_scheme(input: &str) -> Result<(KeyScheme, &str)> {
    let Some((token, body)) = input.split_once(':') else {
        return Ok((KeyScheme::Sr25519, input));
    };

    // Reserved-but-unimplemented schemes get a message that says so, rather than
    // the generic "that is not a scheme" — the difference between a roadmap
    // question and a typo.
    if RESERVED_SCHEMES
        .iter()
        .any(|r| token.eq_ignore_ascii_case(r))
    {
        return Err(KeyError::UnsupportedScheme {
            scheme: token.to_ascii_lowercase(),
            supported: SUPPORTED_SCHEMES,
        });
    }

    Ok((KeyScheme::from_token(token)?, body))
}

/// Redacted. Shows the scheme and the (public) account id, never the key.
impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("scheme", &self.scheme.as_str())
            .field("account", &self.account.to_hex())
            .field("material", &"<redacted>")
            .finish()
    }
}
