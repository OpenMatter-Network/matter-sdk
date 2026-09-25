//! The base signing capability.

use crate::apikey::ApiKey;
use crate::error::Result;
use crate::scheme::{AccountId, KeyScheme};

/// An on-chain identity plus the ability to sign raw bytes.
///
/// The only trait an HSM, KMS, or remote-signer integration must implement; the
/// SDK derives all protocol framing (`/partial-decrypt` auth, extrinsics) from it.
///
/// Implement `matter_sdk::Signer` instead when you must own the framing (e.g.
/// EIP-712). There is no blanket `impl<T: KeySigner> Signer for T`; it would
/// conflict with downstream `impl Signer` blocks.
///
/// [`KeySigner::sign`] is synchronous to keep the trait object-safe
/// (`Arc<dyn KeySigner>`). A signer doing network I/O should block; see
/// `docs/secure-signing.md`.
pub trait KeySigner: Send + Sync {
    /// Which scheme this signer produces signatures for.
    fn scheme(&self) -> KeyScheme;

    /// The 32-byte on-chain account id this signer controls.
    fn account_id(&self) -> AccountId;

    /// Sign `message`, returning the raw 64-byte signature with no framing.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64]>;
}

impl KeySigner for ApiKey {
    fn scheme(&self) -> KeyScheme {
        ApiKey::scheme(self)
    }

    fn account_id(&self) -> AccountId {
        ApiKey::account_id(self)
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        ApiKey::sign(self, message)
    }
}

/// Lets `&dyn KeySigner` and `Arc<dyn KeySigner>` be used as a `KeySigner`.
impl<T: KeySigner + ?Sized> KeySigner for &T {
    fn scheme(&self) -> KeyScheme {
        (**self).scheme()
    }

    fn account_id(&self) -> AccountId {
        (**self).account_id()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        (**self).sign(message)
    }
}

impl<T: KeySigner + ?Sized> KeySigner for std::sync::Arc<T> {
    fn scheme(&self) -> KeyScheme {
        (**self).scheme()
    }

    fn account_id(&self) -> AccountId {
        (**self).account_id()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        (**self).sign(message)
    }
}
