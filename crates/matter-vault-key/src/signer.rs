//! The base signing capability every online path is built from.

use crate::apikey::ApiKey;
use crate::error::Result;
use crate::scheme::{AccountId, KeyScheme};

/// An on-chain identity plus the ability to sign raw bytes.
///
/// This is the **only** trait an HSM, KMS, or remote-signer integration needs to
/// implement. Everything the SDK layers on top — `/partial-decrypt`
/// authorization, extrinsic signatures — is derived from it, so the framing
/// rules live in the SDK and cannot drift per integration.
///
/// # Relationship to `matter_vault::Signer`
///
/// `matter_vault::Signer` is *not* being replaced and is not legacy. The two
/// traits answer different questions:
///
/// * `KeySigner` — "here is an account and a way to sign bytes"; the SDK derives
///   every protocol framing from it. The common case.
/// * `matter_vault::Signer` — "here are the finished auth fields for one
///   `/partial-decrypt` request"; the implementor owns the framing. The general
///   case, and the seam the Ethereum/EIP-712 path needs, because an EIP-712
///   signer has no 32-byte substrate account id and signs structured typed data
///   rather than raw bytes.
///
/// A blanket `impl<T: KeySigner> Signer for T` is deliberately *not* provided: it
/// would coherence-conflict with every existing downstream `impl Signer for
/// MyHsm`.
///
/// # Object safety
///
/// [`KeySigner::sign`] is synchronous so the trait stays object-safe, which is
/// what lets a client store `Option<Arc<dyn KeySigner>>` and keep read-only,
/// API-key, and bring-your-own-signer clients as one concrete type instead of
/// making every call site generic. A signer that must do network I/O should
/// block; `docs/secure-signing.md` already documents the remote-signer pattern
/// that way.
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

/// Forwarding impl so `Arc<dyn KeySigner>` and `&dyn KeySigner` are themselves
/// usable wherever a `KeySigner` is expected.
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
