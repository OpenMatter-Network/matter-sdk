//! Ready-to-submit on-chain call arguments.
//!
//! The SDK does not submit transactions or hold keys — you submit with your own
//! Substrate client (subxt / @polkadot / py-substrate / GSRPC). These typed
//! structs are the *arguments* for the `pallet-secrets` calls, shaped so you
//! can't, for example, store a secret under a different AAD than you sealed it
//! with: the builders take an [`Aad`] tag, the same registry [`crate::encrypt`]
//! uses.

use matter_vault_core::{Aad, EncryptedSecret};

/// Arguments for `secrets.storeSecret(payload, epoch, label, aad)`.
///
/// `label` is a short owner-chosen identifier; `aad` must match what the secret
/// was sealed under, which is why this takes the registry tag rather than raw
/// bytes.
#[derive(Debug, Clone)]
pub struct StoreSecret {
    /// The sealed envelope to publish.
    pub payload: EncryptedSecret,
    /// The epoch the secret was sealed under.
    pub epoch: u32,
    /// A short owner label.
    pub label: Vec<u8>,
    /// The AAD bytes the secret was sealed under.
    pub aad: Vec<u8>,
}

impl StoreSecret {
    /// Build store arguments, deriving the AAD bytes from the registry tag used
    /// at seal time.
    pub fn new(payload: EncryptedSecret, epoch: u32, label: impl Into<Vec<u8>>, aad: Aad) -> Self {
        Self {
            payload,
            epoch,
            label: label.into(),
            aad: aad.as_bytes().to_vec(),
        }
    }
}

/// Arguments for `secrets.rotateSecret(secret_id, payload, epoch, aad)` — re-seal
/// an existing secret in place under the current epoch.
#[derive(Debug, Clone)]
pub struct RotateSecret {
    /// The id of the secret to rotate.
    pub secret_id: u128,
    /// The freshly sealed envelope.
    pub payload: EncryptedSecret,
    /// The epoch the new envelope was sealed under.
    pub epoch: u32,
    /// The AAD bytes (must match the new envelope's seal).
    pub aad: Vec<u8>,
}

impl RotateSecret {
    /// Build rotate arguments from the registry AAD tag used at seal time.
    pub fn new(secret_id: u128, payload: EncryptedSecret, epoch: u32, aad: Aad) -> Self {
        Self {
            secret_id,
            payload,
            epoch,
            aad: aad.as_bytes().to_vec(),
        }
    }
}

/// Arguments for `secrets.grantAccess(secret_id, grantee)` — authorize another
/// account to request decryption of a secret.
#[derive(Debug, Clone)]
pub struct GrantAccess {
    /// The secret to share.
    pub secret_id: u128,
    /// The 32-byte account id being authorized.
    pub grantee: [u8; 32],
}

impl GrantAccess {
    /// Build grant arguments.
    pub fn new(secret_id: u128, grantee: [u8; 32]) -> Self {
        Self { secret_id, grantee }
    }
}
