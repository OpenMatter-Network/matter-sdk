//! Ready-to-submit on-chain call arguments.
//!
//! These typed structs are the *arguments* for the `pallet-secrets` calls, shaped
//! so you can't, for example, store a secret under a different AAD than you
//! sealed it with: the builders take an [`Aad`] tag, the same registry
//! [`crate::encrypt`] uses.
//!
//! They are for callers who submit with their own Substrate client (subxt /
//! @polkadot / py-substrate / GSRPC). With the `chain` feature the SDK can submit
//! them for you — see [`crate::chain::MatterClient`] and its `secrets` façade,
//! which is the shorter path for most callers.

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

/// Who a secret is granted to.
///
/// The chain's `GrantTarget<AccountId>` is an **enum**, not a bare account id.
/// Earlier versions of this builder emitted a raw 32-byte grantee, which the
/// runtime cannot decode — the call data was dead on arrival. Nothing caught it
/// because no end-to-end test exercised `grant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantTarget {
    /// Another user or a resource node, named by account.
    User([u8; 32]),
    /// A deployment: authorizes whichever resource is currently assigned to it,
    /// so the owner need not name an account that only exists after assignment.
    Deployment(u128),
}

impl GrantTarget {
    /// The SCALE variant index the runtime decodes: `User = 0`, `Deployment = 1`.
    pub const fn variant_index(&self) -> u8 {
        match self {
            GrantTarget::User(_) => 0,
            GrantTarget::Deployment(_) => 1,
        }
    }

    /// The variant name, as the metadata spells it.
    pub const fn variant_name(&self) -> &'static str {
        match self {
            GrantTarget::User(_) => "User",
            GrantTarget::Deployment(_) => "Deployment",
        }
    }
}

/// Arguments for `secrets.grantAccess(secret_id, target)` — authorize a principal
/// to request decryption of a secret.
#[derive(Debug, Clone)]
pub struct GrantAccess {
    /// The secret to share.
    pub secret_id: u128,
    /// The principal being authorized.
    pub target: GrantTarget,
}

impl GrantAccess {
    /// Build grant arguments for an account.
    pub fn to_user(secret_id: u128, account: [u8; 32]) -> Self {
        Self {
            secret_id,
            target: GrantTarget::User(account),
        }
    }

    /// Build grant arguments for a deployment.
    pub fn to_deployment(secret_id: u128, deployment: u128) -> Self {
        Self {
            secret_id,
            target: GrantTarget::Deployment(deployment),
        }
    }
}

/// Arguments for `secrets.revokeAccess(secret_id, target)` — withdraw a grant.
///
/// Revocation is how a leaked signer is contained, so it is a first-class call
/// rather than something callers have to hand-roll.
#[derive(Debug, Clone)]
pub struct RevokeAccess {
    /// The secret to stop sharing.
    pub secret_id: u128,
    /// The principal being de-authorized.
    pub target: GrantTarget,
}

impl RevokeAccess {
    /// Build revoke arguments for an account.
    pub fn from_user(secret_id: u128, account: [u8; 32]) -> Self {
        Self {
            secret_id,
            target: GrantTarget::User(account),
        }
    }

    /// Build revoke arguments for a deployment.
    pub fn from_deployment(secret_id: u128, deployment: u128) -> Self {
        Self {
            secret_id,
            target: GrantTarget::Deployment(deployment),
        }
    }
}

/// Arguments for `secrets.deleteSecret(secret_id)` — remove a secret and every
/// grant on it. Owner only, and irreversible.
#[derive(Debug, Clone)]
pub struct DeleteSecret {
    /// The secret to delete.
    pub secret_id: u128,
}

impl DeleteSecret {
    /// Build delete arguments.
    pub fn new(secret_id: u128) -> Self {
        Self { secret_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_target_variant_indices_match_the_runtime_enum() {
        // `pub enum GrantTarget<AccountId> { User(AccountId), Deployment(u128) }`
        // — declaration order is the SCALE index, and getting it wrong grants
        // access to the wrong principal.
        assert_eq!(GrantTarget::User([0u8; 32]).variant_index(), 0);
        assert_eq!(GrantTarget::Deployment(0).variant_index(), 1);
        assert_eq!(GrantTarget::User([0u8; 32]).variant_name(), "User");
        assert_eq!(GrantTarget::Deployment(0).variant_name(), "Deployment");
    }

    #[test]
    fn grant_and_revoke_build_matching_targets() {
        // A grant and its revoke must name the principal identically, or the
        // revoke silently does nothing.
        let account = [7u8; 32];
        assert_eq!(
            GrantAccess::to_user(1, account).target,
            RevokeAccess::from_user(1, account).target
        );
        assert_eq!(
            GrantAccess::to_deployment(1, 42).target,
            RevokeAccess::from_deployment(1, 42).target
        );
    }
}
