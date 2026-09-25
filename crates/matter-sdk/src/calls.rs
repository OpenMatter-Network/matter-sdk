//! Typed `pallet-secrets` call arguments for callers submitting with their own
//! Substrate client. Builders take an [`Aad`] tag so the stored AAD matches the
//! seal. With the `chain` feature, prefer the `secrets` façade on
//! [`crate::chain::MatterClient`].

use matter_sdk_core::{Aad, EncryptedSecret};

/// Arguments for `secrets.storeSecret(payload, epoch, label, aad)`.
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
    /// Build store arguments; `aad` must be the tag used at seal time.
    pub fn new(payload: EncryptedSecret, epoch: u32, label: impl Into<Vec<u8>>, aad: Aad) -> Self {
        Self {
            payload,
            epoch,
            label: label.into(),
            aad: aad.as_bytes().to_vec(),
        }
    }
}

/// Arguments for `secrets.rotateSecret(secret_id, payload, epoch, aad)`: re-seal
/// an existing secret in place under the current epoch.
#[derive(Debug, Clone)]
pub struct RotateSecret {
    /// The secret to rotate.
    pub secret_id: u128,
    /// The freshly sealed envelope.
    pub payload: EncryptedSecret,
    /// The epoch the new envelope was sealed under.
    pub epoch: u32,
    /// The AAD bytes the new envelope was sealed under.
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

/// Who a secret is granted to; mirrors the runtime's `GrantTarget<AccountId>` enum.
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

/// Arguments for `secrets.grantAccess(secret_id, target)`: authorize a principal
/// to request decryption.
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

/// Arguments for `secrets.revokeAccess(secret_id, target)`: withdraw a grant,
/// e.g. to contain a leaked signer.
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

/// Arguments for `secrets.deleteSecret(secret_id)`: remove a secret and every
/// grant on it. Owner only; irreversible.
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
        // Runtime declaration order is the SCALE index; a mismatch grants the
        // wrong principal.
        assert_eq!(GrantTarget::User([0u8; 32]).variant_index(), 0);
        assert_eq!(GrantTarget::Deployment(0).variant_index(), 1);
        assert_eq!(GrantTarget::User([0u8; 32]).variant_name(), "User");
        assert_eq!(GrantTarget::Deployment(0).variant_name(), "Deployment");
    }

    #[test]
    fn grant_and_revoke_build_matching_targets() {
        // A mismatched target makes the revoke a silent no-op.
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
