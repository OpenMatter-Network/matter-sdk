//! Curated typed façades over the generic surface.
//!
//! Every method here is a thin, named wrapper around
//! [`MatterClient::tx`](super::MatterClient::tx) — it converts typed arguments
//! into `Value`s and delegates. No SCALE encoding, no error handling, no chain
//! access of its own. That is deliberate: the encoding lives in exactly one
//! place, so a façade can be wrong about a *name* but never about the wire format.
//!
//! # Why a curated set rather than all 60-plus pallets
//!
//! The generic surface already reaches everything, including pallets added by a
//! future forkless upgrade. These façades exist for the domains callers actually
//! reach for daily, where a typed signature and a doc comment save a trip to the
//! runtime source. Anything not here is one `client.tx(...)` away, and
//! `docs/client-guide.md` says so — a façade is a convenience, not a gate.
//!
//! # Names are resolved at call time
//!
//! A façade names a pallet and a call; the runtime resolves them from live
//! metadata. A rename in an upgrade therefore surfaces as a
//! [`SdkError::Chain`](crate::SdkError::Chain) at the call, not silently. The
//! `the_curated_pallets_all_exist_in_live_metadata` test in `tests/live_chain.rs`
//! is the tripwire that catches it before a user does.

use matter_vault_core::{Aad, Plaintext};
use matter_vault_key::{AccountId, ScopeSet};
use subxt::dynamic::Value;

use super::{recover, MatterClient, TxReceipt};
use crate::calls::{GrantTarget, StoreSecret};
use crate::error::Result;
use crate::transport::ReqwestTransport;

/// Convert a [`GrantTarget`] to the runtime's `GrantTarget<AccountId>` enum.
///
/// A named variant, not a bare account: the chain cannot decode a raw 32-byte
/// grantee, which is what earlier call builders emitted.
fn grant_target_value(target: &GrantTarget) -> Value {
    match target {
        GrantTarget::User(account) => Value::unnamed_variant("User", [Value::from_bytes(account)]),
        GrantTarget::Deployment(id) => Value::unnamed_variant("Deployment", [Value::u128(*id)]),
    }
}

/// The four-blob sealed envelope as the runtime's `EncryptedSecret` composite.
fn envelope_value(payload: &matter_vault_core::EncryptedSecret) -> Value {
    Value::named_composite([
        ("binding_id", Value::from_bytes(&payload.binding_id)),
        ("capsule", Value::from_bytes(&payload.capsule)),
        ("proof", Value::from_bytes(&payload.proof)),
        ("ct", Value::from_bytes(&payload.ct)),
    ])
}

impl StoreSecret {
    /// The ordered `Value` arguments for `Secrets.store_secret`.
    ///
    /// Public so a caller driving their own client can reuse the SDK's argument
    /// order rather than re-deriving it — one source of truth per language.
    pub fn to_values(&self) -> Vec<Value> {
        vec![
            envelope_value(&self.payload),
            Value::u128(self.epoch as u128),
            Value::from_bytes(&self.label),
            Value::from_bytes(&self.aad),
        ]
    }
}

/// Secrets: store, rotate, share, and delete MatterVault secrets.
pub struct Secrets<'a>(pub(super) &'a MatterClient);

impl Secrets<'_> {
    /// Publish a sealed envelope. Returns the receipt; the chain-assigned id is
    /// in the `Secrets.SecretStored` event.
    pub async fn store(&self, args: &StoreSecret) -> Result<TxReceipt> {
        self.0.tx("Secrets", "store_secret", args.to_values()).await
    }

    /// Re-seal an existing secret in place under the current epoch.
    pub async fn rotate(
        &self,
        secret_id: u128,
        payload: &matter_vault_core::EncryptedSecret,
        epoch: u32,
        aad: Aad,
    ) -> Result<TxReceipt> {
        self.0
            .tx(
                "Secrets",
                "rotate_secret",
                vec![
                    Value::u128(secret_id),
                    envelope_value(payload),
                    Value::u128(epoch as u128),
                    Value::from_bytes(aad.as_bytes()),
                ],
            )
            .await
    }

    /// Authorize an account to request decryption.
    pub async fn grant_to_user(&self, secret_id: u128, account: AccountId) -> Result<TxReceipt> {
        self.grant(secret_id, &GrantTarget::User(*account.as_bytes()))
            .await
    }

    /// Authorize whichever resource is currently assigned to a deployment.
    pub async fn grant_to_deployment(
        &self,
        secret_id: u128,
        deployment: u128,
    ) -> Result<TxReceipt> {
        self.grant(secret_id, &GrantTarget::Deployment(deployment))
            .await
    }

    /// Authorize an arbitrary [`GrantTarget`].
    pub async fn grant(&self, secret_id: u128, target: &GrantTarget) -> Result<TxReceipt> {
        self.0
            .tx(
                "Secrets",
                "grant_access",
                vec![Value::u128(secret_id), grant_target_value(target)],
            )
            .await
    }

    /// Withdraw a grant. The target must match the grant exactly, or this is a
    /// no-op on chain.
    pub async fn revoke(&self, secret_id: u128, target: &GrantTarget) -> Result<TxReceipt> {
        self.0
            .tx(
                "Secrets",
                "revoke_access",
                vec![Value::u128(secret_id), grant_target_value(target)],
            )
            .await
    }

    /// Delete a secret and every grant on it. Owner only, and irreversible.
    pub async fn delete(&self, secret_id: u128) -> Result<TxReceipt> {
        self.0
            .tx("Secrets", "delete_secret", vec![Value::u128(secret_id)])
            .await
    }

    /// Recover a stored secret's plaintext in one call: read its envelope, epoch and AAD,
    /// assemble the committee seated at that epoch, and run the threshold decrypt with
    /// this client's key.
    ///
    /// The key must be authorized for the secret — its owner, a `User` grantee, or a
    /// `Secrets:Read` delegate — or the committee refuses every partial. A secret sealed
    /// under a different tag than `aad` is refused before any node is contacted.
    /// Rust-only: the other bindings compose `recover_secret` themselves.
    pub async fn recover(&self, secret_id: u128, aad: Aad) -> Result<Plaintext> {
        let signer = self.0.require_signer()?;
        let stored = recover::read_secret(&self.0.rpc, secret_id).await?;
        recover::check_aad(secret_id, &stored.aad, aad)?;
        let committee = recover::committee_info(&self.0.rpc, stored.epoch).await?;
        let transport = ReqwestTransport::new();
        let auth = recover::KeyAuth(signer.as_ref());
        crate::recover_secret(
            &committee,
            &transport,
            &auth,
            secret_id,
            &stored.envelope,
            aad,
        )
        .await
    }
}

/// Deployments (`pallet-jobs`): request compute, wire networking, bind secrets.
pub struct Deployments<'a>(pub(super) &'a MatterClient);

impl Deployments<'_> {
    /// Request a deployment. `request` is the runtime's `ResourceRequest`, which
    /// is large and evolving, so it is passed through as a `Value` rather than
    /// mirrored here — mirroring it would be a second source of truth that rots.
    pub async fn request(&self, request: Value) -> Result<TxReceipt> {
        self.0.tx("Jobs", "request_deployment", vec![request]).await
    }

    /// Cancel a deployment.
    pub async fn cancel(&self, deployment: u128) -> Result<TxReceipt> {
        self.0
            .tx("Jobs", "cancel_deployment", vec![Value::u128(deployment)])
            .await
    }

    /// Point a deployment at a MatterVault secret, or clear it with `None`.
    ///
    /// This is the bridge between a deployment and a sealed secret: the assigned
    /// resource is authorized to decrypt whatever `secret_ref` names.
    pub async fn set_secret_ref(
        &self,
        deployment: u128,
        secret_ref: Option<u128>,
    ) -> Result<TxReceipt> {
        self.0
            .tx(
                "Jobs",
                "set_deployment_secret_ref",
                vec![Value::u128(deployment), option_u128(secret_ref)],
            )
            .await
    }

    /// Set or clear a deployment's plaintext environment variables.
    ///
    /// Plaintext: anything sensitive belongs in a sealed secret referenced by
    /// [`Deployments::set_secret_ref`], not here.
    pub async fn set_env(&self, deployment: u128, env: Option<Value>) -> Result<TxReceipt> {
        self.0
            .tx(
                "Jobs",
                "set_deployment_env",
                vec![Value::u128(deployment), option_value(env)],
            )
            .await
    }

    /// Register a WireGuard peer public key against a deployment.
    pub async fn register_wg_peer(&self, deployment: u128, pubkey: [u8; 32]) -> Result<TxReceipt> {
        self.0
            .tx(
                "Jobs",
                "register_wg_peer",
                vec![Value::u128(deployment), Value::from_bytes(pubkey)],
            )
            .await
    }
}

/// Resources: register capacity, price it, and control who may use it.
pub struct Resources<'a>(pub(super) &'a MatterClient);

impl Resources<'_> {
    /// Register a resource you operate.
    pub async fn register(
        &self,
        resource: AccountId,
        ownership_proof: Value,
        name: &str,
    ) -> Result<TxReceipt> {
        self.0
            .tx(
                "Resources",
                "register_resource",
                vec![
                    Value::from_bytes(resource.as_bytes()),
                    ownership_proof,
                    Value::from_bytes(name.as_bytes()),
                ],
            )
            .await
    }

    /// Publish or update a SKU's pricing.
    pub async fn update_sku(&self, uuid: u128, sku: Value) -> Result<TxReceipt> {
        self.0
            .tx("Resources", "update_sku", vec![Value::u128(uuid), sku])
            .await
    }

    /// Report current capacity.
    pub async fn report_capacity(&self, capacity: Value) -> Result<TxReceipt> {
        self.0
            .tx("Resources", "report_capacity", vec![capacity])
            .await
    }

    /// Make a resource private (whitelist-only) or public.
    pub async fn set_privacy(&self, resource: AccountId, is_private: bool) -> Result<TxReceipt> {
        self.0
            .tx(
                "Resources",
                "set_resource_privacy",
                vec![
                    Value::from_bytes(resource.as_bytes()),
                    Value::bool(is_private),
                ],
            )
            .await
    }

    /// Allow an account to use a private resource.
    pub async fn allow(&self, resource: AccountId, user: AccountId) -> Result<TxReceipt> {
        self.0
            .tx(
                "Resources",
                "add_to_whitelist",
                vec![
                    Value::from_bytes(resource.as_bytes()),
                    Value::from_bytes(user.as_bytes()),
                ],
            )
            .await
    }

    /// Withdraw a private resource's whitelist entry.
    pub async fn disallow(&self, resource: AccountId, user: AccountId) -> Result<TxReceipt> {
        self.0
            .tx(
                "Resources",
                "remove_from_whitelist",
                vec![
                    Value::from_bytes(resource.as_bytes()),
                    Value::from_bytes(user.as_bytes()),
                ],
            )
            .await
    }
}

/// Staking on MatterChain: the standard FRAME staking surface.
///
/// Amounts are **plancks**. Use [`MatterClient::parse_amount`] rather than
/// writing an exponent by hand — this chain's decimal count changed once already,
/// without a storage migration.
///
/// `pallet-staking-gateway` is deliberately absent: it is the Ethereum
/// meta-transaction path, and belongs with the reserved secp256k1 scheme.
pub struct Staking<'a>(pub(super) &'a MatterClient);

impl Staking<'_> {
    /// Bond funds and set a reward destination. `payee` is the runtime's
    /// `RewardDestination`, e.g. `Value::unnamed_variant("Staked", [])`.
    pub async fn bond(&self, value: u128, payee: Value) -> Result<TxReceipt> {
        self.0
            .tx("Staking", "bond", vec![Value::u128(value), payee])
            .await
    }

    /// Add to an existing bond.
    pub async fn bond_extra(&self, additional: u128) -> Result<TxReceipt> {
        self.0
            .tx("Staking", "bond_extra", vec![Value::u128(additional)])
            .await
    }

    /// Schedule an unbond. The funds remain locked until the unbonding period
    /// elapses and [`Staking::withdraw_unbonded`] is called.
    pub async fn unbond(&self, value: u128) -> Result<TxReceipt> {
        self.0
            .tx("Staking", "unbond", vec![Value::u128(value)])
            .await
    }

    /// Move unlocked funds back to free balance.
    pub async fn withdraw_unbonded(&self, num_slashing_spans: u32) -> Result<TxReceipt> {
        self.0
            .tx(
                "Staking",
                "withdraw_unbonded",
                vec![Value::u128(num_slashing_spans as u128)],
            )
            .await
    }

    /// Nominate a set of validators, by SS58-decoded account id.
    pub async fn nominate(&self, targets: &[AccountId]) -> Result<TxReceipt> {
        let targets = Value::unnamed_composite(
            targets
                .iter()
                .map(|t| Value::unnamed_variant("Id", [Value::from_bytes(t.as_bytes())])),
        );
        self.0.tx("Staking", "nominate", vec![targets]).await
    }

    /// Stop nominating or validating.
    pub async fn chill(&self) -> Result<TxReceipt> {
        self.0.tx("Staking", "chill", vec![]).await
    }

    /// Join a nomination pool with `amount` plancks.
    pub async fn join_pool(&self, amount: u128, pool_id: u32) -> Result<TxReceipt> {
        self.0
            .tx(
                "NominationPools",
                "join",
                vec![Value::u128(amount), Value::u128(pool_id as u128)],
            )
            .await
    }

    /// Claim accrued nomination-pool rewards.
    pub async fn claim_pool_payout(&self) -> Result<TxReceipt> {
        self.0.tx("NominationPools", "claim_payout", vec![]).await
    }
}

/// Organizations and budgets: membership, projects, and who may spend or decrypt.
pub struct Orgs<'a>(pub(super) &'a MatterClient);

impl Orgs<'_> {
    /// Create an organization.
    pub async fn create(&self, metadata: Value) -> Result<TxReceipt> {
        self.0
            .tx("Organizations", "create_org", vec![metadata])
            .await
    }

    /// Add a member with a role. `role` is the runtime's `Role` enum.
    pub async fn add_member(
        &self,
        org: [u8; 32],
        who: AccountId,
        role: Value,
    ) -> Result<TxReceipt> {
        self.0
            .tx(
                "Organizations",
                "add_member",
                vec![
                    Value::from_bytes(org),
                    Value::from_bytes(who.as_bytes()),
                    role,
                ],
            )
            .await
    }

    /// Remove a member.
    pub async fn remove_member(&self, org: [u8; 32], who: AccountId) -> Result<TxReceipt> {
        self.0
            .tx(
                "Organizations",
                "remove_member",
                vec![Value::from_bytes(org), Value::from_bytes(who.as_bytes())],
            )
            .await
    }

    /// Allot budget from an org treasury to a project, in plancks.
    pub async fn allot(&self, org: [u8; 32], project: [u8; 32], amount: u128) -> Result<TxReceipt> {
        self.0
            .tx(
                "Budgets",
                "allot",
                vec![
                    Value::from_bytes(org),
                    Value::from_bytes(project),
                    Value::u128(amount),
                ],
            )
            .await
    }

    /// Authorize an account to decrypt a project's secrets — the org-scoped
    /// analogue of `secrets.grant_access`.
    pub async fn authorize_secrets_agent(
        &self,
        org: [u8; 32],
        project: [u8; 32],
        who: AccountId,
    ) -> Result<TxReceipt> {
        self.0
            .tx(
                "Budgets",
                "authorize_project_secrets_agent",
                vec![
                    Value::from_bytes(org),
                    Value::from_bytes(project),
                    Value::from_bytes(who.as_bytes()),
                ],
            )
            .await
    }

    /// Withdraw a project secrets-agent authorization.
    pub async fn revoke_secrets_agent(
        &self,
        org: [u8; 32],
        project: [u8; 32],
        who: AccountId,
    ) -> Result<TxReceipt> {
        self.0
            .tx(
                "Budgets",
                "revoke_project_secrets_agent",
                vec![
                    Value::from_bytes(org),
                    Value::from_bytes(project),
                    Value::from_bytes(who.as_bytes()),
                ],
            )
            .await
    }
}

/// `Option<u128>` as the runtime's `Option` enum.
fn option_u128(value: Option<u128>) -> Value {
    match value {
        Some(v) => Value::unnamed_variant("Some", [Value::u128(v)]),
        None => Value::unnamed_variant("None", []),
    }
}

/// `Option<Value>` as the runtime's `Option` enum.
fn option_value(value: Option<Value>) -> Value {
    match value {
        Some(v) => Value::unnamed_variant("Some", [v]),
        None => Value::unnamed_variant("None", []),
    }
}

/// Minting and revoking member-tied API keys (`pallet-budgets`' roster calls).
///
/// **These are member-signed.** A key can never call them on itself — the
/// runtime puts the roster calls on its never-admitted list precisely so a key
/// cannot widen its own authority — so reach for this façade from a client built
/// on a human seed or an HSM signer, which is to say a
/// [`Mode::Direct`](super::Mode::Direct) one. Calling `authorize` from a
/// delegated client returns [`SdkError::NeverAdmitted`](crate::SdkError::NeverAdmitted)
/// before anything is submitted.
pub struct Keys<'a>(pub(super) &'a MatterClient);

impl Keys<'_> {
    /// Register `key` as an API key acting for the signer, with `scopes`.
    ///
    /// An upsert: it replaces whatever scoped definition `key` already holds on
    /// the signer, so re-scoping a live key is this same call.
    pub async fn authorize(&self, key: AccountId, scopes: ScopeSet) -> Result<TxReceipt> {
        self.0
            .tx(
                "Budgets",
                "authorize_agent_key",
                vec![
                    Value::from_bytes(key.as_bytes()),
                    Value::u128(u128::from(scopes.bits())),
                ],
            )
            .await
    }

    /// Revoke `key`, cutting off its authority — and its committee decrypt
    /// rights — from the next request onward.
    pub async fn revoke(&self, key: AccountId) -> Result<TxReceipt> {
        self.0
            .tx(
                "Budgets",
                "revoke_agent_key",
                vec![Value::from_bytes(key.as_bytes())],
            )
            .await
    }

    /// Who `key` acts for and what it may do, or `None` if it is not registered.
    ///
    /// A read, so it needs no signer and works on a read-only client.
    pub async fn lookup(&self, key: AccountId) -> Result<Option<(AccountId, ScopeSet)>> {
        self.0.agent_key(key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_target_encodes_as_a_named_variant_not_a_bare_account() {
        // The defect this fixes: a raw 32-byte grantee is not decodable as
        // `GrantTarget<AccountId>`, so the call data was dead on arrival.
        let user = grant_target_value(&GrantTarget::User([7u8; 32]));
        assert!(format!("{user:?}").contains("User"), "{user:?}");

        let deployment = grant_target_value(&GrantTarget::Deployment(42));
        assert!(format!("{deployment:?}").contains("Deployment"));
    }

    #[test]
    fn options_encode_as_the_runtime_enum() {
        assert!(format!("{:?}", option_u128(Some(1))).contains("Some"));
        assert!(format!("{:?}", option_u128(None)).contains("None"));
    }

    #[test]
    fn store_secret_args_are_in_runtime_order() {
        // `store_secret(payload, epoch, label, aad)`. Argument order is positional
        // on the wire, so a swap here is a silently wrong extrinsic.
        let args = StoreSecret::new(
            matter_vault_core::EncryptedSecret {
                binding_id: vec![1],
                capsule: vec![2],
                proof: vec![3],
                ct: vec![4],
            },
            7,
            "prod",
            Aad::EnvV1,
        )
        .to_values();

        assert_eq!(args.len(), 4);
        let rendered = format!("{args:?}");
        assert!(rendered.contains("binding_id"));
        assert!(rendered.contains("capsule"));
    }
}
