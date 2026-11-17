//! Curated typed façades for common domains.
//!
//! A write converts typed arguments to `Value`s and delegates to
//! [`MatterClient::tx`](super::MatterClient::tx), which owns all encoding. A
//! read takes one block's state, fetches its sources there, and hands the raw
//! bytes to a pure decoder in [`read`](super::read). Anything not here is one
//! `client.tx(...)` or `client.query(...)` away.
//!
//! Names resolve against live metadata at call time, so a runtime rename
//! surfaces as [`SdkError::Chain`](crate::SdkError::Chain);
//! `tests/live_chain.rs` checks the curated pallets exist.

use matter_sdk_core::{Aad, Plaintext};
use matter_sdk_key::{AccountId, ScopeSet};
use subxt::dynamic::Value;

use super::read::{
    accounts,
    fees,
    network,
    AccountBalance,
    Block,
    BlockHeader,
    FeeEstimate,
    NetworkInfo,
    NetworkTiming,
    NodeStatus,
    Pin,
    Snapshot,
};
use super::{recover, MatterClient, TxReceipt};
use crate::calls::{GrantTarget, StoreSecret};
use crate::error::Result;
use crate::transport::ReqwestTransport;

/// A [`GrantTarget`] as the runtime's `GrantTarget<AccountId>` enum variant.
fn grant_target_value(target: &GrantTarget) -> Value {
    match target {
        GrantTarget::User(account) => Value::unnamed_variant("User", [Value::from_bytes(account)]),
        GrantTarget::Deployment(id) => Value::unnamed_variant("Deployment", [Value::u128(*id)]),
    }
}

/// The four-blob sealed envelope as the runtime's `EncryptedSecret` composite.
fn envelope_value(payload: &matter_sdk_core::EncryptedSecret) -> Value {
    Value::named_composite([
        ("binding_id", Value::from_bytes(&payload.binding_id)),
        ("capsule", Value::from_bytes(&payload.capsule)),
        ("proof", Value::from_bytes(&payload.proof)),
        ("ct", Value::from_bytes(&payload.ct)),
    ])
}

impl StoreSecret {
    /// The ordered `Value` arguments for `Secrets.store_secret`, for callers
    /// driving their own client.
    pub fn to_values(&self) -> Vec<Value> {
        vec![
            envelope_value(&self.payload),
            Value::u128(self.epoch as u128),
            Value::from_bytes(&self.label),
            Value::from_bytes(&self.aad),
        ]
    }
}

/// Accounts: what an account holds and how much of it can move.
///
/// Reads only, at the latest finalized block unless pinned with
/// [`Accounts::at`]. Works on a read-only client.
pub struct Accounts<'a>(pub(super) &'a MatterClient, pub(super) Pin);

impl Accounts<'_> {
    /// Read at `block` (a block hash) instead of the latest finalized block, so
    /// several reads share one view of the chain.
    pub fn at(self, block: [u8; 32]) -> Self {
        Self(self.0, Pin::Block(block))
    }

    /// What `who` holds: free, on hold and frozen amounts, what a transfer may
    /// move, and the reasons behind each hold and freeze. An account the chain
    /// does not store reads as zeros with `exists == false`.
    pub async fn balance(&self, who: impl Into<AccountId>) -> Result<AccountBalance> {
        let who = who.into();
        let snapshot = self.0.snapshot(self.1).await?;
        let values = snapshot.storage(&accounts::balance_requests(who)).await?;
        accounts::decode_balance(
            self.0.address_of(who),
            self.0.properties.existential_deposit,
            &values,
        )
    }
}

/// The network: which chain this is, its blocks, its timing, and the health of
/// the node answering.
///
/// Reads only. [`NetworkState::head`] reads at the latest finalized block unless
/// pinned with [`NetworkState::at`]; the other reads are not about one block.
pub struct NetworkState<'a>(pub(super) &'a MatterClient, pub(super) Pin);

impl NetworkState<'_> {
    /// Make [`head`](Self::head) describe `block` (a block hash) instead of the
    /// latest finalized block.
    pub fn at(self, block: [u8; 32]) -> Self {
        Self(self.0, Pin::Block(block))
    }

    /// Which chain this is: its name, genesis hash, token and address format, as
    /// read once at connect. No request is made.
    pub fn info(&self) -> NetworkInfo {
        network::info(&self.0.properties)
    }

    /// The latest finalized block, or the pinned one: its height, hash, time and
    /// runtime version. Its `hash` is what a façade's `at` takes, to make
    /// several reads share this block.
    pub async fn head(&self) -> Result<Block> {
        let snapshot = self.0.snapshot(self.1).await?;
        let header = header_at(&snapshot).await?;
        let [now] = snapshot.storage(&network::now_request()).await?;
        let version: network::RuntimeVersionWire =
            snapshot.request_here(network::GET_RUNTIME_VERSION).await?;
        network::decode_block(header, now.as_deref(), &version)
    }

    /// The block at height `number`, or `None` if the chain has not reached it.
    /// Read from headers alone, so it works for blocks whose state the node has
    /// pruned; `at(hash).head()` adds the time and runtime version where it has not.
    pub async fn block(&self, number: u64) -> Result<Option<BlockHeader>> {
        let hash: Option<String> = self
            .0
            .request(
                network::GET_BLOCK_HASH,
                vec![network::block_number_param(number).into()],
            )
            .await?;
        let Some(hash) = hash else {
            return Ok(None);
        };
        let hash = network::hash_from_hex(network::GET_BLOCK_HASH, &hash)?;
        let snapshot = self.0.snapshot(Pin::Block(hash)).await?;
        header_at(&snapshot).await.map(Some)
    }

    /// The node answering this client: its software, peers, whether it is still
    /// syncing, and its best and finalized blocks. About the node, not a block,
    /// so a pin does not apply.
    pub async fn node(&self) -> Result<NodeStatus> {
        let name: String = self.0.request(network::SYSTEM_NAME, Vec::new()).await?;
        let version: String = self.0.request(network::SYSTEM_VERSION, Vec::new()).await?;
        let health: network::HealthWire =
            self.0.request(network::SYSTEM_HEALTH, Vec::new()).await?;
        let best_hash: String = self.0.request(network::GET_BLOCK_HASH, Vec::new()).await?;
        let best_hash = network::hash_from_hex(network::GET_BLOCK_HASH, &best_hash)?;
        let best = header_at(&self.0.snapshot(Pin::Block(best_hash)).await?).await?;
        let finalized = header_at(&self.0.snapshot(Pin::Finalized).await?).await?;
        Ok(network::node_status(
            name, version, &health, best, finalized,
        ))
    }

    /// How the chain measures time: its block time, and the length of a session,
    /// an era and the unbonding period. Constants of the connected runtime; no
    /// request is made.
    pub fn timing(&self) -> Result<NetworkTiming> {
        let [a, b, c, d] = network::TIMING_CONSTANTS;
        network::decode_timing(&[
            self.0.constant_bytes(a)?,
            self.0.constant_bytes(b)?,
            self.0.constant_bytes(c)?,
            self.0.constant_bytes(d)?,
        ])
    }
}

/// Fees: what a call would cost, and who would be charged for it.
///
/// Reads only, at the latest finalized block unless pinned with [`Fees::at`].
pub struct Fees<'a>(pub(super) &'a MatterClient, pub(super) Pin);

impl Fees<'_> {
    /// Read at `block` (a block hash) instead of the latest finalized block, so
    /// several reads share one view of the chain.
    pub fn at(self, block: [u8; 32]) -> Self {
        Self(self.0, Pin::Block(block))
    }

    /// What `pallet.call(args)` would cost this client, and who would be
    /// charged. Takes exactly what [`MatterClient::tx`] takes, and prices the
    /// call as it would be submitted: wrapped in `Proxy.proxy` when the client
    /// acts for a member. Nothing is signed or submitted.
    ///
    /// An estimate, not a quote: the fee is computed for an upper bound on the
    /// signed length, with no tip. It is also not a permission check; a call a
    /// scoped key may not make is still priced. Works on a read-only client,
    /// which learns the fee but not the payer.
    pub async fn estimate(
        &self,
        pallet: &str,
        call: &str,
        args: Vec<Value>,
    ) -> Result<FeeEstimate> {
        let (bytes, wrapped_in_proxy) = self.0.call_as_submitted(pallet, call, args)?;
        let (encoded_len, info_args) = fees::call_info_args(&bytes)?;
        let signer = self.0.account();

        let snapshot = self.0.snapshot(self.1).await?;
        let info = snapshot.call(fees::QUERY_CALL_INFO, &info_args).await?;
        let info = fees::decode_dispatch_info(&info)?;
        // The payer depends on the fee, so this is asked second.
        let payer = match signer {
            Some(signer) => Some(
                snapshot
                    .call(
                        fees::FEE_PAYER,
                        &fees::fee_payer_args(signer, &bytes, info.0),
                    )
                    .await?,
            ),
            None => None,
        };
        let priced = fees::Priced {
            pallet,
            call,
            encoded_len,
            wrapped_in_proxy,
            signer: signer.map(|id| self.0.address_of(id)),
        };
        fees::decode_estimate(priced, info, payer.as_deref(), |id| self.0.address_of(id))
    }
}

/// The header of the block `snapshot` reads at.
async fn header_at(snapshot: &Snapshot<'_>) -> Result<BlockHeader> {
    let header: Option<network::HeaderWire> = snapshot.request_here(network::GET_HEADER).await?;
    network::decode_header(snapshot.at(), header)
}

/// Secrets: store, rotate, share, and delete secrets.
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
        payload: &matter_sdk_core::EncryptedSecret,
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

    /// Recover a stored secret's plaintext: read its envelope, epoch and AAD,
    /// assemble that epoch's committee, and threshold-decrypt with this client's key.
    ///
    /// The key must be the owner, a `User` grantee, or a `Secrets:Read` delegate,
    /// or the committee refuses every partial. A secret sealed under a different
    /// tag than `aad` is refused before any node is contacted. Rust-only.
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
    /// Request a deployment. `request` is the runtime's `ResourceRequest`, passed
    /// through as a `Value`.
    pub async fn request(&self, request: Value) -> Result<TxReceipt> {
        self.0.tx("Jobs", "request_deployment", vec![request]).await
    }

    /// Cancel a deployment.
    pub async fn cancel(&self, deployment: u128) -> Result<TxReceipt> {
        self.0
            .tx("Jobs", "cancel_deployment", vec![Value::u128(deployment)])
            .await
    }

    /// Point a deployment at a secret, or clear it with `None`. The assigned
    /// resource may then decrypt that secret.
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

    /// Set or clear a deployment's **plaintext** environment variables. Put
    /// anything sensitive in a secret via [`Deployments::set_secret_ref`].
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
    ///
    /// `pq_ciphertext` is the 1088-byte ML-KEM-768 ciphertext encapsulated to the
    /// provider's key in `OverlayNetworks.PqKemPubkeys`, from which the provider
    /// derives the tunnel's post-quantum preshared key. Required from spec 330.
    pub async fn register_wg_peer(
        &self,
        deployment: u128,
        pubkey: [u8; 32],
        pq_ciphertext: Vec<u8>,
    ) -> Result<TxReceipt> {
        self.0
            .tx(
                "Jobs",
                "register_wg_peer",
                vec![
                    Value::u128(deployment),
                    Value::from_bytes(pubkey),
                    Value::from_bytes(pq_ciphertext),
                ],
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
/// Amounts are plancks; use [`MatterClient::parse_amount`] rather than a
/// hardcoded exponent. `pallet-staking-gateway` (the Ethereum path) is excluded.
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
    pub async fn bond_extra(&self, max_additional: u128) -> Result<TxReceipt> {
        self.0
            .tx("Staking", "bond_extra", vec![Value::u128(max_additional)])
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
    /// Create an organization; the runtime derives its id from the signer.
    pub async fn create(&self) -> Result<TxReceipt> {
        self.0.tx("Organizations", "create_org", vec![]).await
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

    /// Authorize an account to decrypt a project's secrets (org-scoped
    /// `secrets.grant_access`).
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

/// Minting and revoking member-tied API keys (`pallet-budgets` roster calls).
///
/// **Member-signed only**, from a [`Mode::Direct`](super::Mode::Direct) client:
/// no key may widen its own authority. A delegated client gets
/// [`SdkError::NeverAdmitted`](crate::SdkError::NeverAdmitted) before submission.
pub struct Keys<'a>(pub(super) &'a MatterClient);

impl Keys<'_> {
    /// Register `key` as an API key acting for the signer, with `scopes`. An
    /// upsert: this also re-scopes a live key.
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

    /// Revoke `key`, cutting off its authority and committee decrypt rights from
    /// the next request onward.
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
    /// Works on a read-only client.
    pub async fn lookup(&self, key: AccountId) -> Result<Option<(AccountId, ScopeSet)>> {
        self.0.agent_key(key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_target_encodes_as_a_named_variant_not_a_bare_account() {
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

    mod reads {
        use parity_scale_codec::{Compact, Encode};
        use serde_json::json;

        use crate::chain::read::accounts::balance_requests;
        use crate::chain::read::fees::QUERY_CALL_INFO;
        use crate::chain::read::hex0x;
        use crate::chain::read::testing::{
            offline_client,
            storage_key,
            FakeChain,
            ALICE,
            FAKE_HEAD,
            TOKEN,
        };
        use crate::{AccountId, SdkError};

        /// A chain storing Alice with one free token and nothing else.
        fn chain_with_alice() -> FakeChain {
            let [account, ..] = balance_requests(AccountId(ALICE));
            let info = (7u32, 0u32, 1u32, 0u32, (TOKEN, 0u128, 0u128, 0u128)).encode();
            FakeChain::new().with_storage(storage_key(&account), info)
        }

        #[tokio::test]
        async fn an_unpinned_read_resolves_the_finalized_head_once_then_reads_there() {
            let chain = chain_with_alice();
            let client = offline_client(&chain);

            let balance = client.accounts().balance(ALICE).await.unwrap();
            assert!(balance.exists);
            assert_eq!(balance.free, TOKEN);

            let requests = chain.exchanges();
            let methods: Vec<&str> = requests.iter().map(|r| r.method.as_str()).collect();
            assert_eq!(methods, ["chain_getFinalizedHead", "state_queryStorageAt"]);
            // Every source in the one request, at the head just resolved.
            assert_eq!(requests[1].params[0].as_array().unwrap().len(), 4);
            assert_eq!(requests[1].params[1], json!(hex0x(&FAKE_HEAD)));
        }

        #[tokio::test]
        async fn a_pinned_read_asks_for_no_head_and_reads_at_the_pin() {
            let chain = chain_with_alice();
            let client = offline_client(&chain);
            let pin = [0x77u8; 32];

            client.accounts().at(pin).balance(ALICE).await.unwrap();

            let requests = chain.exchanges();
            assert_eq!(requests.len(), 1, "{requests:?}");
            assert_eq!(requests[0].method, "state_queryStorageAt");
            assert_eq!(requests[0].params[1], json!(hex0x(&pin)));
        }

        #[tokio::test]
        async fn a_refused_request_is_a_chain_error_naming_the_method() {
            let err = offline_client(&FakeChain::refusing())
                .accounts()
                .balance(ALICE)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, SdkError::Chain { target, .. } if target == "chain_getFinalizedHead"),
                "{err:?}"
            );

            let err = offline_client(&FakeChain::refusing())
                .accounts()
                .at(FAKE_HEAD)
                .balance(ALICE)
                .await
                .unwrap_err();
            assert!(
                matches!(&err, SdkError::Chain { target, .. } if target == "state_queryStorageAt"),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn an_unpinned_estimate_prices_the_call_at_the_finalized_head() {
            let info = (Compact(1u64), Compact(2u64), 0u8, 3u128).encode();
            let chain = FakeChain::new().with_runtime_api(QUERY_CALL_INFO, info);

            let estimate = offline_client(&chain)
                .fees()
                .estimate("Staking", "chill", vec![])
                .await
                .unwrap();
            assert_eq!(estimate.partial_fee, 3);
            // Read-only: there is no signer to ask the runtime about.
            assert_eq!((estimate.signer, estimate.payer), (None, None));

            let requests = chain.exchanges();
            let methods: Vec<&str> = requests.iter().map(|r| r.method.as_str()).collect();
            assert_eq!(methods, ["chain_getFinalizedHead", "state_call"]);
            assert_eq!(requests[1].params[0], json!(QUERY_CALL_INFO));
            assert_eq!(requests[1].params[2], json!(hex0x(&FAKE_HEAD)));
        }

        #[tokio::test]
        async fn a_call_the_runtime_does_not_have_is_refused_before_anything_is_asked() {
            let chain = FakeChain::new();

            let err = offline_client(&chain)
                .fees()
                .estimate("Staking", "chil", vec![])
                .await
                .unwrap_err();
            assert!(
                matches!(&err, SdkError::Chain { target, .. } if target == "Staking.chil"),
                "{err:?}"
            );
            assert!(chain.exchanges().is_empty());
        }

        #[tokio::test]
        async fn an_account_nobody_funded_reads_as_absent_not_as_an_error() {
            let chain = FakeChain::new();
            let balance = offline_client(&chain)
                .accounts()
                .balance(ALICE)
                .await
                .unwrap();
            assert!(!balance.exists);
            assert_eq!(balance.total, 0);
        }
    }

    #[test]
    fn store_secret_args_are_in_runtime_order() {
        // `store_secret(payload, epoch, label, aad)`; order is positional on the wire.
        let args = StoreSecret::new(
            matter_sdk_core::EncryptedSecret {
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
