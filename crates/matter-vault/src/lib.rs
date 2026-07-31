//! # matter-vault
//!
//! The Rust SDK for **MatterVault** — seal secrets under the matter-kgc committee
//! and recover them through a signed, threshold `/partial-decrypt` quorum.
//!
//! It wraps the pure [`matter_vault_core`] with the three things the core
//! deliberately leaves out: a committee HTTP [`transport`], the quorum
//! [`decrypt`] orchestration, and request authorization. You choose where your
//! key lives — an [`ApiKey`] the SDK holds under documented guardrails, or a
//! [`KeySigner`]/[`Signer`] you implement over an HSM, KMS, or wallet. [`calls`]
//! builds extrinsic arguments for callers submitting with their own client.
//!
//! ```no_run
//! # async fn demo() -> Result<(), matter_vault::SdkError> {
//! # let (epoch, threshold): (u32, usize) = (0, 3);
//! # let joint_pk: Vec<u8> = vec![];
//! # let shared_a: Vec<u8> = vec![];
//! # let secret_id = 0u128;
//! # let block_hash = [0u8; 32];
//! # let nodes: Vec<matter_vault::CommitteeNode> = vec![];
//! use matter_vault::{decrypt, ApiKey, DecryptRequest, ReqwestTransport};
//! use matter_vault_core::Aad;
//!
//! // 1. Seal (pure, no network) — publish the envelope with your chain client.
//! let env = matter_vault_core::encrypt(&joint_pk, epoch, b"API_KEY=swordfish", Aad::EnvV1.as_bytes(), None)?;
//!
//! // 2. Later, recover it from the committee. An ApiKey is a Signer.
//! let key = ApiKey::parse(&std::env::var("MATTER_API_KEY").unwrap())?;
//! let transport = ReqwestTransport::new();
//! let plaintext = decrypt(&transport, &key, &DecryptRequest {
//!     secret_id, epoch, binding_id: &env.binding_id, aad: Aad::EnvV1.as_bytes(),
//!     capsule: &env.capsule, ct: &env.ct, shared_a: &shared_a,
//!     block_hash, threshold, nodes: &nodes,
//! }).await?;
//! assert_eq!(plaintext.expose(), b"API_KEY=swordfish");
//! # Ok(()) }
//! ```
//!
//! See `SECURITY.md` and `docs/secure-signing.md` for the secure-signing and
//! secret-handling guarantees, including what an [`ApiKey`] does and does not
//! protect against.

mod calls;
#[cfg(feature = "chain")]
pub mod chain;
mod committee;
mod error;
mod signer;
mod transport;

pub use calls::{DeleteSecret, GrantAccess, GrantTarget, RevokeAccess, RotateSecret, StoreSecret};
pub use committee::{decrypt, CommitteeNode, DecryptRequest};
pub use error::{Result, SdkError};
// Re-export the core surface so consumers need only depend on `matter-vault`.
#[doc(inline)]
pub use matter_vault_core::{self, encrypt, Aad, CoreError, EncryptedSecret, Plaintext};
// Likewise the key surface: an ApiKey is a Signer, so callers should not have to
// name a second crate to build one.
#[doc(inline)]
pub use matter_vault_key::{AccountId, ApiKey, KeyError, KeyScheme, KeySigner};
pub use signer::{partial_decrypt_auth, RequestAuth, Signer, SigningRequest, Sr25519Signer};
pub use transport::{Health, ReqwestTransport, Transport};

/// Chain-derived committee state at a secret's stored epoch — everything
/// [`recover_secret`] needs besides the envelope itself. The caller fetches
/// these fields with its own Substrate client.
#[derive(Debug, Clone)]
pub struct CommitteeInfo {
    /// The epoch the secret was sealed under (which this state is for).
    pub epoch: u32,
    /// The committee threshold `t` in force for `epoch`.
    pub threshold: usize,
    /// Bincode `shared_a` for `epoch`, read from chain.
    pub shared_a: Vec<u8>,
    /// The candidate committee nodes (at least `threshold` must be healthy).
    pub nodes: Vec<CommitteeNode>,
    /// A recent finalized block hash (freshness anchor for request signatures).
    pub block_hash: [u8; 32],
}

/// Recover one stored secret in a single call — a thin composition of
/// [`decrypt`] over a fetched [`EncryptedSecret`] and [`CommitteeInfo`]; no new
/// crypto, and errors are exactly [`decrypt`]'s.
///
/// Takes the AAD as a registry [`Aad`] tag (not raw bytes) so an embedded
/// consumer can't drift from the tag the secret was sealed under.
pub async fn recover_secret(
    committee: &CommitteeInfo,
    transport: &impl Transport,
    signer: &impl Signer,
    secret_id: u128,
    secret: &EncryptedSecret,
    aad: Aad,
) -> Result<Plaintext> {
    decrypt(
        transport,
        signer,
        &DecryptRequest {
            secret_id,
            epoch: committee.epoch,
            binding_id: &secret.binding_id,
            aad: aad.as_bytes(),
            capsule: &secret.capsule,
            ct: &secret.ct,
            shared_a: &committee.shared_a,
            block_hash: committee.block_hash,
            threshold: committee.threshold,
            nodes: &committee.nodes,
        },
    )
    .await
}
