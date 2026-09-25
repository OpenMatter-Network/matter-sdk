//! # matter-sdk
//!
//! Rust SDK for MatterChain and OpenMatter Secrets: seal a secret under the
//! matter-kgc committee and recover it through a signed, threshold
//! `/partial-decrypt` quorum. The `chain` feature adds a client for every pallet.
//!
//! Adds to the pure [`matter_sdk_core`] a committee HTTP [`Transport`], quorum
//! [`decrypt`], and request authorization via an [`ApiKey`] or your own
//! [`KeySigner`]/[`Signer`] (HSM, KMS, wallet). [`StoreSecret`] and siblings
//! build extrinsic arguments for callers submitting with their own client.
//!
//! ```no_run
//! # async fn demo() -> Result<(), matter_sdk::SdkError> {
//! # let (epoch, threshold): (u32, usize) = (0, 3);
//! # let joint_pk: Vec<u8> = vec![];
//! # let shared_a: Vec<u8> = vec![];
//! # let secret_id = 0u128;
//! # let block_hash = [0u8; 32];
//! # let nodes: Vec<matter_sdk::CommitteeNode> = vec![];
//! use matter_sdk::{decrypt, ApiKey, DecryptRequest, ReqwestTransport};
//! use matter_sdk_core::Aad;
//!
//! // 1. Seal (pure, no network) — publish the envelope with your chain client.
//! let env = matter_sdk_core::encrypt(&joint_pk, epoch, b"API_KEY=swordfish", Aad::EnvV1.as_bytes(), None)?;
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
//! Security model: `SECURITY.md` and `docs/secure-signing.md`.

mod calls;
#[cfg(feature = "chain")]
pub mod chain;
mod committee;
mod error;
mod signer;
mod transport;

pub use calls::{DeleteSecret, GrantAccess, GrantTarget, RevokeAccess, RotateSecret, StoreSecret};
pub use committee::{decrypt, CommitteeNode, DecryptRequest};
pub use error::{FaultStage, NodeFault, Result, SdkError};
// Re-exported so consumers depend only on `matter-sdk`.
#[doc(inline)]
pub use matter_sdk_core::{self, encrypt, Aad, CoreError, EncryptedSecret, Plaintext};
#[doc(inline)]
pub use matter_sdk_key::{
    Access,
    AccountId,
    ApiKey,
    KeyError,
    KeyScheme,
    KeySigner,
    Scope,
    ScopeParseError,
    ScopeSet,
};
pub use signer::{partial_decrypt_auth, RequestAuth, Signer, SigningRequest, Sr25519Signer};
pub use transport::{Health, ReqwestTransport, Transport};

/// Chain-derived committee state at a secret's stored epoch, as input to
/// [`recover_secret`]. The caller fetches it with its own Substrate client.
#[derive(Debug, Clone)]
pub struct CommitteeInfo {
    /// The epoch the secret was sealed under.
    pub epoch: u32,
    /// The committee threshold `t` for `epoch`.
    pub threshold: usize,
    /// Bincode `shared_a` for `epoch`.
    pub shared_a: Vec<u8>,
    /// Candidate nodes; at least `threshold` must be healthy.
    pub nodes: Vec<CommitteeNode>,
    /// A recent finalized block hash; the freshness anchor for request signatures.
    pub block_hash: [u8; 32],
}

/// Recover one stored secret: [`decrypt`] over a fetched [`EncryptedSecret`] and
/// [`CommitteeInfo`]. Errors are exactly [`decrypt`]'s.
///
/// Takes a registry [`Aad`] tag rather than raw bytes so the caller cannot
/// drift from the tag the secret was sealed under.
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
