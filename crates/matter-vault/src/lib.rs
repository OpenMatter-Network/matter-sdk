//! # matter-vault
//!
//! The Rust SDK for **MatterVault** — seal secrets under the matter-kgc committee
//! and recover them through a signed, threshold `/partial-decrypt` quorum.
//!
//! It wraps the pure [`matter_vault_core`] with the three things the core
//! deliberately leaves out: a committee HTTP [`transport`], the quorum
//! [`decrypt`] orchestration, and a bring-your-own [`Signer`] so your key never
//! enters the library. On-chain submission stays with you — [`calls`] builds the
//! arguments for your own Substrate client.
//!
//! ```no_run
//! # async fn demo() -> Result<(), matter_vault::SdkError> {
//! # let (epoch, threshold): (u32, usize) = (0, 3);
//! # let joint_pk: Vec<u8> = vec![];
//! # let shared_a: Vec<u8> = vec![];
//! # let seed = [0u8; 32];
//! # let secret_id = 0u128;
//! # let block_hash = [0u8; 32];
//! # let nodes: Vec<matter_vault::CommitteeNode> = vec![];
//! use matter_vault::{decrypt, DecryptRequest, ReqwestTransport, Sr25519Signer};
//! use matter_vault_core::Aad;
//!
//! // 1. Seal (pure, no network) — publish the envelope with your chain client.
//! let env = matter_vault_core::encrypt(&joint_pk, epoch, b"API_KEY=swordfish", Aad::EnvV1.as_bytes(), None)?;
//!
//! // 2. Later, recover it from the committee.
//! let transport = ReqwestTransport::new();
//! let signer = Sr25519Signer::from_seed_insecure_dev_only(&seed)?; // dev only!
//! let plaintext = decrypt(&transport, &signer, &DecryptRequest {
//!     secret_id, epoch, binding_id: &env.binding_id, aad: Aad::EnvV1.as_bytes(),
//!     capsule: &env.capsule, ct: &env.ct, shared_a: &shared_a,
//!     block_hash, threshold, nodes: &nodes,
//! }).await?;
//! assert_eq!(plaintext.expose(), b"API_KEY=swordfish");
//! # Ok(()) }
//! ```
//!
//! See `SECURITY.md` and `docs/secure-signing.md` for the secure-signing and
//! secret-handling guarantees.

mod calls;
mod committee;
mod error;
mod signer;
mod transport;

pub use calls::{GrantAccess, RotateSecret, StoreSecret};
pub use committee::{decrypt, CommitteeNode, DecryptRequest};
pub use error::{Result, SdkError};
// Re-export the core surface so consumers need only depend on `matter-vault`.
#[doc(inline)]
pub use matter_vault_core::{self, encrypt, Aad, CoreError, EncryptedSecret, Plaintext};
pub use signer::{RequestAuth, Signer, SigningRequest, Sr25519Signer};
pub use transport::{Health, ReqwestTransport, Transport};
