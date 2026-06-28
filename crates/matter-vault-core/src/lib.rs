//! # matter-vault-core
//!
//! The pure, non-networked cryptographic core of **MatterVault** — the single
//! source of cryptographic truth shared by every MatterSDK language binding
//! (Rust, wasm/TypeScript, Python, Go).
//!
//! It does exactly two things, and nothing else:
//!
//! * **Seal** a secret under the matter-kgc committee's joint public key
//!   ([`encrypt`]) into the four-blob [`EncryptedSecret`] envelope an owner
//!   publishes on chain.
//! * **Open** a secret from an *already-collected* committee quorum
//!   ([`open_secret`]), with the supporting steps a decryptor needs along the
//!   way: the request [`signing_payload`], the per-node [`lagrange_for`]
//!   coefficient, and the up-front [`verify_plaintext_proof`] check.
//!
//! Everything cryptographic delegates to `matter-crypto`; the wire types come
//! from `matter-kgc-proto`. This crate never re-implements either.
//!
//! ## What lives *above* this crate
//!
//! Networking (the `/health` + `/partial-decrypt` HTTP calls), quorum selection,
//! retry/backoff, and request *signing* are deliberately **not** here — they are
//! idiomatic per language and live in the SDK shell (`matter-vault` for Rust, the
//! TypeScript package, …). Keeping them out keeps this core auditable and lets it
//! compile unchanged to native, wasm, and a C ABI. See the crate `wire` module
//! for the shared request/response contract those shells serialize.
//!
//! ## Secret hygiene
//!
//! Recovered plaintext is returned as a [`Plaintext`], a zeroizing buffer that
//! refuses to print its contents. Seal inputs you control should likewise be
//! wiped after use. The library never logs secret material.

mod aad;
mod ctx;
mod decrypt;
mod encrypt;
mod error;
mod types;

pub mod wire;

pub use aad::Aad;
pub use decrypt::{lagrange_for, open_secret, signing_payload, verify_plaintext_proof};
pub use encrypt::encrypt;
pub use error::{CoreError, Result};
pub use types::{EncryptedSecret, PartialInput, Plaintext};
