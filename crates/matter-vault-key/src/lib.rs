//! Key ingestion and signing for MatterVault.
//!
//! One place where an OpenMatter API key becomes a signer, shared by every
//! language binding. It parses the three encodings the OpenMatter dashboard
//! mints — a `0x` 32-byte mini-secret, a BIP39 mnemonic, or a full sr25519 SURI
//! — into an [`ApiKey`] that is zeroizing, redacted, and non-serializable, and
//! exposes the one capability the rest of the SDK builds on, [`KeySigner`].
//!
//! ```
//! use matter_vault_key::{ApiKey, KeySigner};
//!
//! // The well-known substrate development phrase, as used by the conformance
//! // vectors. A real key comes from `MATTER_API_KEY`, never from source.
//! let key = ApiKey::parse(
//!     "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
//! )?;
//!
//! assert_eq!(
//!     key.account_id().to_hex(),
//!     "0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a",
//! );
//!
//! // The key itself never renders.
//! assert!(format!("{key:?}").contains("<redacted>"));
//!
//! let signature = key.sign(b"canonical payload bytes")?;
//! assert_eq!(signature.len(), 64);
//! # Ok::<(), matter_vault_key::KeyError>(())
//! ```
//!
//! # Why this is its own crate
//!
//! `bindings/wasm` compiles for `wasm32-unknown-unknown` and therefore cannot
//! depend on `matter-vault` (reqwest and rustls do not build for that target).
//! If key ingestion lived there, TypeScript would have to re-derive keys with
//! `@polkadot/util-crypto` — precisely the cross-language derivation drift that
//! `testvectors/seed_formats.json` exists to police. Keeping this crate free of
//! networking keeps one implementation for all four languages.
//!
//! # Scope
//!
//! sr25519 only today. [`KeyScheme`] is `#[non_exhaustive]` and [`ApiKey`] hides
//! its material behind a private enum, so the Ethereum/EIP-712 path
//! (`pallet-eth-signing`, `pallet-staking-gateway`) can be added without a
//! breaking change. A `secp256k1:`-prefixed key reports
//! [`KeyError::UnsupportedScheme`] rather than a parse failure.

mod apikey;
mod error;
mod scheme;
mod signer;
mod suri;

pub use apikey::ApiKey;
pub use error::{KeyError, Result};
pub use scheme::{AccountId, KeyScheme};
pub use signer::KeySigner;
