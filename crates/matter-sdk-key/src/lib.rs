//! Key ingestion and signing for MatterSDK.
//!
//! Parses an OpenMatter API key (`0x` mini-secret, BIP39 mnemonic, or sr25519
//! SURI) into an [`ApiKey`] that is zeroizing, redacted, and non-serializable,
//! and defines [`KeySigner`], the signing capability the rest of the SDK uses.
//!
//! ```
//! use matter_sdk_key::{ApiKey, KeySigner};
//!
//! // The public substrate dev phrase. Real keys come from `MATTER_API_KEY`.
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
//! # Ok::<(), matter_sdk_key::KeyError>(())
//! ```
//!
//! No networking dependencies, so it builds for `wasm32-unknown-unknown` and
//! every binding shares one key-derivation implementation. Keep it that way.
//!
//! sr25519 only. A `secp256k1:`-prefixed key reports
//! [`KeyError::UnsupportedScheme`], not a parse failure.

mod apikey;
mod error;
mod scheme;
mod scopes;
mod signer;
mod suri;

pub use apikey::ApiKey;
pub use error::{KeyError, Result};
pub use scheme::{AccountId, KeyScheme};
pub use scopes::{Access, Scope, ScopeParseError, ScopeSet};
pub use signer::KeySigner;
