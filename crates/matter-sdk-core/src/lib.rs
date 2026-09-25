//! Pure, non-networked cryptographic core shared by every MatterSDK binding
//! (Rust, wasm/TypeScript, Python, Go, C).
//!
//! * **Seal** a secret under the committee joint public key: [`encrypt`].
//! * **Open** it from an already-collected quorum: [`open_secret`], with
//!   [`signing_payload`], [`lagrange_for`] and [`verify_plaintext_proof`].
//!
//! Crypto delegates to `matter-crypto`; wire types come from `matter-kgc-proto`
//! (see [`wire`]). Networking, quorum selection, retry, and request signing
//! live in each language's SDK shell, so this crate compiles unchanged to
//! native, wasm, and a C ABI.
//!
//! ## Secret hygiene
//!
//! Recovered plaintext is a [`Plaintext`]: zeroized on drop and never printed.
//! Wipe seal inputs you control after use. The library never logs secret
//! material.

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

/// Crypto protocol version this core speaks, as reported in a node's `/health`.
/// Shells drop nodes reporting a different non-zero version: their partials
/// cannot be aggregated.
pub const CRYPTO_PROTOCOL_VERSION: u16 = matter_kgc_config::protocol::CRYPTO_PROTOCOL_VERSION;

/// Cap on a committee node's response body, enforced by every binding's
/// transport so a hostile node cannot exhaust client memory with an unbounded
/// read.
///
/// Transports check it as chunks arrive rather than pre-allocating. A single
/// bad node can still make a client buffer up to this many bytes.
pub const MAX_COMMITTEE_RESPONSE_BYTES: usize = 1 << 30; // 1 GiB

/// Size of a real `/partial-decrypt` response, measured on testnet.
const OBSERVED_PARTIAL_BYTES: usize = 1_180_574;

// Compile-time, not a test: a cap below a real response is an outage.
const _: () = assert!(
    MAX_COMMITTEE_RESPONSE_BYTES > OBSERVED_PARTIAL_BYTES,
    "MAX_COMMITTEE_RESPONSE_BYTES rejects a real partial-decrypt response"
);
// Headroom: proof size grows with the subset and BGV parameters.
const _: () = assert!(
    MAX_COMMITTEE_RESPONSE_BYTES >= OBSERVED_PARTIAL_BYTES * 8,
    "MAX_COMMITTEE_RESPONSE_BYTES leaves under 8x headroom over a measured response"
);
