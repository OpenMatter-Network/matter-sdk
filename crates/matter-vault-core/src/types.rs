//! Cross-boundary value types.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The four-blob envelope an owner publishes on chain for one sealed secret.
///
/// Maps field-for-field onto the on-chain `pallet_secrets::EncryptedSecret`.
/// Every field is *ciphertext or public commitment* — there is no secret
/// material here — so deriving `Debug` is safe (cf. [`Plaintext`], which is
/// deliberately opaque).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecret {
    /// Caller label bound into both the AEAD key derivation and the
    /// ZKPoPlaintext transcript. Defaults to 32 random bytes when the caller
    /// doesn't supply one. At most `MAX_BINDING_ID` bytes.
    pub binding_id: Vec<u8>,
    /// Bincode-serialized RLWE capsule (the encrypted key seed `μ`).
    pub capsule: Vec<u8>,
    /// Version-tagged ZKPoPlaintext proof that `capsule` is well-formed.
    pub proof: Vec<u8>,
    /// `nonce(12) ‖ AES-256-GCM(ciphertext ‖ tag)` of the payload.
    pub ct: Vec<u8>,
}

/// A recovered secret payload.
///
/// Wraps the plaintext in [`Zeroizing`] so the buffer is wiped when dropped, and
/// deliberately does **not** implement a `Debug`/`Display` that reveals its
/// contents — recovered secrets must never reach a log line. Read the bytes
/// through [`Plaintext::expose`] only at the point of use.
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    /// Wrap recovered bytes.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Plaintext(Zeroizing::new(bytes))
    }

    /// Borrow the underlying bytes. Keep the borrow's lifetime as short as
    /// possible and never copy the bytes into an un-zeroized buffer.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length of the recovered payload in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the recovered payload is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for Plaintext {
    /// Redacts the contents; prints only the length.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Plaintext(<redacted {} bytes>)", self.0.len())
    }
}

/// One collected committee partial decryption, as a caller hands it back from a
/// `/partial-decrypt` response together with the node's on-chain share
/// commitment and the Lagrange coefficient for the chosen subset.
///
/// Every field is the bincode bytes of the corresponding `matter-crypto` type;
/// the core decodes them in [`crate::open_secret`].
#[derive(Debug, Clone)]
pub struct PartialInput {
    /// Bincode `PartialDecryption` from the node's response.
    pub partial: Vec<u8>,
    /// Bincode `PartDecProof` from the node's response.
    pub proof: Vec<u8>,
    /// Bincode `FeldmanCommitment` (`g_j`) read from chain for the served epoch.
    pub commitment: Vec<u8>,
    /// Bincode Lagrange coefficient `λ` from [`crate::lagrange_for`].
    pub lambda: Vec<u8>,
}
