//! Cross-boundary value types.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The four-blob envelope an owner publishes on chain for one sealed secret.
///
/// Maps field-for-field onto `pallet_secrets::EncryptedSecret`. Holds no
/// secret material, so deriving `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecret {
    /// Label bound into the AEAD key derivation and the ZKPoPlaintext
    /// transcript. Defaults to 32 random bytes. At most
    /// `MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE` bytes.
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
/// Zeroized on drop. `Debug` prints only the length and there is no
/// `Display`: recovered secrets must never reach a log line. Read the bytes
/// through [`Plaintext::expose`] only at the point of use.
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    /// Wrap recovered bytes.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Plaintext(Zeroizing::new(bytes))
    }

    /// Borrow the bytes. Keep the borrow short and never copy them into an
    /// un-zeroized buffer.
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

/// One node's `/partial-decrypt` result plus its evaluation point and on-chain
/// share commitment. Byte fields are bincode of the `matter-crypto` types.
///
/// There is no λ field: [`crate::open_secret`] derives each Lagrange
/// coefficient from the points, so a caller cannot supply a wrong one.
#[derive(Debug, Clone)]
pub struct PartialInput {
    /// The responding node's 1-based DKG evaluation point (`dkg_index`).
    pub point: u64,
    /// Bincode `PartialDecryption` from the node's response.
    pub partial: Vec<u8>,
    /// Bincode `PartDecProof` from the node's response.
    pub proof: Vec<u8>,
    /// Bincode `FeldmanCommitment` (`g_j`) for the served epoch, read from
    /// **chain**, never from the node's response (the node would vouch for
    /// itself).
    pub commitment: Vec<u8>,
}
