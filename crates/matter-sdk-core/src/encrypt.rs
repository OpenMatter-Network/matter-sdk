//! Sealing a secret under the committee joint public key.

use matter_crypto::bgv::params::SecureParams;
use matter_crypto::bgv::PublicKey;
use matter_kgc_config::{
    MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE,
    MAX_ENCRYPTED_SECRET_CAPSULE_SIZE,
    MAX_ENCRYPTED_SECRET_CIPHERTEXT_SIZE,
    MAX_ENCRYPTED_SECRET_PROOF_SIZE,
};
use rand::RngCore;

use crate::ctx;
use crate::error::{CoreError, Result};
use crate::types::EncryptedSecret;

/// Default random binding-id length when the caller doesn't supply one.
const DEFAULT_BINDING_ID_LEN: usize = 32;

/// Seal `plaintext` under the committee joint public key `joint_pk`.
///
/// Contract:
/// * **pre:** `plaintext` non-empty; `joint_pk` is a bincode
///   `PublicKey<SecureParams>` (as returned by the chain's `KgcApi::joint_pk()`);
///   `binding_id`, if supplied, is at most
///   `MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE` bytes.
/// * **post:** returns an [`EncryptedSecret`] whose four fields each fit their
///   on-chain `BoundedVec` bound, ready to publish.
/// * the AEAD seal binds `aad` + `epoch`; the same `aad` and `epoch` must be
///   presented at open time, so callers should pass a registry tag
///   ([`crate::Aad`]) rather than an ad-hoc literal.
///
/// `μ` (the ephemeral key seed) is sampled and zeroized inside
/// `matter_crypto::secret::seal_secret`; this function never sees it.
pub fn encrypt(
    joint_pk: &[u8],
    epoch: u32,
    plaintext: &[u8],
    aad: &[u8],
    binding_id: Option<Vec<u8>>,
) -> Result<EncryptedSecret> {
    if plaintext.is_empty() {
        return Err(CoreError::Empty("plaintext"));
    }

    let pk: PublicKey<SecureParams> =
        bincode::deserialize(joint_pk).map_err(|e| CoreError::Decode {
            field: "joint_pk",
            detail: e.to_string(),
        })?;

    let binding_id = binding_id.unwrap_or_else(|| {
        let mut b = vec![0u8; DEFAULT_BINDING_ID_LEN];
        rand::thread_rng().fill_bytes(&mut b);
        b
    });
    bound(
        "binding_id",
        binding_id.len(),
        MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE,
    )?;

    // Seal via the shared `matter_crypto::secret` path so this SDK, the committee
    // node, and the provider all agree on capsule + proof + AEAD construction.
    let (capsule, pt_proof, sealed) = matter_crypto::secret::seal_secret::<SecureParams>(
        ctx::ensure(),
        &pk,
        &binding_id,
        aad,
        epoch as u64,
        plaintext,
    );

    let mut ct = Vec::with_capacity(12 + sealed.ciphertext.len());
    ct.extend_from_slice(&sealed.nonce);
    ct.extend_from_slice(&sealed.ciphertext);

    let capsule = bincode::serialize(&capsule).map_err(|e| CoreError::Decode {
        field: "capsule",
        detail: e.to_string(),
    })?;
    // Version-tag the proof so a committee node built against a different
    // transcript rejects it loudly rather than failing the check with an
    // indistinguishable `false`.
    let proof =
        matter_kgc_config::wire::encode_tagged(&pt_proof).map_err(|e| CoreError::Decode {
            field: "proof",
            detail: format!("{e:?}"),
        })?;

    bound("capsule", capsule.len(), MAX_ENCRYPTED_SECRET_CAPSULE_SIZE)?;
    bound("proof", proof.len(), MAX_ENCRYPTED_SECRET_PROOF_SIZE)?;
    bound("ct", ct.len(), MAX_ENCRYPTED_SECRET_CIPHERTEXT_SIZE)?;

    Ok(EncryptedSecret {
        binding_id,
        capsule,
        proof,
        ct,
    })
}

/// Reject a field that exceeds its on-chain `BoundedVec` bound.
fn bound(field: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(CoreError::TooLarge { field, max, actual });
    }
    Ok(())
}
