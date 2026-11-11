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

use crate::binding::{binding_id_for, OWNER_BINDING_SALT_BYTES};
use crate::ctx;
use crate::error::{CoreError, Result};
use crate::types::EncryptedSecret;

const DEFAULT_BINDING_ID_LEN: usize = 32;

/// Seal `plaintext` for the account that will own the secret on chain.
///
/// The envelope's binding id is an owner-bound binding id
/// ([`crate::binding_id_for`]) under a fresh random salt, so the chain accepts
/// it only as a secret of `owner`. **Prefer this over [`encrypt`]** for
/// anything you will store.
///
/// * **pre:** `owner` is the 32-byte account id the store is dispatched as —
///   for a proxied store, the account acted for, not the key that signs. The
///   rest as [`encrypt`].
/// * **post:** `binding_commits_to(owner, &envelope.binding_id)`.
pub fn seal_for(
    owner: &[u8],
    joint_pk: &[u8],
    epoch: u32,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedSecret> {
    let mut salt = [0u8; OWNER_BINDING_SALT_BYTES];
    rand::thread_rng().fill_bytes(&mut salt);
    let binding_id = binding_id_for(owner, &salt)?;
    encrypt(joint_pk, epoch, plaintext, aad, Some(binding_id.to_vec()))
}

/// Seal `plaintext` under the committee joint public key `joint_pk`, under a
/// binding id you choose. For a secret you will store, use [`seal_for`]: the
/// default here is a random label that commits to no owner.
///
/// * **pre:** `plaintext` non-empty; `joint_pk` is a bincode
///   `PublicKey<SecureParams>` (from `KgcApi::joint_pk()`); `binding_id`, if
///   given, is 1 to `MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE` bytes, else 32
///   random bytes.
/// * **post:** every field fits its on-chain `BoundedVec` bound.
/// * The seal binds `aad` + `epoch`; open must present the same values (use
///   [`crate::Aad`]).
///
/// The key seed `μ` is sampled and zeroized inside `matter_crypto`; this
/// function never sees it.
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

    // An explicit id that is empty binds nothing: a mistake, never a choice.
    if binding_id.as_deref().is_some_and(<[u8]>::is_empty) {
        return Err(CoreError::Empty("binding_id"));
    }
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
    // Version-tagged so a node with a different transcript rejects it loudly
    // instead of returning an indistinguishable `false`.
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
pub(crate) fn bound(field: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(CoreError::TooLarge { field, max, actual });
    }
    Ok(())
}
