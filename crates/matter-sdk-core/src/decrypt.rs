//! Pure committee-decryption steps, each delegating to `matter_crypto::secret`.

use std::collections::BTreeSet;

use bincode::Options;
use matter_crypto::bgv::params::SecureParams;
use matter_crypto::bgv::poly::crt::CrtPoly;
use matter_crypto::bgv::poly::PolyParameters;
use matter_crypto::bgv::{BgvParameters, Ciphertext, PublicKey};
use matter_crypto::feldman::FeldmanCommitment;
use matter_crypto::secret::{self, OpenError, PartialDecryptionEntry, SealedSecrets};
use matter_crypto::threshold::partial_decrypt::PartialDecryption;
use matter_crypto::zkp::partial_decrypt::PartDecProof;
use matter_kgc_config::{
    protocol,
    MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE,
    MAX_ENCRYPTED_SECRET_CAPSULE_SIZE,
    MAX_ENCRYPTED_SECRET_CIPHERTEXT_SIZE,
    MAX_ENCRYPTED_SECRET_PROOF_SIZE,
};

use crate::ctx;
use crate::encrypt::bound;
use crate::error::{CoreError, Result};
use crate::types::{PartialInput, Plaintext};

type Cipher = <SecureParams as BgvParameters>::CiphertextParams;
type LambdaScalar = <Cipher as PolyParameters>::Residue;
/// Owned `(partial, proof, commitment, λ)` that [`PartialDecryptionEntry`]
/// borrows.
type DecodedPartial = (
    PartialDecryption<SecureParams>,
    PartDecProof<SecureParams>,
    FeldmanCommitment<SecureParams>,
    LambdaScalar,
);

/// Decode ceiling for inputs with no on-chain bound (`joint_pk`, `shared_a`,
/// partials, their proofs, share commitments). Refuses absurd input before
/// bincode sees it; an order of magnitude above a measured response.
const MAX_DECODE_BYTES: usize = 16 << 20;

/// Decode one bincode field into `T`, attributing any error to `field`.
///
/// Fixed-int encoding with **no trailing bytes**, so each value has exactly one
/// accepted encoding. `max` is checked before decoding.
fn de<T: serde::de::DeserializeOwned>(field: &'static str, bytes: &[u8], max: usize) -> Result<T> {
    bound(field, bytes.len(), max)?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| CoreError::Decode {
            field,
            detail: e.to_string(),
        })
}

/// Decode a version-tagged blob: check the tag, then decode the body with
/// [`de`]'s strictness.
fn de_tagged<T: serde::de::DeserializeOwned>(
    field: &'static str,
    bytes: &[u8],
    max: usize,
) -> Result<T> {
    bound(field, bytes.len(), max)?;
    let body = protocol::untag(bytes).map_err(|e| CoreError::Decode {
        field,
        detail: format!("{e:?}"),
    })?;
    de(field, body, max)
}

/// The evaluation points of `partials`: non-empty, non-zero, distinct.
///
/// Points are `u64` and `q` is far larger, so integer checks equal checks
/// modulo `q`.
fn subset_points(partials: &[PartialInput]) -> Result<Vec<u64>> {
    if partials.is_empty() {
        return Err(CoreError::InvalidSubset("no partials supplied".into()));
    }
    let points: Vec<u64> = partials.iter().map(|p| p.point).collect();
    if points.contains(&0) {
        return Err(CoreError::InvalidSubset(
            "point 0 is not an evaluation point".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    if let Some(dup) = points.iter().find(|&&p| !seen.insert(p)) {
        return Err(CoreError::InvalidSubset(format!(
            "point {dup} appears twice"
        )));
    }
    Ok(points)
}

/// The canonical bytes a requester signs for a `/partial-decrypt` request,
/// binding `(secret_id, subset, block_hash, recipient_index)`.
///
/// `recipient_index` is the responding node's 1-based `dkg_index`. Sign once per
/// node so a signature cannot be replayed to another node in the subset.
pub fn signing_payload(
    secret_id: u128,
    subset: &[u64],
    block_hash: &[u8; 32],
    recipient_index: u64,
) -> Vec<u8> {
    matter_kgc_proto::partial_decrypt_signing_payload(
        secret_id,
        subset,
        block_hash,
        recipient_index,
    )
}

/// The bincode Lagrange coefficient `λ` for `point` over `subset`: the
/// request's `lagrange_coeff` field.
pub fn lagrange_for(point: u64, subset: &[u64]) -> Result<Vec<u8>> {
    let lambda = secret::lagrange_coefficient::<SecureParams>(point, subset);
    bincode::serialize(&lambda).map_err(|e| CoreError::Decode {
        field: "lambda",
        detail: e.to_string(),
    })
}

/// Verify a capsule's ZKPoPlaintext proof under `joint_pk`, bound to
/// `binding_id` + `epoch`.
///
/// Subset-independent: run once before contacting any node. `false` usually
/// means the capsule was proved under a different KGC epoch. `tagged_proof` is
/// the version-tagged on-chain proof blob.
pub fn verify_plaintext_proof(
    joint_pk: &[u8],
    capsule: &[u8],
    tagged_proof: &[u8],
    binding_id: &[u8],
    epoch: u32,
) -> Result<bool> {
    bound(
        "binding_id",
        binding_id.len(),
        MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE,
    )?;
    let pk: PublicKey<SecureParams> = de("joint_pk", joint_pk, MAX_DECODE_BYTES)?;
    let capsule: Ciphertext<SecureParams> =
        de("capsule", capsule, MAX_ENCRYPTED_SECRET_CAPSULE_SIZE)?;
    let proof = de_tagged("proof", tagged_proof, MAX_ENCRYPTED_SECRET_PROOF_SIZE)?;
    Ok(secret::verify_secret_proof::<SecureParams>(
        ctx::ensure(),
        &pk,
        &capsule,
        &proof,
        binding_id,
        epoch as u64,
    ))
}

/// Verify the collected quorum's ZKPoPartDec proofs, aggregate to recover the
/// key seed, and AEAD-open the payload.
///
/// * **pre:** `partials` is a `t`-subset, each with its node's point and its
///   share commitment read from chain; `shared_a` and the capsule belong to the
///   served epoch; `aad`/`epoch` match the seal.
/// * **enforced:** points non-empty, non-zero, distinct
///   ([`CoreError::InvalidSubset`], before any decoding); inputs within size
///   bounds ([`CoreError::TooLarge`]) and without trailing bytes
///   ([`CoreError::Decode`]). λ is derived from the points.
/// * **errors:** [`CoreError::Aggregate`] (retry another subset) vs
///   [`CoreError::Aead`] (terminal).
///
/// `ct` is `nonce(12) ‖ ciphertext`. The order of `partials` does not matter.
#[allow(clippy::too_many_arguments)]
pub fn open_secret(
    shared_a: &[u8],
    capsule: &[u8],
    secret_id: u128,
    epoch: u32,
    binding_id: &[u8],
    aad: &[u8],
    ct: &[u8],
    partials: &[PartialInput],
) -> Result<Plaintext> {
    let points = subset_points(partials)?;
    bound(
        "binding_id",
        binding_id.len(),
        MAX_ENCRYPTED_SECRET_BINDING_ID_SIZE,
    )?;
    bound("ct", ct.len(), MAX_ENCRYPTED_SECRET_CIPHERTEXT_SIZE)?;

    let shared_a: CrtPoly<Cipher> = de("shared_a", shared_a, MAX_DECODE_BYTES)?;
    let capsule: Ciphertext<SecureParams> =
        de("capsule", capsule, MAX_ENCRYPTED_SECRET_CAPSULE_SIZE)?;

    if ct.len() < 12 {
        return Err(CoreError::InvalidLength {
            field: "ct (nonce prefix)",
            expected: 12,
            actual: ct.len(),
        });
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&ct[..12]);
    let sealed = SealedSecrets {
        ciphertext: ct[12..].to_vec(),
        nonce,
    };

    let decoded: Vec<DecodedPartial> = partials
        .iter()
        .map(|p| {
            Ok((
                de("partial", &p.partial, MAX_DECODE_BYTES)?,
                de("partial proof", &p.proof, MAX_DECODE_BYTES)?,
                de("commitment", &p.commitment, MAX_DECODE_BYTES)?,
                secret::lagrange_coefficient::<SecureParams>(p.point, &points),
            ))
        })
        .collect::<Result<_>>()?;

    let entries: Vec<PartialDecryptionEntry<SecureParams>> = decoded
        .iter()
        .map(
            |(partial, proof, commitment, lambda)| PartialDecryptionEntry {
                partial,
                proof,
                commitment,
                lambda: *lambda,
            },
        )
        .collect();

    secret::verify_aggregate_open::<SecureParams>(
        ctx::ensure(),
        &entries,
        &capsule,
        &shared_a,
        &secret_id.to_be_bytes(),
        epoch as u64,
        binding_id,
        aad,
        &sealed,
    )
    .map(Plaintext::new)
    .map_err(|e| match e {
        OpenError::Aggregate(a) => CoreError::Aggregate(format!("{a:?}")),
        OpenError::Aead => CoreError::Aead,
    })
}
