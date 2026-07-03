//! The pure committee-decryption steps.
//!
//! Networking, the quorum retry loop, and request signing live in the per-language
//! SDK shell above this crate; here we expose only the steps that must not drift
//! between the browser, the committee, and the provider, each delegating to
//! `matter_crypto::secret`:
//!
//!   1. [`signing_payload`] — the exact bytes a requester signs per request.
//!   2. [`lagrange_for`]    — the Lagrange coefficient for a node over a subset.
//!   3. [`verify_plaintext_proof`] — the subset-independent ZKPoPlaintext check.
//!   4. [`open_secret`]     — verify the collected partials, aggregate, AEAD-open.

use matter_crypto::bgv::params::SecureParams;
use matter_crypto::bgv::poly::crt::CrtPoly;
use matter_crypto::bgv::poly::PolyParameters;
use matter_crypto::bgv::{BgvParameters, Ciphertext, PublicKey};
use matter_crypto::feldman::FeldmanCommitment;
use matter_crypto::secret::{self, OpenError, PartialDecryptionEntry, SealedSecrets};
use matter_crypto::threshold::partial_decrypt::PartialDecryption;
use matter_crypto::zkp::partial_decrypt::PartDecProof;

use crate::ctx;
use crate::error::{CoreError, Result};
use crate::types::{PartialInput, Plaintext};

/// Ciphertext-side BGV parameters.
type Cipher = <SecureParams as BgvParameters>::CiphertextParams;
/// Lagrange-coefficient scalar in `Z_q`.
type LambdaScalar = <Cipher as PolyParameters>::Residue;
/// One decoded partial: `(partial, proof, commitment, λ)`, owned so the
/// borrowing [`PartialDecryptionEntry`] can reference it.
type DecodedPartial = (
    PartialDecryption<SecureParams>,
    PartDecProof<SecureParams>,
    FeldmanCommitment<SecureParams>,
    LambdaScalar,
);

/// Decode a bincode field into `T`, attributing the error to `field`.
fn de<T: serde::de::DeserializeOwned>(field: &'static str, bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).map_err(|e| CoreError::Decode {
        field,
        detail: e.to_string(),
    })
}

/// The canonical bytes a requester signs for a `/partial-decrypt` request,
/// binding `(secret_id, subset, block_hash, recipient_index)`. A thin typed
/// wrapper over the shared `matter-kgc-proto` helper so the SDK and the committee
/// node sign and verify the identical payload.
///
/// `recipient_index` is the responding node's 1-based `dkg_index`: the requester
/// signs once per node with that node's index, so a signature can't be replayed
/// to a different node in the subset (MV-C1).
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

/// The bincode-encoded Lagrange coefficient `λ` for `point` over `subset` — the
/// `lagrange_coeff` field of the request, reused when aggregating that node's
/// partial.
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
/// Subset-independent, so a decryptor can run it once up front before contacting
/// any committee node. A `false` result usually means epoch drift (the capsule
/// was proved under a different KGC epoch). `tagged_proof` is the version-tagged
/// on-chain proof blob.
pub fn verify_plaintext_proof(
    joint_pk: &[u8],
    capsule: &[u8],
    tagged_proof: &[u8],
    binding_id: &[u8],
    epoch: u32,
) -> Result<bool> {
    let pk: PublicKey<SecureParams> = de("joint_pk", joint_pk)?;
    let capsule: Ciphertext<SecureParams> = de("capsule", capsule)?;
    let proof =
        matter_kgc_config::wire::decode_tagged(tagged_proof).map_err(|e| CoreError::Decode {
            field: "proof",
            detail: format!("{e:?}"),
        })?;
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
/// Contract:
/// * **pre:** `partials` is an internally-consistent subset of at least `t`
///   proven partials, each carrying the Lagrange `λ` for the *same* subset;
///   `shared_a` and the capsule belong to the secret's *served* epoch (the
///   committee returns these in the response after a rotation); `aad`/`epoch`
///   match what the secret was sealed under.
/// * **post:** returns the recovered [`Plaintext`] (a zeroizing buffer).
/// * **errors:** [`CoreError::Aggregate`] (retry a different subset) vs
///   [`CoreError::Aead`] (terminal — wrong key/epoch/aad, no subset can help).
///
/// `ct` is the on-chain `nonce(12) ‖ ciphertext`.
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
    let shared_a: CrtPoly<Cipher> = de("shared_a", shared_a)?;
    let capsule: Ciphertext<SecureParams> = de("capsule", capsule)?;

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

    // Decode into owned values first; `PartialDecryptionEntry` borrows them.
    let decoded: Vec<DecodedPartial> = partials
        .iter()
        .map(|p| {
            Ok((
                de("partial", &p.partial)?,
                de("proof", &p.proof)?,
                de("commitment", &p.commitment)?,
                de("lambda", &p.lambda)?,
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
