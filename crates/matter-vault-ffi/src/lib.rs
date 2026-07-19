//! C ABI over [`matter_vault_core`].
//!
//! A thin, stable C surface so non-Rust runtimes (starting with Go via cgo) can
//! call the one cryptographic core instead of re-implementing it. All
//! cryptography stays in the core; this layer only marshals bytes across the
//! boundary.
//!
//! ## Ownership
//!
//! Every function that returns bytes returns an [`MvBuf`] the Rust side
//! allocated; the caller **must** hand it back to [`mv_free`] (or
//! [`mv_envelope_free`]) exactly once. Input pointers are borrowed for the call
//! only and never freed here.
//!
//! ## Errors
//!
//! Functions that can fail return an `i32`: `0` on success, negative on error
//! (see the `MV_ERR_*` constants). On error, any out-params are left as empty
//! [`MvBuf`]s (`ptr == null`, `len == 0`).

#![allow(clippy::missing_safety_doc)]

use std::slice;

use matter_vault_core as core;

/// Success.
pub const MV_OK: i32 = 0;
/// A pointer argument was null or a fixed-width field had the wrong length.
pub const MV_ERR_INVALID_ARG: i32 = -1;
/// The cryptographic operation failed (see the core's error categories).
pub const MV_ERR_CRYPTO: i32 = -2;

/// An owned byte buffer crossing the C boundary. Free with [`mv_free`].
#[repr(C)]
pub struct MvBuf {
    /// Pointer to the bytes, or null on error / empty.
    pub ptr: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

impl MvBuf {
    /// An empty buffer (used on error paths).
    fn empty() -> Self {
        MvBuf {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

/// Move a `Vec<u8>` into an [`MvBuf`] the caller owns.
fn into_buf(v: Vec<u8>) -> MvBuf {
    let mut boxed = v.into_boxed_slice();
    let buf = MvBuf {
        ptr: boxed.as_mut_ptr(),
        len: boxed.len(),
    };
    std::mem::forget(boxed);
    buf
}

/// Free a buffer returned by this library. Passing a null/empty buffer is a no-op;
/// double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn mv_free(buf: MvBuf) {
    if !buf.ptr.is_null() && buf.len != 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            buf.ptr, buf.len,
        )));
    }
}

/// The four-blob sealed envelope. Free with [`mv_envelope_free`].
#[repr(C)]
pub struct MvEnvelope {
    /// Caller label bound into the seal.
    pub binding_id: MvBuf,
    /// Bincode RLWE capsule.
    pub capsule: MvBuf,
    /// Version-tagged ZKPoPlaintext proof.
    pub proof: MvBuf,
    /// `nonce ‖ ciphertext`.
    pub ct: MvBuf,
}

impl MvEnvelope {
    /// An all-empty envelope, used to honor the "out is empty on error" contract.
    fn empty() -> Self {
        MvEnvelope {
            binding_id: MvBuf::empty(),
            capsule: MvBuf::empty(),
            proof: MvBuf::empty(),
            ct: MvBuf::empty(),
        }
    }
}

/// Free all four buffers of an envelope produced by [`mv_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn mv_envelope_free(env: MvEnvelope) {
    mv_free(env.binding_id);
    mv_free(env.capsule);
    mv_free(env.proof);
    mv_free(env.ct);
}

/// Borrow a `*const u8`/len pair as a slice, or `None` if null.
unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        (len == 0).then_some(&[])
    } else {
        Some(slice::from_raw_parts(ptr, len))
    }
}

/// The canonical request signing payload for
/// `(secret_id, subset, block_hash, recipient_index)`.
///
/// `secret_id` is 16 big-endian bytes; `block_hash` is 32 bytes; `subset` is an
/// array of `subset_len` `u64`s; `recipient_index` is the responding node's
/// 1-based `dkg_index` (the request is signed once per node, MV-C1). Writes the
/// payload bytes to `*out`. Returns [`MV_OK`] or [`MV_ERR_INVALID_ARG`].
#[no_mangle]
pub unsafe extern "C" fn mv_signing_payload(
    secret_id: *const u8,
    subset: *const u64,
    subset_len: usize,
    block_hash: *const u8,
    recipient_index: u64,
    out: *mut MvBuf,
) -> i32 {
    if out.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    *out = MvBuf::empty();
    let (Some(sid), Some(bh)) = (as_slice(secret_id, 16), as_slice(block_hash, 32)) else {
        return MV_ERR_INVALID_ARG;
    };
    if sid.len() != 16 || bh.len() != 32 {
        return MV_ERR_INVALID_ARG;
    }
    let subset = if subset.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(subset, subset_len)
    };
    let sid = u128::from_be_bytes(sid.try_into().unwrap());
    let bh: [u8; 32] = bh.try_into().unwrap();
    *out = into_buf(core::signing_payload(sid, subset, &bh, recipient_index));
    MV_OK
}

/// The bincode Lagrange coefficient for `point` over `subset`. Writes to `*out`.
#[no_mangle]
pub unsafe extern "C" fn mv_lagrange_for(
    point: u64,
    subset: *const u64,
    subset_len: usize,
    out: *mut MvBuf,
) -> i32 {
    if out.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    *out = MvBuf::empty();
    let subset = if subset.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(subset, subset_len)
    };
    match core::lagrange_for(point, subset) {
        Ok(bytes) => {
            *out = into_buf(bytes);
            MV_OK
        }
        Err(_) => MV_ERR_CRYPTO,
    }
}

/// Seal `secrets` under `joint_pk` with associated data `aad`. `binding_id` may
/// be null (a random one is generated). Writes the envelope to `*out`. Returns
/// [`MV_OK`], [`MV_ERR_INVALID_ARG`], or [`MV_ERR_CRYPTO`].
#[no_mangle]
pub unsafe extern "C" fn mv_encrypt(
    joint_pk: *const u8,
    joint_pk_len: usize,
    epoch: u32,
    secrets: *const u8,
    secrets_len: usize,
    aad: *const u8,
    aad_len: usize,
    binding_id: *const u8,
    binding_id_len: usize,
    out: *mut MvEnvelope,
) -> i32 {
    if out.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    // Honor the module contract ("out is empty on every error path") up front, so
    // a conforming C caller that frees the envelope after a non-OK return never
    // frees an uninitialized pointer. Every other entry point clears its out-param
    // here; `mv_encrypt` was the lone exception (audit MV-H1).
    *out = MvEnvelope::empty();
    let (Some(pk), Some(sec), Some(aad)) = (
        as_slice(joint_pk, joint_pk_len),
        as_slice(secrets, secrets_len),
        as_slice(aad, aad_len),
    ) else {
        return MV_ERR_INVALID_ARG;
    };
    let binding = if binding_id.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(binding_id, binding_id_len).to_vec())
    };
    match core::encrypt(pk, epoch, sec, aad, binding) {
        Ok(env) => {
            *out = MvEnvelope {
                binding_id: into_buf(env.binding_id),
                capsule: into_buf(env.capsule),
                proof: into_buf(env.proof),
                ct: into_buf(env.ct),
            };
            MV_OK
        }
        Err(core::CoreError::Empty(_) | core::CoreError::Decode { .. }) => MV_ERR_INVALID_ARG,
        Err(_) => MV_ERR_CRYPTO,
    }
}

/// Verify a capsule's version-tagged plaintext proof up front. Writes `1`/`0` to
/// `*out_valid`. Returns [`MV_OK`], [`MV_ERR_INVALID_ARG`], or [`MV_ERR_CRYPTO`].
#[no_mangle]
pub unsafe extern "C" fn mv_verify_plaintext_proof(
    joint_pk: *const u8,
    joint_pk_len: usize,
    capsule: *const u8,
    capsule_len: usize,
    proof: *const u8,
    proof_len: usize,
    binding_id: *const u8,
    binding_id_len: usize,
    epoch: u32,
    out_valid: *mut u8,
) -> i32 {
    if out_valid.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    *out_valid = 0;
    let (Some(pk), Some(cap), Some(pf), Some(bid)) = (
        as_slice(joint_pk, joint_pk_len),
        as_slice(capsule, capsule_len),
        as_slice(proof, proof_len),
        as_slice(binding_id, binding_id_len),
    ) else {
        return MV_ERR_INVALID_ARG;
    };
    match core::verify_plaintext_proof(pk, cap, pf, bid, epoch) {
        Ok(v) => {
            *out_valid = v as u8;
            MV_OK
        }
        Err(_) => MV_ERR_CRYPTO,
    }
}

/// One collected committee partial as borrowed input buffers (see [`mv_open_secret`]).
#[repr(C)]
pub struct MvPartialInput {
    /// Bincode `PartialDecryption` from the node response.
    pub partial: *const u8,
    /// Length of `partial` in bytes.
    pub partial_len: usize,
    /// Bincode `PartDecProof` from the node response.
    pub proof: *const u8,
    /// Length of `proof` in bytes.
    pub proof_len: usize,
    /// Bincode `FeldmanCommitment` read from chain.
    pub commitment: *const u8,
    /// Length of `commitment` in bytes.
    pub commitment_len: usize,
    /// Bincode Lagrange coefficient for the node over the subset.
    pub lambda: *const u8,
    /// Length of `lambda` in bytes.
    pub lambda_len: usize,
}

/// Verify the collected quorum, aggregate, and AEAD-open the payload.
///
/// `secret_id` is 16 big-endian bytes; `partials` is an array of `partials_len`
/// [`MvPartialInput`]. Writes the recovered plaintext to `*out` (a copy — the
/// caller owns it; treat it as sensitive). Returns [`MV_OK`], [`MV_ERR_INVALID_ARG`],
/// or [`MV_ERR_CRYPTO`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn mv_open_secret(
    shared_a: *const u8,
    shared_a_len: usize,
    capsule: *const u8,
    capsule_len: usize,
    secret_id: *const u8,
    epoch: u32,
    binding_id: *const u8,
    binding_id_len: usize,
    aad: *const u8,
    aad_len: usize,
    ct: *const u8,
    ct_len: usize,
    partials: *const MvPartialInput,
    partials_len: usize,
    out: *mut MvBuf,
) -> i32 {
    if out.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    *out = MvBuf::empty();
    let (Some(sa), Some(cap), Some(sid), Some(bid), Some(aad), Some(ct)) = (
        as_slice(shared_a, shared_a_len),
        as_slice(capsule, capsule_len),
        as_slice(secret_id, 16),
        as_slice(binding_id, binding_id_len),
        as_slice(aad, aad_len),
        as_slice(ct, ct_len),
    ) else {
        return MV_ERR_INVALID_ARG;
    };
    if sid.len() != 16 || (partials.is_null() && partials_len != 0) {
        return MV_ERR_INVALID_ARG;
    }
    let sid = u128::from_be_bytes(sid.try_into().unwrap());
    let raw = if partials_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(partials, partials_len)
    };
    let mut inputs = Vec::with_capacity(raw.len());
    for p in raw {
        let (Some(partial), Some(proof), Some(commitment), Some(lambda)) = (
            as_slice(p.partial, p.partial_len),
            as_slice(p.proof, p.proof_len),
            as_slice(p.commitment, p.commitment_len),
            as_slice(p.lambda, p.lambda_len),
        ) else {
            return MV_ERR_INVALID_ARG;
        };
        inputs.push(core::PartialInput {
            partial: partial.to_vec(),
            proof: proof.to_vec(),
            commitment: commitment.to_vec(),
            lambda: lambda.to_vec(),
        });
    }
    match core::open_secret(sa, cap, sid, epoch, bid, aad, ct, &inputs) {
        Ok(pt) => {
            *out = into_buf(pt.expose().to_vec());
            MV_OK
        }
        Err(_) => MV_ERR_CRYPTO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for audit MV-H1: `mv_encrypt` must overwrite `*out` with empty
    /// buffers on an error path. A malformed `joint_pk` triggers an error; if the
    /// envelope were left as the caller's (here, sentinel) memory, a conforming
    /// consumer's `mv_envelope_free` would be a wild free.
    #[test]
    fn mv_encrypt_clears_out_on_error() {
        fn sentinel() -> MvBuf {
            MvBuf {
                ptr: 0xAB as *mut u8,
                len: 0xABAB,
            }
        }
        let mut env = MvEnvelope {
            binding_id: sentinel(),
            capsule: sentinel(),
            proof: sentinel(),
            ct: sentinel(),
        };
        let bad_pk = [0u8; 4]; // too short to decode as a bincode PublicKey
        let secrets = [1u8, 2, 3];
        let aad = [7u8; 2];
        let rc = unsafe {
            mv_encrypt(
                bad_pk.as_ptr(),
                bad_pk.len(),
                0,
                secrets.as_ptr(),
                secrets.len(),
                aad.as_ptr(),
                aad.len(),
                std::ptr::null(),
                0,
                &mut env,
            )
        };
        assert_eq!(rc, MV_ERR_INVALID_ARG);
        for buf in [&env.binding_id, &env.capsule, &env.proof, &env.ct] {
            assert!(buf.ptr.is_null(), "out buffer must be cleared on error");
            assert_eq!(buf.len, 0, "out buffer len must be zero on error");
        }
    }
}
