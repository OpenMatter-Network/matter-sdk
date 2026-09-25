//! C ABI over [`matter_sdk_core`]. All cryptography stays in the core; this layer
//! only marshals bytes.
//!
//! ## Ownership
//!
//! Every returned [`MsdkBuf`] **must** be released exactly once with [`msdk_free`]
//! (or [`msdk_envelope_free`]), which wipes the bytes first. Inputs are borrowed
//! for the call only.
//!
//! ## Pointer arguments
//!
//! Inputs are `(pointer, length)` pairs. Null means empty only with a zero length;
//! null with a non-zero length is [`MSDK_ERR_INVALID_ARG`].
//!
//! ## Errors
//!
//! Fallible functions return `0` or a negative `MSDK_ERR_*` code. On error,
//! out-params are left empty (`ptr == null`, `len == 0`). No panic unwinds into the
//! caller: every entry point runs under `guard` and a panic becomes
//! [`MSDK_ERR_INTERNAL`].

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use matter_sdk_core as core;
use zeroize::Zeroize;

mod apikey;

pub use apikey::{
    msdk_apikey_account_id,
    msdk_apikey_free,
    msdk_apikey_parse,
    msdk_apikey_scheme,
    msdk_apikey_sign,
    MsdkApiKey,
    MSDK_ERR_KEY,
};

/// Success.
pub const MSDK_OK: i32 = 0;
/// A required pointer was null, a `(pointer, length)` pair was null with a non-zero
/// length, or a fixed-width field had the wrong length.
pub const MSDK_ERR_INVALID_ARG: i32 = -1;
/// The cryptographic operation failed.
pub const MSDK_ERR_CRYPTO: i32 = -2;
/// A panic was caught at the boundary (a library bug); retrying will not help.
pub const MSDK_ERR_INTERNAL: i32 = -4;

/// Run an entry point's body, turning a panic into [`MSDK_ERR_INTERNAL`].
///
/// Unwinding across the C boundary is undefined behaviour. `AssertUnwindSafe` is
/// sound: on a panic the caller sees only the error code.
pub(crate) fn guard(body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(MSDK_ERR_INTERNAL)
}

/// [`guard`] for entry points with no return code (the `free` functions).
pub(crate) fn guard_void(body: impl FnOnce()) {
    // A free that panicked has at worst leaked.
    let _ = catch_unwind(AssertUnwindSafe(body));
}

/// An owned byte buffer crossing the C boundary. Free with [`msdk_free`].
#[repr(C)]
pub struct MsdkBuf {
    /// Pointer to the bytes, or null on error / empty.
    pub ptr: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

impl MsdkBuf {
    /// An empty buffer (used on error paths).
    pub(crate) fn empty() -> Self {
        MsdkBuf {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

/// Move a `Vec<u8>` into an [`MsdkBuf`] the caller owns.
pub(crate) fn into_buf(v: Vec<u8>) -> MsdkBuf {
    let mut boxed = v.into_boxed_slice();
    let buf = MsdkBuf {
        ptr: boxed.as_mut_ptr(),
        len: boxed.len(),
    };
    std::mem::forget(boxed);
    buf
}

/// Zero a buffer's bytes in place, with writes the optimiser may not elide.
///
/// # Safety
///
/// `buf` must be null/empty or a live buffer returned by this library.
unsafe fn wipe(buf: &MsdkBuf) {
    if !buf.ptr.is_null() && buf.len != 0 {
        slice::from_raw_parts_mut(buf.ptr, buf.len).zeroize();
    }
}

/// Wipe and free a buffer returned by this library. Null/empty is a no-op.
///
/// # Safety
///
/// `buf` must be null/empty or a not-yet-freed buffer this library returned.
#[no_mangle]
pub unsafe extern "C" fn msdk_free(buf: MsdkBuf) {
    guard_void(|| {
        wipe(&buf);
        if !buf.ptr.is_null() && buf.len != 0 {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                buf.ptr, buf.len,
            )));
        }
    })
}

/// The four-blob sealed envelope. Free with [`msdk_envelope_free`].
#[repr(C)]
pub struct MsdkEnvelope {
    /// Caller label bound into the seal.
    pub binding_id: MsdkBuf,
    /// Bincode RLWE capsule.
    pub capsule: MsdkBuf,
    /// Version-tagged ZKPoPlaintext proof.
    pub proof: MsdkBuf,
    /// `nonce ‖ ciphertext`.
    pub ct: MsdkBuf,
}

impl MsdkEnvelope {
    /// Used on error paths.
    fn empty() -> Self {
        MsdkEnvelope {
            binding_id: MsdkBuf::empty(),
            capsule: MsdkBuf::empty(),
            proof: MsdkBuf::empty(),
            ct: MsdkBuf::empty(),
        }
    }
}

/// Free all four buffers of an envelope produced by [`msdk_encrypt`].
///
/// # Safety
///
/// Every buffer in `env` must satisfy [`msdk_free`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn msdk_envelope_free(env: MsdkEnvelope) {
    guard_void(|| {
        msdk_free(env.binding_id);
        msdk_free(env.capsule);
        msdk_free(env.proof);
        msdk_free(env.ct);
    })
}

/// Borrow a `(ptr, len)` pair as a slice; null with a non-zero `len` is `None`.
///
/// # Safety
///
/// A non-null `ptr` must be valid for `len` reads of `T` for the call.
unsafe fn as_slice<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if ptr.is_null() {
        (len == 0).then_some(&[])
    } else {
        Some(slice::from_raw_parts(ptr, len))
    }
}

/// The crypto protocol version this library speaks. A node whose `/health` reports
/// a different non-zero version cannot serve partials this library aggregates.
///
/// # Safety
///
/// None beyond the C calling convention; the function takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn msdk_crypto_protocol_version() -> i32 {
    guard(|| i32::from(core::CRYPTO_PROTOCOL_VERSION))
}

/// Writes to `*out` the cap, in bytes, every transport must enforce on a committee
/// node's response body.
///
/// # Safety
///
/// `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_max_committee_response_bytes(out: *mut u64) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out = core::MAX_COMMITTEE_RESPONSE_BYTES as u64;
        MSDK_OK
    })
}

/// Writes the canonical request signing payload to `*out`.
///
/// `secret_id` is 16 big-endian bytes; `block_hash` is 32 bytes; `recipient_index`
/// is the responding node's 1-based `dkg_index` (sign once per node).
///
/// # Safety
///
/// `secret_id` must point to 16 readable bytes and `block_hash` to 32; `subset`
/// must be valid for `subset_len` reads (or null with `subset_len == 0`); `out`
/// must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_signing_payload(
    secret_id: *const u8,
    subset: *const u64,
    subset_len: usize,
    block_hash: *const u8,
    recipient_index: u64,
    out: *mut MsdkBuf,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out = MsdkBuf::empty();
        let (Some(sid), Some(bh), Some(subset)) = (
            as_slice(secret_id, 16),
            as_slice(block_hash, 32),
            as_slice(subset, subset_len),
        ) else {
            return MSDK_ERR_INVALID_ARG;
        };
        let (Ok(sid), Ok(bh)) = (<[u8; 16]>::try_from(sid), <[u8; 32]>::try_from(bh)) else {
            return MSDK_ERR_INVALID_ARG;
        };
        *out = into_buf(core::signing_payload(
            u128::from_be_bytes(sid),
            subset,
            &bh,
            recipient_index,
        ));
        MSDK_OK
    })
}

/// Writes the bincode Lagrange coefficient for `point` over `subset` to `*out`.
///
/// # Safety
///
/// `subset` must be valid for `subset_len` reads (or null with
/// `subset_len == 0`); `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_lagrange_for(
    point: u64,
    subset: *const u64,
    subset_len: usize,
    out: *mut MsdkBuf,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out = MsdkBuf::empty();
        let Some(subset) = as_slice(subset, subset_len) else {
            return MSDK_ERR_INVALID_ARG;
        };
        match core::lagrange_for(point, subset) {
            Ok(bytes) => {
                *out = into_buf(bytes);
                MSDK_OK
            }
            Err(_) => MSDK_ERR_CRYPTO,
        }
    })
}

/// Seal `secrets` under `joint_pk` with associated data `aad`, writing the envelope
/// to `*out`. A null `binding_id` (length 0) generates a random one.
///
/// # Safety
///
/// Each `(pointer, length)` pair must be valid for that many reads (or null
/// with length 0); `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_encrypt(
    joint_pk: *const u8,
    joint_pk_len: usize,
    epoch: u32,
    secrets: *const u8,
    secrets_len: usize,
    aad: *const u8,
    aad_len: usize,
    binding_id: *const u8,
    binding_id_len: usize,
    out: *mut MsdkEnvelope,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        // Clear first so a caller that frees after an error never frees garbage.
        *out = MsdkEnvelope::empty();
        let (Some(pk), Some(sec), Some(aad), Some(binding)) = (
            as_slice(joint_pk, joint_pk_len),
            as_slice(secrets, secrets_len),
            as_slice(aad, aad_len),
            as_slice(binding_id, binding_id_len),
        ) else {
            return MSDK_ERR_INVALID_ARG;
        };
        let binding = (!binding_id.is_null()).then(|| binding.to_vec());
        match core::encrypt(pk, epoch, sec, aad, binding) {
            Ok(env) => {
                *out = MsdkEnvelope {
                    binding_id: into_buf(env.binding_id),
                    capsule: into_buf(env.capsule),
                    proof: into_buf(env.proof),
                    ct: into_buf(env.ct),
                };
                MSDK_OK
            }
            Err(core::CoreError::Empty(_) | core::CoreError::Decode { .. }) => MSDK_ERR_INVALID_ARG,
            Err(_) => MSDK_ERR_CRYPTO,
        }
    })
}

/// Verify a capsule's plaintext proof before collecting partials. On [`MSDK_OK`],
/// `*out_valid` is `1` (valid) or `0` (invalid); undecodable inputs return
/// [`MSDK_ERR_CRYPTO`].
///
/// # Safety
///
/// Each `(pointer, length)` pair must be valid for that many reads (or null
/// with length 0); `out_valid` must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_verify_plaintext_proof(
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
    guard(|| {
        if out_valid.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out_valid = 0;
        let (Some(pk), Some(cap), Some(pf), Some(bid)) = (
            as_slice(joint_pk, joint_pk_len),
            as_slice(capsule, capsule_len),
            as_slice(proof, proof_len),
            as_slice(binding_id, binding_id_len),
        ) else {
            return MSDK_ERR_INVALID_ARG;
        };
        match core::verify_plaintext_proof(pk, cap, pf, bid, epoch) {
            Ok(v) => {
                *out_valid = v as u8;
                MSDK_OK
            }
            Err(_) => MSDK_ERR_CRYPTO,
        }
    })
}

/// One committee partial as borrowed input buffers (see [`msdk_open_secret`]).
#[repr(C)]
pub struct MsdkPartialInput {
    /// The responding node's 1-based DKG evaluation point (`dkg_index`). Lagrange
    /// coefficients are derived from the points; a zero or repeated point is rejected.
    pub point: u64,
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
}

/// Verify the collected quorum, aggregate, and AEAD-open the payload.
///
/// `secret_id` is 16 big-endian bytes. Writes the recovered plaintext to `*out`;
/// release it with [`msdk_free`], which wipes it.
///
/// # Safety
///
/// `secret_id` must point to 16 readable bytes; each other `(pointer, length)`
/// pair, including the buffers inside each partial, must be valid for that many
/// reads (or null with length 0); `out` must be writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn msdk_open_secret(
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
    partials: *const MsdkPartialInput,
    partials_len: usize,
    out: *mut MsdkBuf,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out = MsdkBuf::empty();
        let (Some(sa), Some(cap), Some(sid), Some(bid), Some(aad), Some(ct), Some(raw)) = (
            as_slice(shared_a, shared_a_len),
            as_slice(capsule, capsule_len),
            as_slice(secret_id, 16),
            as_slice(binding_id, binding_id_len),
            as_slice(aad, aad_len),
            as_slice(ct, ct_len),
            as_slice(partials, partials_len),
        ) else {
            return MSDK_ERR_INVALID_ARG;
        };
        let Ok(sid) = <[u8; 16]>::try_from(sid) else {
            return MSDK_ERR_INVALID_ARG;
        };
        let inputs: Option<Vec<core::PartialInput>> = raw
            .iter()
            .map(|p| {
                Some(core::PartialInput {
                    point: p.point,
                    partial: as_slice(p.partial, p.partial_len)?.to_vec(),
                    proof: as_slice(p.proof, p.proof_len)?.to_vec(),
                    commitment: as_slice(p.commitment, p.commitment_len)?.to_vec(),
                })
            })
            .collect();
        let Some(inputs) = inputs else {
            return MSDK_ERR_INVALID_ARG;
        };
        match core::open_secret(
            sa,
            cap,
            u128::from_be_bytes(sid),
            epoch,
            bid,
            aad,
            ct,
            &inputs,
        ) {
            Ok(pt) => {
                *out = into_buf(pt.expose().to_vec());
                MSDK_OK
            }
            Err(core::CoreError::InvalidSubset(_)) => MSDK_ERR_INVALID_ARG,
            Err(_) => MSDK_ERR_CRYPTO,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Source scan: a new entry point that forgets the guard fails here.
    #[test]
    fn every_exported_function_is_panic_guarded() {
        for (file, src) in [
            ("lib.rs", include_str!("lib.rs")),
            ("apikey.rs", include_str!("apikey.rs")),
        ] {
            let mut rest = src;
            let mut seen = 0;
            while let Some(at) = rest.find("extern \"C\" fn ") {
                let after = &rest[at..];
                let open = after.find('{').expect("fn body");
                let body = after[open + 1..].trim_start();
                let name = after["extern \"C\" fn ".len()..].split('(').next().unwrap();
                assert!(
                    body.starts_with("guard(") || body.starts_with("guard_void("),
                    "{file}: `{name}` does not run its body under guard()"
                );
                seen += 1;
                rest = &after[open..];
            }
            assert!(seen > 0, "{file}: found no exported functions");
        }
    }

    #[test]
    fn reports_the_core_protocol_version() {
        let v = unsafe { msdk_crypto_protocol_version() };
        assert_eq!(v, i32::from(core::CRYPTO_PROTOCOL_VERSION));
    }

    #[test]
    fn reports_the_core_response_cap() {
        let mut cap = 0u64;
        assert_eq!(
            unsafe { msdk_max_committee_response_bytes(&mut cap) },
            MSDK_OK
        );
        assert_eq!(cap, core::MAX_COMMITTEE_RESPONSE_BYTES as u64);
    }

    #[test]
    fn a_panic_becomes_an_error_code() {
        assert_eq!(guard(|| panic!("a bug")), MSDK_ERR_INTERNAL);
        assert_eq!(guard(|| MSDK_OK), MSDK_OK);
    }

    #[test]
    fn freeing_wipes_the_buffer_first() {
        let buf = into_buf(b"top secret".to_vec());
        // SAFETY: `buf` came from `into_buf` and is still live.
        let live = unsafe { slice::from_raw_parts(buf.ptr, buf.len) };
        assert_eq!(live, b"top secret");
        unsafe { wipe(&buf) };
        assert!(live.iter().all(|&b| b == 0), "not wiped: {live:?}");
        unsafe { msdk_free(buf) };
    }

    #[test]
    fn null_with_a_length_is_invalid_everywhere() {
        let sid = [0u8; 16];
        let bh = [0u8; 32];
        let mut out = MsdkBuf::empty();
        let rc = unsafe {
            msdk_signing_payload(sid.as_ptr(), std::ptr::null(), 3, bh.as_ptr(), 1, &mut out)
        };
        assert_eq!(rc, MSDK_ERR_INVALID_ARG, "signing_payload subset");
        let rc = unsafe { msdk_lagrange_for(1, std::ptr::null(), 3, &mut out) };
        assert_eq!(rc, MSDK_ERR_INVALID_ARG, "lagrange_for subset");
        let mut env = MsdkEnvelope::empty();
        let pk = [0u8; 4];
        let secret = [1u8];
        let rc = unsafe {
            msdk_encrypt(
                pk.as_ptr(),
                pk.len(),
                0,
                secret.as_ptr(),
                1,
                std::ptr::null(),
                0,
                std::ptr::null(),
                8,
                &mut env,
            )
        };
        assert_eq!(rc, MSDK_ERR_INVALID_ARG, "encrypt binding_id");
    }

    #[test]
    fn msdk_encrypt_clears_out_on_error() {
        fn sentinel() -> MsdkBuf {
            MsdkBuf {
                ptr: 0xAB as *mut u8,
                len: 0xABAB,
            }
        }
        let mut env = MsdkEnvelope {
            binding_id: sentinel(),
            capsule: sentinel(),
            proof: sentinel(),
            ct: sentinel(),
        };
        let bad_pk = [0u8; 4]; // too short to decode as a bincode PublicKey
        let secrets = [1u8, 2, 3];
        let aad = [7u8; 2];
        let rc = unsafe {
            msdk_encrypt(
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
        assert_eq!(rc, MSDK_ERR_INVALID_ARG);
        for buf in [&env.binding_id, &env.capsule, &env.proof, &env.ct] {
            assert!(buf.ptr.is_null(), "out buffer must be cleared on error");
            assert_eq!(buf.len, 0, "out buffer len must be zero on error");
        }
    }
}
