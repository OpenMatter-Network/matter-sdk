//! C ABI over [`matter_vault_key`]: API-key ingestion and signing.
//!
//! Key *derivation* is as much a cross-language contract as the cryptography —
//! `testvectors/api_keys.json` pins it — so Go shares this implementation rather
//! than deriving with go-subkey. Doing it natively would silently diverge on the
//! parts that matter: applying SURI junctions, rejecting a phrase-less URI that
//! would fall back to the public development phrase, and reporting a reserved
//! `secp256k1:` scheme as unsupported rather than malformed.
//!
//! ## Ownership
//!
//! [`mv_apikey_parse`] returns an opaque handle the caller **must** release with
//! [`mv_apikey_free`] exactly once. The key material lives behind that handle and
//! never crosses the boundary; only the public account id and signatures do.

use std::slice;

use matter_vault_key::{ApiKey, KeyError};

use crate::{into_buf, MvBuf, MV_ERR_INVALID_ARG, MV_OK};

/// The key was empty, malformed, or named an unsupported scheme.
pub const MV_ERR_KEY: i32 = -3;

/// An opaque handle to a parsed API key. Free with [`mv_apikey_free`].
///
/// A pointer-sized opaque type rather than a struct, so adding scheme support
/// later cannot change the ABI.
pub type MvApiKey = *mut ApiKey;

/// Length of a substrate `AccountId32`.
const ACCOUNT_ID_BYTES: usize = 32;
/// Length of a raw sr25519 signature.
const SIGNATURE_BYTES: usize = 64;

fn key_status(_: KeyError) -> i32 {
    // KeyError never embeds key material, but the C boundary carries codes only.
    // Callers needing the reason should parse in a language binding that can
    // surface the message (or call `mv_apikey_parse` and report generically).
    MV_ERR_KEY
}

/// Parse an API key into a handle.
///
/// `key_ptr`/`key_len` are UTF-8 bytes: a `0x` mini-secret, a BIP39 mnemonic, or
/// an sr25519 SURI, each optionally `sr25519:`-prefixed. On success `*out` holds
/// a handle; on error `*out` is null.
#[no_mangle]
pub unsafe extern "C" fn mv_apikey_parse(
    key_ptr: *const u8,
    key_len: usize,
    out: *mut MvApiKey,
) -> i32 {
    if out.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    *out = std::ptr::null_mut();
    if key_ptr.is_null() {
        return MV_ERR_INVALID_ARG;
    }

    let bytes = slice::from_raw_parts(key_ptr, key_len);
    let Ok(text) = std::str::from_utf8(bytes) else {
        return MV_ERR_INVALID_ARG;
    };

    match ApiKey::parse(text) {
        Ok(key) => {
            *out = Box::into_raw(Box::new(key));
            MV_OK
        }
        Err(e) => key_status(e),
    }
}

/// Release a handle from [`mv_apikey_parse`], wiping the key material. Passing
/// null is a no-op; double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn mv_apikey_free(key: MvApiKey) {
    if !key.is_null() {
        drop(Box::from_raw(key));
    }
}

/// Write the key's 32-byte account id into `out`.
#[no_mangle]
pub unsafe extern "C" fn mv_apikey_account_id(key: MvApiKey, out: *mut MvBuf) -> i32 {
    if out.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    *out = MvBuf::empty();
    if key.is_null() {
        return MV_ERR_INVALID_ARG;
    }

    let account = (*key).account_id();
    *out = into_buf(account.as_bytes().to_vec());
    debug_assert_eq!((*out).len, ACCOUNT_ID_BYTES);
    MV_OK
}

/// Write the key's scheme token (e.g. `"sr25519"`, UTF-8, no NUL) into `out`.
#[no_mangle]
pub unsafe extern "C" fn mv_apikey_scheme(key: MvApiKey, out: *mut MvBuf) -> i32 {
    if out.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    *out = MvBuf::empty();
    if key.is_null() {
        return MV_ERR_INVALID_ARG;
    }

    *out = into_buf((*key).scheme().as_str().as_bytes().to_vec());
    MV_OK
}

/// Sign `msg` with the key, writing the raw 64-byte signature into `out`.
///
/// No framing is applied: the caller wraps it as a SCALE `MultiSignature` or an
/// extrinsic signature as needed.
#[no_mangle]
pub unsafe extern "C" fn mv_apikey_sign(
    key: MvApiKey,
    msg_ptr: *const u8,
    msg_len: usize,
    out: *mut MvBuf,
) -> i32 {
    if out.is_null() {
        return MV_ERR_INVALID_ARG;
    }
    *out = MvBuf::empty();
    if key.is_null() || (msg_ptr.is_null() && msg_len != 0) {
        return MV_ERR_INVALID_ARG;
    }

    let msg = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg_ptr, msg_len)
    };

    match (*key).sign(msg) {
        Ok(sig) => {
            *out = into_buf(sig.to_vec());
            debug_assert_eq!((*out).len, SIGNATURE_BYTES);
            MV_OK
        }
        Err(e) => key_status(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR_SEED_HEX: &str =
        "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
    const VECTOR_ACCOUNT_ID_HEX: &str =
        "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

    unsafe fn parse(key: &str) -> (i32, MvApiKey) {
        let mut handle: MvApiKey = std::ptr::null_mut();
        let status = mv_apikey_parse(key.as_ptr(), key.len(), &mut handle);
        (status, handle)
    }

    unsafe fn take(buf: MvBuf) -> Vec<u8> {
        let out = slice::from_raw_parts(buf.ptr, buf.len).to_vec();
        crate::mv_free(buf);
        out
    }

    #[test]
    fn parse_and_sign_round_trip() {
        unsafe {
            let (status, key) = parse(VECTOR_SEED_HEX);
            assert_eq!(status, MV_OK);
            assert!(!key.is_null());

            let mut account = MvBuf::empty();
            assert_eq!(mv_apikey_account_id(key, &mut account), MV_OK);
            assert_eq!(hex::encode(take(account)), VECTOR_ACCOUNT_ID_HEX);

            let mut scheme = MvBuf::empty();
            assert_eq!(mv_apikey_scheme(key, &mut scheme), MV_OK);
            assert_eq!(take(scheme), b"sr25519");

            let msg = b"canonical payload";
            let mut sig = MvBuf::empty();
            assert_eq!(
                mv_apikey_sign(key, msg.as_ptr(), msg.len(), &mut sig),
                MV_OK
            );
            assert_eq!(take(sig).len(), SIGNATURE_BYTES);

            mv_apikey_free(key);
        }
    }

    #[test]
    fn rejected_keys_leave_a_null_handle() {
        // Mirrors the MV-H1 contract: out-params are cleared on every error path,
        // so a caller that ignores the status cannot use a stale pointer.
        unsafe {
            for bad in ["", "//Alice", "secp256k1:0xdeadbeef", "0xnothex"] {
                let (status, key) = parse(bad);
                assert_ne!(status, MV_OK, "{bad:?} should be rejected");
                assert!(key.is_null(), "{bad:?} left a non-null handle");
            }
        }
    }

    #[test]
    fn null_arguments_are_rejected_not_dereferenced() {
        unsafe {
            let mut handle: MvApiKey = std::ptr::null_mut();
            assert_eq!(
                mv_apikey_parse(std::ptr::null(), 0, &mut handle),
                MV_ERR_INVALID_ARG
            );
            assert!(handle.is_null());

            let mut buf = MvBuf::empty();
            assert_eq!(
                mv_apikey_account_id(std::ptr::null_mut(), &mut buf),
                MV_ERR_INVALID_ARG
            );
            assert!(buf.ptr.is_null());
            assert_eq!(
                mv_apikey_sign(std::ptr::null_mut(), std::ptr::null(), 0, &mut buf),
                MV_ERR_INVALID_ARG
            );
            assert!(buf.ptr.is_null());
        }
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        unsafe { mv_apikey_free(std::ptr::null_mut()) };
    }
}
