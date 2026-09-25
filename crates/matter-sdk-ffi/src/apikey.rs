//! C ABI over [`matter_sdk_key`]: API-key ingestion and signing.
//!
//! Key derivation is a cross-language contract (`testvectors/api_keys.json`), so
//! bindings call this rather than deriving natively.
//!
//! [`msdk_apikey_parse`] returns an opaque handle the caller **must** release with
//! [`msdk_apikey_free`] exactly once. Key material never crosses the boundary;
//! only the account id and signatures do.

use std::slice;

use matter_sdk_key::{ApiKey, KeyError};

use crate::{guard, guard_void, into_buf, MsdkBuf, MSDK_ERR_INVALID_ARG, MSDK_OK};

/// The key was empty, malformed, or named an unsupported scheme.
pub const MSDK_ERR_KEY: i32 = -3;

/// An opaque handle to a parsed API key. Free with [`msdk_apikey_free`].
///
/// Opaque pointer (not a struct) so new schemes cannot change the ABI.
pub type MsdkApiKey = *mut ApiKey;

const ACCOUNT_ID_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

fn key_status(_: KeyError) -> i32 {
    // KeyError never embeds key material; the C boundary carries codes only.
    MSDK_ERR_KEY
}

/// Parse an API key into a handle.
///
/// `key_ptr`/`key_len` are UTF-8: a `0x` mini-secret, a BIP39 mnemonic, or an
/// sr25519 SURI, each optionally `sr25519:`-prefixed. On error `*out` is null.
///
/// # Safety
///
/// `key_ptr` must be valid for `key_len` reads; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_apikey_parse(
    key_ptr: *const u8,
    key_len: usize,
    out: *mut MsdkApiKey,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out = std::ptr::null_mut();
        if key_ptr.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }

        let bytes = slice::from_raw_parts(key_ptr, key_len);
        let Ok(text) = std::str::from_utf8(bytes) else {
            return MSDK_ERR_INVALID_ARG;
        };

        match ApiKey::parse(text) {
            Ok(key) => {
                *out = Box::into_raw(Box::new(key));
                MSDK_OK
            }
            Err(e) => key_status(e),
        }
    })
}

/// Release a handle, wiping the key material. Null is a no-op.
///
/// # Safety
///
/// `key` must be null or a live handle from [`msdk_apikey_parse`] that has not
/// been freed yet.
#[no_mangle]
pub unsafe extern "C" fn msdk_apikey_free(key: MsdkApiKey) {
    guard_void(|| {
        if !key.is_null() {
            drop(Box::from_raw(key));
        }
    })
}

/// Write the key's 32-byte account id into `out`.
///
/// # Safety
///
/// `key` must be null or a live handle; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_apikey_account_id(key: MsdkApiKey, out: *mut MsdkBuf) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out = MsdkBuf::empty();
        if key.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }

        let account = (*key).account_id();
        *out = into_buf(account.as_bytes().to_vec());
        debug_assert_eq!((*out).len, ACCOUNT_ID_BYTES);
        MSDK_OK
    })
}

/// Write the key's scheme token (e.g. `"sr25519"`, UTF-8, no NUL) into `out`.
///
/// # Safety
///
/// `key` must be null or a live handle; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_apikey_scheme(key: MsdkApiKey, out: *mut MsdkBuf) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out = MsdkBuf::empty();
        if key.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }

        *out = into_buf((*key).scheme().as_str().as_bytes().to_vec());
        MSDK_OK
    })
}

/// Sign `msg`, writing the raw 64-byte sr25519 signature (no framing) into `out`.
///
/// # Safety
///
/// `key` must be null or a live handle; `msg_ptr` must be valid for `msg_len`
/// reads (or null with `msg_len == 0`); `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn msdk_apikey_sign(
    key: MsdkApiKey,
    msg_ptr: *const u8,
    msg_len: usize,
    out: *mut MsdkBuf,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return MSDK_ERR_INVALID_ARG;
        }
        *out = MsdkBuf::empty();
        if key.is_null() || (msg_ptr.is_null() && msg_len != 0) {
            return MSDK_ERR_INVALID_ARG;
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
                MSDK_OK
            }
            Err(e) => key_status(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR_SEED_HEX: &str =
        "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
    const VECTOR_ACCOUNT_ID_HEX: &str =
        "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

    unsafe fn parse(key: &str) -> (i32, MsdkApiKey) {
        let mut handle: MsdkApiKey = std::ptr::null_mut();
        let status = msdk_apikey_parse(key.as_ptr(), key.len(), &mut handle);
        (status, handle)
    }

    unsafe fn take(buf: MsdkBuf) -> Vec<u8> {
        let out = slice::from_raw_parts(buf.ptr, buf.len).to_vec();
        crate::msdk_free(buf);
        out
    }

    #[test]
    fn parse_and_sign_round_trip() {
        unsafe {
            let (status, key) = parse(VECTOR_SEED_HEX);
            assert_eq!(status, MSDK_OK);
            assert!(!key.is_null());

            let mut account = MsdkBuf::empty();
            assert_eq!(msdk_apikey_account_id(key, &mut account), MSDK_OK);
            assert_eq!(hex::encode(take(account)), VECTOR_ACCOUNT_ID_HEX);

            let mut scheme = MsdkBuf::empty();
            assert_eq!(msdk_apikey_scheme(key, &mut scheme), MSDK_OK);
            assert_eq!(take(scheme), b"sr25519");

            let msg = b"canonical payload";
            let mut sig = MsdkBuf::empty();
            assert_eq!(
                msdk_apikey_sign(key, msg.as_ptr(), msg.len(), &mut sig),
                MSDK_OK
            );
            assert_eq!(take(sig).len(), SIGNATURE_BYTES);

            msdk_apikey_free(key);
        }
    }

    #[test]
    fn rejected_keys_leave_a_null_handle() {
        unsafe {
            for bad in ["", "//Alice", "secp256k1:0xdeadbeef", "0xnothex"] {
                let (status, key) = parse(bad);
                assert_ne!(status, MSDK_OK, "{bad:?} should be rejected");
                assert!(key.is_null(), "{bad:?} left a non-null handle");
            }
        }
    }

    #[test]
    fn null_arguments_are_rejected_not_dereferenced() {
        unsafe {
            let mut handle: MsdkApiKey = std::ptr::null_mut();
            assert_eq!(
                msdk_apikey_parse(std::ptr::null(), 0, &mut handle),
                MSDK_ERR_INVALID_ARG
            );
            assert!(handle.is_null());

            let mut buf = MsdkBuf::empty();
            assert_eq!(
                msdk_apikey_account_id(std::ptr::null_mut(), &mut buf),
                MSDK_ERR_INVALID_ARG
            );
            assert!(buf.ptr.is_null());
            assert_eq!(
                msdk_apikey_sign(std::ptr::null_mut(), std::ptr::null(), 0, &mut buf),
                MSDK_ERR_INVALID_ARG
            );
            assert!(buf.ptr.is_null());
        }
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        unsafe { msdk_apikey_free(std::ptr::null_mut()) };
    }
}
