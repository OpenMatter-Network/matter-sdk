//! The `/partial-decrypt` wire contract: request/response types re-exported
//! from `matter-kgc-proto` (the crate the committee node uses), plus `0x`-hex
//! helpers for their binary fields.

#[doc(inline)]
pub use matter_kgc_proto::{
    partial_decrypt_signing_payload,
    AuthScheme,
    PartialDecryptRequest,
    PartialDecryptResponse,
    PARTIAL_DECRYPT_SIGNING_DOMAIN,
};

use crate::error::{CoreError, Result};

/// Encode bytes as a `"0x"`-prefixed lowercase hex string (the wire form for
/// every binary field in [`PartialDecryptRequest`] / [`PartialDecryptResponse`]).
pub fn to_0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    s.push_str(&hex::encode(bytes));
    s
}

/// Decode a `"0x"`-prefixed (or bare) hex string into bytes.
///
/// `field` names the value in the error. Non-hex input is a
/// [`CoreError::Hex`].
pub fn from_0x(field: &'static str, s: &str) -> Result<Vec<u8>> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(trimmed).map_err(|source| CoreError::Hex { field, source })
}

/// Render a `u128` secret id as `"0x"` + 32 hex chars (16 big-endian bytes).
pub fn secret_id_to_hex(secret_id: u128) -> String {
    to_0x(&secret_id.to_be_bytes())
}

/// Parse a `"0x"`+hex secret id back into a `u128`, requiring exactly 16 bytes.
pub fn secret_id_from_hex(s: &str) -> Result<u128> {
    let bytes = from_0x("secret_id", s)?;
    let arr: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidLength {
            field: "secret_id",
            expected: 16,
            actual: bytes.len(),
        })?;
    Ok(u128::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_with_and_without_prefix() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hexed = to_0x(&bytes);
        assert_eq!(hexed, "0xdeadbeef");
        assert_eq!(from_0x("x", &hexed).unwrap(), bytes);
        assert_eq!(from_0x("x", "deadbeef").unwrap(), bytes);
    }

    #[test]
    fn secret_id_round_trips() {
        let id = 0x0123_4567_89ab_cdef_u128;
        let h = secret_id_to_hex(id);
        assert_eq!(secret_id_from_hex(&h).unwrap(), id);
    }

    #[test]
    fn secret_id_rejects_wrong_length() {
        let err = secret_id_from_hex("0x00").unwrap_err();
        assert!(matches!(
            err,
            CoreError::InvalidLength {
                field: "secret_id",
                expected: 16,
                ..
            }
        ));
    }
}
