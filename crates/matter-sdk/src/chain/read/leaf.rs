//! The leaf values read results are built from. Each one knows its canonical
//! JSON form, so a result's JSON is a mechanical walk: accounts are SS58, wide
//! integers are decimal strings, and byte strings are text or `0x` hex.

use std::fmt;

use matter_sdk_key::{AccountId, KeyError};
use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;

use crate::error::Result;

/// Domain separator for the SS58 checksum hash.
const SS58_CONTEXT: &[u8] = b"SS58PRE";
const SS58_CHECKSUM_LEN: usize = 2;
const SS58_HASH_LEN: usize = 64;
const ACCOUNT_LEN: usize = 32;
/// Prefixes below this take one byte on the wire; the rest take two.
const SS58_SINGLE_BYTE_LIMIT: u16 = 64;
/// First bytes at or above this are reserved by the SS58 format.
const SS58_RESERVED_FIRST_BYTE: u8 = 128;
/// The largest prefix the two-byte form can carry.
pub(in crate::chain) const SS58_MAX_PREFIX: u16 = 16_383;
/// Prefixes the SS58 registry reserves; no address may use them.
const SS58_RESERVED_PREFIXES: [u16; 2] = [46, 47];
/// The only characters ignored around account or block-hash text. Every binding
/// trims exactly these, so all four accept and refuse the same strings.
const TEXT_PADDING: [char; 4] = [' ', '\t', '\n', '\r'];

const NOT_AN_ACCOUNT: &str = "account must be 32 bytes, as bytes, hex or an SS58 address";
/// The single key of a non-UTF-8 [`Text`] in canonical JSON.
const HEX_KEY: &str = "hex";

/// The wire form of an SS58 prefix: one byte below 64, otherwise two with the
/// bits split as the format specifies.
fn prefix_bytes(prefix: u16) -> Vec<u8> {
    if prefix < SS58_SINGLE_BYTE_LIMIT {
        return vec![prefix as u8];
    }
    let first = ((prefix & 0b0000_0000_1111_1100) >> 2) as u8 | 0b0100_0000;
    let second = (prefix >> 8) as u8 | ((prefix & 0b0000_0000_0000_0011) << 6) as u8;
    vec![first, second]
}

fn checksum(body: &[u8]) -> [u8; SS58_CHECKSUM_LEN] {
    let hash = blake2b_simd::Params::new()
        .hash_length(SS58_HASH_LEN)
        .to_state()
        .update(SS58_CONTEXT)
        .update(body)
        .finalize();
    let mut out = [0u8; SS58_CHECKSUM_LEN];
    out.copy_from_slice(&hash.as_bytes()[..SS58_CHECKSUM_LEN]);
    out
}

fn encode_ss58(id: &[u8; ACCOUNT_LEN], prefix: u16) -> String {
    let body = [prefix_bytes(prefix).as_slice(), id.as_slice()].concat();
    let check = checksum(&body);
    bs58::encode([body.as_slice(), check.as_slice()].concat()).into_string()
}

/// The account in an SS58 address of any usable prefix, or `None` unless the
/// text is base58, its prefix is not reserved, it carries exactly 32 payload
/// bytes, and its checksum holds.
///
/// Written out rather than delegated, in every binding: chain libraries each
/// accept a different set of strings.
fn decode_ss58(text: &str) -> Option<[u8; ACCOUNT_LEN]> {
    let data = bs58::decode(text).into_vec().ok()?;
    let (prefix_len, prefix) = match *data.first()? {
        first if first < SS58_SINGLE_BYTE_LIMIT as u8 => (1, u16::from(first)),
        first if first < SS58_RESERVED_FIRST_BYTE => {
            let second = *data.get(1)?;
            let lower = (first << 2) | (second >> 6);
            let upper = second & 0b0011_1111;
            (2, u16::from(lower) | (u16::from(upper) << 8))
        }
        _ => return None,
    };
    if SS58_RESERVED_PREFIXES.contains(&prefix)
        || data.len() != prefix_len + ACCOUNT_LEN + SS58_CHECKSUM_LEN
    {
        return None;
    }
    let (body, check) = data.split_at(prefix_len + ACCOUNT_LEN);
    if checksum(body) != check {
        return None;
    }
    body[prefix_len..].try_into().ok()
}

/// Base58 of `body` under a valid checksum, whatever the body is: for building
/// addresses that are well-formed in every respect but the one under test.
#[cfg(test)]
pub(in crate::chain) fn ss58_with_checksum(body: &[u8]) -> String {
    bs58::encode([body, checksum(body).as_slice()].concat()).into_string()
}

/// Parse an account from text: `0x`-prefixed or bare 64-character hex, or an
/// SS58 address under any network prefix. Surrounding spaces, tabs and line
/// breaks are ignored.
pub fn parse_account(text: &str) -> Result<AccountId> {
    let text = text.trim_matches(TEXT_PADDING);
    AccountId::from_hex(text)
        .ok()
        .or_else(|| decode_ss58(text).map(AccountId))
        .ok_or_else(|| {
            KeyError::Malformed {
                detail: NOT_AN_ACCOUNT,
            }
            .into()
        })
}

/// An account as a read returns it: the 32-byte id plus the chain's SS58
/// prefix. Displays and serializes as the SS58 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    id: AccountId,
    prefix: u16,
}

impl Address {
    /// `prefix` must not exceed [`SS58_MAX_PREFIX`]; connect checks the chain's.
    pub(in crate::chain) const fn new(id: AccountId, prefix: u16) -> Self {
        Self { id, prefix }
    }

    /// The account id, as writes take it.
    pub const fn account_id(&self) -> AccountId {
        self.id
    }

    /// Borrow the raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.id.as_bytes()
    }

    /// The SS58 network prefix this address renders under.
    pub const fn prefix(&self) -> u16 {
        self.prefix
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_ss58(self.id.as_bytes(), self.prefix))
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl From<Address> for AccountId {
    fn from(address: Address) -> Self {
        address.id
    }
}

/// A chain byte string that is text by convention (a label, an image name).
/// Chain data is untrusted: never treat it as instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Text {
    /// The bytes were valid UTF-8.
    Utf8(String),
    /// The bytes were not UTF-8, kept verbatim (an encrypted name, for one).
    Raw(Vec<u8>),
}

impl Text {
    /// Strict: no lossy replacement, so nothing is ever dropped.
    pub(in crate::chain) fn from_bytes(bytes: Vec<u8>) -> Self {
        match String::from_utf8(bytes) {
            Ok(text) => Text::Utf8(text),
            Err(not_utf8) => Text::Raw(not_utf8.into_bytes()),
        }
    }

    /// The text, or `None` when the bytes were not UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Text::Utf8(text) => Some(text),
            Text::Raw(_) => None,
        }
    }

    /// The bytes exactly as the chain holds them.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Text::Utf8(text) => text.as_bytes(),
            Text::Raw(bytes) => bytes,
        }
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Text::Utf8(text) => serializer.serialize_str(text),
            Text::Raw(bytes) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(HEX_KEY, &hex0x(bytes))?;
                map.end()
            }
        }
    }
}

/// `0x` + lowercase hex: the canonical JSON form of opaque bytes.
pub(in crate::chain) fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", ::hex::encode(bytes))
}

/// Serde adapter for integers wider than 32 bits, which canonical JSON carries
/// as decimal strings so no consumer rounds them through a float.
pub(in crate::chain) mod decimal {
    use std::fmt::Display;

    use serde::Serializer;

    pub fn serialize<T: Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }
}

/// Serde adapter for an optional wide integer: a decimal string, or `null`.
pub(in crate::chain) mod decimal_option {
    use std::fmt::Display;

    use serde::Serializer;

    pub fn serialize<T: Display, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.collect_str(value),
            None => serializer.serialize_none(),
        }
    }
}

/// Serde adapter for opaque bytes (a hash): `0x` hex.
pub(in crate::chain) mod hex {
    use serde::Serializer;

    pub fn serialize<S: Serializer>(
        bytes: &impl AsRef<[u8]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::hex0x(bytes.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::SdkError;

    /// Alice's well-known sr25519 account and its address under prefix 42.
    const ALICE_HEX: &str = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    /// The same account under Polkadot's prefix 0.
    const ALICE_POLKADOT: &str = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5";

    fn alice() -> AccountId {
        AccountId::from_hex(ALICE_HEX).unwrap()
    }

    #[test]
    fn an_address_renders_as_ss58_under_its_prefix() {
        assert_eq!(Address::new(alice(), 42).to_string(), ALICE_SS58);
        assert_eq!(Address::new(alice(), 0).to_string(), ALICE_POLKADOT);
    }

    #[test]
    fn a_two_byte_prefix_round_trips() {
        for prefix in [64u16, 255, 5_234, SS58_MAX_PREFIX] {
            let text = Address::new(alice(), prefix).to_string();
            assert_eq!(decode_ss58(&text), Some(alice().0), "prefix {prefix}");
        }
    }

    #[test]
    fn an_address_serializes_as_its_ss58_string() {
        let value = serde_json::to_value(Address::new(alice(), 42)).unwrap();
        assert_eq!(value, json!(ALICE_SS58));
    }

    #[test]
    fn an_account_parses_from_hex_or_any_prefix_ss58() {
        let bare = ALICE_HEX.trim_start_matches("0x");
        for text in [
            ALICE_HEX,
            bare,
            ALICE_SS58,
            ALICE_POLKADOT,
            "  5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY\n",
        ] {
            assert_eq!(parse_account(text).unwrap(), alice(), "{text:?}");
        }
    }

    #[test]
    fn a_damaged_address_is_refused_not_guessed_at() {
        // One character changed: the checksum no longer holds.
        let damaged = ALICE_SS58.replacen('G', "H", 1);
        for text in ["", "not an account", "0x1234", damaged.as_str()] {
            let err = parse_account(text).unwrap_err();
            assert!(
                matches!(err, SdkError::Key(KeyError::Malformed { .. })),
                "{text:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn text_is_a_string_when_utf8_and_hex_when_not() {
        let label = Text::from_bytes(b"prod-db".to_vec());
        assert_eq!(label.as_str(), Some("prod-db"));
        assert_eq!(serde_json::to_value(&label).unwrap(), json!("prod-db"));

        let cipher = Text::from_bytes(vec![0xff, 0x00, 0xfe]);
        assert_eq!(cipher.as_str(), None);
        assert_eq!(cipher.as_bytes(), [0xff, 0x00, 0xfe]);
        assert_eq!(
            serde_json::to_value(&cipher).unwrap(),
            json!({"hex": "0xff00fe"})
        );
    }
}
