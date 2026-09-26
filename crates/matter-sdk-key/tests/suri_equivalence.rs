//! The hand-rolled SURI splitter (`src/suri.rs`, which keeps `regex` out of the wasm) must
//! derive the same account as `subxt_signer::SecretUri`, used here as an oracle.
//!
//! The oracle's full feature set is a dev-dependency, so it never links into the `cdylib`.

use std::str::FromStr;

use matter_sdk_key::ApiKey;
use subxt_signer::sr25519::Keypair;
use subxt_signer::SecretUri;

const MNEMONIC: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
const HEX: &str = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";

/// The oracle's account for `input`, or `None` if it rejects it.
fn oracle(input: &str) -> Option<[u8; 32]> {
    let uri = SecretUri::from_str(input).ok()?;
    Keypair::from_uri(&uri).ok().map(|k| k.public_key().0)
}

/// This crate's account for `input`, or `None` if it rejects it.
fn ours(input: &str) -> Option<[u8; 32]> {
    ApiKey::parse(input)
        .ok()
        .map(|k| *k.account_id().as_bytes())
}

const ACCEPTED: &[&str] = &[
    MNEMONIC,
    HEX,
    // Hard, soft, numeric, and mixed junction paths.
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//hard",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk/soft",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//hard/soft",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk/soft//hard",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//0",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//42//stash",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk/a/b/c/d",
    // Junction code over 32 bytes, so it is blake2-hashed.
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    // Passwords: applied to a mnemonic, ignored for hex.
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk///pw",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//hard///pw",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk///pw/with/slashes",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk///",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e//hard",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e/soft",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e//hard/soft",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e///ignored",
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
    // A `:` is legal inside a junction or password; it must not read as a scheme prefix.
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk///pa:ss",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//a:b",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//hard/so:ft///p:w",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e///p:w",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e//a:b",
];

const REJECTED_BY_BOTH: &[&str] = &[
    // Trailing separators: `[^/]+` needs a character after the slashes.
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk/",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//hard/",
    // Characters outside the `[\d\w ]` phrase class.
    "bottom-drive-obey",
    "bottom.drive.obey",
    "bottom+drive",
    "café au lait",
    "not actually a mnemonic at all",
    "0xnothex",
];

/// The one deliberate divergence: the oracle substitutes the public dev phrase when none
/// is present; this crate refuses.
const ACCEPTED_ONLY_BY_ORACLE: &[&str] = &["//Alice", "/soft", "//Alice//stash", "///pw"];

#[test]
fn accepted_inputs_derive_identical_accounts() {
    for input in ACCEPTED {
        let expected = oracle(input)
            .unwrap_or_else(|| panic!("oracle rejected a case listed as accepted: {input:?}"));
        let actual =
            ours(input).unwrap_or_else(|| panic!("we rejected what the oracle accepts: {input:?}"));
        assert_eq!(
            actual, expected,
            "derived a different account than SecretUri for {input:?}"
        );
    }
}

#[test]
fn rejected_inputs_are_rejected_by_both() {
    for input in REJECTED_BY_BOTH {
        assert!(
            oracle(input).is_none(),
            "oracle accepted a case listed as rejected: {input:?}"
        );
        assert!(
            ours(input).is_none(),
            "we accepted what the oracle rejects: {input:?}"
        );
    }
}

#[test]
fn we_refuse_the_dev_phrase_fallback_the_oracle_allows() {
    for input in ACCEPTED_ONLY_BY_ORACLE {
        assert!(
            oracle(input).is_some(),
            "expected the oracle to accept {input:?} via the dev-phrase fallback"
        );
        assert!(
            ours(input).is_none(),
            "{input:?} must not derive the public dev account"
        );
    }
}

#[test]
fn junctions_are_not_quietly_dropped() {
    let root = ours(HEX).unwrap();
    for path in ["//hard", "/soft", "//hard/soft", "//1", "//a//b"] {
        let derived = ours(&format!("{HEX}{path}")).unwrap();
        assert_ne!(derived, root, "junction {path:?} was dropped");
        assert_eq!(derived, oracle(&format!("{HEX}{path}")).unwrap());
    }
}

#[test]
fn passwords_change_mnemonic_derivation_but_not_hex() {
    // Upstream ignores the password for a raw hex seed.
    assert_ne!(
        ours(MNEMONIC).unwrap(),
        ours(&format!("{MNEMONIC}///pw")).unwrap()
    );
    assert_eq!(ours(HEX).unwrap(), ours(&format!("{HEX}///pw")).unwrap());

    assert_eq!(
        ours(&format!("{MNEMONIC}///pw")).unwrap(),
        oracle(&format!("{MNEMONIC}///pw")).unwrap()
    );
}
