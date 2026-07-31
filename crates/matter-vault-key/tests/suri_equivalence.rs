//! The hand-rolled SURI splitter must agree with the ecosystem's parser.
//!
//! `src/suri.rs` replaces `subxt_signer::SecretUri` to keep `regex` — 764 KB of
//! the browser artifact — out of the shipped wasm. A splitter that disagreed
//! with the ecosystem would derive the *wrong account*: a silent, expensive
//! failure that no unit test of our own choosing would catch, because we would
//! be asserting against our own belief.
//!
//! So this test uses the real parser as an oracle. `subxt-signer`'s full feature
//! set is a **dev-dependency**, which does not link into a `cdylib`, so the
//! oracle stays available here and absent from the artifact.
//!
//! The comparison is made at the only level that matters: the derived account.
//! Two splitters that disagree about how to slice the string but derive the same
//! key are equivalent for every purpose this crate has.

use std::str::FromStr;

use matter_vault_key::ApiKey;
use subxt_signer::sr25519::Keypair;
use subxt_signer::SecretUri;

const MNEMONIC: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
const HEX: &str = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";

/// What the ecosystem parser derives for `input`, or `None` if it rejects it.
fn oracle(input: &str) -> Option<[u8; 32]> {
    let uri = SecretUri::from_str(input).ok()?;
    Keypair::from_uri(&uri).ok().map(|k| k.public_key().0)
}

/// What this crate derives for `input`, or `None` if it rejects it.
fn ours(input: &str) -> Option<[u8; 32]> {
    ApiKey::parse(input)
        .ok()
        .map(|k| *k.account_id().as_bytes())
}

/// Inputs the oracle accepts. Every one must derive an identical account here.
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
    // A junction whose code exceeds 32 bytes, so it is blake2-hashed.
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    // Passwords: applied to a mnemonic, ignored for hex.
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk///pw",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk//hard///pw",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk///pw/with/slashes",
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk///",
    // Hex with the same shapes.
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e//hard",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e/soft",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e//hard/soft",
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e///ignored",
    // 24-word mnemonic.
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
];

/// Inputs neither parser may accept. Some the oracle rejects outright; the rest
/// are the phrase-less forms it *accepts* by falling back to the public dev
/// phrase, which this crate deliberately refuses — see `ACCEPTED_ONLY_BY_ORACLE`.
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
    // Structurally fine, but not a real key.
    "not actually a mnemonic at all",
    "0xnothex",
];

/// The one deliberate divergence: the oracle silently substitutes the public
/// well-known development phrase when no phrase is present. This crate refuses.
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
    // The failure mode this whole module risks: parsing the phrase correctly but
    // losing the derivation path, silently returning the *root* account. That is
    // exactly the live defect in the Python binding, which routes hex SURIs to a
    // raw-seed constructor.
    let root = ours(HEX).unwrap();
    for path in ["//hard", "/soft", "//hard/soft", "//1", "//a//b"] {
        let derived = ours(&format!("{HEX}{path}")).unwrap();
        assert_ne!(derived, root, "junction {path:?} was dropped");
        assert_eq!(derived, oracle(&format!("{HEX}{path}")).unwrap());
    }
}

#[test]
fn passwords_change_mnemonic_derivation_but_not_hex() {
    // Upstream strips `0x` before consulting the password, so a password is
    // meaningful for a mnemonic and inert for a raw seed. Getting this backwards
    // would derive a wrong-but-plausible account.
    assert_ne!(
        ours(MNEMONIC).unwrap(),
        ours(&format!("{MNEMONIC}///pw")).unwrap()
    );
    assert_eq!(ours(HEX).unwrap(), ours(&format!("{HEX}///pw")).unwrap());

    // And both match the oracle.
    assert_eq!(
        ours(&format!("{MNEMONIC}///pw")).unwrap(),
        oracle(&format!("{MNEMONIC}///pw")).unwrap()
    );
}
