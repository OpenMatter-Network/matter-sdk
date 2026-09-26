//! API-key ingestion contract.
//!
//! The `#[ignore]`d emitter writes `testvectors/api_keys.json`, which every binding replays.
//! It stays separate from `seed_formats.json`, a positive-only vector shared with other repos.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-sdk-key --test parse -- --ignored
//! ```

use matter_sdk_key::{AccountId, ApiKey, KeyError, KeyScheme, KeySigner};
use serde_json::json;

/// Substrate dev phrase; the same constants as `tests/seed_formats.rs` and every binding.
const VECTOR_MNEMONIC: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
const VECTOR_SEED_HEX: &str = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
const VECTOR_ACCOUNT_ID_HEX: &str =
    "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

fn account_hex(key: &ApiKey) -> String {
    hex::encode(key.account_id().as_bytes())
}

#[test]
fn hex_mnemonic_and_prefixed_forms_all_derive_the_same_account() {
    let forms = [
        VECTOR_MNEMONIC,
        VECTOR_SEED_HEX,
        &format!("sr25519:{VECTOR_MNEMONIC}"),
        &format!("sr25519:{VECTOR_SEED_HEX}"),
        // Keys from env vars and files often carry newlines.
        &format!("  {VECTOR_SEED_HEX}\n"),
        // Scheme token is case-insensitive.
        &format!("SR25519:{VECTOR_SEED_HEX}"),
    ];
    for form in forms {
        let key = ApiKey::parse(form).expect("should parse");
        assert_eq!(account_hex(&key), VECTOR_ACCOUNT_ID_HEX, "form: {form:?}");
        assert_eq!(key.scheme(), KeyScheme::Sr25519);
    }
}

#[test]
fn from_seed_matches_the_hex_encoding() {
    let mut seed = [0u8; 32];
    hex::decode_to_slice(&VECTOR_SEED_HEX[2..], &mut seed).unwrap();

    let from_seed = ApiKey::from_seed(&seed).unwrap();
    let from_hex = ApiKey::parse(VECTOR_SEED_HEX).unwrap();
    assert_eq!(from_seed.account_id(), from_hex.account_id());
}

#[test]
fn suri_junctions_derive_a_different_account_than_the_root() {
    // Reference behaviour for every binding: hex SURIs apply junctions too.
    let root = ApiKey::parse(VECTOR_SEED_HEX).unwrap();
    let hard = ApiKey::parse(&format!("{VECTOR_SEED_HEX}//hard")).unwrap();
    let soft = ApiKey::parse(&format!("{VECTOR_SEED_HEX}/soft")).unwrap();

    assert_ne!(root.account_id(), hard.account_id());
    assert_ne!(root.account_id(), soft.account_id());
    assert_ne!(hard.account_id(), soft.account_id());

    // The mnemonic form of the same secret derives identically.
    let hard_from_mnemonic = ApiKey::parse(&format!("{VECTOR_MNEMONIC}//hard")).unwrap();
    assert_eq!(hard.account_id(), hard_from_mnemonic.account_id());
}

#[test]
fn empty_and_whitespace_are_rejected() {
    for input in ["", "   ", "\n\t", "sr25519:", "sr25519:   "] {
        assert!(
            matches!(ApiKey::parse(input), Err(KeyError::Empty)),
            "input {input:?} should be Empty"
        );
    }
}

#[test]
fn phraseless_suris_never_silently_become_the_public_dev_account() {
    // `SecretUri` substitutes the public dev phrase when none is given, so an unset
    // env var would otherwise yield a working, publicly-controlled signer.
    for input in ["//Alice", "/soft", "//Alice//stash", "sr25519://Alice"] {
        let err = ApiKey::parse(input).expect_err("must reject phraseless SURI");
        assert!(
            matches!(err, KeyError::Malformed { .. }),
            "input {input:?} gave {err:?}"
        );
    }

    // An explicit dev phrase still works; only implicit derivation is refused.
    let alice = ApiKey::parse(&format!("{VECTOR_MNEMONIC}//Alice")).unwrap();
    assert_ne!(account_hex(&alice), VECTOR_ACCOUNT_ID_HEX);
}

#[test]
fn reserved_schemes_report_as_unsupported_not_malformed() {
    // A secp256k1 key is 32-byte hex like an sr25519 mini-secret; only the prefix
    // tells them apart.
    for input in [
        "secp256k1:0x4c0883a69102937d6231471b5dbb6204fe512961708279e6dbf2e2f0e1f1f1f1",
        "ecdsa:0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e",
        "ed25519:bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    ] {
        let err = ApiKey::parse(input).expect_err("reserved scheme must be rejected");
        let KeyError::UnsupportedScheme { supported, .. } = &err else {
            panic!("input {input:?} gave {err:?}, want UnsupportedScheme");
        };
        assert_eq!(*supported, "sr25519");
    }
}

#[test]
fn a_colon_inside_a_suri_is_not_a_scheme_prefix() {
    // Only a bare identifier before the first `:` is a scheme; a password or
    // junction may contain `:`.
    for (suri, prefixed) in [
        (
            format!("{VECTOR_MNEMONIC}///pa:ss"),
            format!("sr25519:{VECTOR_MNEMONIC}///pa:ss"),
        ),
        (
            format!("{VECTOR_SEED_HEX}//a:b"),
            format!("SR25519:{VECTOR_SEED_HEX}//a:b"),
        ),
    ] {
        let bare = ApiKey::parse(&suri).expect("a colon in a SURI must parse");
        let with_scheme = ApiKey::parse(&prefixed).expect("a prefixed colon SURI must parse");
        assert_eq!(bare.account_id(), with_scheme.account_id(), "{suri:?}");
    }
}

#[test]
fn an_unknown_prefix_is_malformed_and_never_echoed() {
    // An unrecognised token before `:` may be key material (hex without `0x`),
    // so it is reported as malformed without repeating it.
    for input in ["banana:whatever", "fac7959dbfe72f052e5a0c3c8d6530f2:x"] {
        let err = ApiKey::parse(input).expect_err("unknown prefix must be rejected");
        assert!(
            matches!(err, KeyError::Malformed { .. }),
            "{input:?} gave {err:?}"
        );
        let token = input.split(':').next().unwrap();
        assert!(
            !format!("{err} {err:?}").contains(token),
            "{input:?} echoed: {err}"
        );
    }
}

#[test]
fn unknown_schemes_and_bad_encodings_are_malformed_or_unsupported() {
    for input in [
        // Too short / too long / non-hex.
        "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb779747",
        "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e00",
        "0xgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
    ] {
        assert!(
            matches!(ApiKey::parse(input), Err(KeyError::Malformed { .. })),
            "input should be Malformed: {input:?}"
        );
    }

    // Right shape, wrong checksum: recognised as BIP39, rejected while deriving.
    let bad_checksum = "bottom drive obey lake curtain smoke basket hold race lonely fit zoo";
    assert!(
        matches!(
            ApiKey::parse(bad_checksum),
            Err(KeyError::Derivation { .. }) | Err(KeyError::Malformed { .. })
        ),
        "bad BIP39 checksum must not derive a key"
    );
}

#[test]
fn debug_redacts_the_key_but_shows_the_account() {
    let key = ApiKey::parse(VECTOR_SEED_HEX).unwrap();
    let rendered = format!("{key:?}");

    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(rendered.contains(VECTOR_ACCOUNT_ID_HEX), "{rendered}");
    // Neither encoding of the secret may appear, in any casing.
    let lower = rendered.to_ascii_lowercase();
    assert!(!lower.contains(&VECTOR_SEED_HEX[2..]), "{rendered}");
    assert!(!lower.contains("bottom drive"), "{rendered}");
}

#[test]
fn errors_never_echo_the_input() {
    // KeyErrors get logged; upstream errors can disclose secret characters and
    // offsets, so no upstream source is ever forwarded.
    let secret_body = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
    let inputs = [
        format!("0x{secret_body}00"),
        format!("0x{}", &secret_body[..62]),
        format!("secp256k1:0x{secret_body}"),
        format!("{VECTOR_MNEMONIC} zoo"),
        format!("//{secret_body}"),
        // A `:` after the phrase must not turn the phrase into a "scheme".
        format!("{VECTOR_MNEMONIC} zoo///pa:ss"),
        format!("{VECTOR_MNEMONIC} zoo//a:b"),
        format!("{secret_body}:x"),
        format!("{secret_body}///p:w"),
    ];

    for input in inputs {
        let Err(err) = ApiKey::parse(&input) else {
            panic!("expected {input:?} to be rejected");
        };
        let message = format!("{err} {err:?}").to_ascii_lowercase();
        assert!(
            !message.contains(secret_body),
            "error leaked the key for {input:?}: {message}"
        );
        for word in VECTOR_MNEMONIC.split(' ') {
            assert!(
                !message.contains(word),
                "error leaked mnemonic word {word:?} for {input:?}: {message}"
            );
        }
    }
}

#[test]
fn signs_verifiably_as_the_claimed_account() {
    let key = ApiKey::parse(VECTOR_MNEMONIC).unwrap();
    let message = b"canonical payload bytes";
    let signature = KeySigner::sign(&key, message).unwrap();

    assert_eq!(signature.len(), 64);
    // `account_id` and `sign` must agree.
    let public = subxt_signer::sr25519::PublicKey(*key.account_id().as_bytes());
    assert!(subxt_signer::sr25519::verify(
        &subxt_signer::sr25519::Signature(signature),
        message,
        &public,
    ));
}

#[test]
fn account_id_hex_round_trips() {
    let key = ApiKey::parse(VECTOR_SEED_HEX).unwrap();
    let id = key.account_id();
    assert_eq!(AccountId::from_hex(&id.to_hex()).unwrap(), id);
    assert_eq!(AccountId::from_hex(VECTOR_ACCOUNT_ID_HEX).unwrap(), id);
    assert!(AccountId::from_hex("0xdeadbeef").is_err());
}

#[test]
#[ignore = "writes testvectors/api_keys.json; run explicitly to regenerate"]
fn emit_api_key_vectors() {
    // Bare lowercase hex for binary fields, per testvectors/README.md.
    let vectors = json!({
        "comment": "API-key ingestion contract. `valid` cases must parse to `account_id_hex`; \
                    `invalid` cases must be rejected with the named error kind. Sibling of \
                    seed_formats.json, which pins positive derivation only.",
        "valid": [
            { "name": "bare mnemonic", "key": VECTOR_MNEMONIC,
              "account_id_hex": VECTOR_ACCOUNT_ID_HEX },
            { "name": "bare hex mini-secret", "key": VECTOR_SEED_HEX,
              "account_id_hex": VECTOR_ACCOUNT_ID_HEX },
            { "name": "scheme-prefixed hex", "key": format!("sr25519:{VECTOR_SEED_HEX}"),
              "account_id_hex": VECTOR_ACCOUNT_ID_HEX },
            { "name": "surrounding whitespace", "key": format!("  {VECTOR_SEED_HEX}\n"),
              "account_id_hex": VECTOR_ACCOUNT_ID_HEX },
            { "name": "hex with hard junction", "key": format!("{VECTOR_SEED_HEX}//hard"),
              "account_id_hex": account_hex(&ApiKey::parse(&format!("{VECTOR_SEED_HEX}//hard")).unwrap()) },
            { "name": "mnemonic with hard junction", "key": format!("{VECTOR_MNEMONIC}//hard"),
              "account_id_hex": account_hex(&ApiKey::parse(&format!("{VECTOR_MNEMONIC}//hard")).unwrap()) },
            { "name": "colon inside a password is not a scheme",
              "key": format!("{VECTOR_MNEMONIC}///pa:ss"),
              "account_id_hex": account_hex(&ApiKey::parse(&format!("{VECTOR_MNEMONIC}///pa:ss")).unwrap()) },
            { "name": "colon inside a junction is not a scheme",
              "key": format!("sr25519:{VECTOR_SEED_HEX}//a:b"),
              "account_id_hex": account_hex(&ApiKey::parse(&format!("{VECTOR_SEED_HEX}//a:b")).unwrap()) },
        ],
        "invalid": [
            { "name": "empty", "key": "", "error": "empty" },
            { "name": "whitespace only", "key": "   ", "error": "empty" },
            { "name": "scheme with no body", "key": "sr25519:", "error": "empty" },
            { "name": "phraseless suri would use the public dev phrase",
              "key": "//Alice", "error": "malformed" },
            { "name": "reserved ethereum scheme", "error": "unsupported_scheme",
              "key": "secp256k1:0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e" },
            { "name": "unknown scheme prefix", "key": "banana:whatever", "error": "malformed" },
            { "name": "unprefixed hex before a colon is never echoed", "error": "malformed",
              "key": "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e:x" },
            { "name": "hex too short", "error": "malformed",
              "key": "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb779747" },
            { "name": "hex non-hex character", "error": "malformed",
              "key": "0xgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg" },
        ]
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testvectors/api_keys.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap()).unwrap();
    println!("wrote {path}");
}
