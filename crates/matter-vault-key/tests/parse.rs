//! The API-key ingestion contract.
//!
//! The `#[ignore]`d emitter writes `testvectors/api_keys.json`, which every
//! language binding replays. It is a deliberate *sibling* of
//! `seed_formats.json` rather than an extension of it: that file is a positive
//! derivation vector the OpenMatter dashboard also replays, and mixing negative
//! cases in would muddy an artifact shared across repos.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-vault-key --test parse -- --ignored
//! ```

use matter_vault_key::{AccountId, ApiKey, KeyError, KeyScheme, KeySigner};
use serde_json::json;

/// The well-known substrate dev phrase — the same constants asserted by
/// `crates/matter-vault/tests/seed_formats.rs` and every binding.
const VECTOR_MNEMONIC: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
const VECTOR_SEED_HEX: &str = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
const VECTOR_ACCOUNT_ID_HEX: &str =
    "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

fn account_hex(key: &ApiKey) -> String {
    hex::encode(key.account_id().as_bytes())
}

// --- The accepted encodings -------------------------------------------------

#[test]
fn hex_mnemonic_and_prefixed_forms_all_derive_the_same_account() {
    let forms = [
        VECTOR_MNEMONIC,
        VECTOR_SEED_HEX,
        &format!("sr25519:{VECTOR_MNEMONIC}"),
        &format!("sr25519:{VECTOR_SEED_HEX}"),
        // Whitespace: keys arrive from env vars and files, which pick up newlines.
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
    // Pins the MV-M3 refactor: the raw-bytes path must stay byte-for-byte the
    // path the hex phrase takes.
    let mut seed = [0u8; 32];
    hex::decode_to_slice(&VECTOR_SEED_HEX[2..], &mut seed).unwrap();

    let from_seed = ApiKey::from_seed(&seed).unwrap();
    let from_hex = ApiKey::parse(VECTOR_SEED_HEX).unwrap();
    assert_eq!(from_seed.account_id(), from_hex.account_id());
}

#[test]
fn suri_junctions_derive_a_different_account_than_the_root() {
    // Junctions must actually be applied. Python's `chain.py` branches on the
    // `0x` prefix and routes hex SURIs to `create_from_seed`, which silently
    // drops junctions and derives the *root* account; this asserts the Rust
    // reference behaviour that binding has to match.
    let root = ApiKey::parse(VECTOR_SEED_HEX).unwrap();
    let hard = ApiKey::parse(&format!("{VECTOR_SEED_HEX}//hard")).unwrap();
    let soft = ApiKey::parse(&format!("{VECTOR_SEED_HEX}/soft")).unwrap();

    assert_ne!(root.account_id(), hard.account_id());
    assert_ne!(root.account_id(), soft.account_id());
    assert_ne!(hard.account_id(), soft.account_id());

    // And the mnemonic form of the same secret derives identically.
    let hard_from_mnemonic = ApiKey::parse(&format!("{VECTOR_MNEMONIC}//hard")).unwrap();
    assert_eq!(hard.account_id(), hard_from_mnemonic.account_id());
}

// --- The rejections ---------------------------------------------------------

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
    // `SecretUri::from_str` falls back to the *public* well-known development
    // phrase when no phrase is captured, so `//Alice` yields a globally-known
    // keypair. An unset environment variable silently producing a working,
    // publicly-controlled signer is the worst failure this type can have.
    for input in ["//Alice", "/soft", "//Alice//stash", "sr25519://Alice"] {
        let err = ApiKey::parse(input).expect_err("must reject phraseless SURI");
        assert!(
            matches!(err, KeyError::Malformed { .. }),
            "input {input:?} gave {err:?}"
        );
    }

    // Spelling the dev phrase out in full still works — the guard is against
    // *implicit* derivation, not against dev accounts.
    let alice = ApiKey::parse(&format!("{VECTOR_MNEMONIC}//Alice")).unwrap();
    assert_ne!(account_hex(&alice), VECTOR_ACCOUNT_ID_HEX);
}

#[test]
fn reserved_schemes_report_as_unsupported_not_malformed() {
    // An Ethereum secp256k1 private key is also 32 bytes of hex, so it is
    // indistinguishable from an sr25519 mini-secret by shape. The explicit
    // prefix is the only way to tell them apart, and it must produce a roadmap
    // answer rather than a parse failure.
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
fn unknown_schemes_and_bad_encodings_are_malformed_or_unsupported() {
    // Unknown scheme token.
    assert!(matches!(
        ApiKey::parse("banana:whatever"),
        Err(KeyError::UnsupportedScheme { .. })
    ));

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

// --- The redaction contract -------------------------------------------------

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
    // A KeyError is routinely logged. Upstream errors are not careful here —
    // subxt_signer renders `Invalid character 'g' at position 5`, disclosing a
    // character of the secret and its offset — so this crate never forwards an
    // upstream source.
    let secret_body = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
    let inputs = [
        format!("0x{secret_body}00"),
        format!("0x{}", &secret_body[..62]),
        format!("secp256k1:0x{secret_body}"),
        format!("{VECTOR_MNEMONIC} zoo"),
        format!("//{secret_body}"),
    ];

    for input in inputs {
        let Err(err) = ApiKey::parse(&input) else {
            panic!("expected {input:?} to be rejected");
        };
        let message = err.to_string().to_ascii_lowercase();
        assert!(
            !message.contains(secret_body),
            "error leaked the key for {input:?}: {message}"
        );
        assert!(
            !message.contains("bottom drive"),
            "error leaked the mnemonic for {input:?}: {message}"
        );
    }
}

// --- The signing capability -------------------------------------------------

#[test]
fn signs_verifiably_as_the_claimed_account() {
    let key = ApiKey::parse(VECTOR_MNEMONIC).unwrap();
    let message = b"canonical payload bytes";
    let signature = KeySigner::sign(&key, message).unwrap();

    assert_eq!(signature.len(), 64);
    // Prove the signature actually verifies under the account id the key
    // advertises — otherwise `account_id` and `sign` could disagree silently.
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

// --- The cross-language vector ----------------------------------------------

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
        ],
        "invalid": [
            { "name": "empty", "key": "", "error": "empty" },
            { "name": "whitespace only", "key": "   ", "error": "empty" },
            { "name": "scheme with no body", "key": "sr25519:", "error": "empty" },
            { "name": "phraseless suri would use the public dev phrase",
              "key": "//Alice", "error": "malformed" },
            { "name": "reserved ethereum scheme", "error": "unsupported_scheme",
              "key": "secp256k1:0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e" },
            { "name": "unknown scheme", "key": "banana:whatever", "error": "unsupported_scheme" },
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
