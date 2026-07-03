//! Cross-language seed-format conformance.
//!
//! The `#[ignore]`d emitter writes `testvectors/seed_formats.json`, which every
//! language binding (and the dashboard that mints API keys) replays — pinning
//! "one secret, two encodings, same account" against upstream derivation drift
//! in subxt-signer, @polkadot/keyring, substrate-interface, and gsrpc.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-vault --test seed_formats -- --ignored
//! ```

use matter_vault::Sr25519Signer;
use serde_json::json;

/// The well-known substrate dev phrase — mirrored as consts in
/// `src/signer.rs` tests and every binding's conformance suite.
const VECTOR_MNEMONIC: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
const VECTOR_SEED_HEX: &str =
    "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
const VECTOR_ACCOUNT_ID_HEX: &str =
    "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

#[test]
#[ignore = "writes testvectors/seed_formats.json; run explicitly to regenerate"]
fn emit_seed_format_vectors() {
    let from_mnemonic = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_MNEMONIC).unwrap();
    let from_hex = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_SEED_HEX).unwrap();
    assert_eq!(from_mnemonic.account_id(), from_hex.account_id());
    assert_eq!(hex::encode(from_mnemonic.account_id()), VECTOR_ACCOUNT_ID_HEX);

    // Bare lowercase hex, per the testvectors/README.md convention.
    let vectors = json!({
        "cases": [{
            "mnemonic": VECTOR_MNEMONIC,
            "mini_secret_hex": VECTOR_SEED_HEX.trim_start_matches("0x"),
            "account_id_hex": VECTOR_ACCOUNT_ID_HEX,
        }]
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testvectors/seed_formats.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap()).unwrap();
    println!("wrote {path}");
}
