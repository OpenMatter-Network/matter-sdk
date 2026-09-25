//! Cross-language seed-format conformance: one secret, mnemonic or hex, same account.
//!
//! The `#[ignore]`d emitter writes `testvectors/seed_formats.json`, which every binding
//! and the API-key dashboard replay, catching derivation drift in subxt-signer,
//! @polkadot/keyring, substrate-interface, and gsrpc.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-sdk --test seed_formats -- --ignored
//! ```

use matter_sdk::Sr25519Signer;
use serde_json::json;

/// Substrate dev phrase; mirrored in `src/signer.rs` tests and every binding.
const VECTOR_MNEMONIC: &str =
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
const VECTOR_SEED_HEX: &str = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
const VECTOR_ACCOUNT_ID_HEX: &str =
    "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

#[test]
#[ignore = "writes testvectors/seed_formats.json; run explicitly to regenerate"]
fn emit_seed_format_vectors() {
    let from_mnemonic = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_MNEMONIC).unwrap();
    let from_hex = Sr25519Signer::from_uri_insecure_dev_only(VECTOR_SEED_HEX).unwrap();
    assert_eq!(from_mnemonic.account_id(), from_hex.account_id());
    assert_eq!(
        hex::encode(from_mnemonic.account_id()),
        VECTOR_ACCOUNT_ID_HEX
    );

    // Bare lowercase hex, per testvectors/README.md.
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
