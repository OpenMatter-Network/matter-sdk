//! Code shown in the docs and README, compiled here and byte-compared against them.
//!
//! Hand-built `Value`s are encoded against the spec-330 metadata, since nothing else
//! checks them before a node rejects them.
#![cfg(feature = "chain")]

use matter_sdk::chain::Value;
use parity_scale_codec::Decode;
use subxt::tx::Payload;

// guide:quantum-guard-request:start
fn quantum_guard_request(treasury: [u8; 32], sealed_env: u128, policy_root: [u8; 32]) -> Value {
    let none = || Value::unnamed_variant("None", []);
    let some = |v: Value| Value::unnamed_variant("Some", [v]);
    let engine = "ghcr.io/openmatter-network/quantum-guard/engine@sha256:…";

    let container = Value::named_composite([
        ("image", Value::from_bytes("nousresearch/hermes-agent")),
        ("tag", Value::from_bytes("latest")),
        (
            "ports",
            some(Value::unnamed_composite([Value::named_composite([
                ("container_port", Value::u128(8089)),
                ("protocol", Value::unnamed_variant("Tcp", [])),
            ])])),
        ),
        // The engine, mounted read-only from its own image.
        (
            "volumes",
            some(Value::unnamed_composite([Value::named_composite([
                ("name", Value::from_bytes("zkfw-engine")),
                ("target", Value::from_bytes("/opt/zkfw")),
                (
                    "source",
                    some(Value::named_variant(
                        "Image",
                        [("reference", Value::from_bytes(engine))],
                    )),
                ),
            ])])),
        ),
        ("command", none()),
        ("privileged", some(Value::bool(true))),
    ]);

    Value::named_composite([
        (
            "config",
            Value::unnamed_variant("ContainerRequest", [container]),
        ),
        ("expiration", none()),
        ("requirements", Value::u128(1)),
        ("treasury", Value::from_bytes(treasury)),
        ("private_resources_only", Value::bool(false)),
        ("allowed_resources", none()),
        ("simple_env_vars", none()),
        ("secret_ref", some(Value::u128(sealed_env))),
        ("tls_secret_ref", none()),
        (
            "launch",
            some(Value::named_composite([
                (
                    "launcher",
                    some(Value::unnamed_composite([Value::from_bytes(
                        "/opt/zkfw/zkfw-sandboxd",
                    )])),
                ),
                ("user", some(Value::from_bytes("0"))),
            ])),
        ),
        ("policy_root", some(Value::from_bytes(policy_root))),
        ("restart_policy", none()),
    ])
}
// guide:quantum-guard-request:end

fn spec330() -> subxt::Metadata {
    let bytes: &[u8] = include_bytes!("../../../testvectors/spec330_metadata.scale");
    subxt::Metadata::decode(&mut &bytes[..]).expect("fixture decodes")
}

#[test]
fn the_guide_request_encodes_against_the_runtime() {
    let request = quantum_guard_request([7; 32], 42, [9; 32]);
    let call = subxt::dynamic::tx("Jobs", "request_deployment", vec![request]);
    call.encode_call_data(&spec330())
        .expect("the guide's ResourceRequest must match spec 330");
}

#[test]
fn the_guide_shows_exactly_this_code() {
    let source = include_str!("guide_examples.rs");
    let start = "// guide:quantum-guard-request:start\n";
    let end = "// guide:quantum-guard-request:end";
    let body = &source[source.find(start).unwrap() + start.len()..source.find(end).unwrap()];
    let guide = include_str!("../../../docs/deployments.md");
    assert!(
        guide.contains(body.trim_end()),
        "docs/deployments.md must show the QuantumGuard request exactly as \
         tests/guide_examples.rs builds it"
    );
}

#[test]
fn a_request_missing_a_field_is_refused() {
    // Proves the encode check is not vacuous.
    let Value { value, .. } = quantum_guard_request([7; 32], 42, [9; 32]);
    let subxt::ext::scale_value::ValueDef::Composite(subxt::ext::scale_value::Composite::Named(
        fields,
    )) = value
    else {
        panic!("the request is a named composite");
    };
    let without_restart = fields
        .into_iter()
        .filter(|(name, _)| name != "restart_policy");
    let request = Value::named_composite(without_restart);
    let call = subxt::dynamic::tx("Jobs", "request_deployment", vec![request]);
    assert!(call.encode_call_data(&spec330()).is_err());
}

/// Stands in for a PKCS#11 or KMS client in the signer example below.
struct HsmSession;

impl HsmSession {
    fn sign_sr25519(&self, _message: &[u8]) -> Result<[u8; 64], matter_sdk::KeyError> {
        unimplemented!("the example only has to compile")
    }
}

// guide:key-signer:start
use std::sync::Arc;

use matter_sdk::chain::{MatterClient, MatterConfig, Network};
use matter_sdk::{AccountId, KeyError, KeyScheme, KeySigner};

/// An HSM-backed signer: the key never leaves the device.
struct HsmSigner {
    public_key: [u8; 32],
    session: HsmSession, // your PKCS#11 or KMS client
}

impl KeySigner for HsmSigner {
    fn scheme(&self) -> KeyScheme {
        KeyScheme::Sr25519
    }

    fn account_id(&self) -> AccountId {
        AccountId(self.public_key)
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], KeyError> {
        self.session.sign_sr25519(message)
    }
}

async fn connect(signer: HsmSigner) -> matter_sdk::Result<MatterClient> {
    let config = MatterConfig::for_network(Network::Testnet);
    MatterClient::connect_with_signer(config, Arc::new(signer)).await
}
// guide:key-signer:end

#[test]
fn the_signer_example_is_a_key_signer() {
    let signer = HsmSigner {
        public_key: [1; 32],
        session: HsmSession,
    };
    assert_eq!(signer.account_id(), AccountId([1; 32]));
    let _connect = connect; // the example's entry point type-checks
}

#[test]
fn secure_signing_shows_exactly_this_signer() {
    let source = include_str!("guide_examples.rs");
    let start = "// guide:key-signer:start\n";
    let end = "// guide:key-signer:end";
    let body = &source[source.find(start).unwrap() + start.len()..source.find(end).unwrap()];
    let guide = include_str!("../../../docs/secure-signing.md");
    assert!(
        guide.contains(body.trim_end()),
        "docs/secure-signing.md must show the KeySigner example exactly as \
         tests/guide_examples.rs builds it"
    );
}

// readme:quickstart:start
async fn quickstart() -> matter_sdk::Result<()> {
    let client = MatterClient::connect(MatterConfig::for_network(Network::Testnet)).await?;
    let chain = client.properties();
    println!("{} {}", chain.chain_name, chain.spec_version);
    println!(
        "{:?}",
        client.query("Secrets", "NextSecretId", vec![]).await?
    );
    Ok(())
}
// readme:quickstart:end

#[test]
fn the_readme_shows_exactly_this_quickstart() {
    let _quickstart = quickstart; // type-checks the README's Rust quickstart
    let source = include_str!("guide_examples.rs");
    let start = "// readme:quickstart:start\n";
    let end = "// readme:quickstart:end";
    let body = &source[source.find(start).unwrap() + start.len()..source.find(end).unwrap()];
    let readme = include_str!("../../../README.md");
    assert!(
        readme.contains(body.trim_end()),
        "README.md must show the Rust quickstart exactly as tests/guide_examples.rs builds it"
    );
}
