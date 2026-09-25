//! `open_secret` enforces its own preconditions. Replays
//! `testvectors/open_secret.json`; no DKG runs.

use matter_kgc_config::{
    MAX_ENCRYPTED_SECRET_CAPSULE_SIZE,
    MAX_ENCRYPTED_SECRET_CIPHERTEXT_SIZE,
    MAX_ENCRYPTED_SECRET_PROOF_SIZE,
};
use matter_sdk_core::{open_secret, verify_plaintext_proof, CoreError, PartialInput};
use serde_json::Value;

/// One sealed secret plus a `t`-subset of real partials.
struct Fixture {
    joint_pk: Vec<u8>,
    shared_a: Vec<u8>,
    capsule: Vec<u8>,
    proof: Vec<u8>,
    ct: Vec<u8>,
    binding_id: Vec<u8>,
    aad: Vec<u8>,
    secret_id: u128,
    epoch: u32,
    partials: Vec<PartialInput>,
    expected: Vec<u8>,
}

fn hex_field(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("{key} missing")))
        .unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testvectors/open_secret.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let partials = v["partials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| PartialInput {
            point: p["point"].as_u64().expect("point"),
            partial: hex_field(p, "partial_hex"),
            proof: hex_field(p, "proof_hex"),
            commitment: hex_field(p, "commitment_hex"),
        })
        .collect();
    Fixture {
        joint_pk: hex_field(&v, "joint_pk_hex"),
        shared_a: hex_field(&v, "shared_a_hex"),
        capsule: hex_field(&v, "capsule_hex"),
        proof: hex_field(&v, "proof_hex"),
        ct: hex_field(&v, "ct_hex"),
        binding_id: hex_field(&v, "binding_id_hex"),
        aad: hex_field(&v, "aad_hex"),
        secret_id: v["secret_id"].as_str().unwrap().parse().unwrap(),
        epoch: v["epoch"].as_u64().unwrap() as u32,
        partials,
        expected: hex_field(&v, "expected_plaintext_hex"),
    }
}

impl Fixture {
    fn open(&self) -> matter_sdk_core::Result<Vec<u8>> {
        self.open_with(&self.partials)
    }

    fn open_with(&self, partials: &[PartialInput]) -> matter_sdk_core::Result<Vec<u8>> {
        open_secret(
            &self.shared_a,
            &self.capsule,
            self.secret_id,
            self.epoch,
            &self.binding_id,
            &self.aad,
            &self.ct,
            partials,
        )
        .map(|pt| pt.expose().to_vec())
    }
}

/// Undecodable partial: a test using it passes only if its check runs before
/// decoding.
fn junk(point: u64) -> PartialInput {
    PartialInput {
        point,
        partial: vec![0xff; 3],
        proof: vec![0xff; 3],
        commitment: vec![0xff; 3],
    }
}

#[test]
fn opens_from_points_alone() {
    let fx = fixture();
    assert_eq!(fx.open().expect("open"), fx.expected);
}

#[test]
fn partial_order_does_not_matter() {
    let fx = fixture();
    let mut reversed = fx.partials.clone();
    reversed.reverse();
    assert_eq!(fx.open_with(&reversed).expect("open"), fx.expected);
}

#[test]
fn a_mislabelled_point_cannot_open() {
    let fx = fixture();
    let mut wrong = fx.partials.clone();
    wrong[0].point = 2;
    assert!(fx.open_with(&wrong).is_err());
}

#[test]
fn empty_subset_is_rejected() {
    let fx = fixture();
    assert!(matches!(
        fx.open_with(&[]),
        Err(CoreError::InvalidSubset(_))
    ));
}

#[test]
fn zero_point_is_rejected_before_decoding() {
    let fx = fixture();
    let got = fx.open_with(&[junk(1), junk(0), junk(3)]);
    assert!(
        matches!(got, Err(CoreError::InvalidSubset(_))),
        "got {got:?}"
    );
}

#[test]
fn repeated_point_is_rejected_before_decoding() {
    let fx = fixture();
    let got = fx.open_with(&[junk(1), junk(3), junk(1)]);
    assert!(
        matches!(got, Err(CoreError::InvalidSubset(_))),
        "got {got:?}"
    );
}

#[test]
fn trailing_bytes_are_rejected() {
    let fx = fixture();
    let mut shared_a = fx.shared_a.clone();
    shared_a.push(0);
    let got = open_secret(
        &shared_a,
        &fx.capsule,
        fx.secret_id,
        fx.epoch,
        &fx.binding_id,
        &fx.aad,
        &fx.ct,
        &fx.partials,
    );
    assert!(
        matches!(
            got,
            Err(CoreError::Decode {
                field: "shared_a",
                ..
            })
        ),
        "got {got:?}"
    );
}

#[test]
fn trailing_bytes_after_a_tagged_proof_are_rejected() {
    let fx = fixture();
    let mut proof = fx.proof.clone();
    proof.push(0);
    let got = verify_plaintext_proof(&fx.joint_pk, &fx.capsule, &proof, &fx.binding_id, fx.epoch);
    assert!(
        matches!(got, Err(CoreError::Decode { field: "proof", .. })),
        "got {got:?}"
    );
}

#[test]
fn oversized_inputs_are_rejected_before_decoding() {
    let fx = fixture();
    let capsule = vec![0u8; MAX_ENCRYPTED_SECRET_CAPSULE_SIZE + 1];
    let got = open_secret(
        &fx.shared_a,
        &capsule,
        fx.secret_id,
        fx.epoch,
        &fx.binding_id,
        &fx.aad,
        &fx.ct,
        &fx.partials,
    );
    assert!(
        matches!(
            got,
            Err(CoreError::TooLarge {
                field: "capsule",
                ..
            })
        ),
        "got {got:?}"
    );

    let ct = vec![0u8; MAX_ENCRYPTED_SECRET_CIPHERTEXT_SIZE + 1];
    let got = open_secret(
        &fx.shared_a,
        &fx.capsule,
        fx.secret_id,
        fx.epoch,
        &fx.binding_id,
        &fx.aad,
        &ct,
        &fx.partials,
    );
    assert!(
        matches!(got, Err(CoreError::TooLarge { field: "ct", .. })),
        "got {got:?}"
    );

    let proof = vec![0u8; MAX_ENCRYPTED_SECRET_PROOF_SIZE + 1];
    let got = verify_plaintext_proof(&fx.joint_pk, &fx.capsule, &proof, &fx.binding_id, fx.epoch);
    assert!(
        matches!(got, Err(CoreError::TooLarge { field: "proof", .. })),
        "got {got:?}"
    );
}
