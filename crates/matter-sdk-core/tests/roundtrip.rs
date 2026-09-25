//! Seal and open through a real local `(3,5)` DKG, minus the network.
//! `emit_conformance_vectors` (ignored) writes the `testvectors/` fixtures the
//! other bindings replay.

use std::collections::BTreeMap;

use matter_crypto::bgv::params::{SecureCipher, SecureParams};
use matter_crypto::bgv::poly::crt::CrtPoly;
use matter_crypto::bgv::poly::CrtContext;
use matter_crypto::bgv::Ciphertext;
use matter_crypto::dkg::{
    commit_to_contribution,
    derive_shared_a,
    generate_contribution,
    process_contributions,
    DkgOutput,
};
use matter_crypto::secret::{lagrange_coefficient, produce_proven_partial};
use matter_crypto::zkp::plaintext::PlaintextProof;
use matter_crypto::zkp::zkp_aware_smudge_bits;
use matter_sdk_core::{
    encrypt,
    lagrange_for,
    open_secret,
    signing_payload,
    verify_plaintext_proof,
    Aad,
    EncryptedSecret,
    PartialInput,
};

type Params = SecureParams;
type Cipher = SecureCipher;

const SHARED_A_SEED: &[u8] = b"matter-sdk-core-roundtrip";
const N: u64 = 5;
const T: usize = 3;

fn run_dkg(ctx: &CrtContext<Cipher>, epoch: u32) -> Vec<DkgOutput<Params>> {
    let points: Vec<u64> = (1..=N).collect();
    let shared_a = derive_shared_a::<Cipher>(SHARED_A_SEED, epoch);
    // A real committee derives the session id from chain context.
    let ssid = [SHARED_A_SEED, b"/ssid", &epoch.to_be_bytes()].concat();
    let contributions: Vec<_> = points
        .iter()
        .map(|&pt| generate_contribution::<Params>(ctx, pt, &points, T, &shared_a))
        .collect();
    let prior_commitments: Vec<_> = contributions
        .iter()
        .map(|c| commit_to_contribution(c, &ssid, &c.nonce))
        .collect();
    points
        .iter()
        .map(|&pt| {
            process_contributions::<Params>(
                ctx,
                pt,
                &points,
                &contributions,
                &prior_commitments,
                &ssid,
                &shared_a,
                T,
            )
            .expect("DKG must finalise")
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn collect_partials(
    ctx: &CrtContext<Cipher>,
    outputs: &[DkgOutput<Params>],
    subset: &[u64],
    capsule: &Ciphertext<Params>,
    capsule_proof: &PlaintextProof<Params>,
    shared_a: &CrtPoly<Cipher>,
    secret_id: u128,
    epoch: u32,
    binding_id: &[u8],
) -> Vec<PartialInput> {
    let smudge_bits = zkp_aware_smudge_bits::<Params>(subset.len());
    subset
        .iter()
        .map(|&pt| {
            let idx = (pt - 1) as usize;
            let lambda = lagrange_coefficient::<Params>(pt, subset);
            // The node re-verifies the capsule's ZKPoPlaintext before answering.
            let (partial, proof) = produce_proven_partial::<Params>(
                ctx,
                &outputs[idx].joint_pk,
                &outputs[idx].key_share,
                lambda,
                capsule,
                capsule_proof,
                shared_a,
                &outputs[idx].share_commitment,
                smudge_bits,
                binding_id,
                &secret_id.to_be_bytes(),
                epoch as u64,
            )
            .expect("capsule proof verifies, so the node produces a partial");
            PartialInput {
                point: pt,
                partial: bincode::serialize(&partial).unwrap(),
                proof: bincode::serialize(&proof).unwrap(),
                commitment: bincode::serialize(&outputs[idx].share_commitment).unwrap(),
            }
        })
        .collect()
}

/// Returns the envelope plus bincode `joint_pk` and `shared_a`.
fn seal(
    outputs: &[DkgOutput<Params>],
    shared_a: &CrtPoly<Cipher>,
    epoch: u32,
    binding_id: Vec<u8>,
    aad: &[u8],
    plaintext: &[u8],
) -> (EncryptedSecret, Vec<u8>, Vec<u8>) {
    let joint_pk = bincode::serialize(&outputs[0].joint_pk).unwrap();
    let shared_a_bytes = bincode::serialize(shared_a).unwrap();
    let env = encrypt(&joint_pk, epoch, plaintext, aad, Some(binding_id)).expect("seal");
    (env, joint_pk, shared_a_bytes)
}

#[test]
fn seal_then_open_recovers_plaintext() {
    let ctx = CrtContext::gen();
    let epoch = 0u32;
    let outputs = run_dkg(&ctx, epoch);
    let shared_a = derive_shared_a::<Cipher>(SHARED_A_SEED, epoch);

    let secret_id = 0x0123_4567_89ab_cdef_u128;
    let binding_id = b"binding-roundtrip".to_vec();
    let aad = Aad::EnvV1;
    let plaintext = b"DATABASE_URL=postgres://prod\nFOO=bar";

    let (env, joint_pk, shared_a_bytes) = seal(
        &outputs,
        &shared_a,
        epoch,
        binding_id.clone(),
        aad.as_bytes(),
        plaintext,
    );

    assert!(
        verify_plaintext_proof(&joint_pk, &env.capsule, &env.proof, &binding_id, epoch).unwrap()
    );

    let capsule: Ciphertext<Params> = bincode::deserialize(&env.capsule).unwrap();
    let capsule_proof: PlaintextProof<Params> =
        matter_kgc_config::wire::decode_tagged(&env.proof).expect("decode capsule proof");
    let subset = vec![1u64, 3, 5];
    let partials = collect_partials(
        &ctx,
        &outputs,
        &subset,
        &capsule,
        &capsule_proof,
        &shared_a,
        secret_id,
        epoch,
        &binding_id,
    );

    let recovered = open_secret(
        &shared_a_bytes,
        &env.capsule,
        secret_id,
        epoch,
        &binding_id,
        aad.as_bytes(),
        &env.ct,
        &partials,
    )
    .expect("authorized quorum opens the secret");
    assert_eq!(recovered.expose(), plaintext);
}

#[test]
fn wrong_aad_fails_terminally() {
    let ctx = CrtContext::gen();
    let epoch = 2u32;
    let outputs = run_dkg(&ctx, epoch);
    let shared_a = derive_shared_a::<Cipher>(SHARED_A_SEED, epoch);

    let secret_id = 7u128;
    let binding_id = b"binding-aad".to_vec();
    let plaintext = b"TOKEN=swordfish";

    let (env, _pk, shared_a_bytes) = seal(
        &outputs,
        &shared_a,
        epoch,
        binding_id.clone(),
        Aad::EnvV1.as_bytes(),
        plaintext,
    );
    let capsule: Ciphertext<Params> = bincode::deserialize(&env.capsule).unwrap();
    let capsule_proof: PlaintextProof<Params> =
        matter_kgc_config::wire::decode_tagged(&env.proof).expect("decode capsule proof");
    let subset = vec![1u64, 2, 3];
    let partials = collect_partials(
        &ctx,
        &outputs,
        &subset,
        &capsule,
        &capsule_proof,
        &shared_a,
        secret_id,
        epoch,
        &binding_id,
    );

    let err = open_secret(
        &shared_a_bytes,
        &env.capsule,
        secret_id,
        epoch,
        &binding_id,
        Aad::TlsV1.as_bytes(),
        &env.ct,
        &partials,
    )
    .expect_err("wrong aad must not open");
    assert!(matches!(err, matter_sdk_core::CoreError::Aead));
}

#[test]
fn signing_payload_is_deterministic_and_binds_inputs() {
    let block_hash = [0x11u8; 32];
    let a = signing_payload(1, &[1, 2, 3], &block_hash, 2);
    let b = signing_payload(1, &[1, 2, 3], &block_hash, 2);
    assert_eq!(a, b, "same inputs → same bytes");
    assert_ne!(a, signing_payload(2, &[1, 2, 3], &block_hash, 2));
    assert_ne!(a, signing_payload(1, &[1, 2, 4], &block_hash, 2));
    assert_ne!(a, signing_payload(1, &[1, 2, 3], &[0x22u8; 32], 2));
    assert_ne!(a, signing_payload(1, &[1, 2, 3], &block_hash, 3));
}

/// Writes the cross-language conformance fixtures:
/// `cargo test -p matter-sdk-core --test roundtrip -- --ignored --nocapture`
#[test]
#[ignore = "fixture generator; run on demand"]
fn emit_conformance_vectors() {
    use serde_json::json;

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testvectors");
    std::fs::create_dir_all(dir).unwrap();

    // Every binding must match these byte-for-byte.
    let block_hash = [0x11u8; 32];
    let sp_cases: Vec<_> = [
        (1u128, vec![1u64, 2, 3], 2u64),
        (0xdead_beefu128, vec![2u64, 5, 9, 11], 9u64),
    ]
    .into_iter()
    .map(|(secret_id, subset, recipient_index)| {
        json!({
            "secret_id": secret_id.to_string(),
            "subset": subset,
            "recipient_index": recipient_index,
            "block_hash_hex": hex::encode(block_hash),
            "payload_hex": hex::encode(signing_payload(secret_id, &subset, &block_hash, recipient_index)),
        })
    })
    .collect();
    write_json(dir, "signing_payload.json", &json!({ "cases": sp_cases }));

    let lg_cases: Vec<_> = [(1u64, vec![1u64, 3, 5]), (3, vec![1, 3, 5])]
        .into_iter()
        .map(|(point, subset)| {
            json!({
                "point": point,
                "subset": subset,
                "lambda_hex": hex::encode(lagrange_for(point, &subset).unwrap()),
            })
        })
        .collect();
    write_json(dir, "lagrange.json", &json!({ "cases": lg_cases }));

    // Every binding's open_secret must recover `expected_plaintext`.
    let ctx = CrtContext::gen();
    let epoch = 0u32;
    let outputs = run_dkg(&ctx, epoch);
    let shared_a = derive_shared_a::<Cipher>(SHARED_A_SEED, epoch);
    let secret_id = 0x0123_4567_89ab_cdef_u128;
    let binding_id = b"binding-vector".to_vec();
    let aad = Aad::EnvV1;
    let plaintext = b"DATABASE_URL=postgres://prod\nFOO=bar";
    let (env, joint_pk, shared_a_bytes) = seal(
        &outputs,
        &shared_a,
        epoch,
        binding_id.clone(),
        aad.as_bytes(),
        plaintext,
    );
    let capsule: Ciphertext<Params> = bincode::deserialize(&env.capsule).unwrap();
    let capsule_proof: PlaintextProof<Params> =
        matter_kgc_config::wire::decode_tagged(&env.proof).expect("decode capsule proof");
    let subset = vec![1u64, 3, 5];
    let partials = collect_partials(
        &ctx,
        &outputs,
        &subset,
        &capsule,
        &capsule_proof,
        &shared_a,
        secret_id,
        epoch,
        &binding_id,
    );

    let partials_json: Vec<_> = partials
        .iter()
        .map(|p| {
            json!({
                "partial_hex": hex::encode(&p.partial),
                "proof_hex": hex::encode(&p.proof),
                "commitment_hex": hex::encode(&p.commitment),
                "point": p.point,
            })
        })
        .collect();

    let mut meta = BTreeMap::new();
    meta.insert("n", N.to_string());
    meta.insert("t", T.to_string());

    write_json(
        dir,
        "open_secret.json",
        &json!({
            "meta": meta,
            "joint_pk_hex": hex::encode(&joint_pk),
            "shared_a_hex": hex::encode(&shared_a_bytes),
            "secret_id": secret_id.to_string(),
            "epoch": epoch,
            "binding_id_hex": hex::encode(&binding_id),
            "aad_hex": hex::encode(aad.as_bytes()),
            "capsule_hex": hex::encode(&env.capsule),
            "proof_hex": hex::encode(&env.proof),
            "ct_hex": hex::encode(&env.ct),
            "subset": subset,
            "partials": partials_json,
            "expected_plaintext_hex": hex::encode(plaintext),
        }),
    );
}

fn write_json(dir: &str, name: &str, value: &serde_json::Value) {
    let path = format!("{dir}/{name}");
    std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    eprintln!("wrote {path}");
}
