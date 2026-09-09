//! End-to-end orchestration tracer for the Rust SDK.
//!
//! A `FakeCommittee` implements [`Transport`] by computing *real* partial
//! decryptions with `matter-crypto` (it plays the role of `t` honest nodes), so
//! [`matter_vault::decrypt`] is exercised over its full path — quorum selection,
//! request building, signing, fan-out, aggregation, AEAD-open — without a socket.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

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
use matter_vault::{
    decrypt,
    recover_secret,
    CommitteeInfo,
    CommitteeNode,
    DecryptRequest,
    Health,
    Sr25519Signer,
    Transport,
};
use matter_vault_core::wire::{to_0x, PartialDecryptRequest, PartialDecryptResponse};
use matter_vault_core::{encrypt, Aad};

type Params = SecureParams;
type Cipher = SecureCipher;

const SEED: &[u8] = b"matter-vault-sdk-decrypt-test";
const N: u64 = 5;
const T: usize = 3;
const EPOCH: u32 = 0;

/// `t` honest committee nodes that answer `/partial-decrypt` with real partials.
struct FakeCommittee {
    ctx: CrtContext<Cipher>,
    outputs: Vec<DkgOutput<Params>>,
    shared_a: CrtPoly<Cipher>,
    capsule: Ciphertext<Params>,
    capsule_proof: PlaintextProof<Params>,
    binding_id: Vec<u8>,
    secret_id: u128,
    by_endpoint: BTreeMap<String, u64>,
    /// If set, this node claims a *different* served epoch (a misbehaving node the
    /// SDK must drop rather than abort the whole decrypt on — MV-H2).
    bad_epoch_node: Option<u64>,
    /// Endpoints whose `/health` errors, as an unreachable node does.
    unreachable_health: BTreeSet<String>,
    /// Endpoints that pass `/health` but refuse the real request — the shape that
    /// stranded a testnet deployment while every node looked up from outside.
    refuse_partial: BTreeSet<String>,
}

// The futures are built eagerly (compute, then return a ready future) so they
// stay `Send` without requiring the committee state to be `Sync` — hence the
// explicit `impl Future` form rather than `async fn`.
#[allow(clippy::manual_async_fn)]
impl Transport for FakeCommittee {
    fn health(&self, endpoint: &str) -> impl Future<Output = matter_vault::Result<Health>> + Send {
        let down = self.unreachable_health.contains(endpoint);
        let endpoint = endpoint.to_string();
        async move {
            if down {
                return Err(matter_vault::SdkError::Transport {
                    endpoint,
                    detail: "connection refused".into(),
                });
            }
            Ok(serde_json::from_value(serde_json::json!({
                "status": "active",
                "epoch": EPOCH,
                "crypto_protocol_version": 2
            }))
            .unwrap())
        }
    }

    fn partial_decrypt(
        &self,
        endpoint: &str,
        req: &PartialDecryptRequest,
    ) -> impl Future<Output = matter_vault::Result<PartialDecryptResponse>> + Send {
        let point = self.by_endpoint[endpoint];
        // Passes `/health`, then refuses the real request — the shape that
        // stranded a testnet deployment while every node looked up from outside.
        let refused = self
            .refuse_partial
            .contains(endpoint)
            .then(|| endpoint.to_string());
        let resp = if refused.is_some() {
            // Never read on this path; the SDK drops the node first.
            PartialDecryptResponse {
                node_index: point,
                partial: to_0x(b"x"),
                proof: to_0x(b"x"),
                crypto_protocol_version: 2,
                served_epoch: EPOCH,
                shared_a: None,
                joint_pk: None,
                served_threshold: T as u32,
            }
        } else if self.bad_epoch_node == Some(point) {
            // Misbehaving node: claims a rotated epoch. partial/proof are never
            // read on this path — the SDK drops the node before using them.
            PartialDecryptResponse {
                node_index: point,
                partial: to_0x(b"x"),
                proof: to_0x(b"x"),
                crypto_protocol_version: 2,
                served_epoch: EPOCH + 1,
                shared_a: None,
                joint_pk: None,
                served_threshold: T as u32,
            }
        } else {
            let idx = (point - 1) as usize;
            let lambda = lagrange_coefficient::<Params>(point, &req.subset);
            let smudge = zkp_aware_smudge_bits::<Params>(req.subset.len());
            let (partial, proof) = produce_proven_partial::<Params>(
                &self.ctx,
                &self.outputs[idx].joint_pk,
                &self.outputs[idx].key_share,
                lambda,
                &self.capsule,
                &self.capsule_proof,
                &self.shared_a,
                &self.outputs[idx].share_commitment,
                smudge,
                &self.binding_id,
                &self.secret_id.to_be_bytes(),
                EPOCH as u64,
            )
            .expect("capsule proof verifies, so the node produces a partial");
            PartialDecryptResponse {
                node_index: point,
                partial: to_0x(&bincode::serialize(&partial).unwrap()),
                proof: to_0x(&bincode::serialize(&proof).unwrap()),
                crypto_protocol_version: 2,
                served_epoch: EPOCH,
                shared_a: None,
                joint_pk: None,
                served_threshold: T as u32,
            }
        };
        async move {
            match refused {
                Some(endpoint) => Err(matter_vault::SdkError::Transport {
                    endpoint,
                    detail: "503 Service Unavailable".into(),
                }),
                None => Ok(resp),
            }
        }
    }
}

fn run_dkg(ctx: &CrtContext<Cipher>) -> Vec<DkgOutput<Params>> {
    let points: Vec<u64> = (1..=N).collect();
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);
    // Session id binding the commit-before-reveal round (shared across the
    // simulated nodes; a real committee derives it from chain context).
    let ssid = [SEED, b"/ssid", &EPOCH.to_be_bytes()].concat();
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
            .expect("DKG finalises")
        })
        .collect()
}

#[tokio::test]
async fn decrypt_recovers_the_secret_from_a_quorum() {
    let ctx = CrtContext::gen();
    let outputs = run_dkg(&ctx);
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);

    let secret_id = 0xfeed_face_u128;
    let aad = Aad::EnvV1;
    let plaintext = b"API_KEY=swordfish\nDB=postgres://prod";
    let joint_pk = bincode::serialize(&outputs[0].joint_pk).unwrap();
    let env = encrypt(&joint_pk, EPOCH, plaintext, aad.as_bytes(), None).expect("seal");
    let capsule: Ciphertext<Params> = bincode::deserialize(&env.capsule).unwrap();
    let shared_a_bytes = bincode::serialize(&shared_a).unwrap();

    // Build nodes (all five offered; the SDK will pick a threshold quorum).
    let nodes: Vec<CommitteeNode> = (1..=N)
        .map(|point| CommitteeNode {
            index: point,
            endpoint: format!("http://node-{point}"),
            share_commitment: bincode::serialize(&outputs[(point - 1) as usize].share_commitment)
                .unwrap(),
        })
        .collect();
    let by_endpoint: BTreeMap<String, u64> = nodes
        .iter()
        .map(|n| (n.endpoint.clone(), n.index))
        .collect();

    let capsule_proof: PlaintextProof<Params> =
        matter_kgc_config::wire::decode_tagged(&env.proof).expect("decode capsule proof");
    let committee = FakeCommittee {
        ctx,
        outputs,
        shared_a,
        capsule,
        capsule_proof,
        binding_id: env.binding_id.clone(),
        secret_id,
        by_endpoint,
        bad_epoch_node: None,
        unreachable_health: BTreeSet::new(),
        refuse_partial: BTreeSet::new(),
    };
    let signer = Sr25519Signer::from_seed_insecure_dev_only(&[9u8; 32]).unwrap();

    let recovered = decrypt(
        &committee,
        &signer,
        &DecryptRequest {
            secret_id,
            epoch: EPOCH,
            binding_id: &env.binding_id,
            aad: aad.as_bytes(),
            capsule: &env.capsule,
            ct: &env.ct,
            shared_a: &shared_a_bytes,
            block_hash: [0x11; 32],
            threshold: T,
            nodes: &nodes,
        },
    )
    .await
    .expect("quorum opens the secret");

    assert_eq!(recovered.expose(), plaintext);
}

#[tokio::test]
async fn recover_secret_composes_the_full_recovery() {
    // The one-call helper must round-trip a sealed envelope end to end from the
    // fetched pieces (envelope + committee state), taking the AAD as a registry
    // tag rather than raw bytes.
    let ctx = CrtContext::gen();
    let outputs = run_dkg(&ctx);
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);

    let secret_id = 0xda7a_u128;
    let aad = Aad::DatasetSourceCredsV1;
    // The canonical dataset-source payload shape (docs/agent-credential-delivery.md).
    let plaintext = br#"{"kind":"s3","bucket_name":"b","region":"eu-1","object_key":"k","access_key_id":"AK","secret_access_key":"SK"}"#;
    let joint_pk = bincode::serialize(&outputs[0].joint_pk).unwrap();
    let env = encrypt(&joint_pk, EPOCH, plaintext, aad.as_bytes(), None).expect("seal");
    let capsule: Ciphertext<Params> = bincode::deserialize(&env.capsule).unwrap();
    let capsule_proof: PlaintextProof<Params> =
        matter_kgc_config::wire::decode_tagged(&env.proof).expect("decode capsule proof");

    let nodes: Vec<CommitteeNode> = (1..=N)
        .map(|point| CommitteeNode {
            index: point,
            endpoint: format!("http://node-{point}"),
            share_commitment: bincode::serialize(&outputs[(point - 1) as usize].share_commitment)
                .unwrap(),
        })
        .collect();
    let by_endpoint: BTreeMap<String, u64> = nodes
        .iter()
        .map(|n| (n.endpoint.clone(), n.index))
        .collect();

    let committee_info = CommitteeInfo {
        epoch: EPOCH,
        threshold: T,
        shared_a: bincode::serialize(&shared_a).unwrap(),
        nodes,
        block_hash: [0x22; 32],
    };
    let committee = FakeCommittee {
        ctx,
        outputs,
        shared_a,
        capsule,
        capsule_proof,
        binding_id: env.binding_id.clone(),
        secret_id,
        by_endpoint,
        bad_epoch_node: None,
        unreachable_health: BTreeSet::new(),
        refuse_partial: BTreeSet::new(),
    };
    let signer = Sr25519Signer::from_seed_insecure_dev_only(&[7u8; 32]).unwrap();

    let recovered = recover_secret(&committee_info, &committee, &signer, secret_id, &env, aad)
        .await
        .expect("one-call helper opens the secret");

    assert_eq!(recovered.expose(), plaintext);
}

#[tokio::test]
async fn too_few_healthy_nodes_is_quorum_unavailable() {
    // Only one node offered, threshold 3 → no quorum, typed error, no panic.
    let ctx = CrtContext::gen();
    let outputs = run_dkg(&ctx);
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);
    let joint_pk = bincode::serialize(&outputs[0].joint_pk).unwrap();
    let env = encrypt(&joint_pk, EPOCH, b"X=1", Aad::EnvV1.as_bytes(), None).unwrap();
    let capsule: Ciphertext<Params> = bincode::deserialize(&env.capsule).unwrap();
    let shared_a_bytes = bincode::serialize(&shared_a).unwrap();

    let node = CommitteeNode {
        index: 1,
        endpoint: "http://node-1".into(),
        share_commitment: bincode::serialize(&outputs[0].share_commitment).unwrap(),
    };
    let capsule_proof: PlaintextProof<Params> =
        matter_kgc_config::wire::decode_tagged(&env.proof).expect("decode capsule proof");
    let committee = FakeCommittee {
        ctx,
        outputs,
        shared_a,
        capsule,
        capsule_proof,
        binding_id: env.binding_id.clone(),
        secret_id: 1,
        by_endpoint: BTreeMap::from([("http://node-1".to_string(), 1u64)]),
        bad_epoch_node: None,
        unreachable_health: BTreeSet::new(),
        refuse_partial: BTreeSet::new(),
    };
    let signer = Sr25519Signer::from_seed_insecure_dev_only(&[1u8; 32]).unwrap();

    let err = decrypt(
        &committee,
        &signer,
        &DecryptRequest {
            secret_id: 1,
            epoch: EPOCH,
            binding_id: &env.binding_id,
            aad: Aad::EnvV1.as_bytes(),
            capsule: &env.capsule,
            ct: &env.ct,
            shared_a: &shared_a_bytes,
            block_hash: [0; 32],
            threshold: T,
            nodes: std::slice::from_ref(&node),
        },
    )
    .await
    .expect_err("must not form a quorum");
    let matter_vault::SdkError::QuorumUnavailable {
        needed: 3,
        active: 1,
        ref faults,
    } = err
    else {
        panic!("expected QuorumUnavailable, got {err:?}");
    };
    // Nothing was *dropped* here — the caller simply supplied too few nodes.
    // Distinguishing that from "four nodes were dropped" is the whole point of
    // carrying the faults: both used to render as a bare count.
    assert!(
        faults.is_empty(),
        "no node failed, so no fault should be reported: {faults:?}"
    );
}

#[tokio::test]
async fn decrypt_excludes_a_node_serving_a_wrong_epoch() {
    // Node 1 (lowest index, picked into the first subset) claims a rotated epoch.
    // The SDK must drop it and form a quorum from the honest remainder rather than
    // let one misbehaving node deny the whole decrypt (MV-H2).
    let ctx = CrtContext::gen();
    let outputs = run_dkg(&ctx);
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);

    let secret_id = 0x0abc_u128;
    let aad = Aad::EnvV1;
    let plaintext = b"RESILIENT=yes";
    let joint_pk = bincode::serialize(&outputs[0].joint_pk).unwrap();
    let env = encrypt(&joint_pk, EPOCH, plaintext, aad.as_bytes(), None).expect("seal");
    let capsule: Ciphertext<Params> = bincode::deserialize(&env.capsule).unwrap();
    let shared_a_bytes = bincode::serialize(&shared_a).unwrap();
    let capsule_proof: PlaintextProof<Params> =
        matter_kgc_config::wire::decode_tagged(&env.proof).expect("decode capsule proof");

    let nodes: Vec<CommitteeNode> = (1..=N)
        .map(|point| CommitteeNode {
            index: point,
            endpoint: format!("http://node-{point}"),
            share_commitment: bincode::serialize(&outputs[(point - 1) as usize].share_commitment)
                .unwrap(),
        })
        .collect();
    let by_endpoint: BTreeMap<String, u64> = nodes
        .iter()
        .map(|n| (n.endpoint.clone(), n.index))
        .collect();

    let committee = FakeCommittee {
        ctx,
        outputs,
        shared_a,
        capsule,
        capsule_proof,
        binding_id: env.binding_id.clone(),
        secret_id,
        by_endpoint,
        bad_epoch_node: Some(1),
        unreachable_health: BTreeSet::new(),
        refuse_partial: BTreeSet::new(),
    };
    let signer = Sr25519Signer::from_seed_insecure_dev_only(&[5u8; 32]).unwrap();

    let recovered = decrypt(
        &committee,
        &signer,
        &DecryptRequest {
            secret_id,
            epoch: EPOCH,
            binding_id: &env.binding_id,
            aad: aad.as_bytes(),
            capsule: &env.capsule,
            ct: &env.ct,
            shared_a: &shared_a_bytes,
            block_hash: [0x11; 32],
            threshold: T,
            nodes: &nodes,
        },
    )
    .await
    .expect("quorum forms after excluding the node serving a wrong epoch");

    assert_eq!(recovered.expose(), plaintext);
}

/// The 2026-09-09 testnet shape, reproduced.
///
/// A guarded deployment failed to recover its policy DEK with
/// `quorum unavailable: need 3 healthy nodes, found 2`, twice, while all five
/// committee nodes answered `/health` 200 from the operator's laptop *and* from
/// the provider host running the container. Two nodes were reachable for
/// `/health` but refused the real request from that caller.
///
/// Diagnosing it took reading three servers' logs, because the SDK reported only
/// a count: every per-node reason was discarded at the drop site. This asserts
/// the error now carries what it took those logs to reconstruct.
#[tokio::test]
async fn quorum_unavailable_names_the_nodes_that_failed_and_why() {
    let ctx = CrtContext::gen();
    let outputs = run_dkg(&ctx);
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);

    let secret_id = 157u128;
    let joint_pk = bincode::serialize(&outputs[0].joint_pk).unwrap();
    let env = encrypt(&joint_pk, EPOCH, b"policy-dek", Aad::EnvV1.as_bytes(), None).expect("seal");
    let capsule: Ciphertext<Params> = bincode::deserialize(&env.capsule).unwrap();
    let shared_a_bytes = bincode::serialize(&shared_a).unwrap();

    let nodes: Vec<CommitteeNode> = (1..=N)
        .map(|point| CommitteeNode {
            index: point,
            endpoint: format!("http://node-{point}"),
            share_commitment: bincode::serialize(&outputs[(point - 1) as usize].share_commitment)
                .unwrap(),
        })
        .collect();
    let by_endpoint: BTreeMap<String, u64> = nodes
        .iter()
        .map(|n| (n.endpoint.clone(), n.index))
        .collect();
    let capsule_proof: PlaintextProof<Params> =
        matter_kgc_config::wire::decode_tagged(&env.proof).expect("decode capsule proof");

    let committee = FakeCommittee {
        ctx,
        outputs,
        shared_a,
        capsule,
        capsule_proof,
        binding_id: env.binding_id.clone(),
        secret_id,
        by_endpoint,
        bad_epoch_node: None,
        // node-1 is simply unreachable...
        unreachable_health: BTreeSet::from(["http://node-1".to_string()]),
        // ...while 4 and 5 pass /health and then refuse the real request.
        refuse_partial: BTreeSet::from(["http://node-4".to_string(), "http://node-5".to_string()]),
    };
    let signer = Sr25519Signer::from_seed_insecure_dev_only(&[1u8; 32]).unwrap();

    let err = decrypt(
        &committee,
        &signer,
        &DecryptRequest {
            secret_id,
            epoch: EPOCH,
            binding_id: &env.binding_id,
            aad: Aad::EnvV1.as_bytes(),
            capsule: &env.capsule,
            ct: &env.ct,
            shared_a: &shared_a_bytes,
            block_hash: [0; 32],
            threshold: T,
            nodes: &nodes,
        },
    )
    .await
    .expect_err("two nodes refuse the real request, so no subset completes");

    let matter_vault::SdkError::QuorumUnavailable { ref faults, .. } = err else {
        panic!("expected QuorumUnavailable, got {err:?}");
    };

    // The health-stage drop and both partial-decrypt refusals are all named.
    let by_index: BTreeMap<u64, &matter_vault::NodeFault> =
        faults.iter().map(|f| (f.index, f)).collect();

    assert_eq!(
        by_index[&1].stage,
        matter_vault::FaultStage::Health,
        "node 1 never answered /health"
    );
    for point in [4u64, 5] {
        assert_eq!(
            by_index[&point].stage,
            matter_vault::FaultStage::PartialDecrypt,
            "node {point} passed /health and then refused the real request"
        );
        assert!(
            by_index[&point].detail.contains("503"),
            "the node's own reason must survive: {:?}",
            by_index[&point].detail
        );
    }

    // And a caller that only logs `{e}` still gets all of it — which is what
    // `zkfw-policyd` does, and why the original incident was undiagnosable.
    let rendered = err.to_string();
    assert!(rendered.contains("http://node-1"), "{rendered}");
    assert!(rendered.contains("http://node-4"), "{rendered}");
    assert!(rendered.contains("503"), "{rendered}");
}
