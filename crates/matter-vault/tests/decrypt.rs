//! End-to-end orchestration tracer for the Rust SDK.
//!
//! A `FakeCommittee` implements [`Transport`] by computing *real* partial
//! decryptions with `matter-crypto` (it plays the role of `t` honest nodes), so
//! [`matter_vault::decrypt`] is exercised over its full path — quorum selection,
//! request building, signing, fan-out, aggregation, AEAD-open — without a socket.

use std::collections::BTreeMap;
use std::future::Future;

use matter_crypto::bgv::params::{SecureCipher, SecureParams};
use matter_crypto::bgv::poly::crt::CrtPoly;
use matter_crypto::bgv::poly::CrtContext;
use matter_crypto::bgv::Ciphertext;
use matter_crypto::dkg::{
    derive_shared_a,
    generate_contribution,
    process_contributions,
    DkgOutput,
};
use matter_crypto::secret::{lagrange_coefficient, produce_proven_partial};
use matter_crypto::zkp::zkp_aware_smudge_bits;
use matter_vault::{decrypt, CommitteeNode, DecryptRequest, Health, Sr25519Signer, Transport};
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
    secret_id: u128,
    by_endpoint: BTreeMap<String, u64>,
}

// The futures are built eagerly (compute, then return a ready future) so they
// stay `Send` without requiring the committee state to be `Sync` — hence the
// explicit `impl Future` form rather than `async fn`.
#[allow(clippy::manual_async_fn)]
impl Transport for FakeCommittee {
    fn health(&self, _endpoint: &str) -> impl Future<Output = matter_vault::Result<Health>> + Send {
        async move {
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
        let idx = (point - 1) as usize;
        let lambda = lagrange_coefficient::<Params>(point, &req.subset);
        let smudge = zkp_aware_smudge_bits::<Params>(req.subset.len());
        let (partial, proof) = produce_proven_partial::<Params>(
            &self.ctx,
            &self.outputs[idx].key_share,
            lambda,
            &self.capsule,
            &self.shared_a,
            &self.outputs[idx].share_commitment,
            smudge,
            &self.secret_id.to_be_bytes(),
            EPOCH as u64,
        );
        let resp = PartialDecryptResponse {
            node_index: point,
            partial: to_0x(&bincode::serialize(&partial).unwrap()),
            proof: to_0x(&bincode::serialize(&proof).unwrap()),
            crypto_protocol_version: 2,
            served_epoch: EPOCH,
            shared_a: None,
            joint_pk: None,
            served_threshold: T as u32,
        };
        async move { Ok(resp) }
    }
}

fn run_dkg(ctx: &CrtContext<Cipher>) -> Vec<DkgOutput<Params>> {
    let points: Vec<u64> = (1..=N).collect();
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);
    let contributions: Vec<_> = points
        .iter()
        .map(|&pt| generate_contribution::<Params>(ctx, pt, &points, T, &shared_a))
        .collect();
    points
        .iter()
        .map(|&pt| {
            process_contributions::<Params>(ctx, pt, &points, &contributions, &shared_a, T)
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

    let committee = FakeCommittee {
        ctx,
        outputs,
        shared_a,
        capsule,
        secret_id,
        by_endpoint,
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
    let committee = FakeCommittee {
        ctx,
        outputs,
        shared_a,
        capsule,
        secret_id: 1,
        by_endpoint: BTreeMap::from([("http://node-1".to_string(), 1u64)]),
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
    assert!(matches!(
        err,
        matter_vault::SdkError::QuorumUnavailable {
            needed: 3,
            active: 1
        }
    ));
}
