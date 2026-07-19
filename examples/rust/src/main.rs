//! MatterVault Rust SDK — runnable end-to-end demo.
//!
//! Run with: `cargo run -p matter-vault-example`
//!
//! It seals a secret, shows the on-chain call you would submit, then recovers the
//! secret from a committee — all against a throwaway committee built in-process so
//! the demo needs no live network. In a real integration the committee runs
//! elsewhere; your app only ever calls `matter-vault`, and you submit the
//! `StoreSecret` call with your own Substrate client.

use std::collections::BTreeMap;
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
use matter_vault::matter_vault_core::wire::{to_0x, PartialDecryptRequest, PartialDecryptResponse};
use matter_vault::{
    decrypt,
    encrypt,
    Aad,
    CommitteeNode,
    DecryptRequest,
    Health,
    Sr25519Signer,
    StoreSecret,
    Transport,
};

type Params = SecureParams;
type Cipher = SecureCipher;

const N: u64 = 5;
const T: usize = 3;
const EPOCH: u32 = 0;
const SEED: &[u8] = b"matter-vault-example-committee";

#[tokio::main]
async fn main() {
    println!("MatterVault demo: seal a secret, then recover it from a {T}-of-{N} committee.\n");

    // --- A throwaway committee (stands in for nodes you'd reach over HTTP). ---
    let ctx = CrtContext::gen();
    let outputs = run_dkg(&ctx);
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);
    let joint_pk = bincode::serialize(&outputs[0].joint_pk).unwrap();

    // === 1. SEAL (pure, no network) ==========================================
    let secret_id = 0xc0ffee_u128; // your chain assigns this when you store.
    let plaintext = b"DATABASE_URL=postgres://prod\nAPI_KEY=swordfish";
    let env = encrypt(&joint_pk, EPOCH, plaintext, Aad::EnvV1.as_bytes(), None).expect("seal");
    println!(
        "Sealed {} bytes -> capsule {}B, proof {}B, ct {}B",
        plaintext.len(),
        env.capsule.len(),
        env.proof.len(),
        env.ct.len()
    );

    // === 2. STORE (you submit these args with your own Substrate client) ======
    let store = StoreSecret::new(env.clone(), EPOCH, b"prod-env".to_vec(), Aad::EnvV1);
    println!(
        "Would submit secrets.storeSecret(payload, epoch={}, label={:?}, aad={:?})",
        store.epoch,
        String::from_utf8_lossy(&store.label),
        String::from_utf8_lossy(&store.aad),
    );

    // === 3. DECRYPT (collect a threshold quorum from the committee) ==========
    let committee = LocalCommittee::new(
        ctx,
        outputs,
        shared_a.clone(),
        &env.capsule,
        &env.proof,
        &env.binding_id,
        secret_id,
    );
    let nodes = committee.nodes();
    let shared_a_bytes = bincode::serialize(&shared_a).unwrap();
    // Dev-only signer: never load a raw key like this in production.
    let signer = Sr25519Signer::from_seed_insecure_dev_only(&[42u8; 32]).expect("signer");

    let recovered = decrypt(
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
            block_hash: [0x11; 32],
            threshold: T,
            nodes: &nodes,
        },
    )
    .await
    .expect("quorum opens the secret");

    assert_eq!(recovered.expose(), plaintext);
    println!("\nRecovered secret matches the original. ✔");
}

// --------------------------------------------------------------------------
// Everything below mimics the committee; a real app never writes any of it.
// --------------------------------------------------------------------------

struct LocalCommittee {
    ctx: CrtContext<Cipher>,
    outputs: Vec<DkgOutput<Params>>,
    shared_a: CrtPoly<Cipher>,
    capsule: Ciphertext<Params>,
    capsule_proof: PlaintextProof<Params>,
    binding_id: Vec<u8>,
    secret_id: u128,
    by_endpoint: BTreeMap<String, u64>,
}

impl LocalCommittee {
    fn new(
        ctx: CrtContext<Cipher>,
        outputs: Vec<DkgOutput<Params>>,
        shared_a: CrtPoly<Cipher>,
        capsule_bytes: &[u8],
        proof_bytes: &[u8],
        binding_id: &[u8],
        secret_id: u128,
    ) -> Self {
        let capsule: Ciphertext<Params> = bincode::deserialize(capsule_bytes).unwrap();
        let capsule_proof: PlaintextProof<Params> =
            matter_kgc_config::wire::decode_tagged(proof_bytes).expect("decode capsule proof");
        let by_endpoint = (1..=N).map(|p| (format!("http://node-{p}"), p)).collect();
        Self {
            ctx,
            outputs,
            shared_a,
            capsule,
            capsule_proof,
            binding_id: binding_id.to_vec(),
            secret_id,
            by_endpoint,
        }
    }

    fn nodes(&self) -> Vec<CommitteeNode> {
        (1..=N)
            .map(|point| CommitteeNode {
                index: point,
                endpoint: format!("http://node-{point}"),
                share_commitment: bincode::serialize(
                    &self.outputs[(point - 1) as usize].share_commitment,
                )
                .unwrap(),
            })
            .collect()
    }
}

#[allow(clippy::manual_async_fn)] // eager build keeps the future Send without Sync state
impl Transport for LocalCommittee {
    fn health(&self, _endpoint: &str) -> impl Future<Output = matter_vault::Result<Health>> + Send {
        async move {
            Ok(Health {
                status: "active".to_string(),
                epoch: EPOCH,
                crypto_protocol_version: 2,
            })
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
