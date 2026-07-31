//! MV-C1 replay attack, reproduced and defeated with real crypto — offline.
//!
//! A committee node's decision is faithfully simulated: on each `/partial-decrypt`
//! the fake node reconstructs the signing payload **with its own index** and
//! verifies the sr25519 signature before producing a *real* `matter-crypto`
//! partial (exactly what the live node does). That reproduces the attack
//! end-to-end without a socket:
//!
//! * `v1` scheme (pre-fix): the payload binds no node, so one signature verifies
//!   at every node — a single malicious in-subset node replays it to the others,
//!   harvests `t` partials, and opens the secret alone. **Attack succeeds.**
//! * `v2` scheme (this fix): the payload binds the responding node's index, so a
//!   signature made for node `i` fails at every other node. The replayer collects
//!   one partial, never a quorum. **Attack defeated.**
//! * The honest SDK path (`decrypt`, signing per node) still opens the secret
//!   under `v2`. **No regression.**

use std::collections::BTreeMap;
use std::future::Future;
use std::str::FromStr;

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
use matter_vault::{decrypt, CommitteeNode, DecryptRequest, Health, Sr25519Signer, Transport};
use matter_vault_core::wire::{
    from_0x,
    secret_id_to_hex,
    to_0x,
    PartialDecryptRequest,
    PartialDecryptResponse,
};
use matter_vault_core::{
    encrypt,
    lagrange_for,
    open_secret,
    signing_payload,
    Aad,
    EncryptedSecret,
    PartialInput,
};
use subxt_signer::sr25519::{self, Keypair};
use subxt_signer::SecretUri;

type Params = SecureParams;
type Cipher = SecureCipher;

const SEED: &[u8] = b"mvc1-replay-attack-fixture";
const N: u64 = 5;
const T: usize = 3;
const EPOCH: u32 = 0;
const SECRET_ID: u128 = 0xC1;
const SIGNER_SEED: [u8; 32] = [9u8; 32];
const BLOCK_HASH: [u8; 32] = [0x11; 32];

/// The `/partial-decrypt` payload the *deployed* committee verified before MV-C1
/// (domain `v1`, no responding-node binding). Inlined here because the SDK no
/// longer produces it — it is the attacker's knowledge of the old protocol.
fn v1_payload(secret_id: u128, subset: &[u64], block_hash: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"matter-kgc/partial-decrypt/v1/");
    buf.extend_from_slice(&secret_id.to_be_bytes());
    buf.extend_from_slice(&(subset.len() as u64).to_be_bytes());
    for s in subset {
        buf.extend_from_slice(&s.to_be_bytes());
    }
    buf.extend_from_slice(block_hash);
    buf
}

#[derive(Clone, Copy, PartialEq)]
enum Scheme {
    /// Pre-fix: verify the v1 payload (no node binding).
    V1,
    /// This fix: verify the v2 payload bound to the node's own index.
    V2,
}

/// The DKG output + sealed secret, produced once and shared by reference (the
/// crypto types are intentionally not `Clone`).
struct Fixture {
    ctx: CrtContext<Cipher>,
    outputs: Vec<DkgOutput<Params>>,
    shared_a: CrtPoly<Cipher>,
    shared_a_bytes: Vec<u8>,
    capsule: Ciphertext<Params>,
    capsule_proof: PlaintextProof<Params>,
    env: EncryptedSecret,
    plaintext: Vec<u8>,
    nodes: Vec<CommitteeNode>,
    by_endpoint: BTreeMap<String, u64>,
}

fn dkg_and_seal() -> Fixture {
    let ctx = CrtContext::gen();
    let points: Vec<u64> = (1..=N).collect();
    let shared_a = derive_shared_a::<Cipher>(SEED, EPOCH);
    let ssid = [SEED, b"/ssid", &EPOCH.to_be_bytes()].concat();
    let contributions: Vec<_> = points
        .iter()
        .map(|&pt| generate_contribution::<Params>(&ctx, pt, &points, T, &shared_a))
        .collect();
    let prior_commitments: Vec<_> = contributions
        .iter()
        .map(|c| commit_to_contribution(c, &ssid, &c.nonce))
        .collect();
    let outputs: Vec<DkgOutput<Params>> = points
        .iter()
        .map(|&pt| {
            process_contributions::<Params>(
                &ctx,
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
        .collect();

    let plaintext = b"API_KEY=swordfish\nDATABASE_URL=postgres://prod".to_vec();
    let joint_pk = bincode::serialize(&outputs[0].joint_pk).unwrap();
    let env = encrypt(&joint_pk, EPOCH, &plaintext, Aad::EnvV1.as_bytes(), None).expect("seal");
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
    let by_endpoint = nodes
        .iter()
        .map(|n| (n.endpoint.clone(), n.index))
        .collect();

    Fixture {
        shared_a_bytes: bincode::serialize(&shared_a).unwrap(),
        ctx,
        outputs,
        shared_a,
        capsule,
        capsule_proof,
        env,
        plaintext,
        nodes,
        by_endpoint,
    }
}

/// `t` honest nodes that **verify the request signature the way the real node
/// does** — reconstructing the payload with their own index — before producing a
/// real partial. A failed verification is a per-node fault (the SDK drops it),
/// mirroring the live 401.
struct VerifyingCommittee<'a> {
    fx: &'a Fixture,
    scheme: Scheme,
}

impl VerifyingCommittee<'_> {
    /// Reproduce the node's authentication decision for `our_index`.
    fn authenticates(&self, our_index: u64, req: &PartialDecryptRequest) -> bool {
        let expected = match self.scheme {
            Scheme::V1 => v1_payload(SECRET_ID, &req.subset, &BLOCK_HASH),
            Scheme::V2 => signing_payload(SECRET_ID, &req.subset, &BLOCK_HASH, our_index),
        };
        let (Ok(requester), Ok(multisig)) = (
            from_0x("requester", &req.requester),
            from_0x("signature", &req.signature),
        ) else {
            return false;
        };
        // SCALE MultiSignature = 1-byte Sr25519 variant (0x01) ‖ 64-byte sig.
        if requester.len() != 32 || multisig.len() != 65 || multisig[0] != 0x01 {
            return false;
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&multisig[1..]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&requester);
        sr25519::verify(&sr25519::Signature(sig), &expected, &sr25519::PublicKey(pk))
    }

    fn real_partial(&self, point: u64, subset: &[u64]) -> PartialDecryptResponse {
        let idx = (point - 1) as usize;
        let lambda = lagrange_coefficient::<Params>(point, subset);
        let smudge = zkp_aware_smudge_bits::<Params>(subset.len());
        let (partial, proof) = produce_proven_partial::<Params>(
            &self.fx.ctx,
            &self.fx.outputs[idx].joint_pk,
            &self.fx.outputs[idx].key_share,
            lambda,
            &self.fx.capsule,
            &self.fx.capsule_proof,
            &self.fx.shared_a,
            &self.fx.outputs[idx].share_commitment,
            smudge,
            &self.fx.env.binding_id,
            &SECRET_ID.to_be_bytes(),
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
    }
}

#[allow(clippy::manual_async_fn)]
impl Transport for VerifyingCommittee<'_> {
    fn health(&self, _endpoint: &str) -> impl Future<Output = matter_vault::Result<Health>> + Send {
        async move {
            Ok(serde_json::from_value(serde_json::json!({
                "status": "active", "epoch": EPOCH, "crypto_protocol_version": 2
            }))
            .unwrap())
        }
    }

    fn partial_decrypt(
        &self,
        endpoint: &str,
        req: &PartialDecryptRequest,
    ) -> impl Future<Output = matter_vault::Result<PartialDecryptResponse>> + Send {
        let point = self.fx.by_endpoint[endpoint];
        // Only nodes that authenticate the (possibly replayed) signature answer.
        let resp = self
            .authenticates(point, req)
            .then(|| self.real_partial(point, &req.subset));
        async move {
            resp.ok_or_else(|| {
                matter_vault::SdkError::Signer("node rejected the request signature".into())
            })
        }
    }
}

/// Frame an sr25519 signature over `payload` as the wire `(requester, signature)`
/// pair — exactly what the SDK's `Sr25519Signer` emits.
fn sign_wire(keypair: &Keypair, payload: &[u8]) -> (String, String) {
    let sig = keypair.sign(payload);
    let mut multisig = Vec::with_capacity(65);
    multisig.push(0x01); // MultiSignature::Sr25519
    multisig.extend_from_slice(&sig.0);
    (to_0x(&keypair.public_key().0), to_0x(&multisig))
}

/// The MV-C1 attack: a single malicious in-subset node holds ONE authorized
/// signature and replays it to every node in the subset, harvesting partials to
/// open the secret alone. Returns the recovered plaintext if the attack works.
///
/// `scheme` picks which single signature the malicious node holds:
/// * `V1` — the lone, non-node-bound signature the old protocol produced.
/// * `V2` — the signature the requester made **for the malicious node itself**
///   (`subset[0]`), the only one it legitimately receives under the fix.
fn replay_attack(
    committee: &VerifyingCommittee,
    keypair: &Keypair,
    scheme: Scheme,
) -> Option<Vec<u8>> {
    let fx = committee.fx;
    let subset: Vec<u64> = fx.nodes.iter().take(T).map(|n| n.index).collect();
    let payload = match scheme {
        Scheme::V1 => v1_payload(SECRET_ID, &subset, &BLOCK_HASH),
        Scheme::V2 => signing_payload(SECRET_ID, &subset, &BLOCK_HASH, subset[0]),
    };
    let (requester, signature) = sign_wire(keypair, &payload);

    // Replay the identical requester+signature to every node, computing each
    // node's public Lagrange coefficient locally (as MV-C1 describes).
    let mut partials: Vec<PartialInput> = Vec::new();
    for node in fx.nodes.iter().take(T) {
        let lambda = lagrange_for(node.index, &subset).unwrap();
        let req = PartialDecryptRequest {
            secret_id: secret_id_to_hex(SECRET_ID),
            subset: subset.clone(),
            lagrange_coeff: to_0x(&lambda),
            requester: requester.clone(),
            block_hash: to_0x(&BLOCK_HASH),
            signature: signature.clone(),
            auth: Default::default(),
            eth_address: None,
            valid_until: None,
            eth_signature: None,
        };
        if !committee.authenticates(node.index, &req) {
            continue; // the live node returns 401; no partial
        }
        let resp = committee.real_partial(node.index, &subset);
        partials.push(PartialInput {
            partial: from_0x("partial", &resp.partial).unwrap(),
            proof: from_0x("proof", &resp.proof).unwrap(),
            commitment: node.share_commitment.clone(),
            lambda,
        });
    }

    if partials.len() < T {
        return None; // below threshold → the attack can't even attempt to open
    }
    open_secret(
        &fx.shared_a_bytes,
        &fx.env.capsule,
        SECRET_ID,
        EPOCH,
        &fx.env.binding_id,
        Aad::EnvV1.as_bytes(),
        &fx.env.ct,
        &partials,
    )
    .ok()
    .map(|pt| pt.expose().to_vec())
}

fn attacker_keypair() -> Keypair {
    let uri = SecretUri::from_str(&format!("0x{}", hex::encode(SIGNER_SEED))).unwrap();
    Keypair::from_uri(&uri).unwrap()
}

#[tokio::test]
async fn recipient_binding_defeats_the_replay_attack() {
    let fx = dkg_and_seal();
    let keypair = attacker_keypair();

    // (1) Pre-fix: against v1 nodes, one replayed signature harvests a quorum.
    let v1 = VerifyingCommittee {
        fx: &fx,
        scheme: Scheme::V1,
    };
    let stolen = replay_attack(&v1, &keypair, Scheme::V1);
    assert_eq!(
        stolen.as_deref(),
        Some(fx.plaintext.as_slice()),
        "MV-C1 (pre-fix): a single in-subset node recovers the secret by replay"
    );

    // (2) This fix: against v2 nodes, the same replay is rejected by every peer,
    //     so the attacker never reaches a quorum.
    let v2 = VerifyingCommittee {
        fx: &fx,
        scheme: Scheme::V2,
    };
    let defeated = replay_attack(&v2, &keypair, Scheme::V2);
    assert_eq!(
        defeated, None,
        "MV-C1 (fixed): recipient binding stops the replay below threshold"
    );

    // (3) No regression: the honest SDK path (signs per node) still opens it.
    let signer = Sr25519Signer::from_seed_insecure_dev_only(&SIGNER_SEED).unwrap();
    let recovered = decrypt(
        &v2,
        &signer,
        &DecryptRequest {
            secret_id: SECRET_ID,
            epoch: EPOCH,
            binding_id: &fx.env.binding_id,
            aad: Aad::EnvV1.as_bytes(),
            capsule: &fx.env.capsule,
            ct: &fx.env.ct,
            shared_a: &fx.shared_a_bytes,
            block_hash: BLOCK_HASH,
            threshold: T,
            nodes: &fx.nodes,
        },
    )
    .await
    .expect("authorized per-node signing still opens the secret");
    assert_eq!(recovered.expose(), fx.plaintext.as_slice());
}
