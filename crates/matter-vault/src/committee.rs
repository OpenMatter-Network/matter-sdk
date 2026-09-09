//! Threshold-decrypt orchestration: form a quorum, sign once, fan out, open.
//!
//! This is the network-facing half the pure core deliberately omits. The crypto
//! still lives in [`matter_vault_core`]; here we only choose a quorum, build the
//! signed requests, collect the partials, and hand them back to the core.

use matter_vault_core::wire::{from_0x, secret_id_to_hex, to_0x, PartialDecryptRequest};
use matter_vault_core::{lagrange_for, open_secret, PartialInput, Plaintext};

use crate::error::{FaultStage, NodeFault, Result, SdkError};
use crate::signer::{Signer, SigningRequest};
use crate::transport::Transport;

/// One committee node the SDK can query, with the on-chain data a decryptor needs.
#[derive(Debug, Clone)]
pub struct CommitteeNode {
    /// The node's 1-based DKG evaluation point (`dkg_index`).
    pub index: u64,
    /// The node's public base URL (no trailing `/partial-decrypt`).
    pub endpoint: String,
    /// Bincode `FeldmanCommitment` (`g_j`) for the secret's epoch, read from chain.
    pub share_commitment: Vec<u8>,
}

/// Everything needed to recover one secret. The caller fetches the chain-derived
/// fields (`shared_a`, per-node `share_commitment`, `threshold`, node endpoints)
/// with its own Substrate client; the SDK owns the committee round trip.
#[derive(Debug, Clone)]
pub struct DecryptRequest<'a> {
    /// The secret id.
    pub secret_id: u128,
    /// The epoch the secret was sealed under (and that `shared_a`/commitments are for).
    pub epoch: u32,
    /// The secret's binding id (from its on-chain envelope).
    pub binding_id: &'a [u8],
    /// The AAD the secret was sealed under (use a [`matter_vault_core::Aad`] tag).
    pub aad: &'a [u8],
    /// Bincode capsule from the envelope.
    pub capsule: &'a [u8],
    /// The `nonce ‖ ciphertext` from the envelope.
    pub ct: &'a [u8],
    /// Bincode `shared_a` for `epoch`, read from chain.
    pub shared_a: &'a [u8],
    /// A recent finalized block hash (freshness anchor for the request signature).
    pub block_hash: [u8; 32],
    /// The committee threshold `t` in force for `epoch`.
    pub threshold: usize,
    /// The candidate committee nodes (at least `threshold` must be healthy).
    pub nodes: &'a [CommitteeNode],
}

/// Recover a secret by collecting and aggregating a threshold quorum of partial
/// decryptions.
///
/// Steps: health-probe → pick `threshold` active nodes → sign the request once →
/// query each node → verify + aggregate + AEAD-open. The returned [`Plaintext`]
/// is a zeroizing buffer.
///
/// Errors: [`SdkError::QuorumUnavailable`] if too few nodes are healthy — it
/// carries a [`NodeFault`] per dropped node saying which one and why, which is
/// the only place that information exists;
/// [`SdkError::EpochRotated`] if the committee served a different epoch than the
/// supplied state (refetch and retry); [`SdkError::Core`] with
/// [`matter_vault_core::CoreError::Aead`] if the secret can't be opened at all.
pub async fn decrypt<T, S>(transport: &T, signer: &S, req: &DecryptRequest<'_>) -> Result<Plaintext>
where
    T: Transport,
    S: Signer,
{
    // 1. Health-probe and keep the active nodes. Sequential: a committee is
    //    small, and concurrency here is an optimization to measure, not assume.
    //
    //    Every node that drops out records why. This used to be
    //    `if let Ok(health) = …`, which discarded both the transport error and
    //    the not-active case, leaving only a count — and a count cannot tell an
    //    operator whether the committee is down or this caller simply cannot
    //    reach part of it.
    let mut active: Vec<&CommitteeNode> = Vec::new();
    let mut faults: Vec<NodeFault> = Vec::new();
    for node in req.nodes {
        match transport.health(&node.endpoint).await {
            Ok(health) if health.is_active() => active.push(node),
            Ok(health) => faults.push(NodeFault {
                index: node.index,
                endpoint: node.endpoint.clone(),
                stage: FaultStage::Inactive,
                detail: format!(
                    "status {:?}, epoch {}, crypto protocol v{}",
                    health.status, health.epoch, health.crypto_protocol_version
                ),
            }),
            Err(e) => faults.push(NodeFault {
                index: node.index,
                endpoint: node.endpoint.clone(),
                stage: FaultStage::Health,
                detail: e.to_string(),
            }),
        }
    }
    if active.len() < req.threshold {
        return Err(SdkError::QuorumUnavailable {
            needed: req.threshold,
            active: active.len(),
            faults,
        });
    }
    active.sort_by_key(|n| n.index);

    // 2. Assemble a quorum. A node that fails or serves a *different* epoch is a
    //    per-node fault: drop it and re-form the subset from the remaining nodes,
    //    rather than letting one node deny the whole decrypt (audit MV-H2). A
    //    *genuine* rotation still surfaces as `threshold` nodes agreeing on the
    //    same new served_epoch (counted in `rotated_votes`). Each fault removes a
    //    node from `available`, so the loop terminates.
    let mut available = active;
    let mut rotated_votes: std::collections::BTreeMap<u32, usize> =
        std::collections::BTreeMap::new();

    while available.len() >= req.threshold {
        let chosen: Vec<&CommitteeNode> = available.iter().take(req.threshold).copied().collect();
        let subset: Vec<u64> = chosen.iter().map(|n| n.index).collect();

        let mut partials: Vec<PartialInput> = Vec::with_capacity(chosen.len());
        let mut faulty: Option<u64> = None;
        for node in &chosen {
            let lambda = lagrange_for(node.index, &subset)?;

            // Sign per node: the payload binds this node's index, so the auth
            // fields we hand it can't be replayed by it to any peer (MV-C1). The
            // signer never reveals its key; we only receive the auth fields.
            let auth = signer.authorize(&SigningRequest {
                secret_id: req.secret_id,
                subset: &subset,
                recipient_index: node.index,
                block_hash: req.block_hash,
                valid_until: None,
            })?;

            let request = PartialDecryptRequest {
                secret_id: secret_id_to_hex(req.secret_id),
                subset: subset.clone(),
                lagrange_coeff: to_0x(&lambda),
                requester: auth.requester,
                block_hash: to_0x(&req.block_hash),
                signature: auth.signature,
                auth: auth.auth,
                eth_address: auth.eth_address,
                valid_until: auth.valid_until,
                eth_signature: auth.eth_signature,
            };

            let resp = match transport.partial_decrypt(&node.endpoint, &request).await {
                Ok(resp) => resp,
                // Treat an unreachable/erroring node as a per-node fault — but
                // keep the reason: this is the drop that matters most, because a
                // node that passed `/health` and then refused the real request
                // is a different problem from one that was never reachable.
                Err(e) => {
                    faults.push(NodeFault {
                        index: node.index,
                        endpoint: node.endpoint.clone(),
                        stage: FaultStage::PartialDecrypt,
                        detail: e.to_string(),
                    });
                    faulty = Some(node.index);
                    break;
                }
            };

            // A served_epoch that differs means this node is serving a different
            // key than the caller's state is for. If a `threshold` of nodes agree
            // on the same new epoch it's a real rotation (fail loudly so the caller
            // refetches); otherwise it's one misbehaving node — drop it.
            // (0 = older node serving current.)
            if resp.served_epoch != 0 && resp.served_epoch != req.epoch {
                let votes = rotated_votes.entry(resp.served_epoch).or_insert(0);
                *votes += 1;
                if *votes >= req.threshold {
                    return Err(SdkError::EpochRotated {
                        served: resp.served_epoch,
                        provided: req.epoch,
                    });
                }
                faults.push(NodeFault {
                    index: node.index,
                    endpoint: node.endpoint.clone(),
                    stage: FaultStage::EpochMismatch,
                    detail: format!(
                        "served epoch {}, state supplied for {}",
                        resp.served_epoch, req.epoch
                    ),
                });
                faulty = Some(node.index);
                break;
            }

            partials.push(PartialInput {
                partial: from_0x("partial", &resp.partial)?,
                proof: from_0x("proof", &resp.proof)?,
                commitment: node.share_commitment.clone(),
                lambda,
            });
        }

        match faulty {
            Some(bad) => {
                available.retain(|n| n.index != bad);
                continue;
            }
            // 3. Verify the proofs, aggregate, and AEAD-open — all in the pure core.
            None => {
                return Ok(open_secret(
                    req.shared_a,
                    req.capsule,
                    req.secret_id,
                    req.epoch,
                    req.binding_id,
                    req.aad,
                    req.ct,
                    &partials,
                )?);
            }
        }
    }

    // Ran out of good nodes. If divergent served_epochs dominated, surface the most
    // common one as a rotation (refetch + retry); otherwise no quorum could form.
    if let Some((&served, _)) = rotated_votes.iter().max_by_key(|(_, &votes)| votes) {
        return Err(SdkError::EpochRotated {
            served,
            provided: req.epoch,
        });
    }
    Err(SdkError::QuorumUnavailable {
        needed: req.threshold,
        active: available.len(),
        faults,
    })
}
