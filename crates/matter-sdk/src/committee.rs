//! Threshold-decrypt orchestration: choose a quorum, sign per node, collect
//! partials. All crypto stays in [`matter_sdk_core`].

use matter_sdk_core::wire::{from_0x, secret_id_to_hex, to_0x, PartialDecryptRequest};
use matter_sdk_core::{
    lagrange_for,
    open_secret,
    PartialInput,
    Plaintext,
    CRYPTO_PROTOCOL_VERSION,
};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;

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
    /// Bincode `FeldmanCommitment` (`g_j`) for the secret's epoch.
    pub share_commitment: Vec<u8>,
}

/// Everything needed to recover one secret. The caller reads `shared_a`,
/// `threshold`, node endpoints and per-node `share_commitment` from chain with
/// its own Substrate client.
#[derive(Debug, Clone)]
pub struct DecryptRequest<'a> {
    /// The secret id.
    pub secret_id: u128,
    /// The epoch the secret was sealed under; `shared_a` and commitments must match.
    pub epoch: u32,
    /// The binding id from the on-chain envelope.
    pub binding_id: &'a [u8],
    /// The AAD the secret was sealed under (use a [`matter_sdk_core::Aad`] tag).
    pub aad: &'a [u8],
    /// Bincode capsule from the envelope.
    pub capsule: &'a [u8],
    /// The `nonce ‖ ciphertext` from the envelope.
    pub ct: &'a [u8],
    /// Bincode `shared_a` for `epoch`.
    pub shared_a: &'a [u8],
    /// A recent finalized block hash; the freshness anchor for request signatures.
    pub block_hash: [u8; 32],
    /// The committee threshold `t` for `epoch`.
    pub threshold: usize,
    /// Candidate nodes; at least `threshold` must be healthy.
    pub nodes: &'a [CommitteeNode],
}

/// `0` (field absent) is accepted: the version tag on every proof still binds
/// the transcript.
fn speaks_our_protocol(reported: u16) -> bool {
    reported == 0 || reported == CRYPTO_PROTOCOL_VERSION
}

/// Choose `threshold` of `available` uniformly at random, in index order.
///
/// Random so no single node sees, or can deny, every decrypt.
fn choose_quorum<'n, R: Rng + ?Sized>(
    available: &[&'n CommitteeNode],
    threshold: usize,
    rng: &mut R,
) -> Vec<&'n CommitteeNode> {
    let mut chosen: Vec<&CommitteeNode> =
        available.choose_multiple(rng, threshold).copied().collect();
    chosen.sort_by_key(|n| n.index);
    chosen
}

/// Recover a secret from a threshold quorum of partial decryptions.
///
/// Health-probes nodes, picks `threshold` active ones at random, signs per node,
/// then verifies, aggregates, and AEAD-opens. A failing node is dropped and the
/// quorum re-formed. The returned [`Plaintext`] is a zeroizing buffer.
///
/// Errors: [`SdkError::QuorumUnavailable`] (with a [`NodeFault`] per dropped
/// node) if too few nodes are usable; [`SdkError::EpochRotated`] if the
/// committee served a different epoch (refetch and retry); [`SdkError::Core`]
/// with [`matter_sdk_core::CoreError::Aead`] if the secret cannot be opened.
pub async fn decrypt<T, S>(transport: &T, signer: &S, req: &DecryptRequest<'_>) -> Result<Plaintext>
where
    T: Transport,
    S: Signer,
{
    // 1. Health-probe sequentially (committees are small); record why each
    //    dropped node dropped.
    let mut active: Vec<&CommitteeNode> = Vec::new();
    let mut faults: Vec<NodeFault> = Vec::new();
    for node in req.nodes {
        match transport.health(&node.endpoint).await {
            Ok(health) if !speaks_our_protocol(health.crypto_protocol_version) => {
                faults.push(NodeFault {
                    index: node.index,
                    endpoint: node.endpoint.clone(),
                    stage: FaultStage::ProtocolVersion,
                    detail: format!(
                        "speaks crypto protocol v{}, this SDK speaks v{CRYPTO_PROTOCOL_VERSION}",
                        health.crypto_protocol_version
                    ),
                })
            }
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

    // 2. A node that fails or serves a different epoch is dropped and the subset
    //    re-formed, so one node cannot deny the decrypt. A genuine rotation is
    //    `threshold` nodes agreeing on the same new epoch. Each fault shrinks
    //    `available`, so the loop terminates.
    let mut available = active;
    let mut rotated_votes: std::collections::BTreeMap<u32, usize> =
        std::collections::BTreeMap::new();

    while available.len() >= req.threshold {
        let chosen = choose_quorum(&available, req.threshold, &mut OsRng);
        let subset: Vec<u64> = chosen.iter().map(|n| n.index).collect();

        let mut partials: Vec<PartialInput> = Vec::with_capacity(chosen.len());
        let mut faulty: Option<u64> = None;
        for node in &chosen {
            let lambda = lagrange_for(node.index, &subset)?;

            // The payload binds this node's index, so it cannot replay the auth
            // to a peer. The signer never reveals its key.
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

            // `threshold` votes for the same new epoch is a rotation; fewer is one
            // misbehaving node. 0 means an older node serving the current epoch.
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
                point: node.index,
                partial: from_0x("partial", &resp.partial)?,
                proof: from_0x("proof", &resp.proof)?,
                commitment: node.share_commitment.clone(),
            });
        }

        match faulty {
            Some(bad) => {
                available.retain(|n| n.index != bad);
                continue;
            }
            // 3. Verify, aggregate, and AEAD-open in the pure core.
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

    // Out of good nodes: report the most-voted divergent epoch as a rotation.
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;

    fn nodes(n: u64) -> Vec<CommitteeNode> {
        (1..=n)
            .map(|index| CommitteeNode {
                index,
                endpoint: format!("http://node-{index}"),
                share_commitment: Vec::new(),
            })
            .collect()
    }

    #[test]
    fn a_quorum_is_t_distinct_available_nodes_in_index_order() {
        let all = nodes(7);
        let available: Vec<&CommitteeNode> = all.iter().collect();
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..100 {
            let chosen = choose_quorum(&available, 4, &mut rng);
            let indices: Vec<u64> = chosen.iter().map(|n| n.index).collect();
            assert_eq!(indices.len(), 4);
            assert!(
                indices.windows(2).all(|w| w[0] < w[1]),
                "sorted and distinct: {indices:?}"
            );
        }
    }

    #[test]
    fn quorum_selection_is_not_the_fixed_lowest_indices() {
        let all = nodes(5);
        let available: Vec<&CommitteeNode> = all.iter().collect();
        let mut rng = StdRng::seed_from_u64(42);
        let draws: Vec<Vec<u64>> = (0..200)
            .map(|_| {
                choose_quorum(&available, 3, &mut rng)
                    .iter()
                    .map(|n| n.index)
                    .collect()
            })
            .collect();
        let distinct: BTreeSet<&Vec<u64>> = draws.iter().collect();
        assert!(distinct.len() > 1, "every draw was {:?}", draws[0]);
        for index in 1..=5u64 {
            let hits = draws.iter().filter(|d| d.contains(&index)).count();
            // Expected 120/200; 60 is a loose floor a skewed choice cannot meet.
            assert!(hits >= 60, "node {index} chosen only {hits}/200 times");
        }
    }
}
