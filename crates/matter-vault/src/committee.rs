//! Threshold-decrypt orchestration: form a quorum, sign once, fan out, open.
//!
//! This is the network-facing half the pure core deliberately omits. The crypto
//! still lives in [`matter_vault_core`]; here we only choose a quorum, build the
//! signed requests, collect the partials, and hand them back to the core.

use matter_vault_core::wire::{from_0x, secret_id_to_hex, to_0x, PartialDecryptRequest};
use matter_vault_core::{lagrange_for, open_secret, PartialInput, Plaintext};

use crate::error::{Result, SdkError};
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
/// Errors: [`SdkError::QuorumUnavailable`] if too few nodes are healthy;
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
    let mut active: Vec<&CommitteeNode> = Vec::new();
    for node in req.nodes {
        if let Ok(health) = transport.health(&node.endpoint).await {
            if health.is_active() {
                active.push(node);
            }
        }
    }
    if active.len() < req.threshold {
        return Err(SdkError::QuorumUnavailable {
            needed: req.threshold,
            active: active.len(),
        });
    }

    // 2. Choose the lowest-indexed `threshold` nodes as the subset `S`.
    active.sort_by_key(|n| n.index);
    let chosen: Vec<&CommitteeNode> = active.into_iter().take(req.threshold).collect();
    let subset: Vec<u64> = chosen.iter().map(|n| n.index).collect();

    // 3. Sign once for this (secret, subset, block_hash). The signer never
    //    reveals its key; we only receive the auth fields.
    let auth = signer.authorize(&SigningRequest {
        secret_id: req.secret_id,
        subset: &subset,
        block_hash: req.block_hash,
        valid_until: None,
    })?;

    // 4. Query each chosen node and collect its partial.
    let mut partials: Vec<PartialInput> = Vec::with_capacity(chosen.len());
    for node in &chosen {
        let lambda = lagrange_for(node.index, &subset)?;
        let request = PartialDecryptRequest {
            secret_id: secret_id_to_hex(req.secret_id),
            subset: subset.clone(),
            lagrange_coeff: to_0x(&lambda),
            requester: auth.requester.clone(),
            block_hash: to_0x(&req.block_hash),
            signature: auth.signature.clone(),
            auth: auth.auth,
            eth_address: auth.eth_address.clone(),
            valid_until: auth.valid_until,
            eth_signature: auth.eth_signature.clone(),
        };
        let resp = transport.partial_decrypt(&node.endpoint, &request).await?;

        // A served_epoch that differs means a rotation happened and the caller's
        // shared_a/commitments are for the wrong key. Fail loudly rather than
        // aggregate against the wrong key. (0 = older node serving current.)
        if resp.served_epoch != 0 && resp.served_epoch != req.epoch {
            return Err(SdkError::EpochRotated {
                served: resp.served_epoch,
                provided: req.epoch,
            });
        }

        partials.push(PartialInput {
            partial: from_0x("partial", &resp.partial)?,
            proof: from_0x("proof", &resp.proof)?,
            commitment: node.share_commitment.clone(),
            lambda,
        });
    }

    // 5. Verify the proofs, aggregate, and AEAD-open — all in the pure core.
    Ok(open_secret(
        req.shared_a,
        req.capsule,
        req.secret_id,
        req.epoch,
        req.binding_id,
        req.aad,
        req.ct,
        &partials,
    )?)
}
