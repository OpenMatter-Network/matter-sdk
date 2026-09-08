//! One-call recovery of a stored secret.
//!
//! [`crate::recover_secret`] leaves the chain reads to the caller. Doing them here, once,
//! means every embedded consumer assembles the committee the same way instead of each
//! porting the same runtime-API calls — and the guard, the agent and a test double all
//! see the same refusals.

use matter_vault_core::wire::AuthScheme;
use parity_scale_codec::{Decode, Encode};
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::PolkadotConfig;

use crate::committee::CommitteeNode;
use crate::error::{Result, SdkError};
use crate::signer::{partial_decrypt_auth, RequestAuth, Signer, SigningRequest};
use crate::{Aad, CommitteeInfo, EncryptedSecret, KeySigner};

const SECRET_PAYLOAD: &str = "SecretsApi_secret_payload";
const SECRET_EPOCH: &str = "SecretsApi_secret_epoch";
const SECRET_AAD: &str = "SecretsApi_secret_aad";
const DKG_OUTPUT_AT_EPOCH: &str = "KgcApi_dkg_output_at_epoch";
const THRESHOLD_AT_EPOCH: &str = "KgcApi_threshold_params_at_epoch";
const COMMITTEE_AT_EPOCH: &str = "KgcApi_committee_at_epoch";
const KGC_NODES: &str = "KgcApi_kgc_nodes";
const SHARE_COMMITMENT: &str = "KgcApi_share_commitment";

type Rpc = LegacyRpcMethods<PolkadotConfig>;
type Account = [u8; 32];

/// `EncryptedSecret` as the chain encodes it: four length-prefixed byte strings, in this
/// order. Decoded here rather than through the metadata so the layout is pinned by a test.
#[derive(Decode)]
struct ChainEnvelope {
    binding_id: Vec<u8>,
    capsule: Vec<u8>,
    proof: Vec<u8>,
    ct: Vec<u8>,
}

/// `pallet_kgc::KgcNodeInfo` as the chain encodes it. The registry's index is decoded only
/// to keep the layout honest; the epoch's committee snapshot is the authority on indices.
#[derive(Decode)]
struct ChainNodeInfo {
    endpoint: Vec<u8>,
    _dkg_index: u64,
}

/// A stored secret as the chain holds it.
pub(super) struct StoredSecret {
    pub envelope: EncryptedSecret,
    pub epoch: u32,
    /// The AAD the sealer committed to. Empty for secrets stored before the chain recorded
    /// it; those can only be opened by a caller who already knows the tag.
    pub aad: Vec<u8>,
}

/// Frames a client's key as committee-request authorization, so a client built from one
/// API key needs no second signer type.
pub(super) struct KeyAuth<'a>(pub &'a dyn KeySigner);

impl Signer for KeyAuth<'_> {
    fn auth_scheme(&self) -> AuthScheme {
        AuthScheme::Substrate
    }

    fn authorize(&self, req: &SigningRequest<'_>) -> Result<RequestAuth> {
        partial_decrypt_auth(self.0, req)
    }
}

fn chain_err(target: &str, detail: impl std::fmt::Display) -> SdkError {
    SdkError::Chain {
        target: target.to_string(),
        detail: detail.to_string(),
    }
}

async fn call<T: Decode>(rpc: &Rpc, method: &str, args: &[u8]) -> Result<T> {
    let bytes = rpc
        .state_call(method, Some(args), None)
        .await
        .map_err(|e| chain_err(method, e))?;
    T::decode(&mut &bytes[..]).map_err(|e| chain_err(method, e))
}

pub(super) async fn read_secret(rpc: &Rpc, secret_id: u128) -> Result<StoredSecret> {
    let args = secret_id.encode();
    let envelope: Option<ChainEnvelope> = call(rpc, SECRET_PAYLOAD, &args).await?;
    let envelope = envelope
        .ok_or_else(|| chain_err(SECRET_PAYLOAD, format!("secret {secret_id} does not exist")))?;
    let epoch: Option<u32> = call(rpc, SECRET_EPOCH, &args).await?;
    let epoch = epoch
        .ok_or_else(|| chain_err(SECRET_EPOCH, format!("secret {secret_id} has no record")))?;
    let aad: Option<Vec<u8>> = call(rpc, SECRET_AAD, &args).await?;
    Ok(StoredSecret {
        envelope: EncryptedSecret {
            binding_id: envelope.binding_id,
            capsule: envelope.capsule,
            proof: envelope.proof,
            ct: envelope.ct,
        },
        epoch,
        aad: aad.unwrap_or_default(),
    })
}

/// Refuse to open a secret under a tag it was not sealed under: the open would fail
/// anyway, but only after a committee round trip, and with an error that blames the
/// ciphertext rather than the caller's tag.
pub(super) fn check_aad(secret_id: u128, sealed_under: &[u8], requested: Aad) -> Result<()> {
    if sealed_under.is_empty() || sealed_under == requested.as_bytes() {
        return Ok(());
    }
    Err(SdkError::AadMismatch {
        secret_id,
        sealed_under: String::from_utf8_lossy(sealed_under).into_owned(),
        requested: String::from_utf8_lossy(requested.as_bytes()).into_owned(),
    })
}

pub(super) async fn committee_info(rpc: &Rpc, epoch: u32) -> Result<CommitteeInfo> {
    let epoch_args = epoch.encode();
    let output: Option<(Vec<u8>, Vec<u8>)> = call(rpc, DKG_OUTPUT_AT_EPOCH, &epoch_args).await?;
    let (_joint_pk, shared_a) = output.ok_or_else(|| {
        chain_err(
            DKG_OUTPUT_AT_EPOCH,
            format!("no DKG output at epoch {epoch}"),
        )
    })?;
    let (_committee_size, threshold): (u64, u64) =
        call(rpc, THRESHOLD_AT_EPOCH, &epoch_args).await?;
    let committee: Vec<(Account, u64)> = call(rpc, COMMITTEE_AT_EPOCH, &epoch_args).await?;
    if committee.is_empty() {
        return Err(chain_err(
            COMMITTEE_AT_EPOCH,
            format!("no committee seated at epoch {epoch}"),
        ));
    }
    let registry: Vec<(Account, ChainNodeInfo)> = call(rpc, KGC_NODES, &[]).await?;
    let endpoints: Vec<(Account, Vec<u8>)> = registry
        .into_iter()
        .map(|(id, info)| (id, info.endpoint))
        .collect();
    let mut commitments: Vec<(Account, Vec<u8>)> = Vec::with_capacity(committee.len());
    for (id, _) in &committee {
        let g_j: Option<Vec<u8>> = call(rpc, SHARE_COMMITMENT, &(epoch, *id).encode()).await?;
        if let Some(g_j) = g_j {
            commitments.push((*id, g_j));
        }
    }
    let nodes = assemble_nodes(&committee, &endpoints, &commitments, epoch)?;
    if (nodes.len() as u64) < threshold {
        return Err(chain_err(
            KGC_NODES,
            format!(
                "only {} of epoch {epoch}'s committee is reachable; need {threshold}",
                nodes.len()
            ),
        ));
    }
    let head = rpc
        .chain_get_finalized_head()
        .await
        .map_err(|e| chain_err("chain_getFinalizedHead", e))?;
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(head.as_ref());
    Ok(CommitteeInfo {
        epoch,
        threshold: threshold as usize,
        shared_a,
        nodes,
        block_hash,
    })
}

/// Join an epoch's committee against the current registry's endpoints and the epoch's
/// share commitments, sorted by DKG index.
///
/// A member rotated out of the registry, or announcing an endpoint that is not an absolute
/// `http(s)` URL, is dropped: the quorum tolerates up to `n - t` missing members. A kept
/// member without its share commitment is an error, since its partial could never be
/// verified without `g_j`.
fn assemble_nodes(
    committee: &[(Account, u64)],
    endpoints: &[(Account, Vec<u8>)],
    commitments: &[(Account, Vec<u8>)],
    epoch: u32,
) -> Result<Vec<CommitteeNode>> {
    let lookup = |table: &[(Account, Vec<u8>)], id: &Account| -> Option<Vec<u8>> {
        table.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone())
    };
    let mut nodes = Vec::with_capacity(committee.len());
    for (id, dkg_index) in committee {
        let Some(endpoint) = lookup(endpoints, id).and_then(|raw| parse_endpoint(&raw)) else {
            continue;
        };
        let share_commitment = lookup(commitments, id).ok_or_else(|| {
            chain_err(
                SHARE_COMMITMENT,
                format!("share commitment missing for reachable node {dkg_index} at epoch {epoch}"),
            )
        })?;
        nodes.push(CommitteeNode {
            index: *dkg_index,
            endpoint,
            share_commitment,
        });
    }
    nodes.sort_by_key(|n| n.index);
    Ok(nodes)
}

/// An on-chain endpoint as the transport expects it, or `None` for anything that is not an
/// absolute `http(s)` URL.
fn parse_endpoint(raw: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(raw).ok()?.trim();
    (s.starts_with("https://") || s.starts_with("http://"))
        .then(|| s.trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(n: u8) -> Account {
        [n; 32]
    }

    fn committee() -> Vec<(Account, u64)> {
        vec![(acct(3), 30), (acct(1), 10), (acct(2), 20)]
    }

    fn endpoints() -> Vec<(Account, Vec<u8>)> {
        vec![
            (acct(1), b"https://kgc1.example".to_vec()),
            (acct(2), b"https://kgc2.example/".to_vec()),
            (acct(3), b"https://kgc3.example".to_vec()),
        ]
    }

    fn commitments() -> Vec<(Account, Vec<u8>)> {
        vec![
            (acct(1), b"g1".to_vec()),
            (acct(2), b"g2".to_vec()),
            (acct(3), b"g3".to_vec()),
        ]
    }

    fn indices(nodes: &[CommitteeNode]) -> Vec<u64> {
        nodes.iter().map(|n| n.index).collect()
    }

    #[test]
    fn assemble_nodes_joins_the_tables_and_sorts_by_dkg_index() {
        let nodes = assemble_nodes(&committee(), &endpoints(), &commitments(), 7).unwrap();
        assert_eq!(indices(&nodes), vec![10, 20, 30]);
        assert_eq!(
            nodes[1].endpoint, "https://kgc2.example",
            "trailing slash trimmed"
        );
        assert_eq!(nodes[1].share_commitment, b"g2");
    }

    #[test]
    fn assemble_nodes_drops_members_the_registry_no_longer_lists_or_that_announce_junk() {
        let endpoints = vec![
            (acct(1), b"https://kgc1.example".to_vec()),
            (acct(2), b"ftp://kgc2.example".to_vec()),
        ];
        let nodes = assemble_nodes(&committee(), &endpoints, &commitments(), 7).unwrap();
        assert_eq!(indices(&nodes), vec![10]);
    }

    #[test]
    fn assemble_nodes_refuses_a_kept_member_without_its_share_commitment() {
        let commitments = vec![(acct(2), b"g2".to_vec()), (acct(3), b"g3".to_vec())];
        let err = assemble_nodes(&committee(), &endpoints(), &commitments, 7).unwrap_err();
        assert!(matches!(err, SdkError::Chain { .. }), "{err}");
        assert!(err.to_string().contains("node 10"), "{err}");
    }

    #[test]
    fn chain_envelope_decodes_the_pallets_field_order() {
        let encoded = (
            b"bind".to_vec(),
            b"cap".to_vec(),
            b"proof".to_vec(),
            b"ct".to_vec(),
        )
            .encode();
        let e = ChainEnvelope::decode(&mut &encoded[..]).unwrap();
        assert_eq!(
            (e.binding_id, e.capsule, e.proof, e.ct),
            (
                b"bind".to_vec(),
                b"cap".to_vec(),
                b"proof".to_vec(),
                b"ct".to_vec()
            )
        );
    }

    #[test]
    fn chain_node_info_decodes_the_pallets_field_order() {
        let encoded = (b"https://kgc1.example".to_vec(), 10u64).encode();
        let info = ChainNodeInfo::decode(&mut &encoded[..]).unwrap();
        assert_eq!(info.endpoint, b"https://kgc1.example");
        assert_eq!(info._dkg_index, 10);
    }

    #[test]
    fn check_aad_accepts_the_same_tag_or_a_legacy_empty_one_and_refuses_another() {
        assert!(check_aad(
            1,
            Aad::QuantumGuardPolicyDekV1.as_bytes(),
            Aad::QuantumGuardPolicyDekV1
        )
        .is_ok());
        assert!(check_aad(1, b"", Aad::QuantumGuardPolicyDekV1).is_ok());
        let err = check_aad(1, Aad::EnvV1.as_bytes(), Aad::QuantumGuardPolicyDekV1).unwrap_err();
        assert!(
            matches!(err, SdkError::AadMismatch { secret_id: 1, .. }),
            "{err}"
        );
    }
}
