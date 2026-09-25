//! Recipient binding: `decrypt` signs once per quorum node with that node's own
//! `recipient_index`, so a signature sent to one node cannot be replayed to a peer.

use std::cell::RefCell;
use std::future::Future;

use matter_sdk::{
    decrypt,
    CommitteeNode,
    DecryptRequest,
    Health,
    RequestAuth,
    Result,
    Signer,
    SigningRequest,
    Transport,
};
use matter_sdk_core::wire::{to_0x, AuthScheme, PartialDecryptRequest, PartialDecryptResponse};

const T: usize = 3;
const EPOCH: u32 = 0;

/// Records each `recipient_index` and returns a signature unique to that index.
#[derive(Default)]
struct RecordingSigner {
    seen_indices: RefCell<Vec<u64>>,
}

impl Signer for RecordingSigner {
    fn auth_scheme(&self) -> AuthScheme {
        AuthScheme::Substrate
    }

    fn authorize(&self, req: &SigningRequest<'_>) -> Result<RequestAuth> {
        self.seen_indices.borrow_mut().push(req.recipient_index);
        Ok(RequestAuth {
            auth: AuthScheme::Substrate,
            requester: to_0x(&[0u8; 32]),
            signature: format!("0x{:016x}", req.recipient_index),
            eth_address: None,
            valid_until: None,
            eth_signature: None,
        })
    }
}

/// Captures the signature each endpoint received; answers with an empty partial so
/// the fan-out reaches every node.
#[derive(Default)]
struct CapturingTransport {
    received: RefCell<Vec<(String, String)>>,
}

#[allow(clippy::manual_async_fn)]
impl Transport for CapturingTransport {
    fn health(&self, _endpoint: &str) -> impl Future<Output = Result<Health>> + Send {
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
    ) -> impl Future<Output = Result<PartialDecryptResponse>> + Send {
        self.received
            .borrow_mut()
            .push((endpoint.to_string(), req.signature.clone()));
        let resp = PartialDecryptResponse {
            node_index: 0,
            partial: to_0x(b""),
            proof: to_0x(b""),
            crypto_protocol_version: 2,
            served_epoch: EPOCH,
            shared_a: None,
            joint_pk: None,
            served_threshold: T as u32,
        };
        async move { Ok(resp) }
    }
}

#[tokio::test]
async fn decrypt_signs_once_per_node_with_that_nodes_index() {
    let nodes: Vec<CommitteeNode> = (1..=T as u64)
        .map(|index| CommitteeNode {
            index,
            endpoint: format!("http://node-{index}"),
            share_commitment: vec![],
        })
        .collect();

    let signer = RecordingSigner::default();
    let transport = CapturingTransport::default();

    // Aggregation fails (nothing real to open), but only after signing and fan-out.
    let _ = decrypt(
        &transport,
        &signer,
        &DecryptRequest {
            secret_id: 0xC1,
            epoch: EPOCH,
            binding_id: b"bind",
            aad: b"aad",
            capsule: b"",
            ct: &[0u8; 12],
            shared_a: b"",
            block_hash: [0x11; 32],
            threshold: T,
            nodes: &nodes,
        },
    )
    .await;

    assert_eq!(*signer.seen_indices.borrow(), vec![1, 2, 3]);

    let sigs: Vec<String> = transport
        .received
        .borrow()
        .iter()
        .map(|(_, sig)| sig.clone())
        .collect();
    assert_eq!(sigs.len(), 3, "each node in the quorum was queried");
    let unique: std::collections::BTreeSet<&String> = sigs.iter().collect();
    assert_eq!(unique.len(), 3, "each node got a different signature");

    for (endpoint, sig) in transport.received.borrow().iter() {
        let idx: u64 = endpoint.trim_start_matches("http://node-").parse().unwrap();
        assert_eq!(*sig, format!("0x{idx:016x}"));
    }
}
