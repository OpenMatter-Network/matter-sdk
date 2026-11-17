//! An in-memory chain for read tests: answers the JSON-RPC methods reads use
//! from fixed state and records every exchange, so a test can assert what was
//! asked and at which block, and the vector emitter can write the transcript the
//! other bindings replay.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};
use subxt::ext::subxt_rpcs::client::{RawRpcFuture, RawRpcSubscription, RawValue, RpcClientT};
use subxt::ext::subxt_rpcs::Error as RpcError;

use super::leaf::hex0x;
use super::StorageRequest;
use crate::chain::{ChainProperties, MatterClient, Mode};

/// The finalized head a [`FakeChain`] reports unless told otherwise.
pub(in crate::chain) const FAKE_HEAD: [u8; 32] = [0xf1; 32];

/// The well-known development account, and its address under prefix 42.
pub(in crate::chain) const ALICE: [u8; 32] = [
    0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9, 0x9f, 0xd6,
    0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d,
];
pub(in crate::chain) const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
/// One whole token at 18 decimals, as on the live networks.
pub(in crate::chain) const TOKEN: u128 = 1_000_000_000_000_000_000;
/// The existential deposit a test chain declares: 0.001 token.
pub(in crate::chain) const ED: u128 = TOKEN / 1_000;

/// One JSON-RPC exchange the fake took part in: the node's answer (which may be
/// `null`), or the message it refused the request with.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::chain) struct Exchange {
    pub method: String,
    pub params: Json,
    pub result: Result<Json, String>,
}

/// Fixed chain state behind the JSON-RPC surface. Clones share one exchange log.
#[derive(Clone)]
pub(in crate::chain) struct FakeChain {
    head: [u8; 32],
    storage: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Scripted answers to exact requests, consulted before the built-in ones.
    scripted: Vec<(String, Json, Result<Json, String>)>,
    /// Runtime-API answers by API name, whatever the arguments: the arguments
    /// are the read's to get right, and the transcript records them.
    runtime_apis: Vec<(String, Result<Vec<u8>, String>)>,
    /// Whether the connection is down: every request is refused.
    refusing: bool,
    log: Arc<Mutex<Vec<Exchange>>>,
}

impl FakeChain {
    pub(in crate::chain) fn new() -> Self {
        Self {
            head: FAKE_HEAD,
            storage: BTreeMap::new(),
            scripted: Vec::new(),
            runtime_apis: Vec::new(),
            refusing: false,
            log: Arc::default(),
        }
    }

    /// A chain whose connection is down.
    pub(in crate::chain) fn refusing() -> Self {
        Self {
            refusing: true,
            ..Self::new()
        }
    }

    /// The same chain with `value` stored under the raw storage `key`.
    pub(in crate::chain) fn with_storage(self, key: Vec<u8>, value: Vec<u8>) -> Self {
        let storage = self.storage.into_iter().chain([(key, value)]).collect();
        Self { storage, ..self }
    }

    /// The same chain answering `method(params)` with `result`.
    pub(in crate::chain) fn with_rpc(self, method: &str, params: Json, result: Json) -> Self {
        self.scripting(method, params, Ok(result))
    }

    /// The same chain refusing `method(params)` with `message`.
    pub(in crate::chain) fn with_refusal(self, method: &str, params: Json, message: &str) -> Self {
        self.scripting(method, params, Err(message.to_string()))
    }

    /// The same chain answering the runtime API `api` with SCALE `bytes`.
    pub(in crate::chain) fn with_runtime_api(self, api: &str, bytes: Vec<u8>) -> Self {
        self.answering_runtime_api(api, Ok(bytes))
    }

    /// The same chain refusing the runtime API `api` with `message`.
    pub(in crate::chain) fn refusing_runtime_api(self, api: &str, message: &str) -> Self {
        self.answering_runtime_api(api, Err(message.to_string()))
    }

    fn answering_runtime_api(self, api: &str, answer: Result<Vec<u8>, String>) -> Self {
        let runtime_apis = self
            .runtime_apis
            .into_iter()
            .chain([(api.to_string(), answer)])
            .collect();
        Self {
            runtime_apis,
            ..self
        }
    }

    fn scripting(self, method: &str, params: Json, answer: Result<Json, String>) -> Self {
        let scripted = self
            .scripted
            .into_iter()
            .chain([(method.to_string(), params, answer)])
            .collect();
        Self { scripted, ..self }
    }

    /// Every exchange so far, in order.
    pub(in crate::chain) fn exchanges(&self) -> Vec<Exchange> {
        self.log
            .lock()
            .expect("the log lock is never poisoned")
            .clone()
    }

    fn answer(&self, method: &str, params: &Json) -> Result<Json, RpcError> {
        if self.refusing {
            return Err(RpcError::Client("connection refused".into()));
        }
        let scripted = self
            .scripted
            .iter()
            .find(|(m, p, _)| m == method && p == params);
        if let Some((_, _, answer)) = scripted {
            return answer
                .clone()
                .map_err(|message| RpcError::Client(message.into()));
        }
        match method {
            "state_call" => {
                let api = params[0].as_str().unwrap_or_default();
                match self.runtime_apis.iter().find(|(name, _)| name == api) {
                    Some((_, Ok(bytes))) => Ok(json!(hex0x(bytes))),
                    Some((_, Err(message))) => Err(RpcError::Client(message.clone().into())),
                    None => Err(RpcError::Client(
                        format!("FakeChain does not implement {api}").into(),
                    )),
                }
            }
            "chain_getFinalizedHead" => Ok(json!(hex0x(&self.head))),
            "state_queryStorageAt" => {
                let changes: Vec<Json> = params[0]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|key| {
                        let raw =
                            hex::decode(key.as_str().unwrap_or_default().trim_start_matches("0x"))
                                .unwrap_or_default();
                        json!([key, self.storage.get(&raw).map(|value| hex0x(value))])
                    })
                    .collect();
                Ok(json!([{ "block": params[1], "changes": changes }]))
            }
            other => Err(RpcError::Client(
                format!("FakeChain does not answer {other}").into(),
            )),
        }
    }
}

impl RpcClientT for FakeChain {
    fn request_raw<'a>(
        &'a self,
        method: &'a str,
        params: Option<Box<RawValue>>,
    ) -> RawRpcFuture<'a, Box<RawValue>> {
        // A request with no parameters is sent without any; a transcript always
        // records a list.
        let params: Json = params
            .and_then(|raw| serde_json::from_str(raw.get()).ok())
            .unwrap_or_else(|| json!([]));
        let answer = self.answer(method, &params);
        self.log
            .lock()
            .expect("the log lock is never poisoned")
            .push(Exchange {
                method: method.to_string(),
                params,
                result: answer
                    .as_ref()
                    .map(Json::clone)
                    .map_err(ToString::to_string),
            });
        let answer = answer.and_then(|value| {
            RawValue::from_string(value.to_string()).map_err(RpcError::Deserialization)
        });
        Box::pin(async move { answer })
    }

    fn subscribe_raw<'a>(
        &'a self,
        sub: &'a str,
        _params: Option<Box<RawValue>>,
        _unsub: &'a str,
    ) -> RawRpcFuture<'a, RawRpcSubscription> {
        Box::pin(async move {
            Err(RpcError::Client(
                format!("FakeChain does not serve the {sub} subscription").into(),
            ))
        })
    }
}

/// Properties of a testnet-like chain: prefix 42, 18 decimals.
pub(in crate::chain) fn test_properties() -> ChainProperties {
    ChainProperties {
        genesis_hash: [0u8; 32],
        chain_name: "MatterChain Fake".to_string(),
        spec_version: 330,
        token_symbol: "MTR-Test".to_string(),
        ss58_prefix: 42,
        token_decimals_declared: 18,
        token_decimals_effective: 18,
        existential_deposit: ED,
    }
}

/// The raw key `request` is stored under in the spec-330 runtime.
pub(in crate::chain) fn storage_key(request: &StorageRequest) -> Vec<u8> {
    offline_client(&FakeChain::new())
        .storage_key(request)
        .expect("the fixture runtime has this entry")
}

/// A signer that is only an identity: reads never sign.
struct Identity(crate::AccountId);

impl crate::KeySigner for Identity {
    fn scheme(&self) -> crate::KeyScheme {
        crate::KeyScheme::Sr25519
    }

    fn account_id(&self) -> crate::AccountId {
        self.0
    }

    fn sign(&self, _message: &[u8]) -> std::result::Result<[u8; 64], crate::KeyError> {
        Err(crate::KeyError::Malformed {
            detail: "a read must not sign",
        })
    }
}

/// A client over `chain` that would sign as `signer`, for `mode`'s member if any.
pub(in crate::chain) fn offline_client_as(
    chain: &FakeChain,
    signer: crate::AccountId,
    mode: Mode,
) -> MatterClient {
    let signer: std::sync::Arc<dyn crate::KeySigner> = std::sync::Arc::new(Identity(signer));
    MatterClient::offline_as(chain.clone(), test_properties(), Some(signer), mode)
}

/// A read-only client over `chain`, using the spec-330 metadata fixture.
pub(in crate::chain) fn offline_client(chain: &FakeChain) -> MatterClient {
    MatterClient::offline(chain.clone(), test_properties())
}
