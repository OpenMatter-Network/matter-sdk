//! Friendly reads of chain state: one call answers one question, with the
//! pallet, storage key and SCALE layout hidden.
//!
//! A read has four parts. A domain module names its **sources** and holds a
//! **pure decoder** from raw bytes to a typed result; [`Snapshot`] is the only
//! **fetch**, and it reads every source at one block; the **façade method** in
//! `facade.rs` wires the three together.
//!
//! Decoders are strict: a value must have exactly the layout this SDK knows, so
//! a runtime that has changed it fails loudly at the read instead of returning
//! something plausible and wrong.

pub(super) mod accounts;
pub(super) mod fees;
mod leaf;
pub(super) mod network;
#[cfg(test)]
pub(super) mod testing;
#[cfg(test)]
mod vectors;

use std::collections::HashMap;

use parity_scale_codec::{Decode, DecodeAll};
use serde::de::DeserializeOwned;
use serde_json::Value as Json;
use subxt::dynamic::Value;
use subxt::ext::subxt_rpcs::client::RpcParams;
use subxt::utils::H256;

pub use self::accounts::{AccountBalance, BalanceLock, BalanceReason, LockReasons};
pub use self::fees::{BilledTo, DispatchClass, FeeEstimate, Weight};
#[cfg(test)]
pub(super) use self::leaf::hex0x;
pub(super) use self::leaf::SS58_MAX_PREFIX;
pub use self::leaf::{parse_account, Address, Text};
pub use self::network::{Block, BlockHeader, NetworkInfo, NetworkTiming, NodeStatus};
use super::{chain_error, rpc_error, MatterClient};
use crate::error::{Result, SdkError};

const FINALIZED_HEAD: &str = "chain_getFinalizedHead";
const QUERY_STORAGE_AT: &str = "state_queryStorageAt";
const STATE_CALL: &str = "state_call";

/// A storage entry, as the runtime metadata spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StorageEntry {
    pub pallet: &'static str,
    pub entry: &'static str,
}

impl StorageEntry {
    pub(super) const fn new(pallet: &'static str, entry: &'static str) -> Self {
        Self { pallet, entry }
    }

    /// `Pallet.Entry`: how errors and the read catalogue name this source.
    pub(super) fn target(&self) -> String {
        format!("{}.{}", self.pallet, self.entry)
    }
}

/// A pallet constant, as the runtime metadata spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConstantEntry {
    pub pallet: &'static str,
    pub name: &'static str,
}

impl ConstantEntry {
    pub(super) const fn new(pallet: &'static str, name: &'static str) -> Self {
        Self { pallet, name }
    }

    /// `Pallet.Name`: how errors and the read catalogue name this source.
    pub(super) fn target(&self) -> String {
        format!("{}.{}", self.pallet, self.name)
    }
}

/// One storage value to fetch: an entry and its map keys (empty for a plain
/// value).
#[derive(Debug, Clone)]
pub(super) struct StorageRequest {
    pub entry: StorageEntry,
    pub keys: Vec<Value>,
}

/// Which block a façade reads at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Pin {
    /// The latest finalized block, resolved once per read.
    #[default]
    Finalized,
    /// A block the caller chose, so several reads can share one view.
    Block([u8; 32]),
}

/// One block's state. Every source of a read goes through the same snapshot,
/// so a result never mixes two blocks.
pub(super) struct Snapshot<'a> {
    client: &'a MatterClient,
    at: H256,
}

impl MatterClient {
    /// Resolve `pin` to a block, asking the node only when it is not given.
    pub(super) async fn snapshot(&self, pin: Pin) -> Result<Snapshot<'_>> {
        let at = match pin {
            Pin::Block(hash) => H256(hash),
            Pin::Finalized => self
                .rpc
                .chain_get_finalized_head()
                .await
                .map_err(|e| rpc_error(FINALIZED_HEAD, e))?,
        };
        Ok(Snapshot { client: self, at })
    }

    /// One JSON-RPC request, answered with its result as `T`. A failure names
    /// the method.
    pub(super) async fn request<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: Vec<Json>,
    ) -> Result<T> {
        self.raw_request(method, params)
            .await
            .map_err(|e| rpc_error(method, e))
    }

    /// One JSON-RPC request, with the transport's own error.
    async fn raw_request<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<Json>,
    ) -> std::result::Result<T, subxt::ext::subxt_rpcs::Error> {
        let params = params
            .into_iter()
            .try_fold(RpcParams::new(), |mut all, param| {
                all.push(param).map(|()| all)
            })?;
        self.raw.request(method, params).await
    }

    /// A constant's SCALE bytes, from the connected runtime's metadata.
    pub(super) fn constant_bytes(&self, constant: ConstantEntry) -> Result<Vec<u8>> {
        self.api
            .metadata()
            .pallet_by_name(constant.pallet)
            .and_then(|pallet| pallet.constant_by_name(constant.name))
            .map(|found| found.value().to_vec())
            .ok_or_else(|| SdkError::Chain {
                target: constant.target(),
                detail: "no such constant in the live runtime metadata".to_string(),
            })
    }

    /// The raw key `request` is stored under, from the connected runtime's metadata.
    pub(super) fn storage_key(&self, request: &StorageRequest) -> Result<Vec<u8>> {
        let StorageEntry { pallet, entry } = request.entry;
        let address = subxt::dynamic::storage(pallet, entry, request.keys.clone());
        self.api
            .storage()
            .address_bytes(&address)
            .map_err(|e| chain_error(pallet, entry, e))
    }
}

impl Snapshot<'_> {
    /// The block this snapshot reads at.
    pub(super) fn at(&self) -> [u8; 32] {
        self.at.0
    }

    /// Call the runtime API `api` (`Trait_method`) with SCALE-encoded `args` at
    /// this snapshot's block, returning its SCALE-encoded answer. A failure names
    /// the API, not the transport: that is what the caller asked for.
    pub(super) async fn call(&self, api: &'static str, args: &[u8]) -> Result<Vec<u8>> {
        let params = vec![
            Json::String(api.to_string()),
            Json::String(leaf::hex0x(args)),
            Json::String(hex0x_block(&self.at.0)),
        ];
        let answer: String = self
            .client
            .raw_request(STATE_CALL, params)
            .await
            .map_err(|e| rpc_error(api, e))?;
        ::hex::decode(answer.trim_start_matches("0x")).map_err(|_| SdkError::Chain {
            target: api.to_string(),
            detail: "the node answered with something that is not hex".to_string(),
        })
    }

    /// One JSON-RPC request whose only parameter is this snapshot's block.
    pub(super) async fn request_here<T: DeserializeOwned>(
        &self,
        method: &'static str,
    ) -> Result<T> {
        self.client
            .request(method, vec![Json::String(hex0x_block(&self.at.0))])
            .await
    }

    /// Fetch several storage values in one request. The result is in request
    /// order; `None` is a value the chain does not store.
    pub(super) async fn storage<const N: usize>(
        &self,
        requests: &[StorageRequest; N],
    ) -> Result<[Option<Vec<u8>>; N]> {
        let keys = requests
            .iter()
            .map(|request| self.client.storage_key(request))
            .collect::<Result<Vec<_>>>()?;
        let sets = self
            .client
            .rpc
            .state_query_storage_at(keys.iter().map(Vec::as_slice), Some(self.at))
            .await
            .map_err(|e| rpc_error(QUERY_STORAGE_AT, e))?;
        let answers: HashMap<&[u8], Option<&[u8]>> = sets
            .iter()
            .flat_map(|set| &set.changes)
            .map(|(key, value)| (key.0.as_slice(), value.as_ref().map(|v| v.0.as_slice())))
            .collect();

        let values = keys
            .iter()
            .zip(requests)
            .map(|(key, request)| {
                answers
                    .get(key.as_slice())
                    .map(|value| value.map(<[u8]>::to_vec))
                    .ok_or_else(|| SdkError::Chain {
                        target: request.entry.target(),
                        detail: format!("the node's {QUERY_STORAGE_AT} answer left this key out"),
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        // One value per request by construction.
        Ok(values
            .try_into()
            .unwrap_or_else(|_| unreachable!("one answer is collected per request")))
    }
}

fn hex0x_block(hash: &[u8; 32]) -> String {
    leaf::hex0x(hash)
}

/// Decode `bytes` as exactly a `T`, naming `target` when the layout differs.
pub(super) fn decode_strict<T: Decode>(target: &str, bytes: &[u8]) -> Result<T> {
    T::decode_all(&mut &bytes[..]).map_err(|e| SdkError::Chain {
        target: target.to_string(),
        detail: format!("the value does not have the layout this SDK decodes: {e}"),
    })
}
