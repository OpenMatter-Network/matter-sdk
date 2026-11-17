//! Network reads: which chain this is, its blocks, its timing, and the health of
//! the node answering.

use serde::{Deserialize, Serialize};

use super::leaf::{decimal, decimal_option, hex};
use super::{decode_strict, ConstantEntry, StorageEntry, StorageRequest};
use crate::chain::ChainProperties;
use crate::error::{Result, SdkError};

pub(in crate::chain) const GET_HEADER: &str = "chain_getHeader";
pub(in crate::chain) const GET_BLOCK_HASH: &str = "chain_getBlockHash";
pub(in crate::chain) const GET_RUNTIME_VERSION: &str = "state_getRuntimeVersion";
pub(in crate::chain) const SYSTEM_NAME: &str = "system_name";
pub(in crate::chain) const SYSTEM_VERSION: &str = "system_version";
pub(in crate::chain) const SYSTEM_HEALTH: &str = "system_health";

pub(in crate::chain) const NOW: StorageEntry = StorageEntry::new("Timestamp", "Now");

pub(in crate::chain) const BLOCK_TIME: ConstantEntry =
    ConstantEntry::new("Babe", "ExpectedBlockTime");
pub(in crate::chain) const SESSION_BLOCKS: ConstantEntry =
    ConstantEntry::new("Babe", "EpochDuration");
pub(in crate::chain) const SESSIONS_PER_ERA: ConstantEntry =
    ConstantEntry::new("Staking", "SessionsPerEra");
pub(in crate::chain) const BONDING_DURATION: ConstantEntry =
    ConstantEntry::new("Staking", "BondingDuration");

const HASH_LEN: usize = 32;
const HEX_PREFIX: &str = "0x";
const HEX_RADIX: u32 = 16;

/// `chain_getHeader`'s answer, the fields a read uses. The block number is hex
/// text: it is 64 bits wide on this chain.
#[derive(Deserialize)]
pub(in crate::chain) struct HeaderWire {
    #[serde(rename = "parentHash")]
    parent_hash: String,
    number: String,
}

/// `state_getRuntimeVersion`'s answer, the field a read uses.
#[derive(Deserialize)]
pub(in crate::chain) struct RuntimeVersionWire {
    #[serde(rename = "specVersion")]
    spec_version: u32,
}

/// `system_health`'s answer.
#[derive(Deserialize)]
pub(in crate::chain) struct HealthWire {
    peers: u32,
    #[serde(rename = "isSyncing")]
    is_syncing: bool,
    #[serde(rename = "shouldHavePeers")]
    should_have_peers: bool,
}

/// Which chain this client is connected to, as read once at connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct NetworkInfo {
    /// The chain's name, e.g. `MatterChain Testnet`.
    pub chain_name: String,
    /// Block 0's hash: what tells one chain from another.
    #[serde(with = "hex")]
    pub genesis_hash: [u8; 32],
    /// The runtime's version at connect.
    pub spec_version: u32,
    /// The token's symbol, e.g. `MTR`.
    pub token_symbol: String,
    /// Decimal places in one token: divide plancks by ten to this power.
    /// Consensus-backed, from the runtime rather than the node's chain spec.
    pub token_decimals: u32,
    /// The prefix addresses on this chain are rendered under.
    pub ss58_prefix: u32,
    /// The smallest balance an account may hold and stay alive, in plancks.
    #[serde(with = "decimal")]
    pub existential_deposit: u128,
}

/// A block's place in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BlockHeader {
    /// The block's height.
    #[serde(with = "decimal")]
    pub number: u64,
    /// The block's hash: pass it to a façade's `at` to read at this block.
    #[serde(with = "hex")]
    pub hash: [u8; 32],
    /// The hash of the block before it.
    #[serde(with = "hex")]
    pub parent_hash: [u8; 32],
}

/// A block and what its state says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Block {
    /// The block's height.
    #[serde(with = "decimal")]
    pub number: u64,
    /// The block's hash: pass it to a façade's `at` to read at this block.
    #[serde(with = "hex")]
    pub hash: [u8; 32],
    /// The hash of the block before it.
    #[serde(with = "hex")]
    pub parent_hash: [u8; 32],
    /// When the block was authored, in milliseconds since the Unix epoch.
    /// `None` for a block that records no time (the genesis block).
    #[serde(with = "decimal_option")]
    pub timestamp_ms: Option<u64>,
    /// The runtime version that executed the block.
    pub spec_version: u32,
}

/// The node answering this client, and how far it has got.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct NodeStatus {
    /// The node software's name.
    pub name: String,
    /// The node software's version.
    pub version: String,
    /// How many peers the node is connected to.
    pub peers: u32,
    /// Whether the node is still catching up with the chain.
    pub is_syncing: bool,
    /// Whether the node expects peers at all (a single dev node does not).
    pub should_have_peers: bool,
    /// The newest block the node knows. It can still be reverted.
    #[serde(with = "decimal")]
    pub best_number: u64,
    /// That block's hash.
    #[serde(with = "hex")]
    pub best_hash: [u8; 32],
    /// The newest block that can no longer be reverted.
    #[serde(with = "decimal")]
    pub finalized_number: u64,
    /// That block's hash.
    #[serde(with = "hex")]
    pub finalized_hash: [u8; 32],
}

/// How the chain measures time. Blocks and eras are the chain's own units; the
/// SDK does not turn them into wall-clock estimates for you.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct NetworkTiming {
    /// The target time between blocks, in milliseconds.
    #[serde(with = "decimal")]
    pub block_time_ms: u64,
    /// Blocks in one session.
    #[serde(with = "decimal")]
    pub session_blocks: u64,
    /// Sessions in one era.
    pub sessions_per_era: u32,
    /// Blocks in one era: `session_blocks * sessions_per_era`.
    #[serde(with = "decimal")]
    pub era_blocks: u64,
    /// Eras unbonded funds stay locked before they can be withdrawn.
    pub bonding_duration_eras: u32,
}

fn unexpected(target: &str, detail: impl std::fmt::Display) -> SdkError {
    SdkError::Chain {
        target: target.to_string(),
        detail: detail.to_string(),
    }
}

/// A 32-byte hash from the `0x` hex a node answers with.
pub(in crate::chain) fn hash_from_hex(target: &str, text: &str) -> Result<[u8; 32]> {
    let mut hash = [0u8; HASH_LEN];
    ::hex::decode_to_slice(text.trim_start_matches(HEX_PREFIX), &mut hash)
        .map_err(|_| unexpected(target, "the node did not answer with a block hash"))?;
    Ok(hash)
}

/// A block number as `chain_getBlockHash` takes it: hex, so no width is lost.
pub(in crate::chain) fn block_number_param(number: u64) -> String {
    format!("{HEX_PREFIX}{number:x}")
}

fn block_number(text: &str) -> Result<u64> {
    u64::from_str_radix(text.trim_start_matches(HEX_PREFIX), HEX_RADIX)
        .map_err(|_| unexpected(GET_HEADER, "the header's block number is not hex"))
}

/// The chain's identity, from what the client read at connect.
pub(in crate::chain) fn info(properties: &ChainProperties) -> NetworkInfo {
    NetworkInfo {
        chain_name: properties.chain_name.clone(),
        genesis_hash: properties.genesis_hash,
        spec_version: properties.spec_version,
        token_symbol: properties.token_symbol.clone(),
        token_decimals: properties.token_decimals_effective.into(),
        ss58_prefix: properties.ss58_prefix.into(),
        existential_deposit: properties.existential_deposit,
    }
}

/// A header the node holds for `hash`, or the error for one it does not.
pub(in crate::chain) fn decode_header(
    hash: [u8; 32],
    header: Option<HeaderWire>,
) -> Result<BlockHeader> {
    let header =
        header.ok_or_else(|| unexpected(GET_HEADER, "the node does not have this block"))?;
    Ok(BlockHeader {
        number: block_number(&header.number)?,
        hash,
        parent_hash: hash_from_hex(GET_HEADER, &header.parent_hash)?,
    })
}

/// The one storage value a block read needs.
pub(in crate::chain) fn now_request() -> [StorageRequest; 1] {
    [StorageRequest {
        entry: NOW,
        keys: Vec::new(),
    }]
}

/// `Timestamp.Now` is declared 128 bits wide; milliseconds fit 64 with room for
/// half a billion years, so anything wider is not a timestamp.
fn narrow_ms(target: &str, wide: u128) -> Result<u64> {
    u64::try_from(wide).map_err(|_| unexpected(target, format!("{wide} ms does not fit 64 bits")))
}

/// Build a block from its header and what its state holds. Pure.
pub(in crate::chain) fn decode_block(
    header: BlockHeader,
    now: Option<&[u8]>,
    version: &RuntimeVersionWire,
) -> Result<Block> {
    let timestamp_ms = now
        .map(|bytes| decode_strict::<u128>(&NOW.target(), bytes))
        .transpose()?
        .map(|wide| narrow_ms(&NOW.target(), wide))
        .transpose()?;
    Ok(Block {
        number: header.number,
        hash: header.hash,
        parent_hash: header.parent_hash,
        timestamp_ms,
        spec_version: version.spec_version,
    })
}

/// Build the node's status from its own answers and the two headers. Pure.
pub(in crate::chain) fn node_status(
    name: String,
    version: String,
    health: &HealthWire,
    best: BlockHeader,
    finalized: BlockHeader,
) -> NodeStatus {
    NodeStatus {
        name,
        version,
        peers: health.peers,
        is_syncing: health.is_syncing,
        should_have_peers: health.should_have_peers,
        best_number: best.number,
        best_hash: best.hash,
        finalized_number: finalized.number,
        finalized_hash: finalized.hash,
    }
}

/// The constants a timing read needs, in the order [`decode_timing`] takes them.
pub(in crate::chain) const TIMING_CONSTANTS: [ConstantEntry; 4] = [
    BLOCK_TIME,
    SESSION_BLOCKS,
    SESSIONS_PER_ERA,
    BONDING_DURATION,
];

/// Build the chain's timing from its constants' bytes, in
/// [`TIMING_CONSTANTS`] order. Pure.
pub(in crate::chain) fn decode_timing(
    [block_time, session_blocks, sessions_per_era, bonding_duration]: &[Vec<u8>; 4],
) -> Result<NetworkTiming> {
    let block_time_ms = narrow_ms(
        &BLOCK_TIME.target(),
        decode_strict::<u128>(&BLOCK_TIME.target(), block_time)?,
    )?;
    let session_blocks: u64 = decode_strict(&SESSION_BLOCKS.target(), session_blocks)?;
    let sessions_per_era: u32 = decode_strict(&SESSIONS_PER_ERA.target(), sessions_per_era)?;
    let bonding_duration_eras: u32 = decode_strict(&BONDING_DURATION.target(), bonding_duration)?;
    Ok(NetworkTiming {
        block_time_ms,
        session_blocks,
        sessions_per_era,
        era_blocks: session_blocks.saturating_mul(sessions_per_era.into()),
        bonding_duration_eras,
    })
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::Encode;

    use super::*;

    fn header(number: &str) -> Option<HeaderWire> {
        Some(HeaderWire {
            parent_hash: format!("0x{}", "ab".repeat(32)),
            number: number.to_string(),
        })
    }

    #[test]
    fn a_header_number_is_hex_of_any_width() {
        let decoded = decode_header([1; 32], header("0xffffffffffffffff")).unwrap();
        assert_eq!(decoded.number, u64::MAX);
        assert_eq!(decoded.parent_hash, [0xab; 32]);
        assert_eq!(block_number_param(1234), "0x4d2");
    }

    #[test]
    fn a_block_the_node_does_not_have_is_an_error_naming_the_request() {
        for missing in [None, header("not hex")] {
            let err = decode_header([1; 32], missing).unwrap_err();
            assert!(
                matches!(&err, SdkError::Chain { target, .. } if target == GET_HEADER),
                "{err:?}"
            );
        }
    }

    #[test]
    fn a_block_without_a_stored_time_has_none_rather_than_1970() {
        let version = RuntimeVersionWire { spec_version: 330 };
        let genesis = decode_header([0; 32], header("0x0")).unwrap();
        assert_eq!(
            decode_block(genesis.clone(), None, &version)
                .unwrap()
                .timestamp_ms,
            None
        );

        let stamped = decode_block(genesis, Some(&1_700_000_000_000u128.encode()), &version);
        assert_eq!(stamped.unwrap().timestamp_ms, Some(1_700_000_000_000));
    }

    #[test]
    fn a_time_wider_than_64_bits_is_an_error_not_a_truncation() {
        let version = RuntimeVersionWire { spec_version: 330 };
        let block = decode_header([0; 32], header("0x1")).unwrap();
        let err = decode_block(block, Some(&u128::MAX.encode()), &version).unwrap_err();
        assert!(
            matches!(&err, SdkError::Chain { target, .. } if target == "Timestamp.Now"),
            "{err:?}"
        );
    }

    #[test]
    fn an_era_is_its_sessions_times_their_blocks() {
        let timing = decode_timing(&[
            4_000u128.encode(),
            900u64.encode(),
            24u32.encode(),
            7u32.encode(),
        ])
        .unwrap();
        assert_eq!(timing.era_blocks, 21_600);
        assert_eq!(timing.block_time_ms, 4_000);
    }
}
