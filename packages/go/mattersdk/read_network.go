package mattersdk

// Network reads: which chain this is, its blocks, its timing, and the health of
// the node answering.

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

const (
	rpcGetHeader         = "chain_getHeader"
	rpcGetBlockHash      = "chain_getBlockHash"
	rpcGetRuntimeVersion = "state_getRuntimeVersion"
	rpcSystemName        = "system_name"
	rpcSystemVersion     = "system_version"
	rpcSystemHealth      = "system_health"

	hexRadix   = 16
	uint64Bits = 64
)

var timestampNow = storageEntry{"Timestamp", "Now"}

// constantEntry is a pallet constant, as the runtime metadata spells it.
type constantEntry struct{ pallet, name string }

func (c constantEntry) target() string { return c.pallet + "." + c.name }

var (
	constBlockTime       = constantEntry{"Babe", "ExpectedBlockTime"}
	constSessionBlocks   = constantEntry{"Babe", "EpochDuration"}
	constSessionsPerEra  = constantEntry{"Staking", "SessionsPerEra"}
	constBondingDuration = constantEntry{"Staking", "BondingDuration"}
)

// headerWire is chain_getHeader's answer, the fields a read uses. The block
// number is hex text: it is 64 bits wide on this chain.
type headerWire struct {
	ParentHash string `json:"parentHash"`
	Number     string `json:"number"`
}

// runtimeVersionWire is state_getRuntimeVersion's answer, the field a read uses.
type runtimeVersionWire struct {
	SpecVersion *uint32 `json:"specVersion"`
}

// healthWire is system_health's answer. Pointers tell a missing field from a zero.
type healthWire struct {
	Peers           *uint32 `json:"peers"`
	IsSyncing       *bool   `json:"isSyncing"`
	ShouldHavePeers *bool   `json:"shouldHavePeers"`
}

// NetworkInfo is which chain this client is connected to, as read once at connect.
type NetworkInfo struct {
	// ChainName is the chain's name, e.g. MatterChain Testnet.
	ChainName string `json:"chain_name"`
	// GenesisHash is block 0's hash, as 0x hex: what tells one chain from another.
	GenesisHash string `json:"genesis_hash"`
	// SpecVersion is the runtime's version at connect.
	SpecVersion uint32 `json:"spec_version"`
	// TokenSymbol is the token's symbol, e.g. MTR.
	TokenSymbol string `json:"token_symbol"`
	// TokenDecimals is the decimal places in one token: divide plancks by ten to
	// this power. Consensus-backed, from the runtime rather than the node's chain
	// spec.
	TokenDecimals uint32 `json:"token_decimals"`
	// SS58Prefix is the prefix addresses on this chain are rendered under.
	SS58Prefix uint32 `json:"ss58_prefix"`
	// ExistentialDeposit is the smallest balance an account may hold and stay
	// alive, in plancks.
	ExistentialDeposit *big.Int `json:"existential_deposit"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (n NetworkInfo) MarshalJSON() ([]byte, error) { return canonicalBytes(n) }

// BlockHeader is a block's place in the chain.
type BlockHeader struct {
	// Number is the block's height.
	Number uint64 `json:"number"`
	// Hash is the block's hash: pass it to a façade's At to read at this block.
	Hash [32]byte `json:"hash"`
	// ParentHash is the hash of the block before it.
	ParentHash [32]byte `json:"parent_hash"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (h BlockHeader) MarshalJSON() ([]byte, error) { return canonicalBytes(h) }

// Block is a block and what its state says about itself.
type Block struct {
	// Number is the block's height.
	Number uint64 `json:"number"`
	// Hash is the block's hash: pass it to a façade's At to read at this block.
	Hash [32]byte `json:"hash"`
	// ParentHash is the hash of the block before it.
	ParentHash [32]byte `json:"parent_hash"`
	// TimestampMs is when the block was authored, in milliseconds since the Unix
	// epoch. Nil for a block that records no time (the genesis block).
	TimestampMs *uint64 `json:"timestamp_ms"`
	// SpecVersion is the runtime version that executed the block.
	SpecVersion uint32 `json:"spec_version"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (b Block) MarshalJSON() ([]byte, error) { return canonicalBytes(b) }

// NodeStatus is the node answering this client, and how far it has got.
type NodeStatus struct {
	// Name is the node software's name.
	Name string `json:"name"`
	// Version is the node software's version.
	Version string `json:"version"`
	// Peers is how many peers the node is connected to.
	Peers uint32 `json:"peers"`
	// IsSyncing reports whether the node is still catching up with the chain.
	IsSyncing bool `json:"is_syncing"`
	// ShouldHavePeers reports whether the node expects peers at all (a single dev
	// node does not).
	ShouldHavePeers bool `json:"should_have_peers"`
	// BestNumber is the newest block the node knows. It can still be reverted.
	BestNumber uint64 `json:"best_number"`
	// BestHash is that block's hash.
	BestHash [32]byte `json:"best_hash"`
	// FinalizedNumber is the newest block that can no longer be reverted.
	FinalizedNumber uint64 `json:"finalized_number"`
	// FinalizedHash is that block's hash.
	FinalizedHash [32]byte `json:"finalized_hash"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (n NodeStatus) MarshalJSON() ([]byte, error) { return canonicalBytes(n) }

// NetworkTiming is how the chain measures time. Blocks and eras are the chain's
// own units; the SDK does not turn them into wall-clock estimates for you.
type NetworkTiming struct {
	// BlockTimeMs is the target time between blocks, in milliseconds.
	BlockTimeMs uint64 `json:"block_time_ms"`
	// SessionBlocks is the blocks in one session.
	SessionBlocks uint64 `json:"session_blocks"`
	// SessionsPerEra is the sessions in one era.
	SessionsPerEra uint32 `json:"sessions_per_era"`
	// EraBlocks is the blocks in one era: SessionBlocks * SessionsPerEra.
	EraBlocks uint64 `json:"era_blocks"`
	// BondingDurationEras is the eras unbonded funds stay locked before they can
	// be withdrawn.
	BondingDurationEras uint32 `json:"bonding_duration_eras"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (n NetworkTiming) MarshalJSON() ([]byte, error) { return canonicalBytes(n) }

// hashFromHex reads a 32-byte hash from the hex a node answers with.
func hashFromHex(target, text string) ([32]byte, error) {
	var hash [32]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(text, hexPrefix))
	if err != nil || len(raw) != len(hash) {
		return hash, chainErrorf(KindChain, target, "%s: the node did not answer with a block hash", target)
	}
	copy(hash[:], raw)
	return hash, nil
}

// blockNumberParam is a block number as chain_getBlockHash takes it: hex, so no
// width is lost.
func blockNumberParam(number uint64) string { return hexPrefix + strconv.FormatUint(number, hexRadix) }

// networkInfo is the chain's identity, from what the client read at connect.
func networkInfo(properties ChainProperties) NetworkInfo {
	return NetworkInfo{
		ChainName:          properties.ChainName,
		GenesisHash:        properties.GenesisHash,
		SpecVersion:        properties.SpecVersion,
		TokenSymbol:        properties.TokenSymbol,
		TokenDecimals:      uint32(properties.TokenDecimalsEffective),
		SS58Prefix:         uint32(properties.SS58Prefix),
		ExistentialDeposit: new(big.Int).Set(properties.ExistentialDeposit),
	}
}

// decodeHeader reads a header the node holds for hash, or the error for one it
// does not.
func decodeHeader(hash [32]byte, header *headerWire) (BlockHeader, error) {
	if header == nil {
		return BlockHeader{}, chainErrorf(KindChain, rpcGetHeader, "%s: the node does not have this block", rpcGetHeader)
	}
	if !strings.HasPrefix(header.Number, hexPrefix) {
		return BlockHeader{}, chainErrorf(KindChain, rpcGetHeader, "%s: the header's block number is not hex", rpcGetHeader)
	}
	number, err := strconv.ParseUint(strings.TrimPrefix(header.Number, hexPrefix), hexRadix, uint64Bits)
	if err != nil {
		return BlockHeader{}, wrapChainError(KindChain, rpcGetHeader, err, "%s: the header's block number is not hex", rpcGetHeader)
	}
	parent, err := hashFromHex(rpcGetHeader, header.ParentHash)
	if err != nil {
		return BlockHeader{}, err
	}
	return BlockHeader{Number: number, Hash: hash, ParentHash: parent}, nil
}

// nowRequest is the one storage value a block read needs.
func nowRequest() []storageRequest { return []storageRequest{{entry: timestampNow}} }

// narrowMs narrows a 128-bit millisecond count. Timestamp.Now is declared 128
// bits wide; milliseconds fit 64 with room for half a billion years, so anything
// wider is not a timestamp.
func narrowMs(target string, wide *big.Int) (uint64, error) {
	if !wide.IsUint64() {
		return 0, chainErrorf(KindChain, target, "%s: %s ms does not fit 64 bits", target, wide)
	}
	return wide.Uint64(), nil
}

// decodeBlock builds a block from its header and what its state holds. Pure.
func decodeBlock(header BlockHeader, now stored, version runtimeVersionWire) (Block, error) {
	block := Block{Number: header.Number, Hash: header.Hash, ParentHash: header.ParentHash}
	if now.found {
		wide, err := decodeStrict(timestampNow.target(), now.raw, (*scaleReader).u128)
		if err != nil {
			return Block{}, err
		}
		ms, err := narrowMs(timestampNow.target(), wide)
		if err != nil {
			return Block{}, err
		}
		block.TimestampMs = &ms
	}
	if version.SpecVersion == nil {
		return Block{}, chainErrorf(KindChain, rpcGetRuntimeVersion, "%s: the node's answer has no specVersion", rpcGetRuntimeVersion)
	}
	block.SpecVersion = *version.SpecVersion
	return block, nil
}

// nodeStatus builds the node's status from its own answers and the two headers.
// Pure.
func nodeStatus(name, version string, health healthWire, best, finalized BlockHeader) (NodeStatus, error) {
	if health.Peers == nil || health.IsSyncing == nil || health.ShouldHavePeers == nil {
		return NodeStatus{}, chainErrorf(KindChain, rpcSystemHealth, "%s: the node's answer is missing a field", rpcSystemHealth)
	}
	return NodeStatus{
		Name:            name,
		Version:         version,
		Peers:           *health.Peers,
		IsSyncing:       *health.IsSyncing,
		ShouldHavePeers: *health.ShouldHavePeers,
		BestNumber:      best.Number,
		BestHash:        best.Hash,
		FinalizedNumber: finalized.Number,
		FinalizedHash:   finalized.Hash,
	}, nil
}

// timingConstants are the constants a timing read needs, in the order
// decodeTiming takes them.
var timingConstants = []constantEntry{constBlockTime, constSessionBlocks, constSessionsPerEra, constBondingDuration}

// decodeTiming builds the chain's timing from its constants' bytes, in
// timingConstants order. Pure.
func decodeTiming(constants [][]byte) (NetworkTiming, error) {
	if len(constants) != len(timingConstants) {
		return NetworkTiming{}, fmt.Errorf("mattersdk: timing takes %d constants, got %d", len(timingConstants), len(constants))
	}
	wideBlockTime, err := decodeStrict(constBlockTime.target(), constants[0], (*scaleReader).u128)
	if err != nil {
		return NetworkTiming{}, err
	}
	blockTime, err := narrowMs(constBlockTime.target(), wideBlockTime)
	if err != nil {
		return NetworkTiming{}, err
	}
	sessionBlocks, err := decodeStrict(constSessionBlocks.target(), constants[1], (*scaleReader).u64)
	if err != nil {
		return NetworkTiming{}, err
	}
	sessionsPerEra, err := decodeStrict(constSessionsPerEra.target(), constants[2], (*scaleReader).u32)
	if err != nil {
		return NetworkTiming{}, err
	}
	bondingDuration, err := decodeStrict(constBondingDuration.target(), constants[3], (*scaleReader).u32)
	if err != nil {
		return NetworkTiming{}, err
	}
	eraBlocks := uint64(math.MaxUint64)
	if sessionsPerEra == 0 || sessionBlocks <= math.MaxUint64/uint64(sessionsPerEra) {
		eraBlocks = sessionBlocks * uint64(sessionsPerEra)
	}
	return NetworkTiming{
		BlockTimeMs:         blockTime,
		SessionBlocks:       sessionBlocks,
		SessionsPerEra:      sessionsPerEra,
		EraBlocks:           eraBlocks,
		BondingDurationEras: bondingDuration,
	}, nil
}
