package mattersdk

// Friendly reads of chain state: one call answers one question, with the pallet,
// storage key and SCALE layout hidden.
//
// A read has four parts. A read_<domain>.go file names its sources and holds a
// pure decoder from raw bytes to a typed result; snapshot is the only fetch, and
// it reads every source at one block; the façade method in facade.go wires the
// three together.

import (
	"encoding/hex"
	"strings"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

const (
	rpcFinalizedHead  = "chain_getFinalizedHead"
	rpcQueryStorageAt = "state_queryStorageAt"
	rpcGetStorage     = "state_getStorage"
	rpcStateCall      = "state_call"
)

// rpcCaller is one JSON-RPC connection: the chain in production, a fake in tests.
type rpcCaller interface {
	callRPC(result any, method string, params ...any) error
}

func (c *ChainClient) callRPC(result any, method string, params ...any) error {
	return c.api.Client.Call(result, method, params...)
}

// rpc is the connection reads go through.
func (c *MatterClient) rpc() rpcCaller {
	if c.reads != nil {
		return c.reads
	}
	return c.chain
}

// request makes one JSON-RPC request; a refusal is a chain error naming the
// method.
func (c *MatterClient) request(result any, method string, params ...any) error {
	if err := c.rpc().callRPC(result, method, params...); err != nil {
		return wrapChainError(KindChain, method, err, "%s: %v", method, err)
	}
	return nil
}

// storageEntry is a storage entry, as the runtime metadata spells it.
type storageEntry struct{ pallet, entry string }

// target is Pallet.Entry: how errors and the read catalogue name this source.
func (e storageEntry) target() string { return e.pallet + "." + e.entry }

// storageRequest is one storage value to fetch: an entry and its map keys (none
// for a plain value).
type storageRequest struct {
	entry storageEntry
	keys  [][]byte
}

// stored is one storage value. found is false when the chain does not store it,
// which is not the same as storing an empty value.
type stored struct {
	raw   []byte
	found bool
}

// snapshot is one block's state. Every source of a read goes through the same
// snapshot, so a result never mixes two blocks.
type snapshot struct {
	client *MatterClient
	at     [blockHashBytes]byte
}

// snapshot resolves pin to a block, asking the node only when it is not given.
func (c *MatterClient) snapshot(pin *[blockHashBytes]byte) (snapshot, error) {
	if pin != nil {
		return snapshot{client: c, at: *pin}, nil
	}
	at, err := finalizedHead(c.rpc())
	if err != nil {
		return snapshot{}, err
	}
	return snapshot{client: c, at: at}, nil
}

// finalizedHead asks for the latest finalized block: state that cannot be
// reverted, and where a write that has returned is visible.
func finalizedHead(rpc rpcCaller) ([blockHashBytes]byte, error) {
	var head string
	if err := rpc.callRPC(&head, rpcFinalizedHead); err != nil {
		return [blockHashBytes]byte{}, wrapChainError(KindChain, rpcFinalizedHead, err, "%s: %v", rpcFinalizedHead, err)
	}
	return hashFromHex(rpcFinalizedHead, head)
}

// runtimeCallAt calls the runtime API api (Trait_method) with SCALE-encoded args
// at block at, returning its SCALE-encoded answer. A failure names the API, not
// the transport: that is what the caller asked for.
func runtimeCallAt(rpc rpcCaller, api string, args []byte, at [blockHashBytes]byte) ([]byte, error) {
	var answer string
	if err := rpc.callRPC(&answer, rpcStateCall, api, toHex(args), toHex(at[:])); err != nil {
		return nil, wrapChainError(KindChain, api, err, "%s: %v", api, err)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(answer, hexPrefix))
	if err != nil {
		return nil, wrapChainError(KindChain, api, err,
			"%s: the node answered with something that is not hex", api)
	}
	return raw, nil
}

// requestHere makes one JSON-RPC request whose only parameter is this snapshot's
// block.
func (s snapshot) requestHere(result any, method string) error {
	return s.client.request(result, method, toHex(s.at[:]))
}

// call calls the runtime API api at this snapshot's block; see runtimeCallAt.
func (s snapshot) call(api string, args []byte) ([]byte, error) {
	return runtimeCallAt(s.client.rpc(), api, args, s.at)
}

// storage fetches several storage values in one request. The result is in request
// order.
func (s snapshot) storage(requests []storageRequest) ([]stored, error) {
	keys := make([]string, len(requests))
	for i, request := range requests {
		key, err := types.CreateStorageKey(s.client.chain.meta, request.entry.pallet, request.entry.entry, request.keys...)
		if err != nil {
			target := request.entry.target()
			return nil, wrapChainError(KindChain, target, err, "%s: %v (was the runtime upgraded?)", target, err)
		}
		keys[i] = toHex(key)
	}

	var sets []struct {
		Changes [][]*string `json:"changes"`
	}
	if err := s.client.request(&sets, rpcQueryStorageAt, keys, toHex(s.at[:])); err != nil {
		return nil, err
	}
	answers := map[string]*string{}
	for _, set := range sets {
		for _, change := range set.Changes {
			if len(change) == 2 && change[0] != nil {
				answers[*change[0]] = change[1]
			}
		}
	}

	values := make([]stored, len(requests))
	for i, request := range requests {
		target := request.entry.target()
		answer, answered := answers[keys[i]]
		if !answered {
			return nil, chainErrorf(KindChain, target,
				"%s: the node's %s answer left this key out", target, rpcQueryStorageAt)
		}
		if answer == nil {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(*answer, hexPrefix))
		if err != nil {
			return nil, wrapChainError(KindChain, target, err,
				"%s: the node answered with something that is not hex", target)
		}
		values[i] = stored{raw: raw, found: true}
	}
	return values, nil
}
