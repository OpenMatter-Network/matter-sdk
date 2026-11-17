package mattersdk

// Generic access to any pallet, resolved by name against the metadata loaded at
// connect. Storage decodes into a caller-supplied `result` pointer, GSRPC's idiom.
//
// Storage and runtime APIs are read at the latest finalized block: the answer
// cannot be reverted, and a write that has returned is visible.

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

// storedAtFinalized reads the bytes under pallet.entry(keys) at the latest
// finalized block. Nil means nothing is stored there. An entry the runtime does
// not have is refused before the node is asked anything.
func storedAtFinalized(rpc rpcCaller, meta *types.Metadata, pallet, entry string, keys ...[]byte) ([]byte, error) {
	target := pallet + "." + entry
	key, err := types.CreateStorageKey(meta, pallet, entry, keys...)
	if err != nil {
		return nil, wrapChainError(KindChain, target, err, "%s: %v (was the runtime upgraded?)", target, err)
	}
	head, err := finalizedHead(rpc)
	if err != nil {
		return nil, err
	}
	var answer *string
	if err := rpc.callRPC(&answer, rpcGetStorage, toHex(key), toHex(head[:])); err != nil {
		return nil, wrapChainError(KindChain, target, err, "%s: %v", target, err)
	}
	if answer == nil {
		return nil, nil
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(*answer, hexPrefix))
	if err != nil {
		return nil, wrapChainError(KindChain, target, err,
			"%s: the node answered with something that is not hex", target)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	return raw, nil
}

// queryInto decodes what is stored under pallet.entry(keys) into result, and
// reports whether anything is stored there.
func queryInto(rpc rpcCaller, meta *types.Metadata, result any, pallet, entry string, keys ...[]byte) (bool, error) {
	raw, err := storedAtFinalized(rpc, meta, pallet, entry, keys...)
	if err != nil || raw == nil {
		return false, err
	}
	if err := codec.Decode(raw, result); err != nil {
		target := pallet + "." + entry
		return false, wrapChainError(KindChain, target, err, "%s: %v", target, err)
	}
	return true, nil
}

// runtimeAPIAtFinalized calls a runtime API at the latest finalized block.
func runtimeAPIAtFinalized(rpc rpcCaller, method string, args []byte) ([]byte, error) {
	head, err := finalizedHead(rpc)
	if err != nil {
		return nil, err
	}
	return runtimeCallAt(rpc, method, args, head)
}

// Query reads a storage entry into `result`, at the latest finalized block.
//
// Reports (false, nil) when the entry is absent. `keys` are the map keys,
// omitted for a plain value.
//
//	var info AccountInfo
//	found, err := client.Query(&info, "System", "Account", accountID)
func (c *ChainClient) Query(result any, pallet, entry string, keys ...[]byte) (bool, error) {
	return queryInto(c, c.meta, result, pallet, entry, keys...)
}

// QueryRaw reads a storage entry as undecoded SCALE bytes, for entries whose type
// this package does not model. Nil means absent.
func (c *ChainClient) QueryRaw(pallet, entry string, keys ...[]byte) ([]byte, error) {
	return storedAtFinalized(c, c.meta, pallet, entry, keys...)
}

// RuntimeAPI calls a runtime API by its state_call name at the latest finalized
// block, returning raw SCALE bytes for the caller to decode.
//
//	raw, err := client.RuntimeAPI("KgcApi_dkg_epoch", nil)
func (c *ChainClient) RuntimeAPI(method string, args []byte) ([]byte, error) {
	return runtimeAPIAtFinalized(c, method, args)
}

// Constant reads a pallet constant from the live metadata as raw SCALE bytes.
func (c *ChainClient) Constant(pallet, name string) ([]byte, error) {
	for _, p := range c.meta.AsMetadataV14.Pallets {
		if string(p.Name) != pallet {
			continue
		}
		for _, constant := range p.Constants {
			if string(constant.Name) == name {
				return constant.Value, nil
			}
		}
	}
	target := pallet + "." + name
	return nil, chainErrorf(KindChain, target, "%s: no such constant in the live metadata", target)
}

// WaitForFinalized polls the finalized head for up to two minutes until
// `confirm` reports a submitted call's effect is visible, then returns that block
// hash. The committee authorizes against a finalized block, so acting on a
// merely-included extrinsic yields HTTP 403.
//
//	blockHash, err := client.WaitForFinalized(func(at types.Hash) bool {
//	    ok, _ := client.SecretExistsAt(at, id)
//	    return ok
//	})
func (c *ChainClient) WaitForFinalized(confirm func(at types.Hash) bool) (string, error) {
	for i := 0; i < storeFinalityAttempts; i++ {
		time.Sleep(storeFinalityInterval)
		head, err := c.api.RPC.Chain.GetFinalizedHead()
		if err != nil {
			continue
		}
		if confirm(head) {
			return head.Hex(), nil
		}
	}
	return "", fmt.Errorf(
		"not finalized within %v; the extrinsic may still land, so check the chain "+
			"before resubmitting",
		time.Duration(storeFinalityAttempts)*storeFinalityInterval,
	)
}

// SecretExistsAt reports whether a secret is readable at the given block; a
// ready-made WaitForFinalized predicate for a store.
func (c *ChainClient) SecretExistsAt(at types.Hash, id SecretID) (bool, error) {
	return c.secretExistsAt(at, id)
}
