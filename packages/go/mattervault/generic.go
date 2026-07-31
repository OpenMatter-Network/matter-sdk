package mattervault

// The generic, metadata-driven surface: reach any pallet the runtime exposes.
//
// Names resolve against the metadata loaded at connect, so a pallet added by a
// forkless upgrade is reachable without an SDK release. GSRPC decodes storage into
// a caller-supplied target rather than a dynamic value, so these take a `result`
// pointer — that is the library's idiom, and inventing a dynamic value type here
// would be a second decoder to keep correct.

import (
	"fmt"
	"time"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

// Query reads a storage entry into `result`.
//
// Reports (false, nil) when the entry is absent, which is normal control flow —
// an unfunded account simply has no `System.Account` row, and that is not an
// error. `keys` are the map keys, omitted for a plain value.
//
//	var info AccountInfo
//	found, err := client.Query(&info, "System", "Account", accountID)
func (c *ChainClient) Query(result any, pallet, entry string, keys ...[]byte) (bool, error) {
	target := pallet + "." + entry
	key, err := types.CreateStorageKey(c.meta, pallet, entry, keys...)
	if err != nil {
		return false, fmt.Errorf("%s: %w (was the runtime upgraded?)", target, err)
	}
	found, err := c.api.RPC.State.GetStorageLatest(key, result)
	if err != nil {
		return false, fmt.Errorf("%s: %w", target, err)
	}
	return found, nil
}

// QueryRaw reads a storage entry as undecoded SCALE bytes, for entries whose type
// this package does not model. Nil means absent.
func (c *ChainClient) QueryRaw(pallet, entry string, keys ...[]byte) ([]byte, error) {
	target := pallet + "." + entry
	key, err := types.CreateStorageKey(c.meta, pallet, entry, keys...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (was the runtime upgraded?)", target, err)
	}
	raw, err := c.api.RPC.State.GetStorageRawLatest(key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", target, err)
	}
	if raw == nil || len(*raw) == 0 {
		return nil, nil
	}
	return []byte(*raw), nil
}

// RuntimeAPI calls a runtime API by its state_call name, returning raw SCALE
// bytes for the caller to decode.
//
//	raw, err := client.RuntimeAPI("KgcApi_dkg_epoch", nil)
func (c *ChainClient) RuntimeAPI(method string, args []byte) ([]byte, error) {
	raw, err := c.stateCall(method, args)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	return raw, nil
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
	return nil, fmt.Errorf("%s.%s: no such constant in the live metadata", pallet, name)
}

// WaitForFinalized polls the finalized head until `confirm` reports the effect of
// a submitted call is visible there, then returns that block hash.
//
// Finality matters and cannot be skipped: the committee authorizes a
// partial-decrypt against a finalized block, so acting on a merely-included
// extrinsic yields an HTTP 403.
//
// Confirmation is a caller-supplied predicate rather than extrinsic-hash matching
// because GSRPC v4.2.1 has no finalized-extrinsic watcher that works against this
// runtime's signed extensions, and re-deriving an extrinsic hash from a decoded
// block is not something this package can claim to do correctly without a live
// test to prove it. A domain check — "is the secret readable at this block?" — is
// both simpler and a stronger guarantee, since it confirms the *effect* rather
// than the transaction's presence. `StoreSecret` uses exactly this.
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

// SecretExistsAt reports whether a secret is readable at the given block — the
// confirmation predicate for a store, exported so callers can reuse it.
func (c *ChainClient) SecretExistsAt(at types.Hash, id SecretID) (bool, error) {
	return c.secretExistsAt(at, id)
}
