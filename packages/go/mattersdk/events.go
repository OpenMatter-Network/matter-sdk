package mattersdk

// Event decoding via GSRPC's metadata-driven retriever; events_live_test.go
// exercises it against the live chain.

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/registry"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry/parser"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry/retriever"
	regState "github.com/centrifuge/go-substrate-rpc-client/v4/registry/state"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

// Event is one decoded runtime event.
type Event struct {
	// Pallet is the emitting pallet, e.g. "Secrets".
	Pallet string
	// Name is the event name, e.g. "SecretStored".
	Name string
	// Fields are the decoded event fields, in declaration order.
	Fields registry.DecodedFields
	// ExtrinsicIndex is the emitting extrinsic's position in the block, or nil
	// for initialization/finalization events. A block's events are one flat
	// vector, so attributing an event to a submission must compare this.
	ExtrinsicIndex *uint32
}

// String renders "Pallet.Name", the form used in errors and logs.
func (e Event) String() string { return e.Pallet + "." + e.Name }

// EventsAt decodes every event in a block.
func (c *ChainClient) EventsAt(blockHash types.Hash) ([]Event, error) {
	eventRetriever, err := retriever.NewDefaultEventRetriever(
		regState.NewEventProvider(c.api.RPC.State),
		c.api.RPC.State,
	)
	if err != nil {
		return nil, fmt.Errorf("build event retriever: %w", err)
	}

	raw, err := eventRetriever.GetEvents(blockHash)
	if err != nil {
		return nil, fmt.Errorf("decode events at %s: %w", blockHash.Hex(), err)
	}

	events := make([]Event, 0, len(raw))
	for _, e := range raw {
		events = append(events, splitEventName(e))
	}
	return events, nil
}

// FindEvent returns the first `pallet.name` event in a block, or false.
func (c *ChainClient) FindEvent(blockHash types.Hash, pallet, name string) (Event, bool, error) {
	events, err := c.EventsAt(blockHash)
	if err != nil {
		return Event{}, false, err
	}
	for _, e := range events {
		if e.Pallet == pallet && e.Name == name {
			return e, true, nil
		}
	}
	return Event{}, false, nil
}

// splitEventName turns the retriever's "Pallet.Name" into its two parts.
func splitEventName(e *parser.Event) Event {
	var index *uint32
	if e.Phase != nil && e.Phase.IsApplyExtrinsic {
		at := e.Phase.AsApplyExtrinsic
		index = &at
	}
	for i := 0; i < len(e.Name); i++ {
		if e.Name[i] == '.' {
			return Event{
				Pallet:         e.Name[:i],
				Name:           e.Name[i+1:],
				Fields:         e.Fields,
				ExtrinsicIndex: index,
			}
		}
	}
	// No separator: keep the whole name so the unexpected shape stays visible.
	return Event{Name: e.Name, Fields: e.Fields, ExtrinsicIndex: index}
}

// SecretIDFromEvent reads a u128 secret id from a decoded event's first field
// (`Secrets.SecretStored { secret_id, owner }`). The decoded integer type varies
// across runtimes, so the common integer shapes are all accepted.
func SecretIDFromEvent(e Event) (SecretID, error) {
	if len(e.Fields) == 0 {
		return SecretID{}, fmt.Errorf("%s carries no fields", e)
	}
	switch v := e.Fields[0].Value.(type) {
	case *big.Int:
		return ParseSecretID(v.String())
	case types.U128:
		return ParseSecretID(v.Int.String())
	case types.U64:
		return NewSecretID(uint64(v)), nil
	case uint64:
		return NewSecretID(v), nil
	default:
		return SecretID{}, fmt.Errorf(
			"%s field 0 is %T, not an integer secret id", e, e.Fields[0].Value)
	}
}

// ownerFromEvent reads the 32-byte account from `SecretStored`'s second field, or
// nil when absent or not account-shaped, so it never matches.
func ownerFromEvent(e Event) []byte {
	if len(e.Fields) < 2 {
		return nil
	}
	switch v := e.Fields[1].Value.(type) {
	case types.AccountID:
		return v[:]
	case [32]byte:
		return v[:]
	case []byte:
		if len(v) == accountIDBytes {
			return v
		}
	}
	return nil
}

// FindStoredSecret scans a block for a `Secrets.SecretStored` event owned by
// `owner` and returns the chain-assigned id. Matching on the owner, not a
// predicted id, keeps concurrent stores apart.
func (c *ChainClient) FindStoredSecret(blockHash types.Hash, owner []byte) (SecretID, bool, error) {
	events, err := c.EventsAt(blockHash)
	if err != nil {
		return SecretID{}, false, err
	}
	return storedSecretID(events, owner)
}

// storedSecretID reads the id from owner's `Secrets.SecretStored` among events,
// skipping stores by other accounts in the same block.
func storedSecretID(events []Event, owner []byte) (SecretID, bool, error) {
	for _, e := range events {
		if e.Pallet != "Secrets" || e.Name != "SecretStored" {
			continue
		}
		if !bytes.Equal(ownerFromEvent(e), owner) {
			continue
		}
		id, err := SecretIDFromEvent(e)
		if err != nil {
			return SecretID{}, false, err
		}
		return id, true, nil
	}
	return SecretID{}, false, nil
}

// ProxyFailure reports the wrapped call's error from the `Proxy.ProxyExecuted`
// event of extrinsic `index` in `blockHash`. The outer proxy.proxy succeeds
// whenever it dispatches, so this is the only record of a refused delegated call.
func (c *ChainClient) ProxyFailure(blockHash types.Hash, index uint32) (string, bool, error) {
	outcome, err := c.outcomeAt(blockHash, index)
	if err != nil {
		return "", false, err
	}
	if outcome.Proxied == nil {
		return "", false, nil
	}
	return c.describeDispatchError(*outcome.Proxied), true, nil
}

// ProxyFailures reports every wrapped-call failure in a block, as
// "extrinsic N: <error>". Use it to diagnose a WaitForFinalized predicate that
// timed out under a member-tied key.
func (c *ChainClient) ProxyFailures(blockHash types.Hash) ([]string, error) {
	events, err := c.EventsAt(blockHash)
	if err != nil {
		return nil, err
	}
	// Collect each extrinsic that emitted ProxyExecuted, so each is decoded once.
	seen := map[uint32]struct{}{}
	var indices []uint32
	for _, e := range events {
		if e.Pallet != proxyPallet || e.Name != proxyExecutedEvent || e.ExtrinsicIndex == nil {
			continue
		}
		if _, ok := seen[*e.ExtrinsicIndex]; ok {
			continue
		}
		seen[*e.ExtrinsicIndex] = struct{}{}
		indices = append(indices, *e.ExtrinsicIndex)
	}

	var failures []string
	for _, index := range indices {
		detail, failed, err := c.ProxyFailure(blockHash, index)
		if err != nil {
			return nil, err
		}
		if failed {
			failures = append(failures, fmt.Sprintf("extrinsic %d: %s", index, detail))
		}
	}
	return failures, nil
}
