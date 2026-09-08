package mattervault

// Decoding events from a finalized block.
//
// This replaces a real race in StoreSecret. It used to read the
// `Secrets.NextSecretId` counter *before* submitting and then poll for that exact
// id, which is a prediction, not an answer: two concurrent submitters read the same
// counter, and the poll would happily confirm the *other* party's secret.
//
// Reading the id out of the chain's own `Secrets.SecretStored` event removes the
// guess. GSRPC's event retriever is metadata-driven, so this needs no hand-written
// decoder per event — but it is also unproven against a 60-pallet runtime, so
// `events_live_test.go` exercises it against the live chain before anyone relies
// on it.

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
	// ExtrinsicIndex is which extrinsic in the block emitted this event, or nil
	// for events from block initialization or finalization.
	//
	// A block holds every extrinsic's events in one flat vector, so matching on
	// pallet and name alone can pick up somebody else's. Anything that must
	// attribute an event to *our* submission has to compare this.
	ExtrinsicIndex *uint32
}

// String renders "Pallet.Name", the form used in errors and logs.
func (e Event) String() string { return e.Pallet + "." + e.Name }

// EventsAt decodes every event in a block.
//
// Names arrive from the retriever as "Pallet.Name" and are split here so callers
// match on two fields rather than parsing a string at each site.
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
	// No separator: keep the whole thing as the name rather than silently
	// dropping it, so an unexpected shape is visible instead of missing.
	return Event{Name: e.Name, Fields: e.Fields, ExtrinsicIndex: index}
}

// SecretIDFromEvent reads a u128 secret id out of a decoded event's first field.
//
// `Secrets.SecretStored { secret_id, owner }` declares the id first, and SCALE
// field order follows declaration order. The registry decodes a u128 as *big.Int,
// but the concrete type varies by width across runtimes, so the common integer
// shapes are accepted rather than asserting one.
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

// ownerFromEvent reads the 32-byte account out of `SecretStored`'s second field.
//
// This is what makes the id trustworthy: matching on our own account distinguishes
// our store from a concurrent submitter's, which reading a counter cannot do.
// Returns nil when the field is absent or not account-shaped, so a caller treats it
// as "not ours" rather than as a match.
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

// FindStoredSecret scans a block for a `Secrets.SecretStored` event belonging to
// `owner` and returns the chain-assigned id.
//
// Matching on the owner rather than a predicted id is the whole point. StoreSecret
// used to read the `NextSecretId` counter before submitting and then confirm that
// exact id existed — but two concurrent submitters read the same counter, so the
// confirmation could pass on someone else's secret.
func (c *ChainClient) FindStoredSecret(blockHash types.Hash, owner []byte) (SecretID, bool, error) {
	events, err := c.EventsAt(blockHash)
	if err != nil {
		return SecretID{}, false, err
	}
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

// ProxyFailure reports the wrapped call's own error from the
// `Proxy.ProxyExecuted` event emitted by extrinsic `index` in `blockHash`.
//
// This is the only place a delegated call's real outcome lives. The outer
// `proxy.proxy` extrinsic succeeds whenever the proxy *dispatched* something, so
// a caller that stops at "the extrinsic landed" cannot tell a completed call from
// a refused one.
//
// The extrinsic index matters: a block's events are one flat vector, so matching
// on pallet and name alone would happily report someone else's proxy failure.
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
// "extrinsic N: <error>".
//
// The diagnosis half of the delegated path. A domain check remains the way to
// confirm a call worked — it proves the effect rather than the transaction, which
// is why WaitForFinalized takes a predicate — but when that check times out under
// a member-tied key, the reason is here and nowhere else: the outer proxy.proxy
// extrinsic succeeded, so nothing else in the block records that the call was
// refused.
func (c *ChainClient) ProxyFailures(blockHash types.Hash) ([]string, error) {
	events, err := c.EventsAt(blockHash)
	if err != nil {
		return nil, err
	}
	// Which extrinsics emitted a ProxyExecuted at all, so each is decoded once
	// from bytes rather than the whole block being walked per extrinsic.
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
