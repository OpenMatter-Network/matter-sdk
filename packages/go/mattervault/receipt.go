package mattervault

// Reading the outcome of a submitted extrinsic from a block's events.
//
// Under delegation this is not optional bookkeeping. `proxy.proxy` succeeds as
// an extrinsic whenever the proxy *dispatched* something, so "the extrinsic
// landed" says nothing about whether the call inside it ran. The failure is
// reported as Proxy.ProxyExecuted { result: Err(..) } and nowhere else.
//
// The result is decoded from the SCALE bytes rather than from the registry's
// decoded form, because the registry discards variant names: Result's Ok arm and
// DispatchError's Other arm are both variant 0 with no fields, so both arrive as
// a bare byte 0 and no structural rule can tell a success from a failure. The
// byte order is the wire contract; the rendering is not.

import (
	"bytes"
	"fmt"
	"io"

	"github.com/centrifuge/go-substrate-rpc-client/v4/registry"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry/parser"
	regState "github.com/centrifuge/go-substrate-rpc-client/v4/registry/state"
	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

const (
	systemPallet          = "System"
	extrinsicFailedEvent  = "ExtrinsicFailed"
	extrinsicSuccessEvent = "ExtrinsicSuccess"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// extrinsicOutcome is everything a block's events say about one extrinsic.
type extrinsicOutcome struct {
	// Failed is set when the extrinsic itself was refused at dispatch.
	Failed *types.DispatchError
	// Proxied is set when a wrapped call failed inside a successful proxy.proxy.
	Proxied *types.DispatchError
	// SawProxy records that a ProxyExecuted event was attributed to this
	// extrinsic at all. Its absence under delegation means the wrapped call's
	// fate is unknown, which is a failure to report rather than assume away.
	SawProxy bool
	// Events are this extrinsic's events, the wrapped call's included.
	Events []Event
}

// decodeDispatchResult reads a `Result<(), DispatchError>`: 0x00 for Ok, 0x01
// followed by the error for Err. Returns nil for a successful call.
func decodeDispatchResult(decoder *scale.Decoder) (*types.DispatchError, error) {
	tag, err := decoder.ReadOneByte()
	if err != nil {
		return nil, fmt.Errorf("reading the DispatchResult tag: %w", err)
	}
	switch tag {
	case 0:
		return nil, nil
	case 1:
		var dispatchErr types.DispatchError
		if err := decoder.Decode(&dispatchErr); err != nil {
			return nil, fmt.Errorf("decoding the wrapped call's error: %w", err)
		}
		return &dispatchErr, nil
	default:
		return nil, fmt.Errorf("unknown DispatchResult discriminant %d", tag)
	}
}

// eventID resolves "pallet.event" to the two bytes that identify it on the wire.
func eventID(meta *types.Metadata, pallet, event string) (types.EventID, bool) {
	if meta == nil || meta.Version < 14 {
		return types.EventID{}, false
	}
	for _, p := range meta.AsMetadataV14.Pallets {
		if string(p.Name) != pallet || !p.HasEvents {
			continue
		}
		lookup, ok := meta.AsMetadataV14.EfficientLookup[p.Events.Type.Int64()]
		if !ok || !lookup.Def.IsVariant {
			return types.EventID{}, false
		}
		for _, variant := range lookup.Def.Variant.Variants {
			if string(variant.Name) == event {
				return types.EventID{byte(p.Index), byte(variant.Index)}, true
			}
		}
	}
	return types.EventID{}, false
}

// describeDispatchError renders an error the way a caller can act on: a module
// error by its pallet and name, everything else by its variant.
func (c *ChainClient) describeDispatchError(e types.DispatchError) string {
	if e.IsModule {
		if meta, err := c.meta.FindError(e.ModuleError.Index, e.ModuleError.Error); err == nil && meta != nil {
			return fmt.Sprintf("%s.%s", meta.Name, meta.Value)
		}
		return fmt.Sprintf("module error %d/%v", e.ModuleError.Index, e.ModuleError.Error)
	}
	return describeNonModuleDispatchError(e)
}

func describeNonModuleDispatchError(e types.DispatchError) string {
	switch {
	case e.IsOther:
		return "Other"
	case e.IsCannotLookup:
		return "CannotLookup"
	case e.IsBadOrigin:
		return "BadOrigin"
	case e.IsConsumerRemaining:
		return "ConsumerRemaining"
	case e.IsNoProviders:
		return "NoProviders"
	case e.IsTooManyConsumers:
		return "TooManyConsumers"
	case e.IsToken:
		return fmt.Sprintf("Token(%v)", e.TokenError)
	case e.IsArithmetic:
		return fmt.Sprintf("Arithmetic(%v)", e.ArithmeticError)
	case e.IsTransactional:
		return fmt.Sprintf("Transactional(%v)", e.TransactionalError)
	default:
		return "DispatchError"
	}
}

// outcomeAt reads what the block says about the extrinsic at `index`.
//
// The walk mirrors GSRPC's own event parser — compact count, then per event a
// Phase, an EventID, its fields and its topics — but decodes the two events that
// carry a DispatchError itself, from bytes. Every other event is handed to the
// registry purely to advance the decoder past it.
func (c *ChainClient) outcomeAt(blockHash types.Hash, index uint32) (extrinsicOutcome, error) {
	eventRegistry, err := registry.NewFactory().CreateEventRegistry(c.meta)
	if err != nil {
		return extrinsicOutcome{}, wrapChainError(KindChain, "System.Events", err, "build the event registry: %v", err)
	}
	raw, err := regState.NewEventProvider(c.api.RPC.State).GetStorageEvents(c.meta, blockHash)
	if err != nil {
		return extrinsicOutcome{}, wrapChainError(KindChain, "System.Events", err, "read events at %s: %v", blockHash.Hex(), err)
	}
	return parseOutcome(c.meta, eventRegistry, *raw, index)
}

func parseOutcome(meta *types.Metadata, eventRegistry registry.EventRegistry, raw []byte, index uint32) (extrinsicOutcome, error) {
	proxyExecutedID, hasProxyExecuted := eventID(meta, proxyPallet, proxyExecutedEvent)
	extrinsicFailedID, hasExtrinsicFailed := eventID(meta, systemPallet, extrinsicFailedEvent)

	decoder := scale.NewDecoder(bytesReader(raw))
	count, err := decoder.DecodeUintCompact()
	if err != nil {
		return extrinsicOutcome{}, fmt.Errorf("decoding the event count: %w", err)
	}

	var outcome extrinsicOutcome
	for i := uint64(0); i < count.Uint64(); i++ {
		var phase types.Phase
		if err := decoder.Decode(&phase); err != nil {
			return extrinsicOutcome{}, fmt.Errorf("event #%d: decoding the phase: %w", i, err)
		}
		var id types.EventID
		if err := decoder.Decode(&id); err != nil {
			return extrinsicOutcome{}, fmt.Errorf("event #%d: decoding the id: %w", i, err)
		}
		mine := phase.IsApplyExtrinsic && phase.AsApplyExtrinsic == index

		switch {
		case mine && hasProxyExecuted && id == proxyExecutedID:
			outcome.SawProxy = true
			dispatchErr, err := decodeDispatchResult(decoder)
			if err != nil {
				return extrinsicOutcome{}, fmt.Errorf("event #%d: %w", i, err)
			}
			if dispatchErr != nil {
				outcome.Proxied = dispatchErr
			}
			outcome.Events = append(outcome.Events, Event{Pallet: proxyPallet, Name: proxyExecutedEvent})
		case mine && hasExtrinsicFailed && id == extrinsicFailedID:
			var dispatchErr types.DispatchError
			if err := decoder.Decode(&dispatchErr); err != nil {
				return extrinsicOutcome{}, fmt.Errorf("event #%d: decoding ExtrinsicFailed: %w", i, err)
			}
			outcome.Failed = &dispatchErr
			// The event's second field is a DispatchInfo; let the registry's own
			// decoder consume it rather than hand-writing a layout that moves.
			if err := skipRemainingFields(eventRegistry, id, decoder, 1); err != nil {
				return extrinsicOutcome{}, fmt.Errorf("event #%d: %w", i, err)
			}
			outcome.Events = append(outcome.Events, Event{Pallet: systemPallet, Name: extrinsicFailedEvent})
		default:
			eventDecoder, ok := eventRegistry[id]
			if !ok {
				return extrinsicOutcome{}, fmt.Errorf("event #%d: no decoder for id %v", i, id)
			}
			fields, err := eventDecoder.Decode(decoder)
			if err != nil {
				return extrinsicOutcome{}, fmt.Errorf("event #%d: decoding fields: %w", i, err)
			}
			if mine {
				event := splitEventName(&parser.Event{Name: eventDecoder.Name, Fields: fields, Phase: &phase})
				outcome.Events = append(outcome.Events, event)
			}
		}

		var topics []types.Hash
		if err := decoder.Decode(&topics); err != nil {
			return extrinsicOutcome{}, fmt.Errorf("event #%d: decoding topics: %w", i, err)
		}
	}
	return outcome, nil
}

// skipRemainingFields advances the decoder past the fields of `id` after the
// first `consumed` of them, using the metadata's own field decoders.
func skipRemainingFields(eventRegistry registry.EventRegistry, id types.EventID, decoder *scale.Decoder, consumed int) error {
	eventDecoder, ok := eventRegistry[id]
	if !ok {
		return fmt.Errorf("no decoder for id %v", id)
	}
	for i, field := range eventDecoder.Fields {
		if i < consumed {
			continue
		}
		if _, err := field.FieldDecoder.Decode(decoder); err != nil {
			return fmt.Errorf("skipping field %d: %w", i, err)
		}
	}
	return nil
}

// delegatedOutcome turns a decoded outcome into the error a caller should see.
//
// Pure, so the rule that matters most — a wrapped failure is never a success —
// is pinned without a chain.
func delegatedOutcome(o extrinsicOutcome, delegated bool, target string, describe func(types.DispatchError) string) error {
	if o.Failed != nil {
		return chainErrorf(KindChain, target, "%s was refused: %s", target, describe(*o.Failed))
	}
	if !delegated {
		return nil
	}
	if o.Proxied != nil {
		return chainErrorf(KindDispatch, target,
			"%s ran as your principal and failed: %s", target, describe(*o.Proxied))
	}
	if !o.SawProxy {
		// The outer extrinsic neither failed nor reported what it dispatched.
		// Reporting success here would be a guess about someone else's money.
		return chainErrorf(KindChain, target,
			"%s: the proxy.proxy extrinsic finalized without a Proxy.ProxyExecuted event, "+
				"so whether the wrapped call ran is unknown", target)
	}
	return nil
}
