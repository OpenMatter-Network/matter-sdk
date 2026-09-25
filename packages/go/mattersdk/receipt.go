package mattersdk

// Extrinsic outcomes from block events. DispatchResult is decoded from SCALE
// bytes, not the registry's decoded form: the registry drops variant names, so Ok
// and DispatchError::Other both arrive as a bare 0.

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
	// SawProxy records a ProxyExecuted event for this extrinsic. Its absence
	// under delegation means the wrapped call's fate is unknown: an error.
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

// describeDispatchError renders a module error as Pallet.Error, anything else
// by its variant.
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

// outcomeAt reads what the block says about the extrinsic at `index`. The two
// DispatchError-bearing events are decoded from bytes; the registry decodes the rest.
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
			// Let the registry skip DispatchInfo; its layout is not stable.
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

// delegatedOutcome maps a decoded outcome to the caller's error. A wrapped
// failure is never a success.
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
		// No failure, but no dispatch report either: never assume success.
		return chainErrorf(KindChain, target,
			"%s: the proxy.proxy extrinsic finalized without a Proxy.ProxyExecuted event, "+
				"so whether the wrapped call ran is unknown", target)
	}
	return nil
}
