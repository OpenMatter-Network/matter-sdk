package mattersdk

// Delegated mode (runtime spec >= 322): a member-tied API key holds a
// ProxyType::Scoped(ScopeSet) proxy on its member's account and acts through
// proxy.proxy(member, None, call). Its own account has no balance, so a directly
// signed call is refused with "Inability to pay some fees"; the mode is resolved
// at connect so calls are wrapped.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	subkey "github.com/vedhavyas/go-subkey/v2"
)

// pallet-proxy's dispatch surface, as a delegated key uses it.
const (
	proxyPallet        = "Proxy"
	proxyCall          = "Proxy.proxy"
	proxyExecutedEvent = "ProxyExecuted"
	// notProxyError: no proxy for this (key, member) pair, i.e. a revoked or
	// rebound key.
	notProxyError = "NotProxy"
)

// agentKeyStateCall maps a key to its principal.
const agentKeyStateCall = "BudgetsApi_agent_key"

// agentKeyCall detects scoped-key support (spec >= 322). V14 metadata lists calls
// but not runtime APIs, so this call, which shipped with BudgetsApi_agent_key, is
// the locally visible signal.
const agentKeyCall = "Budgets.authorize_agent_key"

// principalEnv names the principal a key acts for when the chain's pointer is stale.
const principalEnv = "MATTER_PRINCIPAL"

// agentKeyLookup lets resolveDelegation be tested without a chain.
type agentKeyLookup interface {
	AgentKey(key []byte) (*Delegation, error)
}

// Delegation is who a client's key acts for, and what it may do.
type Delegation struct {
	// Principal is the member every call actually runs as, and who pays for it.
	Principal []byte
	// Scopes is what the chain says this key may do.
	Scopes ScopeSet
}

// forceProxyTypeNone encodes Option<ProxyType>::None; GSRPC has no generic
// Option[T].
type forceProxyTypeNone struct{}

func (forceProxyTypeNone) Encode(encoder scale.Encoder) error {
	return encoder.PushByte(0)
}

// AgentKey reports who `key` acts for and what it may do, per the chain. A nil
// Delegation means no scoped proxy: the runtime predates scoped keys or the key
// is not registered.
func (c *ChainClient) AgentKey(key []byte) (*Delegation, error) {
	if !supportsAgentKeys(c.meta) {
		return nil, nil
	}
	raw, err := c.stateCall(agentKeyStateCall, key)
	if err != nil {
		// Not absence: returning nil would resolve the client to direct mode and
		// make every later write an unexplained fee refusal.
		return nil, fmt.Errorf("%s: %w", agentKeyStateCall, err)
	}
	return decodeAgentKey(raw)
}

// supportsAgentKeys reports whether this runtime has scoped API keys, via the
// same metadata lookup types.NewCall uses, so gate and encoder cannot disagree.
func supportsAgentKeys(meta *types.Metadata) bool {
	if meta == nil {
		return false
	}
	_, err := meta.FindCallIndex(agentKeyCall)
	return err == nil
}

// decodeAgentKey reads Option<(AccountId32, ScopeSet)>: 37 bytes when Some.
func decodeAgentKey(raw []byte) (*Delegation, error) {
	decoder := scale.NewDecoder(strings.NewReader(string(raw)))
	tag, err := decoder.ReadOneByte()
	if err != nil {
		return nil, fmt.Errorf("%s: reading the Option tag: %w", agentKeyStateCall, err)
	}
	if tag == 0 {
		return nil, nil
	}

	// [32]byte, not types.AccountID, so this does not depend on the metadata's
	// shape for AccountId32.
	var principal [32]byte
	if err := decoder.Decode(&principal); err != nil {
		return nil, fmt.Errorf("%s: decoding the principal: %w", agentKeyStateCall, err)
	}
	var bits types.U32
	if err := decoder.Decode(&bits); err != nil {
		return nil, fmt.Errorf("%s: decoding the scope set: %w", agentKeyStateCall, err)
	}
	return &Delegation{Principal: principal[:], Scopes: ScopeSetFromBits(uint32(bits))}, nil
}

// resolveDelegation asks the chain who `account` acts for.
//
// MATTER_PRINCIPAL overrides the chain for a key whose pointer is stale while its
// proxy stands. Scopes are then unknown, so the full set is assumed: local scope
// checks are off, the runtime alone enforces, and a warning is logged.
func resolveDelegation(chain agentKeyLookup, account []byte, ss58Prefix uint16, log *slog.Logger) (*Delegation, error) {
	if override := strings.TrimSpace(os.Getenv(principalEnv)); override != "" {
		principal, err := decodeAccountText(override)
		if err != nil {
			return nil, err
		}
		log.Warn(
			"acting for an overridden principal without asking the chain; "+
				"local scope checking is disabled and the runtime alone enforces",
			"env", principalEnv, "principal", override)
		return &Delegation{Principal: principal, Scopes: AllScopeSet()}, nil
	}

	delegation, err := chain.AgentKey(account)
	if err != nil || delegation == nil {
		return nil, err
	}
	// Logged once: the first thing to check when debugging a fee rejection.
	log.Info("acting for a member",
		"principal", subkey.SS58Encode(delegation.Principal, ss58Prefix),
		"scopes", delegation.Scopes.String())
	return delegation, nil
}

// decodeAccountText parses MATTER_PRINCIPAL: 0x-hex or SS58.
func decodeAccountText(text string) ([]byte, error) {
	bad := fmt.Errorf(
		"%s is neither 0x-prefixed hex nor a valid SS58 address", principalEnv)
	if strings.HasPrefix(text, "0x") {
		raw, err := hex.DecodeString(text[2:])
		if err != nil || len(raw) != 32 {
			return nil, bad
		}
		return raw, nil
	}
	_, raw, err := subkey.SS58Decode(text)
	if err != nil || len(raw) != 32 {
		return nil, bad
	}
	return raw, nil
}

// callNames resolves an encoded call's index bytes to (pallet, call) names.
func callNames(meta *types.Metadata, index types.CallIndex) (string, string, bool) {
	for _, pallet := range meta.AsMetadataV14.Pallets {
		if !pallet.HasCalls || uint8(pallet.Index) != index.SectionIndex {
			continue
		}
		callType, ok := meta.AsMetadataV14.EfficientLookup[pallet.Calls.Type.Int64()]
		if !ok {
			return "", "", false
		}
		for _, variant := range callType.Def.Variant.Variants {
			if uint8(variant.Index) == index.MethodIndex {
				return string(pallet.Name), string(variant.Name), true
			}
		}
	}
	return "", "", false
}

// refreshOutcome is what a re-read of the chain's grant says about the one this
// client resolved at connect.
type refreshOutcome int

const (
	// refreshUnchanged: the same principal, the same scopes.
	refreshUnchanged refreshOutcome = iota
	// refreshRescoped: still ours, but the scopes moved.
	refreshRescoped
	// refreshGone: revoked, or rebound to a different member.
	refreshGone
)

// afterRefresh compares a fresh grant against the one held. A gone grant stays
// delegated: downgrading to direct would make the next write fail as an
// unexplained fee error.
func afterRefresh(previous, fresh *Delegation) refreshOutcome {
	if previous == nil {
		return refreshUnchanged
	}
	if fresh == nil || !bytes.Equal(fresh.Principal, previous.Principal) {
		return refreshGone
	}
	if fresh.Scopes.Bits() != previous.Scopes.Bits() {
		return refreshRescoped
	}
	return refreshUnchanged
}

// isPoolRejection reports whether the node refused a transaction at validation
// rather than the runtime refusing it at dispatch.
//
// A balance-less key the runtime will not admit is refused here, before any
// block, so a revoked key reports "cannot pay fees" rather than Proxy.NotProxy.
// The JSON-RPC code is authoritative; the text is a fallback.
func isPoolRejection(err error) bool {
	if err == nil {
		return false
	}
	var coded interface{ ErrorCode() int }
	if errors.As(err, &coded) && coded.ErrorCode() == poolRejectionCode {
		return true
	}
	text := err.Error()
	for _, marker := range poolRejectionMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// poolRejectionCode is substrate's "Invalid Transaction" JSON-RPC error.
const poolRejectionCode = 1010

// poolRejectionMarkers match the Rust client's, for when the code is lost.
var poolRejectionMarkers = []string{"1010", "Inability to pay", "InvalidTransaction"}
