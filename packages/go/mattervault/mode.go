package mattervault

// Whether this client signs for itself or acts for a member.
//
// Under runtime spec 322 an OpenMatter API key is not an account with authority
// of its own. It is a delegate holding a ProxyType::Scoped(ScopeSet) proxy on the
// account of the member who minted it, and everything it does it does as that
// member, through proxy.proxy(member, None, call).
//
// The key's own account has no authority and no balance, so a directly signed
// call from a member-tied key is refused in the pool with "Inability to pay some
// fees". Resolving the mode at connect is what lets the client wrap correctly
// instead of submitting that doomed call.

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
	// notProxyError is pallet-proxy's complaint that no definition matches this
	// (key, member) pair — a revoked or rebound key, in practice.
	notProxyError = "NotProxy"
)

// agentKeyStateCall maps a key to its principal.
const agentKeyStateCall = "BudgetsApi_agent_key"

// agentKeyCall is how a runtime older than scoped keys is detected. The call and
// the BudgetsApi_agent_key runtime API shipped together in spec 322, and V14
// metadata carries calls but not runtime-API declarations — so the call is the
// half a GSRPC client can see locally. Reading it beats probing: an RPC that
// fails says nothing about which runtime is on the other end.
const agentKeyCall = "Budgets.authorize_agent_key"

// principalEnv names the principal a key acts for when the chain's pointer is stale.
const principalEnv = "MATTER_PRINCIPAL"

// agentKeyLookup is the one thing resolveDelegation needs from a chain, so the
// resolution logic can be exercised without one. *ChainClient satisfies it.
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

// forceProxyTypeNone encodes Option<ProxyType>::None.
//
// GSRPC has no generic Option[T] — only OptionBytes, OptionBool and friends — so
// this follows the same hand-rolled-constant convention extrinsic.go already uses
// for CheckMetadataHash's Option::None.
type forceProxyTypeNone struct{}

func (forceProxyTypeNone) Encode(encoder scale.Encoder) error {
	return encoder.PushByte(0)
}

// AgentKey reports who `key` acts for and what it may do, per the chain.
//
// A nil Delegation covers both "this chain has no such runtime API" (a runtime
// older than scoped keys) and "the chain has it and says this key is not
// registered": to a caller both mean there is no scoped proxy here.
func (c *ChainClient) AgentKey(key []byte) (*Delegation, error) {
	if !supportsAgentKeys(c.meta) {
		return nil, nil
	}
	raw, err := c.stateCall(agentKeyStateCall, key)
	if err != nil {
		// Not "no delegation": the chain has scoped keys and did not answer, so
		// nothing is known yet. Reporting absence here would resolve the client
		// to Direct and turn every later write into an unexplained fee refusal.
		return nil, fmt.Errorf("%s: %w", agentKeyStateCall, err)
	}
	return decodeAgentKey(raw)
}

// supportsAgentKeys reports whether this runtime has scoped API keys, by looking
// agentKeyCall up in metadata — the same path types.NewCall takes, so the gate
// and the encoder cannot disagree about what the runtime offers.
func supportsAgentKeys(meta *types.Metadata) bool {
	if meta == nil {
		return false
	}
	_, err := meta.FindCallIndex(agentKeyCall)
	return err == nil
}

// decodeAgentKey reads Option<(AccountId32, ScopeSet)> — 37 bytes when Some.
//
// Split from AgentKey so the wire shape can be pinned without a chain.
func decodeAgentKey(raw []byte) (*Delegation, error) {
	decoder := scale.NewDecoder(strings.NewReader(string(raw)))
	tag, err := decoder.ReadOneByte()
	if err != nil {
		return nil, fmt.Errorf("%s: reading the Option tag: %w", agentKeyStateCall, err)
	}
	if tag == 0 {
		return nil, nil
	}

	// The account decodes as an explicit [32]byte rather than types.AccountID so
	// this does not depend on how the metadata happens to shape AccountId32.
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
// MATTER_PRINCIPAL first: the escape hatch for a key whose pointer is stale while
// its proxy still stands. The chain cannot then report the scopes either, so this
// assumes the full set — the local pre-flight check turns off and the runtime's
// filter decides alone. Assuming the empty set would refuse every call locally and
// make the override useless, so the override is loud rather than narrow.
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
	// Said once, and worth saying: a key that was meant to be delegated but
	// resolved direct is the first thing anyone debugging an unexplained fee
	// rejection needs to see.
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

// callNames resolves an encoded call's (pallet, call) back from metadata.
//
// Go submits a pre-built types.Call, which carries only two index bytes, so the
// scope check has to work backwards to the names the table is written in.
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

// afterRefresh compares a fresh grant against the one held.
//
// Pure, because the rule it encodes is the one worth pinning: a key whose grant
// is gone stays delegated. Downgrading it to Direct would make the next write
// sign as the key's own balance-less account and fail as an unexplained fee
// error — the exact silent degradation the mode resolution exists to prevent.
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
// A balance-less key whose call the runtime will not admit is not sponsored at
// fee time, so it is refused here, before any block — which is why a revoked key
// reports "cannot pay fees" rather than Proxy.NotProxy. The JSON-RPC code is the
// reliable signal; the text is a fallback for transports that lose it.
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

// poolRejectionMarkers mirror the Rust client's, so the four bindings agree on
// what a pool rejection looks like when the code is unavailable.
var poolRejectionMarkers = []string{"1010", "Inability to pay", "InvalidTransaction"}
