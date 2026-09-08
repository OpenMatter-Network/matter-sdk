package mattervault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	subkey "github.com/vedhavyas/go-subkey/v2"
)

// metadataWithAgentKeyCall builds V14 metadata that declares
// Budgets.authorize_agent_key, which is what spec 322 looks like from a client
// that can read calls but not runtime-API declarations.
func metadataWithAgentKeyCall() *types.Metadata {
	meta := syntheticMetadata()
	callsType := types.NewSi1LookupTypeIDFromUInt(99)
	meta.AsMetadataV14.Pallets = []types.PalletMetadataV14{{
		Name:     "Budgets",
		Index:    21,
		HasCalls: true,
		Calls:    types.FunctionMetadataV14{Type: callsType},
	}}
	meta.AsMetadataV14.EfficientLookup = map[int64]*types.Si1Type{
		callsType.Int64(): {Def: types.Si1TypeDef{
			IsVariant: true,
			Variant: types.Si1TypeDefVariant{Variants: []types.Si1Variant{
				{Name: "authorize_agent_key", Index: 23},
			}},
		}},
	}
	return meta
}

func TestSupportsAgentKeysIsReadFromMetadata(t *testing.T) {
	if supportsAgentKeys(syntheticMetadata()) {
		t.Fatal("a runtime with no Budgets pallet must not claim scoped-key support")
	}
	if !supportsAgentKeys(metadataWithAgentKeyCall()) {
		t.Fatal("a runtime declaring Budgets.authorize_agent_key supports scoped keys")
	}
}

func TestAPre322RuntimeResolvesDirectWithoutAskingTheChain(t *testing.T) {
	// api is nil: any RPC attempt panics, so surviving this call is the proof
	// that the answer came from metadata alone.
	chain := &ChainClient{meta: syntheticMetadata()}
	got, err := chain.AgentKey(make([]byte, 32))
	if err != nil || got != nil {
		t.Fatalf("want (nil, nil) for a pre-322 runtime, got (%v, %v)", got, err)
	}
}

func TestALookupFailureStopsResolutionRatherThanGoingDirect(t *testing.T) {
	// The failure this guards: a transient RPC error resolves the client to
	// Direct, after which every write is signed as the key's own balance-less
	// account and dies in the pool as a fee error naming nothing.
	boom := errors.New("ws closed")
	got, err := resolveDelegation(&fakeAgentKeys{err: boom}, make([]byte, 32), 42, quietLogger())
	if err == nil {
		t.Fatal("a failed lookup must not be reported as no delegation")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("the original cause must survive: %v", err)
	}
	if got != nil {
		t.Fatalf("no delegation should be returned alongside an error, got %v", got)
	}
}

func TestAnUnregisteredKeyResolvesDirect(t *testing.T) {
	fake := &fakeAgentKeys{}
	got, err := resolveDelegation(fake, make([]byte, 32), 42, quietLogger())
	if err != nil || got != nil {
		t.Fatalf("want (nil, nil), got (%v, %v)", got, err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("the chain should be asked exactly once, got %d", len(fake.calls))
	}
}

func TestDecodeAgentKeyReadsTheOptionTuple(t *testing.T) {
	if got, err := decodeAgentKey([]byte{0x00}); err != nil || got != nil {
		t.Fatalf("0x00 is None: got (%v, %v)", got, err)
	}

	// 37 bytes: Option tag, 32-byte principal, ScopeSet as a bare LE u32 —
	// pinned against the live testnet answer.
	principal := make([]byte, 32)
	for i := range principal {
		principal[i] = byte(i)
	}
	scopes := uint32(0x000FFFFF)
	raw := append([]byte{0x01}, principal...)
	raw = binary.LittleEndian.AppendUint32(raw, scopes)

	got, err := decodeAgentKey(raw)
	if err != nil {
		t.Fatalf("decodeAgentKey: %v", err)
	}
	if string(got.Principal) != string(principal) || got.Scopes.Bits() != scopes {
		t.Fatalf("decoded %x/%v, want %x/%v", got.Principal, got.Scopes, principal, scopes)
	}

	if _, err := decodeAgentKey([]byte{0x01, 0x02}); err == nil {
		t.Fatal("a truncated Some must be an error, not a silent absence")
	}
}

func TestAfterRefreshTellsRevocationFromRescoping(t *testing.T) {
	alice := bytes.Repeat([]byte{1}, 32)
	bob := bytes.Repeat([]byte{2}, 32)
	narrow := SingleScope(ScopeDeployments, AccessWrite)
	wider := narrow.With(ScopeSecrets, AccessRead)
	held := &Delegation{Principal: alice, Scopes: narrow}

	cases := []struct {
		name  string
		fresh *Delegation
		want  refreshOutcome
	}{
		{"the same grant", &Delegation{Principal: alice, Scopes: narrow}, refreshUnchanged},
		{"revoked", nil, refreshGone},
		{"rebound to another member", &Delegation{Principal: bob, Scopes: narrow}, refreshGone},
		{"rescoped", &Delegation{Principal: alice, Scopes: wider}, refreshRescoped},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := afterRefresh(held, c.fresh); got != c.want {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}

	// A direct client has no grant to lose.
	if got := afterRefresh(nil, nil); got != refreshUnchanged {
		t.Fatalf("a direct client is never refreshed, got %v", got)
	}
}

func TestPoolRejectionIsRecognisedByCodeAndByText(t *testing.T) {
	if isPoolRejection(nil) {
		t.Fatal("no error is not a rejection")
	}
	if isPoolRejection(errors.New("connection reset")) {
		t.Fatal("an unrelated failure is not a pool rejection")
	}
	// The text fallback, for transports that lose the JSON-RPC code.
	if !isPoolRejection(errors.New("Invalid Transaction: Inability to pay some fees")) {
		t.Fatal("the fee refusal must be recognised")
	}
	if !isPoolRejection(&codedError{code: 1010, msg: "Invalid Transaction"}) {
		t.Fatal("code 1010 must be recognised")
	}
	if isPoolRejection(&codedError{code: 1002, msg: "Verification Error"}) {
		t.Fatal("a different code is not a pool rejection")
	}
}

// codedError stands in for a JSON-RPC error carrying a numeric code.
type codedError struct {
	code int
	msg  string
}

func (e *codedError) Error() string  { return e.msg }
func (e *codedError) ErrorCode() int { return e.code }

func TestTheResolvedModeIsLoggedAsSS58(t *testing.T) {
	// The principal a user reads here has to be the string the dashboard showed
	// them when they minted the key. Hex would be correct and useless.
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	principal := bytes.Repeat([]byte{1}, 32)
	scopes := SingleScope(ScopeDeployments, AccessWrite).With(ScopeSecrets, AccessRead)

	_, err := resolveDelegation(
		&fakeAgentKeys{delegation: &Delegation{Principal: principal, Scopes: scopes}},
		principal, 42, log)
	if err != nil {
		t.Fatalf("resolveDelegation: %v", err)
	}

	logged := buf.String()
	if want := subkey.SS58Encode(principal, 42); !strings.Contains(logged, want) {
		t.Fatalf("want the principal as %s, got %q", want, logged)
	}
	if !strings.Contains(logged, "deployments:w, secrets:r") {
		t.Fatalf("want the scopes in their readable form, got %q", logged)
	}
}

// quietLogger discards output for tests that are not about what was logged.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
