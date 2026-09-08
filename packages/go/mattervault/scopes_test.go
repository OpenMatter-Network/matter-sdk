package mattervault

// The scope contract, replayed from the fixtures Rust emits.
//
// Both ways, like facade_test.go: a fixture row this binding cannot classify is
// drift, and so is a classification the fixture does not know about.
//
// Plus the one thing only Go has to prove: that an inner types.Call nests inside
// proxy.proxy as a RuntimeCall byte-for-byte. GSRPC gets that right through its
// generic reflection encoder rather than by design, so it is pinned rather than
// trusted.

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/registry"
	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

type scopeBitsFixture struct {
	Scopes []struct {
		Scope    string `json:"scope"`
		Index    int    `json:"index"`
		ReadBit  uint32 `json:"read_bit"`
		WriteBit uint32 `json:"write_bit"`
	} `json:"scopes"`
	AllBits uint32 `json:"all_bits"`
	Algebra []struct {
		Held       uint32 `json:"held"`
		Required   uint32 `json:"required"`
		HeldText   string `json:"held_text"`
		IsSuperset bool   `json:"is_superset"`
	} `json:"algebra"`
}

type requiredScopesFixture struct {
	Calls []struct {
		Pallet       string  `json:"pallet"`
		Call         string  `json:"call"`
		Required     *uint32 `json:"required"`
		RequiredText *string `json:"required_text"`
		ArgSensitive bool    `json:"arg_sensitive"`
	} `json:"calls"`
}

func loadScopeBits(t *testing.T) scopeBitsFixture {
	t.Helper()
	var doc scopeBitsFixture
	load(t, "scope_bits.json", &doc)
	return doc
}

func loadRequiredScopes(t *testing.T) requiredScopesFixture {
	t.Helper()
	var doc requiredScopesFixture
	load(t, "required_scopes.json", &doc)
	if len(doc.Calls) < 100 {
		t.Fatalf("required_scopes.json has only %d rows; regenerate it", len(doc.Calls))
	}
	return doc
}

func TestScopeBitsMatchTheFixture(t *testing.T) {
	fixture := loadScopeBits(t)
	for _, row := range fixture.Scopes {
		scope := Scope(row.Index)
		if got := SingleScope(scope, AccessRead).Bits(); got != row.ReadBit {
			t.Errorf("%s read bit = %d, want %d", row.Scope, got, row.ReadBit)
		}
		if got := SingleScope(scope, AccessWrite).Bits(); got != row.WriteBit {
			t.Errorf("%s write bit = %d, want %d", row.Scope, got, row.WriteBit)
		}
		// The name is what String must emit for that scope alone.
		if got := SingleScope(scope, AccessRead).String(); got != row.Scope+":r" {
			t.Errorf("String() = %q, want %q", got, row.Scope+":r")
		}
	}
	if got := AllScopeSet().Bits(); got != fixture.AllBits {
		t.Errorf("AllScopeSet = %d, want %d", got, fixture.AllBits)
	}
	// A scope added on either side without the other fails here.
	if len(AllScopes) != len(fixture.Scopes) {
		t.Errorf("Go knows %d scopes, the fixture pins %d", len(AllScopes), len(fixture.Scopes))
	}
}

func TestScopeSupersetMatchesTheFixture(t *testing.T) {
	for _, row := range loadScopeBits(t).Algebra {
		held := ScopeSetFromBits(row.Held)
		required := ScopeSetFromBits(row.Required)
		if got := held.IsSuperset(required); got != row.IsSuperset {
			t.Errorf("%s ⊇ %s = %v, want %v", held, required, got, row.IsSuperset)
		}
		if got := held.String(); got != row.HeldText {
			t.Errorf("String() = %q, want %q", got, row.HeldText)
		}
	}
}

func TestReadAndWriteStayIndependent(t *testing.T) {
	readOnly := SingleScope(ScopeSecrets, AccessRead)
	if readOnly.Contains(ScopeSecrets, AccessWrite) {
		t.Error("a read bit must not imply a write bit")
	}
	writeOnly := SingleScope(ScopeSecrets, AccessWrite)
	if writeOnly.Contains(ScopeSecrets, AccessRead) {
		t.Error("a write bit must not imply a read bit")
	}
}

func TestScopeSetRoundTripsThroughText(t *testing.T) {
	for _, set := range []ScopeSet{
		EmptyScopeSet(),
		AllScopeSet(),
		SingleScope(ScopeCommunities, AccessWrite),
		CoveringScopes(ScopeDeployments, ScopeBilling),
	} {
		parsed, err := ParseScopeSet(set.String())
		if err != nil {
			t.Fatalf("ParseScopeSet(%q): %v", set.String(), err)
		}
		if parsed != set {
			t.Errorf("round trip of %q gave %q", set, parsed)
		}
	}

	lenient, err := ParseScopeSet("Deployments:W  Secrets:R")
	if err != nil {
		t.Fatalf("lenient parse: %v", err)
	}
	if got := lenient.String(); got != "deployments:w, secrets:r" {
		t.Errorf("lenient parse gave %q", got)
	}
}

func TestScopeSetRejectsMalformedText(t *testing.T) {
	for _, bad := range []string{
		"deployments",
		"deploy:r",
		"secrets:x",
		// A repeated letter is a confused generator, not a wider set.
		"secrets:rr",
	} {
		if _, err := ParseScopeSet(bad); err == nil {
			t.Errorf("ParseScopeSet(%q) should have failed", bad)
		}
	}
}

func TestRequiredScopesMatchTheFixture(t *testing.T) {
	for _, row := range loadRequiredScopes(t).Calls {
		required, admitted := RequiredScopes(row.Pallet, row.Call)
		target := row.Pallet + "." + row.Call
		if row.Required == nil {
			if admitted {
				t.Errorf("%s should be admitted by no set, got %s", target, required)
			}
			continue
		}
		if !admitted {
			t.Errorf("%s should require %s, got no set", target, *row.RequiredText)
			continue
		}
		if required.Bits() != *row.Required {
			t.Errorf("%s requires %s, want %s", target, required, *row.RequiredText)
		}
	}
}

func TestUnscopedPalletsAreNeverAdmitted(t *testing.T) {
	// A pallet the fixture never mentions must admit nothing, whatever the call —
	// this is where token movement, staking, governance and sudo live, and
	// admitting any of them would be the one mistake in this table that matters.
	scoped := map[string]bool{}
	for _, row := range loadRequiredScopes(t).Calls {
		scoped[row.Pallet] = true
	}
	for _, pallet := range []string{
		"Balances", "Staking", "Sudo", "Proxy", "Utility", "EthSigning",
	} {
		if scoped[pallet] {
			t.Errorf("%s should not be a scoped pallet", pallet)
		}
		for _, call := range []string{"transfer_all", "bond", "sudo", "batch_all", "anything"} {
			if _, admitted := RequiredScopes(pallet, call); admitted {
				t.Errorf("%s.%s must be admitted by no set", pallet, call)
			}
		}
	}
}

func TestArgumentSensitiveRowsTakeTheWiderSetInGo(t *testing.T) {
	// Go's Tx receives an already-encoded types.Call, so unlike the other
	// bindings it cannot read `secret_ref` to decide whether a secret is
	// referenced. It therefore always demands the wider set for those two rows —
	// the fail-safe direction this table documents, and exactly the value the
	// fixture pins for arguments that cannot be read.
	wider := SingleScope(ScopeDeployments, AccessWrite).With(ScopeSecrets, AccessRead)
	for _, row := range loadRequiredScopes(t).Calls {
		if !row.ArgSensitive {
			continue
		}
		required, admitted := RequiredScopes(row.Pallet, row.Call)
		if !admitted || required != wider {
			t.Errorf("%s.%s requires %s, want %s", row.Pallet, row.Call, required, wider)
		}
	}
}

// --- the nesting that only Go has to prove ---------------------------------

func TestAnInnerCallNestsAsARuntimeCall(t *testing.T) {
	// A RuntimeCall on the wire is pallet_index ++ call_index ++ args. types.Call
	// has no custom Encode, so it falls through to the generic reflection encoder,
	// and Args unwraps with no length prefix — which happens to produce exactly
	// that. Correct, but by accident, so pin the bytes.
	inner := types.Call{
		CallIndex: types.CallIndex{SectionIndex: 8, MethodIndex: 3},
		Args:      types.Args{0xde, 0xad, 0xbe, 0xef},
	}
	encoded, err := codec.Encode(inner)
	if err != nil {
		t.Fatalf("encode inner call: %v", err)
	}
	want := []byte{8, 3, 0xde, 0xad, 0xbe, 0xef}
	if string(encoded) != string(want) {
		t.Errorf("inner call encoded as %x, want %x", encoded, want)
	}
}

func TestForceProxyTypeNoneIsASingleZeroByte(t *testing.T) {
	// Option<ProxyType>::None. GSRPC has no generic Option[T], so this is
	// hand-rolled and therefore worth pinning: a wrong tag here would make the
	// chain read the inner call as a proxy type.
	encoded, err := codec.Encode(forceProxyTypeNone{})
	if err != nil {
		t.Fatalf("encode None: %v", err)
	}
	if len(encoded) != 1 || encoded[0] != 0 {
		t.Errorf("Option::None encoded as %x, want 00", encoded)
	}
}

func TestProxyArgumentsEncodeInRuntimeOrder(t *testing.T) {
	// The whole delegated payload: MultiAddress::Id(principal), then
	// Option<ProxyType>::None, then the inner call. Argument order is positional
	// on the wire, so a swap here is a silently wrong extrinsic.
	var principal [32]byte
	for i := range principal {
		principal[i] = 9
	}
	address, err := types.NewMultiAddressFromAccountID(principal[:])
	if err != nil {
		t.Fatalf("multi-address: %v", err)
	}
	inner := types.Call{
		CallIndex: types.CallIndex{SectionIndex: 8, MethodIndex: 3},
		Args:      types.Args{0xde, 0xad, 0xbe, 0xef},
	}

	var buf []byte
	for _, arg := range []any{address, forceProxyTypeNone{}, inner} {
		encoded, err := codec.Encode(arg)
		if err != nil {
			t.Fatalf("encode %T: %v", arg, err)
		}
		buf = append(buf, encoded...)
	}

	// MultiAddress::Id is variant 0, then the raw account.
	want := append([]byte{0}, principal[:]...)
	// Option::None, then the inner RuntimeCall.
	want = append(want, 0, 8, 3, 0xde, 0xad, 0xbe, 0xef)
	if string(buf) != string(want) {
		t.Errorf("proxy args encoded as %x, want %x", buf, want)
	}
	// And the assembled length is what those parts sum to, so nothing silently
	// grew a length prefix.
	if len(buf) != 1+32+1+6 {
		t.Errorf("proxy args are %d bytes, want %d", len(buf), 1+32+1+6)
	}
}

func TestTheScopeCheckNamesWhatIsMissing(t *testing.T) {
	// The whole reason the check runs locally: the chain's own answer to a
	// balance-less delegated key is a complaint about fees that names neither
	// the call nor the scope.
	held := SingleScope(ScopeDeployments, AccessWrite)

	if err := checkScopes("Jobs", "cancel_deployment", held); err != nil {
		t.Errorf("an in-scope call was refused: %v", err)
	}

	err := checkScopes("Volumes", "retire_volume", held)
	if err == nil {
		t.Fatal("an out-of-scope call was allowed")
	}
	for _, want := range []string{"volumes:w", "Volumes.retire_volume", "deployments:w"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestCallsNoKeyMayMakeAreRefusedWhateverTheScopes(t *testing.T) {
	all := AllScopeSet()
	for _, tc := range [][2]string{
		{"Balances", "transfer_all"},
		{"Staking", "bond"},
		{"Sudo", "sudo"},
		// Nesting one of these would let a key launder authority through a batch.
		{"Utility", "batch_all"},
		{"Proxy", "proxy"},
		{"EthSigning", "dispatch_eth_signed"},
		// Provider-signed and root-only calls of pallets that are otherwise scoped.
		{"Jobs", "update_deployment_status"},
		{"Budgets", "authorize_agent_key"},
		{"Organizations", "create_org"},
	} {
		err := checkScopes(tc[0], tc[1], all)
		if err == nil {
			t.Errorf("%s.%s was allowed with every scope held", tc[0], tc[1])
			continue
		}
		if !strings.Contains(err.Error(), "never admitted") {
			t.Errorf("%s.%s: %v", tc[0], tc[1], err)
		}
	}
}

func TestScopeRefusalsCarryABranchableKind(t *testing.T) {
	// Callers must be able to tell "widen this key" from "this call is not for a
	// key at all" without reading message text.
	cases := []struct {
		name    string
		pallet  string
		method  string
		held    ScopeSet
		wantKin ChainErrorKind
	}{
		{"missing scope", "Volumes", "retire_volume", EmptyScopeSet(), KindNotPermitted},
		{"never admitted", "Balances", "transfer_all", AllScopeSet(), KindNeverAdmitted},
		{"laundered through a proxy", "Proxy", "proxy", AllScopeSet(), KindNeverAdmitted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkScopes(c.pallet, c.method, c.held)
			var chainErr *ChainError
			if !errors.As(err, &chainErr) {
				t.Fatalf("want a *ChainError, got %v", err)
			}
			if chainErr.Kind != c.wantKin {
				t.Fatalf("want kind %q, got %q", c.wantKin, chainErr.Kind)
			}
			if chainErr.Target != c.pallet+"."+c.method {
				t.Fatalf("want the call named in Target, got %q", chainErr.Target)
			}
		})
	}
}

// loadSpec322Metadata reads the spec-322 runtime metadata in the version this
// binding actually sees.
//
// GSRPC reads V14 — it has no V15 decoder — which is also what the runtime hands
// back over state_getMetadata, so V14 is not a lesser fixture here but the real
// one. Rust and TypeScript pin the V15 blob alongside it.
func loadSpec322Metadata(t *testing.T) *types.Metadata {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsRel, "spec322_metadata_v14.scale"))
	if err != nil {
		t.Fatalf("read the spec-322 fixture: %v", err)
	}
	meta := &types.Metadata{}
	if err := codec.Decode(raw, meta); err != nil {
		t.Fatalf("decode the spec-322 fixture: %v", err)
	}
	return meta
}

func TestTheSecretRefArgumentIsReadFromTheEncodedCall(t *testing.T) {
	// The chain reads the argument, so a key holding only Deployments:Write may
	// legitimately clear a secret ref. Judging by call name alone refuses that
	// locally — a false refusal the runtime would have allowed.
	meta := loadSpec322Metadata(t)
	calls, err := registry.NewFactory().CreateCallRegistry(meta)
	if err != nil {
		t.Fatalf("build the call registry: %v", err)
	}

	deploymentID := types.NewU128(*big.NewInt(1))
	clearing, err := types.NewCall(meta, "Jobs.set_deployment_secret_ref", deploymentID, optionNoneArg{})
	if err != nil {
		t.Fatalf("encode the clearing call: %v", err)
	}
	got, ok := requiredScopesForCall(meta, calls, clearing)
	if !ok {
		t.Fatal("set_deployment_secret_ref is admitted to a scoped key")
	}
	if want := SingleScope(ScopeDeployments, AccessWrite); got.Bits() != want.Bits() {
		t.Fatalf("clearing a secret ref needs %s, got %s", want, got)
	}

	setting, err := types.NewCall(meta, "Jobs.set_deployment_secret_ref", deploymentID, optionSomeU128(7))
	if err != nil {
		t.Fatalf("encode the setting call: %v", err)
	}
	got, _ = requiredScopesForCall(meta, calls, setting)
	want := SingleScope(ScopeDeployments, AccessWrite).With(ScopeSecrets, AccessRead)
	if got.Bits() != want.Bits() {
		t.Fatalf("setting a secret ref needs %s, got %s", want, got)
	}
}

func TestAnUnreadableArgumentTakesTheWiderSet(t *testing.T) {
	// Fail safe: a local check that cannot read the argument must ask for more,
	// never less. Asking for too much is a refusal the caller can widen the key
	// to fix; asking for too little submits a call the chain will reject.
	meta := loadSpec322Metadata(t)
	calls, err := registry.NewFactory().CreateCallRegistry(meta)
	if err != nil {
		t.Fatalf("build the call registry: %v", err)
	}
	wider := SingleScope(ScopeDeployments, AccessWrite).With(ScopeSecrets, AccessRead)

	deploymentID := types.NewU128(*big.NewInt(1))
	good, err := types.NewCall(meta, "Jobs.set_deployment_secret_ref", deploymentID, optionNoneArg{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	garbled := good
	garbled.Args = types.Args{0xff}
	if got, _ := requiredScopesForCall(meta, calls, garbled); got.Bits() != wider.Bits() {
		t.Fatalf("garbled args must take the wider set %s, got %s", wider, got)
	}

	if got, _ := requiredScopesForCall(meta, nil, good); got.Bits() != wider.Bits() {
		t.Fatalf("no call registry must take the wider set %s, got %s", wider, got)
	}
}

// optionNoneArg encodes Option<T>::None as a call argument.
type optionNoneArg struct{}

func (optionNoneArg) Encode(encoder scale.Encoder) error { return encoder.PushByte(0) }

// optionSomeU128 encodes Option<u128>::Some(v).
type optionSomeU128 uint64

func (o optionSomeU128) Encode(encoder scale.Encoder) error {
	if err := encoder.PushByte(1); err != nil {
		return err
	}
	return encoder.Encode(types.NewU128(*big.NewInt(int64(o))))
}
