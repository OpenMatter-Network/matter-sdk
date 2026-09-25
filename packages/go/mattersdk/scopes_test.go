package mattersdk

// The scope contract, replayed from the Rust-emitted fixtures.

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
		if got := SingleScope(scope, AccessRead).String(); got != row.Scope+":r" {
			t.Errorf("String() = %q, want %q", got, row.Scope+":r")
		}
	}
	if got := AllScopeSet().Bits(); got != fixture.AllBits {
		t.Errorf("AllScopeSet = %d, want %d", got, fixture.AllBits)
	}
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
		// A repeated letter is rejected, not read as a wider set.
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
	// Token movement, staking, governance and sudo live in unscoped pallets.
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
	// By call name alone, argument-sensitive rows take the wider, fail-safe set.
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

func TestAnInnerCallNestsAsARuntimeCall(t *testing.T) {
	// A RuntimeCall is pallet_index ++ call_index ++ args, with no length prefix.
	// GSRPC's reflection encoder produces that for types.Call only by accident.
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
	// Hand-rolled (GSRPC has no generic Option[T]); a wrong tag makes the chain
	// read the inner call as a proxy type.
	encoded, err := codec.Encode(forceProxyTypeNone{})
	if err != nil {
		t.Fatalf("encode None: %v", err)
	}
	if len(encoded) != 1 || encoded[0] != 0 {
		t.Errorf("Option::None encoded as %x, want 00", encoded)
	}
}

func TestProxyArgumentsEncodeInRuntimeOrder(t *testing.T) {
	// MultiAddress::Id(principal), Option<ProxyType>::None, inner call. Order is
	// positional on the wire.
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
	// No part grew a length prefix.
	if len(buf) != 1+32+1+6 {
		t.Errorf("proxy args are %d bytes, want %d", len(buf), 1+32+1+6)
	}
}

func TestTheScopeCheckNamesWhatIsMissing(t *testing.T) {
	// The chain's own refusal is a fee error naming neither call nor scope.
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

// loadSpec322Metadata reads the spec-330 V14 metadata fixture: GSRPC has no V15 decoder,
// and V14 is what state_getMetadata returns.
func loadSpec322Metadata(t *testing.T) *types.Metadata {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsRel, "spec330_metadata_v14.scale"))
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
	// A Deployments:Write key may clear a secret ref; judging by call name alone
	// would falsely refuse it.
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
	// Fail safe: an unreadable argument asks for more scope, never less.
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
