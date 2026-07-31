package mattervault

// Façade parity: this binding must expose exactly the surface
// testvectors/facade_calls.json pins.
//
// The façades are hand-written per language, so the risk is drift — Go growing a
// method Rust does not have, or two languages disagreeing about which call a method
// maps to. The fixture is emitted from Rust and replayed here, checked BOTH ways: a
// row without a method fails, and a method without a row fails.
//
// Go checks the surface by reflection rather than by invoking each method, because
// invoking requires live metadata (types.NewCall resolves against it) and this test
// must run offline. The Rust `live_chain` test separately proves every (pallet, call)
// exists on chain, and `TestFacadeMethodsSubmitTheirPinnedCall` covers routing for the
// methods that can be driven without metadata.

import (
	"reflect"
	"strings"
	"testing"
)

type facadeRow struct {
	Facade string   `json:"facade"`
	Method string   `json:"method"`
	Pallet string   `json:"pallet"`
	Call   string   `json:"call"`
	Args   []string `json:"args"`
}

func loadFacadeRows(t *testing.T) []facadeRow {
	t.Helper()
	var doc struct {
		Calls []facadeRow `json:"calls"`
	}
	load(t, "facade_calls.json", &doc)
	if len(doc.Calls) < 20 {
		// A silently truncated fixture would make every assertion below vacuous.
		t.Fatalf("facade_calls.json has only %d rows; regenerate it", len(doc.Calls))
	}
	return doc.Calls
}

// facadeTypes maps a fixture façade name to the Go type implementing it.
var facadeTypes = map[string]reflect.Type{
	"secrets":     reflect.TypeOf(SecretsFacade{}),
	"deployments": reflect.TypeOf(DeploymentsFacade{}),
	"resources":   reflect.TypeOf(ResourcesFacade{}),
	"staking":     reflect.TypeOf(StakingFacade{}),
	"orgs":        reflect.TypeOf(OrgsFacade{}),
}

// goMethodName converts the fixture's snake_case method to Go's PascalCase.
func goMethodName(method string) string {
	var b strings.Builder
	for _, part := range strings.Split(method, "_") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		b.WriteString(part[1:])
	}
	return b.String()
}

func TestEveryPinnedFacadeMethodExists(t *testing.T) {
	for _, row := range loadFacadeRows(t) {
		facadeType, ok := facadeTypes[row.Facade]
		if !ok {
			t.Errorf("the fixture names an unknown façade: %s", row.Facade)
			continue
		}
		name := goMethodName(row.Method)
		method, found := facadeType.MethodByName(name)
		if !found {
			t.Errorf("%s.%s is missing (fixture row %s.%s)",
				facadeType.Name(), name, row.Facade, row.Method)
			continue
		}
		// Every façade method returns (txHash string, err error).
		if method.Type.NumOut() != 2 {
			t.Errorf("%s.%s returns %d values, want (string, error)",
				facadeType.Name(), name, method.Type.NumOut())
		}
	}
}

func TestNoFacadeMethodIsUnpinned(t *testing.T) {
	// The other direction: an extra method here would be a surface Rust does not
	// have, which is drift even though every fixture row passes.
	pinned := map[string]map[string]bool{}
	for _, row := range loadFacadeRows(t) {
		if pinned[row.Facade] == nil {
			pinned[row.Facade] = map[string]bool{}
		}
		pinned[row.Facade][goMethodName(row.Method)] = true
	}

	for facade, facadeType := range facadeTypes {
		for i := 0; i < facadeType.NumMethod(); i++ {
			name := facadeType.Method(i).Name
			if !pinned[facade][name] {
				t.Errorf("%s.%s is not pinned by facade_calls.json", facadeType.Name(), name)
			}
		}
		if got, want := facadeType.NumMethod(), len(pinned[facade]); got != want {
			t.Errorf("%s has %d methods, fixture pins %d", facadeType.Name(), got, want)
		}
	}
}

func TestTheCuratedFacadesAreTheFiveDocumentedOnes(t *testing.T) {
	// The set of façades is a documented promise (README, docs/parity.md). Adding a
	// sixth should be a deliberate act that updates those too.
	seen := map[string]bool{}
	for _, row := range loadFacadeRows(t) {
		seen[row.Facade] = true
	}
	if len(seen) != len(facadeTypes) {
		t.Errorf("fixture names %d façades, Go implements %d", len(seen), len(facadeTypes))
	}
	for name := range seen {
		if _, ok := facadeTypes[name]; !ok {
			t.Errorf("fixture façade %q has no Go type", name)
		}
	}
}

func TestClientExposesEveryFacadeAccessor(t *testing.T) {
	// The accessors are the API; a missing one makes the façade unreachable even
	// though its type is fine.
	clientType := reflect.TypeOf(&MatterClient{})
	for _, accessor := range []string{"Secrets", "Deployments", "Resources", "Staking", "Orgs"} {
		if _, ok := clientType.MethodByName(accessor); !ok {
			t.Errorf("MatterClient.%s() is missing", accessor)
		}
	}
}

func TestSecretsFacadeCoversAllFivePalletSecretsCalls(t *testing.T) {
	// pallet-secrets has five extrinsics; the SDK previously built three, leaving
	// revoke_access — the call that contains a leaked signer — with no builder.
	covered := map[string]bool{}
	for _, row := range loadFacadeRows(t) {
		if row.Pallet == "Secrets" {
			covered[row.Call] = true
		}
	}
	for _, call := range []string{
		"store_secret", "rotate_secret", "grant_access", "revoke_access", "delete_secret",
	} {
		if !covered[call] {
			t.Errorf("Secrets.%s is not covered by any façade method", call)
		}
	}
}

func TestOptionU128EncodesTheRuntimeEnum(t *testing.T) {
	// set_deployment_secret_ref takes Option<u128>; a bare value where None belongs
	// (or vice versa) silently points a deployment at the wrong secret.
	if got := optionU128(nil); len(got) != 1 || got[0] != 0x00 {
		t.Errorf("None encoded as %v, want [0]", got)
	}

	id := NewSecretID(1)
	some := optionU128(&id)
	if len(some) != 17 {
		t.Fatalf("Some encoded as %d bytes, want 17 (variant + u128)", len(some))
	}
	if some[0] != 0x01 {
		t.Errorf("Some variant byte = %#x, want 0x01", some[0])
	}
	// SCALE encodes a u128 little-endian, so the value byte comes first.
	if some[1] != 0x01 {
		t.Errorf("Some payload starts with %#x, want little-endian 1", some[1])
	}
}
