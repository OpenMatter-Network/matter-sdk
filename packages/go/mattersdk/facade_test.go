package mattersdk

// The façade surface must match testvectors/facade_calls.json both ways: a row
// without a method fails, and a method without a row fails. Checked by reflection
// because invoking needs live metadata.

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

// runtimeAPIRow is a façade method that reads through a state_call rather than
// submitting an extrinsic, so it has no (pallet, call) to pin.
type runtimeAPIRow struct {
	Facade    string   `json:"facade"`
	Method    string   `json:"method"`
	StateCall string   `json:"state_call"`
	Args      []string `json:"args"`
}

func loadFacadeFixture(t *testing.T) ([]facadeRow, []runtimeAPIRow) {
	t.Helper()
	var doc struct {
		Calls          []facadeRow     `json:"calls"`
		RuntimeAPICall []runtimeAPIRow `json:"runtime_api_calls"`
	}
	load(t, "facade_calls.json", &doc)
	if len(doc.Calls) < 20 {
		// A truncated fixture would make every assertion vacuous.
		t.Fatalf("facade_calls.json has only %d rows; regenerate it", len(doc.Calls))
	}
	return doc.Calls, doc.RuntimeAPICall
}

func loadFacadeRows(t *testing.T) []facadeRow {
	t.Helper()
	calls, _ := loadFacadeFixture(t)
	return calls
}

// facadeTypes maps a fixture façade name to the Go type implementing it.
var facadeTypes = map[string]reflect.Type{
	"secrets":     reflect.TypeOf(SecretsFacade{}),
	"deployments": reflect.TypeOf(DeploymentsFacade{}),
	"resources":   reflect.TypeOf(ResourcesFacade{}),
	"staking":     reflect.TypeOf(StakingFacade{}),
	"orgs":        reflect.TypeOf(OrgsFacade{}),
	"keys":        reflect.TypeOf(KeysFacade{}),
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
		// Writes wait for finalization, so a refused call is an error, not a hash.
		if !returnsReceipt(method.Type) {
			t.Errorf("%s.%s returns %v, want (TxReceipt, error)", facadeType.Name(), name, method.Type)
		}
	}
}

func TestEveryPinnedReadExists(t *testing.T) {
	_, reads := loadFacadeFixture(t)
	if len(reads) == 0 {
		t.Fatal("facade_calls.json pins no runtime-API reads; regenerate it")
	}
	for _, row := range reads {
		facadeType, ok := facadeTypes[row.Facade]
		if !ok {
			t.Errorf("the fixture names an unknown façade: %s", row.Facade)
			continue
		}
		name := goMethodName(row.Method)
		if _, found := facadeType.MethodByName(name); !found {
			t.Errorf("%s.%s is missing (fixture read %s.%s)",
				facadeType.Name(), name, row.Facade, row.Method)
		}
	}
}

func TestNoFacadeMethodIsUnpinned(t *testing.T) {
	// A façade's surface is the union of both tables.
	calls, reads := loadFacadeFixture(t)
	pinned := map[string]map[string]bool{}
	for _, row := range calls {
		if pinned[row.Facade] == nil {
			pinned[row.Facade] = map[string]bool{}
		}
		pinned[row.Facade][goMethodName(row.Method)] = true
	}
	for _, row := range reads {
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

func TestTheCuratedFacadesAreTheSixDocumentedOnes(t *testing.T) {
	// Adding a façade must also update README and docs/parity.md.
	calls, reads := loadFacadeFixture(t)
	seen := map[string]bool{}
	for _, row := range calls {
		seen[row.Facade] = true
	}
	for _, row := range reads {
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
	clientType := reflect.TypeOf(&MatterClient{})
	for _, accessor := range []string{
		"Secrets", "Deployments", "Resources", "Staking", "Orgs", "Keys",
	} {
		if _, ok := clientType.MethodByName(accessor); !ok {
			t.Errorf("MatterClient.%s() is missing", accessor)
		}
	}
}

func TestSecretsFacadeCoversAllFivePalletSecretsCalls(t *testing.T) {
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
	// set_deployment_secret_ref takes Option<u128>; a wrong encoding silently points
	// a deployment at the wrong secret.
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
	if some[1] != 0x01 {
		t.Errorf("Some payload starts with %#x, want little-endian 1", some[1])
	}
}

// returnsReceipt reports whether fn's results are exactly (TxReceipt, error).
func returnsReceipt(fn reflect.Type) bool {
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	return fn.NumOut() == 2 && fn.Out(0) == reflect.TypeOf(TxReceipt{}) && fn.Out(1) == errorType
}

func TestTheGenericCallReturnsAReceipt(t *testing.T) {
	method, ok := reflect.TypeOf(&MatterClient{}).MethodByName("Call")
	if !ok {
		t.Fatal("MatterClient.Call is missing")
	}
	if !returnsReceipt(method.Type) {
		t.Fatalf("MatterClient.Call returns %v, want (TxReceipt, error)", method.Type)
	}
}
