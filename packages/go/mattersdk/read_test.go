package mattersdk

// Façade reads against testvectors/facade_reads.json (emitted from Rust): every
// case replayed through the real façade, plus the primitives the decoders stand
// on. A binding that disagrees with a vector has a bug.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

// readExchange is one JSON-RPC request and how the node answered: its result
// (which may be null), or the error it refused with.
type readExchange struct {
	Method string  `json:"method"`
	Params []any   `json:"params"`
	Result any     `json:"result"`
	Error  *string `json:"error"`
}

// readCase is a transcript: what a pinned read asks, and how it must end.
type readCase struct {
	Name      string         `json:"name"`
	Args      map[string]any `json:"args"`
	At        string         `json:"at"`
	Exchanges []readExchange `json:"exchanges"`
	// Expected is the result as a JSON value; nil when the read must fail.
	Expected any `json:"expected"`
	// ExpectedJSON is the result as exactly the canonical bytes.
	ExpectedJSON string `json:"expected_json"`
	// Error names the source a failing read's chain error must carry.
	Error *struct {
		Target string `json:"target"`
	} `json:"error"`
	// Client is who the reading client would sign as, and for which member; nil
	// for a read-only client. Account ids are bare hex.
	Client *struct {
		Signer    *string `json:"signer"`
		Principal *string `json:"principal"`
	} `json:"client"`
}

// identityOnly is a signer that is only an account: reads never sign.
type identityOnly []byte

func (i identityOnly) AccountID() []byte { return i }

func (identityOnly) SignExtrinsic([]byte) ([]byte, error) {
	return nil, errors.New("a read must not sign")
}

type readRow struct {
	Facade string `json:"facade"`
	Method string `json:"method"`
	Args   []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"args"`
	// Pinnable reports whether the read is about one block, and so can be pinned.
	Pinnable bool       `json:"pinnable"`
	Cases    []readCase `json:"cases"`
}

type reasonTable struct {
	Source string `json:"source"`
	Groups []struct {
		Index   uint8  `json:"index"`
		Pallet  string `json:"pallet"`
		Reasons []struct {
			Index uint8  `json:"index"`
			Name  string `json:"name"`
		} `json:"reasons"`
	} `json:"groups"`
}

type readFixture struct {
	PinMethod string `json:"pin_method"`
	Chain     struct {
		SS58Prefix         uint16 `json:"ss58_prefix"`
		ExistentialDeposit string `json:"existential_deposit"`
	} `json:"chain"`
	Accounts struct {
		Accepted []struct {
			Text       string `json:"text"`
			AccountHex string `json:"account_hex"`
		} `json:"accepted"`
		Refused   []string `json:"refused"`
		Addresses []struct {
			AccountHex string `json:"account_hex"`
			Prefix     uint16 `json:"prefix"`
			Address    string `json:"address"`
		} `json:"addresses"`
	} `json:"accounts"`
	Scale struct {
		Valid []struct {
			Type  string `json:"type"`
			Hex   string `json:"hex"`
			Value string `json:"value"`
		} `json:"valid"`
		Invalid []struct {
			Type string `json:"type"`
			Hex  string `json:"hex"`
			Why  string `json:"why"`
		} `json:"invalid"`
	} `json:"scale"`
	Tables struct {
		HoldReasons   reasonTable `json:"hold_reasons"`
		FreezeReasons reasonTable `json:"freeze_reasons"`
		LockReasons   []string    `json:"lock_reasons"`
		DispatchClass []string    `json:"dispatch_classes"`
	} `json:"tables"`
	Reads []readRow `json:"reads"`
}

func loadReadFixture(t *testing.T) readFixture {
	t.Helper()
	var fixture readFixture
	load(t, "facade_reads.json", &fixture)
	if len(fixture.Reads) == 0 {
		// A truncated fixture would make every assertion vacuous.
		t.Fatal("facade_reads.json pins no reads; regenerate it")
	}
	return fixture
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("the fixture holds bad hex %q: %v", text, err)
	}
	return raw
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// fixtureHead is the finalized head a chain with no transcript reports.
var fixtureHead = "0x" + hex.EncodeToString(bytesOf(0xf1, blockHashBytes))

type rpcRequest struct {
	Method string
	Params []any
}

// asJSONValue is v as encoding/json reads it back, so a request built from Go
// values compares with one read from the fixture.
func asJSONValue(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return value
}

// fixtureChain replays one case's transcript. It answers a request only as the
// transcript recorded that exact request, reports the case's block as its
// finalized head unless the transcript says otherwise, and records every request,
// so a test can assert that the read asked exactly what was recorded.
type fixtureChain struct {
	t         *testing.T
	head      string
	exchanges []readExchange
	requests  []rpcRequest
	// override, when set, replaces every answer.
	override func(method string, params []any) (any, error)
}

func newFixtureChain(t *testing.T, testCase *readCase) *fixtureChain {
	t.Helper()
	if testCase == nil {
		return &fixtureChain{t: t, head: fixtureHead}
	}
	return &fixtureChain{t: t, head: "0x" + testCase.At, exchanges: testCase.Exchanges}
}

func (f *fixtureChain) answer(method string, params []any) (any, error) {
	for _, exchange := range f.exchanges {
		if exchange.Method != method || !reflect.DeepEqual(exchange.Params, params) {
			continue
		}
		if exchange.Error != nil {
			return nil, errors.New(*exchange.Error)
		}
		return exchange.Result, nil
	}
	if method == rpcFinalizedHead {
		return f.head, nil
	}
	return nil, fmt.Errorf("the transcript has no answer for %s(%v)", method, params)
}

func (f *fixtureChain) callRPC(result any, method string, params ...any) error {
	sent := []any{}
	if len(params) > 0 {
		sent = asJSONValue(f.t, params).([]any)
	}
	f.requests = append(f.requests, rpcRequest{method, sent})
	answer := f.answer
	if f.override != nil {
		answer = f.override
	}
	value, err := answer(method, sent)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, result)
}

// sameRequests reports whether two request lists match; none asked is none
// recorded, whichever way each list spells empty.
func sameRequests(got, want []rpcRequest) bool {
	return (len(got) == 0 && len(want) == 0) || reflect.DeepEqual(got, want)
}

func requestsOf(testCase readCase) []rpcRequest {
	requests := make([]rpcRequest, len(testCase.Exchanges))
	for i, exchange := range testCase.Exchanges {
		requests[i] = rpcRequest{exchange.Method, exchange.Params}
	}
	return requests
}

// readingClient is a client over chain, using the spec-330 metadata and the chain
// facts the fixture's cases were emitted under. It is read-only unless testCase
// names a client identity.
func readingClient(t *testing.T, fixture readFixture, chain *fixtureChain, testCase *readCase) *MatterClient {
	t.Helper()
	client := readOnlyClient(t, fixture, chain)
	if testCase == nil || testCase.Client == nil {
		return client
	}
	if signer := testCase.Client.Signer; signer != nil {
		client.signer = identityOnly(mustHex(t, *signer))
	}
	if principal := testCase.Client.Principal; principal != nil {
		client.delegation = &Delegation{Principal: mustHex(t, *principal), Scopes: AllScopeSet()}
	}
	return client
}

func readOnlyClient(t *testing.T, fixture readFixture, chain *fixtureChain) *MatterClient {
	t.Helper()
	deposit, ok := new(big.Int).SetString(fixture.Chain.ExistentialDeposit, 10)
	if !ok {
		t.Fatalf("the fixture's existential deposit is not a number: %q", fixture.Chain.ExistentialDeposit)
	}
	return &MatterClient{
		chain: &ChainClient{meta: loadSpec330Metadata(t)},
		reads: chain,
		properties: ChainProperties{
			GenesisHash:            "0x" + hex.EncodeToString(make([]byte, blockHashBytes)),
			ChainName:              "MatterChain Fake",
			SpecVersion:            330,
			TokenSymbol:            "MTR-Test",
			SS58Prefix:             fixture.Chain.SS58Prefix,
			TokenDecimalsDeclared:  18,
			TokenDecimalsEffective: 18,
			ExistentialDeposit:     deposit,
		},
	}
}

// callRead invokes the façade read a row names, by reflection, as a caller would:
// text arguments are parsed, and the block is pinned when asked.
func callRead(t *testing.T, client *MatterClient, fixture readFixture, row readRow, testCase readCase, pinned bool) (any, error) {
	t.Helper()
	accessor := reflect.ValueOf(client).MethodByName(goMethodName(row.Facade))
	if !accessor.IsValid() {
		t.Fatalf("MatterClient.%s() is missing", goMethodName(row.Facade))
	}
	facade := accessor.Call(nil)[0]
	if pinned {
		var block [blockHashBytes]byte
		copy(block[:], mustHex(t, testCase.At))
		facade = facade.MethodByName(goMethodName(fixture.PinMethod)).Call([]reflect.Value{reflect.ValueOf(block)})[0]
	}
	method := facade.MethodByName(goMethodName(row.Method))
	if !method.IsValid() {
		t.Fatalf("%s.%s is missing", row.Facade, row.Method)
	}
	args := []reflect.Value{}
	for _, arg := range row.Args {
		// Wide integers travel as decimal strings: JSON numbers cannot carry 64 bits.
		text, _ := testCase.Args[arg.Name].(string)
		switch arg.Type {
		case "string":
			args = append(args, reflect.ValueOf(text))
		case "call_args":
			// A call's arguments are variadic here, as Call takes them.
			for _, callArg := range callArgsOf(t, testCase.Args[arg.Name]) {
				args = append(args, reflect.ValueOf(callArg))
			}
		case "account":
			account, err := ParseAccount(text)
			if err != nil {
				t.Fatalf("case %s: %v", testCase.Name, err)
			}
			args = append(args, reflect.ValueOf(account))
		case "u64":
			number, err := strconv.ParseUint(text, 10, 64)
			if err != nil {
				t.Fatalf("case %s: %v", testCase.Name, err)
			}
			args = append(args, reflect.ValueOf(number))
		default:
			t.Fatalf("the fixture names an argument type this test does not convert: %s", arg.Type)
		}
	}
	out := method.Call(args)
	// A read answered from facts in hand returns a value alone.
	if len(out) == 1 {
		return out[0].Interface(), nil
	}
	err, _ := out[1].Interface().(error)
	return out[0].Interface(), err
}

// callArgsOf turns a case's call arguments into the values this binding's Call
// takes: go-substrate-rpc-client values, in declared order.
func callArgsOf(t *testing.T, raw any) []any {
	t.Helper()
	list, _ := raw.([]any)
	values := make([]any, len(list))
	for i, item := range list {
		arg, _ := item.(map[string]any)
		kind, _ := arg["type"].(string)
		text, _ := arg["value"].(string)
		switch kind {
		case "u128":
			number, ok := new(big.Int).SetString(text, 10)
			if !ok {
				t.Fatalf("the fixture holds a call argument that is not a number: %q", text)
			}
			values[i] = types.NewU128(*number)
		default:
			t.Fatalf("the fixture names a call argument type this test does not convert: %s", kind)
		}
	}
	return values
}

// assertOutcome checks the read ended as the transcript says: these bytes, or
// this error.
func assertOutcome(t *testing.T, testCase readCase, result any, err error) {
	t.Helper()
	if testCase.Error != nil {
		wantChainErrorAt(t, err, testCase.Error.Target)
		return
	}
	if err != nil {
		t.Fatalf("%s: %v", testCase.Name, err)
	}
	canonical, err := CanonicalJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != testCase.ExpectedJSON {
		t.Fatalf("canonical JSON\n got  %s\n want %s", canonical, testCase.ExpectedJSON)
	}
	// json.Marshal gives the same value, though not the same bytes.
	if got := asJSONValue(t, result); !reflect.DeepEqual(got, testCase.Expected) {
		t.Fatalf("json.Marshal\n got  %v\n want %v", got, testCase.Expected)
	}
}

func readPrimitive(t *testing.T, kind string) func(*scaleReader) string {
	t.Helper()
	switch kind {
	case "u8":
		return func(r *scaleReader) string { return strconv.FormatUint(uint64(r.u8()), 10) }
	case "u16":
		return func(r *scaleReader) string { return strconv.FormatUint(uint64(r.u16()), 10) }
	case "u32":
		return func(r *scaleReader) string { return strconv.FormatUint(uint64(r.u32()), 10) }
	case "u64":
		return func(r *scaleReader) string { return strconv.FormatUint(r.u64(), 10) }
	case "u128":
		return func(r *scaleReader) string { return r.u128().String() }
	case "bool":
		return func(r *scaleReader) string { return strconv.FormatBool(r.boolean()) }
	case "compact_u32":
		return func(r *scaleReader) string { return strconv.FormatUint(uint64(r.compactU32()), 10) }
	case "compact_u64":
		return func(r *scaleReader) string { return strconv.FormatUint(r.compactU64(), 10) }
	case "compact_u128":
		return func(r *scaleReader) string { return r.compactU128().String() }
	case "bytes":
		return func(r *scaleReader) string { return toHex(r.bytes()) }
	default:
		t.Fatalf("the fixture names an unknown primitive: %s", kind)
		return nil
	}
}

func TestTheScaleReaderReadsEachPrimitive(t *testing.T) {
	for _, row := range loadReadFixture(t).Scale.Valid {
		got, err := decodeStrict("test", mustHex(t, row.Hex), readPrimitive(t, row.Type))
		if err != nil || got != row.Value {
			t.Errorf("%s %s: got %q, %v; want %q", row.Type, row.Hex, got, err, row.Value)
		}
	}
}

func TestTheScaleReaderRefusesAValueThatDoesNotFit(t *testing.T) {
	for _, row := range loadReadFixture(t).Scale.Invalid {
		_, err := decodeStrict("Some.Source", mustHex(t, row.Hex), readPrimitive(t, row.Type))
		var chainErr *ChainError
		if !errors.As(err, &chainErr) || chainErr.Kind != KindChain || chainErr.Target != "Some.Source" {
			t.Errorf("%s %s (%s): want a chain error naming the source, got %v", row.Type, row.Hex, row.Why, err)
		}
	}
}

func TestOptionsAndSequencesReadInWireOrder(t *testing.T) {
	type decoded struct {
		none, some bool
		value      uint8
		items      []uint8
	}
	got, err := decodeStrict("test", []byte{0x00, 0x01, 0x07, 0x08, 0x01, 0x02}, func(r *scaleReader) decoded {
		none := r.isSome()
		some := r.isSome()
		return decoded{none, some, r.u8(), readVec(r, (*scaleReader).u8)}
	})
	want := decoded{false, true, 7, []uint8{1, 2}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, %v; want %+v", got, err, want)
	}
	if _, err := decodeStrict("test", []byte{2}, (*scaleReader).isSome); err == nil {
		t.Fatal("an option tag that is neither none nor some must be refused")
	}
}

func TestEveryAcceptedAccountFormNamesTheSameAccount(t *testing.T) {
	for _, row := range loadReadFixture(t).Accounts.Accepted {
		account, err := ParseAccount(row.Text)
		if err != nil || hex.EncodeToString(account) != row.AccountHex {
			t.Errorf("%q: got %x, %v; want %s", row.Text, account, err, row.AccountHex)
		}
	}
}

func TestTextThatIsNotAnAccountIsRefused(t *testing.T) {
	for _, text := range loadReadFixture(t).Accounts.Refused {
		if account, err := ParseAccount(text); !errors.Is(err, ErrBadAccount) {
			t.Errorf("%q: want ErrBadAccount, got %x, %v", text, account, err)
		}
	}
}

func TestAnAddressIsSS58UnderItsPrefixAndParsesBack(t *testing.T) {
	for _, row := range loadReadFixture(t).Accounts.Addresses {
		address := newAddress(mustHex(t, row.AccountHex), row.Prefix)
		if address.String() != row.Address {
			t.Errorf("prefix %d: got %s, want %s", row.Prefix, address, row.Address)
		}
		if got := hex.EncodeToString(address.Bytes()); got != row.AccountHex || address.Prefix() != row.Prefix {
			t.Errorf("prefix %d: the address does not give back its account and prefix", row.Prefix)
		}
		if account, err := ParseAccount(row.Address); err != nil || hex.EncodeToString(account) != row.AccountHex {
			t.Errorf("prefix %d: %s does not parse back: %v", row.Prefix, row.Address, err)
		}
	}
}

// asFixtureTable is a decoder's reason table in the fixture's form.
func asFixtureTable(source string, table map[uint8]reasonGroup) map[string]any {
	indexes := make([]int, 0, len(table))
	for index := range table {
		indexes = append(indexes, int(index))
	}
	sort.Ints(indexes)
	groups := []any{}
	for _, index := range indexes {
		group := table[uint8(index)]
		reasonIndexes := make([]int, 0, len(group.reasons))
		for reason := range group.reasons {
			reasonIndexes = append(reasonIndexes, int(reason))
		}
		sort.Ints(reasonIndexes)
		reasons := []any{}
		for _, reason := range reasonIndexes {
			reasons = append(reasons, map[string]any{"index": reason, "name": group.reasons[uint8(reason)]})
		}
		groups = append(groups, map[string]any{"index": index, "pallet": group.pallet, "reasons": reasons})
	}
	return map[string]any{"source": source, "groups": groups}
}

func TestTheEnumTablesAreTheOnesRustCheckedAgainstTheRuntime(t *testing.T) {
	tables := loadReadFixture(t).Tables
	for _, c := range []struct {
		fixture reasonTable
		table   map[uint8]reasonGroup
	}{
		{tables.HoldReasons, holdReasons},
		{tables.FreezeReasons, freezeReasons},
	} {
		got := asJSONValue(t, asFixtureTable(c.fixture.Source, c.table))
		if want := asJSONValue(t, c.fixture); !reflect.DeepEqual(got, want) {
			t.Errorf("%s\n got  %v\n want %v", c.fixture.Source, got, want)
		}
	}
	if got := asJSONValue(t, lockReasonsByIndex); !reflect.DeepEqual(got, asJSONValue(t, tables.LockReasons)) {
		t.Errorf("lock reasons: got %v, want %v", got, tables.LockReasons)
	}
	if got := asJSONValue(t, dispatchClassesByIndex); !reflect.DeepEqual(got, asJSONValue(t, tables.DispatchClass)) {
		t.Errorf("dispatch classes: got %v, want %v", got, tables.DispatchClass)
	}
}

func TestCanonicalJSONFollowsTheWidthRuleInDeclaredOrder(t *testing.T) {
	type nested struct {
		TransferableKeepAlive *big.Int `json:"transferable_keep_alive"`
	}
	type sample struct {
		BlockNumber uint64      `json:"block_number"`
		SpecVersion uint32      `json:"spec_version"`
		Owner       []byte      `json:"owner"`
		Missing     *nested     `json:"missing"`
		NoStash     *Address    `json:"no_stash"`
		NoLabel     *Text       `json:"no_label"`
		NoAmount    *big.Int    `json:"no_amount"`
		Empty       []nested    `json:"empty"`
		Nested      []nested    `json:"nested"`
		Label       Text        `json:"label"`
		Cipher      Text        `json:"cipher"`
		State       LockReasons `json:"state"`
		Markup      string      `json:"markup,omitempty"`
	}
	value := sample{
		BlockNumber: 1<<64 - 1,
		SpecVersion: 330,
		Owner:       []byte{0xab, 0xcd},
		Nested:      []nested{{big.NewInt(1)}},
		Label:       Text{raw: []byte("prod-db")},
		Cipher:      Text{raw: []byte{0xff, 0x00, 0xfe}},
		State:       LockReasonsAll,
	}
	got, err := CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	// Declared order; absent optionals and an empty tagged string are present;
	// a nil list is an array.
	want := `{"block_number":"18446744073709551615","spec_version":330,"owner":"0xabcd",` +
		`"missing":null,"no_stash":null,"no_label":null,"no_amount":null,"empty":[],` +
		`"nested":[{"transferable_keep_alive":"1"}],"label":"prod-db",` +
		`"cipher":{"hex":"0xff00fe"},"state":"All","markup":""}`
	if got != want {
		t.Fatalf("\n got  %s\n want %s", got, want)
	}
}

func TestCanonicalJSONEscapesOnlyWhatJSONRequires(t *testing.T) {
	got, err := CanonicalJSON(Text{raw: []byte("a\"\\<&>é\u2028\x7f\x01\b\f\n\r\t")})
	if err != nil {
		t.Fatal(err)
	}
	want := "\"a\\\"\\\\<&>é\u2028\x7f\\u0001\\b\\f\\n\\r\\t\""
	if got != want {
		t.Fatalf("\n got  %s\n want %s", got, want)
	}
}

func TestAValueOutsideTheContractIsAnErrorNotAPanic(t *testing.T) {
	type embedded struct {
		BalanceReason
	}
	for _, value := range []any{
		struct{ Untagged int }{},
		struct {
			Ratio float64 `json:"ratio"`
		}{},
		embedded{},
	} {
		if text, err := CanonicalJSON(value); err == nil {
			t.Errorf("%T: want an error, got %s", value, text)
		}
	}
}

func TestAReadThatAsksTheChainHasASecondReturningCaseAndAFailingOne(t *testing.T) {
	for _, row := range loadReadFixture(t).Reads {
		failing, asksTheChain := 0, false
		for _, testCase := range row.Cases {
			if testCase.Error != nil {
				failing++
			}
			asksTheChain = asksTheChain || len(testCase.Exchanges) > 0
		}
		returning := len(row.Cases) - failing
		if returning < 1 || (asksTheChain && (returning < 2 || failing == 0)) {
			t.Errorf("%s.%s has %d returning and %d failing cases", row.Facade, row.Method, returning, failing)
		}
	}
}

func TestAPinnedReadMakesExactlyTheRecordedRequests(t *testing.T) {
	fixture := loadReadFixture(t)
	for _, row := range fixture.Reads {
		if !row.Pinnable {
			continue
		}
		for _, testCase := range row.Cases {
			t.Run(row.Facade+"."+row.Method+"/"+testCase.Name, func(t *testing.T) {
				chain := newFixtureChain(t, &testCase)

				result, err := callRead(t, readingClient(t, fixture, chain, &testCase), fixture, row, testCase, true)

				assertOutcome(t, testCase, result, err)
				// Nothing more: no head to resolve.
				if want := requestsOf(testCase); !sameRequests(chain.requests, want) {
					t.Fatalf("asked %v\nwant  %v", chain.requests, want)
				}
			})
		}
	}
}

func TestAnUnpinnedReadResolvesTheFinalizedHeadOnce(t *testing.T) {
	fixture := loadReadFixture(t)
	for _, row := range fixture.Reads {
		for _, testCase := range row.Cases {
			t.Run(row.Facade+"."+row.Method+"/"+testCase.Name, func(t *testing.T) {
				chain := newFixtureChain(t, &testCase)

				result, err := callRead(t, readingClient(t, fixture, chain, &testCase), fixture, row, testCase, false)

				assertOutcome(t, testCase, result, err)
				// A read about one block asks for the finalized head once, then makes
				// the same requests at it; any other read asks exactly what was recorded.
				// So does a read refused before it asks anything: it never needs a block.
				want := requestsOf(testCase)
				refusedBeforeAsking := testCase.Error != nil && len(testCase.Exchanges) == 0
				if row.Pinnable && !refusedBeforeAsking {
					want = append([]rpcRequest{{rpcFinalizedHead, []any{}}}, want...)
				}
				if !sameRequests(chain.requests, want) {
					t.Fatalf("asked %v\nwant  %v", chain.requests, want)
				}
			})
		}
	}
}

func alice(t *testing.T) []byte {
	t.Helper()
	account, err := ParseAccount("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func wantChainErrorAt(t *testing.T, err error, target string) {
	t.Helper()
	var chainErr *ChainError
	if !errors.As(err, &chainErr) || chainErr.Kind != KindChain || chainErr.Target != target {
		t.Fatalf("want a chain error at %s, got %v", target, err)
	}
}

func TestANodeThatLeavesAKeyOutOfItsAnswerIsAnError(t *testing.T) {
	fixture := loadReadFixture(t)
	chain := newFixtureChain(t, nil)
	chain.override = func(method string, params []any) (any, error) {
		if method == rpcQueryStorageAt {
			return []map[string]any{{"block": params[1], "changes": [][]any{}}}, nil
		}
		return fixtureHead, nil
	}
	_, err := readOnlyClient(t, fixture, chain).Accounts().Balance(alice(t))
	wantChainErrorAt(t, err, "System.Account")
}

func TestANodeThatAnswersWithSomethingThatIsNotHexIsAnError(t *testing.T) {
	fixture := loadReadFixture(t)
	chain := newFixtureChain(t, nil)
	chain.override = func(method string, params []any) (any, error) {
		if method != rpcQueryStorageAt {
			return fixtureHead, nil
		}
		changes := [][]any{}
		for _, key := range params[0].([]any) {
			changes = append(changes, []any{key, "not hex"})
		}
		return []map[string]any{{"block": params[1], "changes": changes}}, nil
	}
	_, err := readOnlyClient(t, fixture, chain).Accounts().Balance(alice(t))
	wantChainErrorAt(t, err, "System.Account")
}

func TestARefusedRequestIsAChainErrorNamingTheMethod(t *testing.T) {
	fixture := loadReadFixture(t)
	chain := newFixtureChain(t, nil)
	chain.override = func(string, []any) (any, error) { return nil, errors.New("socket closed") }
	accounts := readOnlyClient(t, fixture, chain).Accounts()

	_, err := accounts.Balance(alice(t))
	wantChainErrorAt(t, err, rpcFinalizedHead)

	_, err = accounts.At([blockHashBytes]byte{}).Balance(alice(t))
	wantChainErrorAt(t, err, rpcQueryStorageAt)
}

func TestAnAccountThatIsNot32BytesIsRefusedBeforeAnyRequest(t *testing.T) {
	fixture := loadReadFixture(t)
	chain := newFixtureChain(t, nil)
	_, err := readOnlyClient(t, fixture, chain).Accounts().Balance(alice(t)[1:])
	if !errors.Is(err, ErrBadAccount) || len(chain.requests) != 0 {
		t.Fatalf("want ErrBadAccount and no request, got %v after %d requests", err, len(chain.requests))
	}
}

func TestTheCallerOwnsEveryAmountInAResult(t *testing.T) {
	// The widest total saturates; the result must not hand out the package's own
	// constant for a caller to mutate.
	max := new(big.Int).Set(u128Max)
	info := append(make([]byte, 16), append(bytesOf(0xff, 32), make([]byte, 32)...)...)
	balance, err := decodeBalance(newAddress(alice(t), 42), big.NewInt(1),
		[]stored{{raw: info, found: true}, {}, {}, {}})
	if err != nil {
		t.Fatal(err)
	}
	balance.Total.SetInt64(0)
	if u128Max.Cmp(max) != 0 {
		t.Fatal("mutating a result changed the package's u128 maximum")
	}
}
