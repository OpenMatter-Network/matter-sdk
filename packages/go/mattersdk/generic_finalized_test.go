package mattersdk

// The generic reads see the latest finalized block: state that cannot be
// reverted, and where a write that has returned is visible.

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

// answering returns a chain that reports fixtureHead as finalized and answers
// state_getStorage and state_call with the values given (nil is JSON null).
func answering(t *testing.T, storage, runtimeAPI any) *fixtureChain {
	t.Helper()
	chain := newFixtureChain(t, nil)
	chain.override = func(method string, _ []any) (any, error) {
		switch method {
		case rpcFinalizedHead:
			return fixtureHead, nil
		case rpcGetStorage:
			return storage, nil
		case rpcStateCall:
			return runtimeAPI, nil
		}
		return nil, fmt.Errorf("unexpected request %s", method)
	}
	return chain
}

// wantReadAtTheHead checks the chain was asked for the finalized head once, and
// then for method with the head as its last parameter.
func wantReadAtTheHead(t *testing.T, chain *fixtureChain, method string) {
	t.Helper()
	if len(chain.requests) != 2 || chain.requests[0].Method != rpcFinalizedHead || chain.requests[1].Method != method {
		t.Fatalf("asked %v, want %s then %s", chain.requests, rpcFinalizedHead, method)
	}
	params := chain.requests[1].Params
	if at := params[len(params)-1]; at != fixtureHead {
		t.Fatalf("%s read at %v, want the finalized head %s", method, at, fixtureHead)
	}
}

func TestQueryRawReadsAtTheLatestFinalizedBlock(t *testing.T) {
	chain := answering(t, "0x2a000000", nil)
	client := readOnlyClient(t, loadReadFixture(t), chain)

	raw, err := client.QueryRaw("System", "Number")
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x2a, 0, 0, 0}; !reflect.DeepEqual(raw, want) {
		t.Fatalf("got %x, want %x", raw, want)
	}
	wantReadAtTheHead(t, chain, rpcGetStorage)
}

func TestQueryDecodesWhatIsStoredAtTheLatestFinalizedBlock(t *testing.T) {
	chain := answering(t, "0x2a000000", nil)
	client := readOnlyClient(t, loadReadFixture(t), chain)

	var number types.U32
	found, err := client.Query(&number, "System", "Number")
	if err != nil {
		t.Fatal(err)
	}
	if !found || number != 42 {
		t.Fatalf("got (%d, %t), want (42, true)", number, found)
	}
	wantReadAtTheHead(t, chain, rpcGetStorage)
}

func TestAnEntryThatIsNotStoredReadsAsAbsent(t *testing.T) {
	for _, stored := range []any{nil, "0x"} {
		client := readOnlyClient(t, loadReadFixture(t), answering(t, stored, nil))

		raw, err := client.QueryRaw("System", "Number")
		if err != nil || raw != nil {
			t.Fatalf("QueryRaw over %v: got (%x, %v), want (nil, nil)", stored, raw, err)
		}
		var number types.U32
		found, err := client.Query(&number, "System", "Number")
		if err != nil || found {
			t.Fatalf("Query over %v: got (%t, %v), want (false, nil)", stored, found, err)
		}
	}
}

func TestARuntimeAPIIsCalledAtTheLatestFinalizedBlock(t *testing.T) {
	chain := answering(t, nil, "0x07000000")
	client := readOnlyClient(t, loadReadFixture(t), chain)

	raw, err := client.RuntimeAPI("KgcApi_dkg_epoch", nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{7, 0, 0, 0}; !reflect.DeepEqual(raw, want) {
		t.Fatalf("got %x, want %x", raw, want)
	}
	wantReadAtTheHead(t, chain, rpcStateCall)
	if got := chain.requests[1].Params[:2]; !reflect.DeepEqual(got, []any{"KgcApi_dkg_epoch", "0x"}) {
		t.Fatalf("called %v", got)
	}
}

func TestAGenericReadTheNodeRefusesNamesItsSource(t *testing.T) {
	chain := newFixtureChain(t, nil)
	chain.override = func(method string, _ []any) (any, error) {
		if method == rpcFinalizedHead {
			return fixtureHead, nil
		}
		return nil, fmt.Errorf("refused")
	}
	client := readOnlyClient(t, loadReadFixture(t), chain)

	_, err := client.QueryRaw("System", "Number")
	wantChainErrorAt(t, err, "System.Number")
	_, err = client.Query(new(types.U32), "System", "Number")
	wantChainErrorAt(t, err, "System.Number")
	_, err = client.RuntimeAPI("KgcApi_dkg_epoch", nil)
	wantChainErrorAt(t, err, "KgcApi_dkg_epoch")
}
