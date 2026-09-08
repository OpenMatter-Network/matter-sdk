package mattervault

import (
	"errors"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

func decodeResult(t *testing.T, raw []byte) (*types.DispatchError, error) {
	t.Helper()
	return decodeDispatchResult(scale.NewDecoder(bytesReader(raw)))
}

func TestDecodeDispatchResultReadsBothArms(t *testing.T) {
	// Ok(()) and Err(Other) are the pair that makes a structural guess unsound:
	// through GSRPC's registry both collapse to a bare byte 0, because Result's
	// Ok arm and DispatchError's Other arm are both variant 0 with no fields.
	// Only reading the SCALE bytes in order tells them apart.
	if got, err := decodeResult(t, []byte{0x00}); err != nil || got != nil {
		t.Fatalf("Ok(()) is not a failure: got (%v, %v)", got, err)
	}
	got, err := decodeResult(t, []byte{0x01, 0x00})
	if err != nil {
		t.Fatalf("Err(Other): %v", err)
	}
	if got == nil || !got.IsOther {
		t.Fatalf("want Err(Other), got %+v", got)
	}

	// Err(Module { index, error }) — the shape a real pallet error takes.
	got, err = decodeResult(t, []byte{0x01, 0x03, 21, 5, 0, 0, 0})
	if err != nil {
		t.Fatalf("Err(Module): %v", err)
	}
	if got == nil || !got.IsModule || got.ModuleError.Index != 21 {
		t.Fatalf("want Err(Module{21,...}), got %+v", got)
	}

	if _, err := decodeResult(t, []byte{0x02}); err == nil {
		t.Fatal("an unknown Result discriminant must be an error, not a success")
	}
	if _, err := decodeResult(t, []byte{}); err == nil {
		t.Fatal("an empty result must be an error, not a success")
	}
}

func TestADelegatedWrappedFailureIsNeverReportedAsSuccess(t *testing.T) {
	describe := func(types.DispatchError) string { return "Jobs.DeploymentNotFound" }
	moduleErr := &types.DispatchError{IsModule: true}

	// The whole point of the delegated path: proxy.proxy succeeds as an
	// extrinsic even when the call it wrapped did not.
	err := delegatedOutcome(extrinsicOutcome{SawProxy: true, Proxied: moduleErr}, true, "Jobs.cancel_deployment", describe)
	var chainErr *ChainError
	if !errors.As(err, &chainErr) || chainErr.Kind != KindDispatch {
		t.Fatalf("want a dispatch error, got %v", err)
	}

	// A delegated submission whose ProxyExecuted never appeared is a contract
	// violation, not a success: something dispatched, and we cannot say what.
	err = delegatedOutcome(extrinsicOutcome{}, true, "Jobs.cancel_deployment", describe)
	if !errors.As(err, &chainErr) || chainErr.Kind != KindChain {
		t.Fatalf("a missing ProxyExecuted must be an error, got %v", err)
	}

	// The happy path, and the direct-mode path, stay quiet.
	if err := delegatedOutcome(extrinsicOutcome{SawProxy: true}, true, "x", describe); err != nil {
		t.Fatalf("a successful wrapped call is not an error: %v", err)
	}
	if err := delegatedOutcome(extrinsicOutcome{}, false, "x", describe); err != nil {
		t.Fatalf("a direct submission has no ProxyExecuted to find: %v", err)
	}
}

func TestAnExtrinsicFailureIsReportedWhicheverModeItIs(t *testing.T) {
	describe := func(types.DispatchError) string { return "Proxy.NotProxy" }
	failed := &types.DispatchError{IsModule: true}
	for _, delegated := range []bool{true, false} {
		err := delegatedOutcome(extrinsicOutcome{Failed: failed}, delegated, "Jobs.cancel_deployment", describe)
		var chainErr *ChainError
		if !errors.As(err, &chainErr) {
			t.Fatalf("delegated=%v: want a typed error, got %v", delegated, err)
		}
	}
}
