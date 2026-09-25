package mattersdk

import (
	"errors"
	"math"
	"testing"
)

func TestWipeZeroesTheBuffer(t *testing.T) {
	secret := []byte("top secret")
	Wipe(secret)
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte %d not wiped: %q", i, secret)
		}
	}
	Wipe(nil) // a nil slice is a no-op, not a panic
}

func TestSizeToIntRejectsWhatAnIntCannotHold(t *testing.T) {
	if n, ok := sizeToInt(1 << 31); !ok || n != 1<<31 {
		t.Fatalf("2 GiB: got (%d, %v), want it intact", n, ok)
	}
	if _, ok := sizeToInt(math.MaxUint64); ok {
		t.Fatal("a size beyond MaxInt must be refused, not wrapped")
	}
}

func TestStatusCodesMapToTypedErrors(t *testing.T) {
	cases := map[int32]error{
		statusOK:         nil,
		statusInvalidArg: ErrInvalidArg,
		statusCrypto:     ErrCrypto,
		statusKey:        ErrBadAPIKey,
		statusInternal:   ErrInternal,
	}
	for code, want := range cases {
		if got := errFromStatus(code); !errors.Is(got, want) || (want == nil) != (got == nil) {
			t.Fatalf("code %d: got %v, want %v", code, got, want)
		}
	}
}
