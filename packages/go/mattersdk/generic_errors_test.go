package mattersdk

import (
	"errors"
	"testing"
)

func TestReadFailuresAreTypedChainErrors(t *testing.T) {
	chain := &ChainClient{meta: loadSpec322Metadata(t)}

	reads := map[string]func() error{
		"Nope.Entry": func() error {
			_, err := chain.Query(new([]byte), "Nope", "Entry")
			return err
		},
		"Secrets.NoSuchEntry": func() error {
			_, err := chain.QueryRaw("Secrets", "NoSuchEntry")
			return err
		},
		"Balances.NoSuchConstant": func() error {
			_, err := chain.Constant("Balances", "NoSuchConstant")
			return err
		},
	}
	for target, read := range reads {
		err := read()
		var chainErr *ChainError
		if !errors.As(err, &chainErr) {
			t.Errorf("%s: want a *ChainError, got %T (%v)", target, err, err)
			continue
		}
		if chainErr.Kind != KindChain || chainErr.Target != target {
			t.Errorf("%s: kind %q target %q", target, chainErr.Kind, chainErr.Target)
		}
	}
}
