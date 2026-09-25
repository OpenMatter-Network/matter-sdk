package mattersdk

// A 0x-hex mini-secret and its BIP39 mnemonic must derive the same account via
// gsrpc's KeyringPairFromSecret (testvectors/seed_formats.json).

import (
	"encoding/hex"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
)

func TestSeedFormatConformance(t *testing.T) {
	var v struct {
		Cases []struct {
			Mnemonic      string `json:"mnemonic"`
			MiniSecretHex string `json:"mini_secret_hex"`
			AccountIDHex  string `json:"account_id_hex"`
		} `json:"cases"`
	}
	load(t, "seed_formats.json", &v)
	for _, c := range v.Cases {
		fromMnemonic, err := signature.KeyringPairFromSecret(c.Mnemonic, 42)
		if err != nil {
			t.Fatalf("mnemonic: %v", err)
		}
		fromHex, err := signature.KeyringPairFromSecret("0x"+c.MiniSecretHex, 42)
		if err != nil {
			t.Fatalf("hex seed: %v", err)
		}
		if got := hex.EncodeToString(fromMnemonic.PublicKey); got != c.AccountIDHex {
			t.Fatalf("mnemonic pubkey = %s, want %s", got, c.AccountIDHex)
		}
		if got := hex.EncodeToString(fromHex.PublicKey); got != c.AccountIDHex {
			t.Fatalf("hex pubkey = %s, want %s", got, c.AccountIDHex)
		}
	}
}
