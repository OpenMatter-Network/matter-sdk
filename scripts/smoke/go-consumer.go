// Consumer smoke test for matter-sdk-go, built by scripts/smoke-go-module.sh outside this
// repo. Proves a plain `go build` links the prebuilt core: one seal and one sign, a call
// into each crate behind the C ABI.
//
//	usage: smoke <path/to/testvectors/open_secret.json>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	mattersdk "github.com/openmatter-network/matter-sdk-go/v2"
)

const (
	sr25519AccountIDLen = 32
	sr25519SignatureLen = 64
	// Fixed, non-secret seed.
	smokeKey = "0x1111111111111111111111111111111111111111111111111111111111111111"
)

type vector struct {
	JointPkHex string `json:"joint_pk_hex"`
	CapsuleHex string `json:"capsule_hex"`
	AadHex     string `json:"aad_hex"`
	Epoch      uint32 `json:"epoch"`
}

func run(vectorPath string) error {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		return err
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	jointPk, err := hex.DecodeString(v.JointPkHex)
	if err != nil {
		return err
	}
	aad, err := hex.DecodeString(v.AadHex)
	if err != nil {
		return err
	}

	sealed, err := mattersdk.Encrypt(jointPk, v.Epoch, []byte("smoke"), aad, nil)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if want := len(v.CapsuleHex) / 2; len(sealed.Capsule) != want {
		return fmt.Errorf("encrypt produced a %d-byte capsule, want %d", len(sealed.Capsule), want)
	}

	key, err := mattersdk.NewApiKey(smokeKey)
	if err != nil {
		return fmt.Errorf("api key: %w", err)
	}
	defer key.Close()
	if n := len(key.AccountID()); n != sr25519AccountIDLen {
		return fmt.Errorf("account id is %d bytes, want %d", n, sr25519AccountIDLen)
	}
	signature, err := key.Sign([]byte{1})
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if len(signature) != sr25519SignatureLen {
		return fmt.Errorf("signature is %d bytes, want %d", len(signature), sr25519SignatureLen)
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: smoke <open_secret.json>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "go smoke:", err)
		os.Exit(1)
	}
}
