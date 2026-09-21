// Consumer smoke test for github.com/openmatter-network/matter-sdk-go, built by
// scripts/smoke-go-module.sh in a module OUTSIDE this repository, against the assembled
// (or published) module — never packages/go/mattersdk.
//
// The module's own conformance suite runs from the module cache as well; this program
// proves the part a suite cannot: that a plain `go build` of somebody else's code links
// the prebuilt core and runs with nothing on the library path. It seals (the core's RNG)
// and signs (the key core), one call into each of the two crates behind the C ABI.
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
	// A fixed, obviously-not-secret seed.
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
