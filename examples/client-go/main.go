// Connect to OpenMatter from an apiKey and exercise the Go client surface.
//
// Read-only by default. Every call here is a read unless you opt into submission
// with MATTER_SUBMIT=yes, so running it costs nothing and cannot change chain
// state by accident.
//
//	LD_LIBRARY_PATH=../../target/release MATTER_API_KEY=$TEST_KEY go run .
//
//	MATTER_API_KEY   the key; falls back to MATTER_SIGNER_SEED, then TEST_KEY
//	MATTER_RPC_URL   endpoint override (default: testnet)
//	MATTER_NETWORK   testnet (default) or mainnet
//	MATTER_CONFIRM   must be "yes" for a signing client on mainnet
//	MATTER_SUBMIT    must be "yes" to submit anything
//
// Build prerequisite: cargo build -p matter-vault-ffi --release
package main

import (
	"encoding/binary"
	"fmt"
	"os"

	mv "github.com/openmatter-network/matter-sdk/packages/go/mattervault"
)

// Opt-in gate for anything that costs gas.
const (
	submitEnv   = "MATTER_SUBMIT"
	submitValue = "yes"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// ConnectFromEnv reads MATTER_API_KEY / MATTER_SIGNER_SEED, applies the mainnet
	// guard, and connects read-only when no key is set — a legitimate outcome rather
	// than an error. TEST_KEY is this repo's own fallback, so it is mapped in first.
	if os.Getenv("MATTER_API_KEY") == "" && os.Getenv("MATTER_SIGNER_SEED") == "" {
		if fallback := os.Getenv("TEST_KEY"); fallback != "" {
			os.Setenv("MATTER_API_KEY", fallback)
		}
	}

	client, key, err := mv.ConnectFromEnv()
	if err != nil {
		return err
	}
	defer client.Close()
	if key != nil {
		// Note what this prints: the account, never the key. String() is redacted,
		// so even a careless log is safe.
		defer key.Close()
		fmt.Printf("Connected with %s\n", key)
	} else {
		fmt.Println("No key set — connected read-only.")
	}

	describeChain(client)
	if err := readState(client); err != nil {
		return err
	}
	demonstrateAmounts(client)
	if err := maybeSubmit(client); err != nil {
		return err
	}

	fmt.Println("\nDone.")
	return nil
}

func describeChain(client *mv.MatterClient) {
	p := client.Properties()
	fmt.Println("\n--- chain ---")
	fmt.Printf("  name            : %s\n", p.ChainName)
	fmt.Printf("  spec_version    : %d\n", p.SpecVersion)
	fmt.Printf("  token           : %s\n", p.TokenSymbol)
	fmt.Printf("  ss58 prefix     : %d\n", p.SS58Prefix)
	fmt.Printf("  decimals (spec) : %d\n", p.TokenDecimalsDeclared)
	fmt.Printf("  decimals (live) : %d\n", p.TokenDecimalsEffective)
	if p.DecimalsDisagree() {
		fmt.Println("  ^ the node's chain spec disagrees with its runtime; the live value wins")
	}
	if address := client.Address(); address != "" {
		fmt.Printf("  signing as      : %s\n", address)
	} else {
		fmt.Println("  signing as      : (read-only)")
	}
}

// readState uses the generic, metadata-driven surface: any pallet the runtime
// exposes, resolved by name.
func readState(client *mv.MatterClient) error {
	fmt.Println("\n--- reads (the generic surface) ---")

	next, err := client.QueryRaw("Secrets", "NextSecretId")
	if err != nil {
		return err
	}
	if next == nil {
		fmt.Println("  Secrets.NextSecretId        = absent")
	} else {
		fmt.Printf("  Secrets.NextSecretId        = %d\n", binary.LittleEndian.Uint64(next[:8]))
	}

	// Absence is normal control flow, not an error: an unfunded account has no row.
	if id := client.AccountID(); id != nil {
		account, err := client.QueryRaw("System", "Account", id)
		if err != nil {
			return err
		}
		if account == nil {
			fmt.Println("  System.Account(me)          = absent (unfunded account)")
		} else {
			// AccountInfo starts with a u32 nonce.
			fmt.Printf("  System.Account(me).nonce    = %d\n", binary.LittleEndian.Uint32(account[:4]))
		}
	}

	epoch, err := client.RuntimeAPI("KgcApi_dkg_epoch", nil)
	if err != nil {
		return err
	}
	fmt.Printf("  KgcApi_dkg_epoch            = %d\n", binary.LittleEndian.Uint32(epoch[:4]))
	return nil
}

// demonstrateAmounts shows that amounts are integer plancks, never floats.
func demonstrateAmounts(client *mv.MatterClient) {
	fmt.Println("\n--- amounts (always plancks, never floats) ---")
	one := client.OneToken()
	fmt.Printf("  1 %s = %s plancks\n", client.Properties().TokenSymbol, one)

	if parsed, err := client.ParseAmount("1.5"); err == nil {
		fmt.Printf("  \"1.5\" = %s plancks\n", parsed)
	}
	fmt.Printf("  %s plancks reads back as %s\n", one, client.FormatAmount(one))

	// Excess precision is rejected rather than rounded: losing someone's funds to a
	// silent truncation is not a trade worth making for convenience.
	tooPrecise := "0." + repeat("0", 40) + "1"
	if _, err := client.ParseAmount(tooPrecise); err != nil {
		fmt.Printf("  over-precise amount rejected: %v\n", err)
	}
}

// maybeSubmit shows what submission looks like. Gated, because it costs gas.
func maybeSubmit(client *mv.MatterClient) error {
	fmt.Println("\n--- writes ---")

	if client.AccountID() == nil {
		fmt.Println("  read-only client: nothing to submit.")
		return nil
	}
	if os.Getenv(submitEnv) != submitValue {
		fmt.Println("  would submit Staking.chill() via the curated staking façade:")
		fmt.Println("      client.Staking().Chill()")
		fmt.Println("  and the same call through the generic surface:")
		fmt.Println("      call, _ := types.NewCall(meta, \"Staking.chill\"); client.Tx(call)")
		fmt.Printf("  set %s=%s to actually send it (costs a fee).\n", submitEnv, submitValue)
		return nil
	}

	// `chill` is the demo call because it is idempotent, self-targeted, and a no-op
	// for an account that is not nominating — the cheapest way to prove the signing
	// path end-to-end without moving funds.
	fmt.Println("  submitting Staking.chill() ...")
	txHash, err := client.Staking().Chill()
	if err != nil {
		return err
	}
	fmt.Printf("  submitted: %s\n", txHash)
	fmt.Println("  (use client.Chain().WaitForFinalized with a domain check to confirm)")
	return nil
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
