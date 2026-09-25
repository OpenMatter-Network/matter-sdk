// Connect from an apiKey and exercise the Go client surface. Read-only unless
// MATTER_SUBMIT=yes. Environment variables: examples/README.md.
//
//	cargo build -p matter-sdk-ffi --release   # prerequisite
//	MATTER_API_KEY=$TEST_KEY go run .
package main

import (
	"encoding/binary"
	"fmt"
	"os"

	mattersdk "github.com/openmatter-network/matter-sdk-go/v2"
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
	// guard, and connects read-only when neither is set. TEST_KEY is this repo's
	// fallback, so map it in first.
	if os.Getenv("MATTER_API_KEY") == "" && os.Getenv("MATTER_SIGNER_SEED") == "" {
		if fallback := os.Getenv("TEST_KEY"); fallback != "" {
			os.Setenv("MATTER_API_KEY", fallback)
		}
	}

	client, key, err := mattersdk.ConnectFromEnv()
	if err != nil {
		return err
	}
	defer client.Close()
	if key != nil {
		// Prints the account only: String() is redacted.
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

func describeChain(client *mattersdk.MatterClient) {
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

// readState uses the generic surface: any pallet, resolved by name from metadata.
func readState(client *mattersdk.MatterClient) error {
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

	// Absence is not an error: an unfunded account has no row.
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

func demonstrateAmounts(client *mattersdk.MatterClient) {
	fmt.Println("\n--- amounts (always plancks, never floats) ---")
	one := client.OneToken()
	fmt.Printf("  1 %s = %s plancks\n", client.Properties().TokenSymbol, one)

	if parsed, err := client.ParseAmount("1.5"); err == nil {
		fmt.Printf("  \"1.5\" = %s plancks\n", parsed)
	}
	fmt.Printf("  %s plancks reads back as %s\n", one, client.FormatAmount(one))

	tooPrecise := "0." + repeat("0", 40) + "1"
	if _, err := client.ParseAmount(tooPrecise); err != nil {
		fmt.Printf("  over-precise amount rejected: %v\n", err)
	}
}

func maybeSubmit(client *mattersdk.MatterClient) error {
	fmt.Println("\n--- writes ---")

	if client.AccountID() == nil {
		fmt.Println("  read-only client: nothing to submit.")
		return nil
	}
	if os.Getenv(submitEnv) != submitValue {
		fmt.Println("  would submit Staking.chill() via the curated staking façade:")
		fmt.Println("      client.Staking().Chill()")
		fmt.Println("  and the same call through the generic surface:")
		fmt.Println("      client.Call(\"Staking\", \"chill\")")
		fmt.Printf("  set %s=%s to actually send it (costs a fee).\n", submitEnv, submitValue)
		return nil
	}

	// `chill` is idempotent, self-targeted, and a no-op for a non-nominator: the
	// cheapest signed call that moves no funds.
	fmt.Println("  submitting Staking.chill() ...")
	receipt, err := client.Staking().Chill()
	if err != nil {
		return err
	}
	fmt.Printf("  finalized in block %s (tx %s)\n", receipt.BlockHash.Hex(), receipt.TxHash)
	return nil
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
