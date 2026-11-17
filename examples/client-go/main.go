// Connect from an apiKey and exercise the Go client surface. Read-only unless
// MATTER_SUBMIT=yes. Environment variables: examples/README.md.
//
//	cargo build -p matter-sdk-ffi --release   # prerequisite
//	MATTER_API_KEY=$TEST_KEY go run .
package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	mattersdk "github.com/openmatter-network/matter-sdk-go/v2"
)

// Opt-in gate for anything that costs gas.
const (
	submitEnv   = "MATTER_SUBMIT"
	submitValue = "yes"
)

// sampleAccount is the well-known development account, read when no key is set so
// a read-only run still shows a real balance.
const sampleAccount = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

// The call this tour submits behind the gate, and so the one it prices.
const (
	writePallet = "Staking"
	writeCall   = "chill"
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
	if err := readBalance(client); err != nil {
		return err
	}
	if err := preflight(client); err != nil {
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
// Storage decodes into a GSRPC type, never by byte offset; a runtime API answers
// SCALE bytes, decoded the same way.
func readState(client *mattersdk.MatterClient) error {
	fmt.Println("\n--- reads (the generic surface) ---")

	var next types.U128
	found, err := client.Query(&next, "Secrets", "NextSecretId")
	if err != nil {
		return err
	}
	if found {
		fmt.Printf("  Secrets.NextSecretId        = %s\n", next.String())
	} else {
		fmt.Println("  Secrets.NextSecretId        = absent")
	}

	// Absence is not an error: an unfunded account has no row.
	if id := client.AccountID(); id != nil {
		var account types.AccountInfo
		found, err := client.Query(&account, "System", "Account", id)
		if err != nil {
			return err
		}
		if found {
			fmt.Printf("  System.Account(me).nonce    = %d\n", account.Nonce)
		} else {
			fmt.Println("  System.Account(me)          = absent (unfunded account)")
		}
	}

	answer, err := client.RuntimeAPI("KgcApi_dkg_epoch", nil)
	if err != nil {
		return err
	}
	var epoch types.U32
	if err := codec.Decode(answer, &epoch); err != nil {
		return fmt.Errorf("KgcApi_dkg_epoch: %w", err)
	}
	fmt.Printf("  KgcApi_dkg_epoch            = %d\n", epoch)
	return nil
}

// readBalance uses a façade read: one question, one call, no pallet or encoding
// knowledge.
func readBalance(client *mattersdk.MatterClient) error {
	fmt.Println("\n--- reads (friendly helpers) ---")

	who := client.AccountID()
	if who == nil {
		sample, err := mattersdk.ParseAccount(sampleAccount)
		if err != nil {
			return err
		}
		who = sample
	}
	// Two reads, one block: the balance is pinned to the head just read.
	head, err := client.Network().Head()
	if err != nil {
		return err
	}
	balance, err := client.Accounts().At(head.Hash).Balance(who)
	if err != nil {
		return err
	}
	amount := func(plancks *big.Int) string { return tokens(client, plancks) }

	fmt.Printf("  at block        : %d\n", head.Number)
	fmt.Printf("  account         : %s\n", balance.Account)
	fmt.Printf("  exists          : %t\n", balance.Exists)
	fmt.Printf("  total           : %s\n", amount(balance.Total))
	// Not Free: freezes and the existential deposit hold some of it back.
	fmt.Printf("  transferable    : %s\n", amount(balance.Transferable))
	for _, hold := range balance.Holds {
		fmt.Printf("  on hold         : %s for %s\n", amount(hold.Amount), hold.Reason)
	}
	for _, freeze := range balance.Freezes {
		fmt.Printf("  frozen          : %s for %s\n", amount(freeze.Amount), freeze.Reason)
	}
	return nil
}

// tokens renders an amount of plancks as the chain's token, for printing.
func tokens(client *mattersdk.MatterClient, plancks *big.Int) string {
	return client.FormatAmount(plancks) + " " + client.Properties().TokenSymbol
}

// chargedTo reports whose balance a fee comes out of, and how the tour knows. The
// runtime's answer comes first; where it has none, the signer is the working
// assumption; a read-only client charges nobody, so the sample account stands in.
func chargedTo(estimate mattersdk.FeeEstimate) ([]byte, string, error) {
	switch {
	case estimate.Payer != nil && estimate.BilledTo != nil:
		return estimate.Payer.Bytes(), "an organization's treasury", nil
	case estimate.Payer != nil:
		return estimate.Payer.Bytes(), "per the runtime", nil
	case estimate.Signer != nil:
		return estimate.Signer.Bytes(), "the signer; the runtime did not say", nil
	}
	sample, err := mattersdk.ParseAccount(sampleAccount)
	return sample, "a sample account; this client is read-only", err
}

// preflight puts three reads together: can whoever pays for this tour's write
// afford it?
func preflight(client *mattersdk.MatterClient) error {
	fmt.Println("\n--- pre-flight (three reads, one block) ---")

	// Every read is pinned to one block, so the fee and the balance agree.
	head, err := client.Network().Head()
	if err != nil {
		return err
	}
	estimate, err := client.Fees().At(head.Hash).Estimate(writePallet, writeCall)
	if err != nil {
		return err
	}
	payer, how, err := chargedTo(estimate)
	if err != nil {
		return err
	}
	balance, err := client.Accounts().At(head.Hash).Balance(payer)
	if err != nil {
		return err
	}
	// A fee may not take the payer below the existential deposit.
	spendable := balance.TransferableKeepAlive
	deposit := client.Network().Info().ExistentialDeposit

	fmt.Printf("  call            : %s.%s\n", estimate.Pallet, estimate.Call)
	fmt.Printf("  at block        : %d\n", head.Number)
	fmt.Printf("  fee             : %s for %d bytes\n", tokens(client, estimate.PartialFee), estimate.EncodedLen)
	fmt.Printf("  charged to      : %s (%s)\n", balance.Account, how)
	fmt.Printf("  can spend       : %s, keeping the existential deposit of %s\n",
		tokens(client, spendable), tokens(client, deposit))
	left := new(big.Int).Sub(spendable, estimate.PartialFee)
	if left.Sign() >= 0 {
		fmt.Printf("  verdict         : affordable, leaving %s\n", tokens(client, left))
	} else {
		fmt.Printf("  verdict         : short by %s\n", tokens(client, left.Neg(left)))
	}
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
