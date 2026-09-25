// Live Secrets round trip against a chain + committee: seal -> secrets.storeSecret
// (pays a fee) -> read back -> threshold-decrypt -> verify. Needs a FUNDED account.
// Environment variables: examples/README.md.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	mattersdk "github.com/openmatter-network/matter-sdk-go/v2"
)

const (
	defaultSecret = "API_KEY=swordfish\nDATABASE_URL=postgres://prod"
	ss58Format    = 42
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		os.Exit(1)
	}
}

// guardMainnet refuses mainnet without MATTER_CONFIRM=yes. It checks the URL as well
// as MATTER_NETWORK: a mistyped MATTER_RPC_URL is the likelier mistake.
func guardMainnet(rpcURL string) error {
	network := getenv("MATTER_NETWORK", "testnet")
	if network != "mainnet" && !strings.Contains(rpcURL, "mainnet") {
		return nil
	}
	if os.Getenv("MATTER_CONFIRM") == "yes" {
		fmt.Fprintln(os.Stderr, "WARNING: running against MAINNET with real funds (MATTER_CONFIRM=yes).")
		return nil
	}
	return fmt.Errorf(
		"refusing to run a gas-paying harness against mainnet (%s) without explicit "+
			"confirmation: set MATTER_CONFIRM=yes. This spends real funds", rpcURL)
}

func run() error {
	// Default endpoint per network: testvectors/networks.json.
	defaultRPC := mattersdk.TestnetRPC
	switch network := getenv("MATTER_NETWORK", "testnet"); network {
	case "testnet":
	case "mainnet":
		defaultRPC = mattersdk.MainnetRPC
	default:
		return fmt.Errorf("MATTER_NETWORK must be testnet or mainnet, got %q", network)
	}
	rpcURL := getenv("MATTER_RPC_URL", defaultRPC)
	if err := guardMainnet(rpcURL); err != nil {
		return err
	}
	seed := os.Getenv("MATTER_SIGNER_SEED")
	if seed == "" {
		seed = os.Getenv("TEST_KEY")
	}
	if seed == "" {
		return fmt.Errorf("set MATTER_SIGNER_SEED or TEST_KEY (sr25519 SURI / 0x-seed)")
	}
	secret := getenv("MATTER_SECRET", defaultSecret)
	existing := os.Getenv("MATTER_SECRET_ID")
	aad := mattersdk.AadEnvV1

	kp, err := signature.KeyringPairFromSecret(seed, ss58Format)
	if err != nil {
		return err
	}
	fmt.Printf("Account: %s\n", kp.Address)

	chain, err := mattersdk.NewChainClient(rpcURL)
	if err != nil {
		return err
	}

	jointPk, err := chain.JointPk()
	if err != nil {
		return err
	}
	epoch, err := chain.DkgEpoch()
	if err != nil {
		return err
	}
	fmt.Printf("Connected. Committee epoch=%d, joint_pk=%dB\n", epoch, len(jointPk))

	var secretID mattersdk.SecretID
	if existing != "" {
		secretID, err = mattersdk.ParseSecretID(existing)
		if err != nil {
			return err
		}
		fmt.Printf("Using existing secret %s.\n", secretID)
	} else {
		env, err := mattersdk.Encrypt(jointPk, epoch, []byte(secret), mattersdk.AadBytes(aad), nil)
		if err != nil {
			return err
		}
		fmt.Printf("Sealed %dB -> capsule %dB, proof %dB, ct %dB\n", len(secret), len(env.Capsule), len(env.Proof), len(env.CT))
		fmt.Println("Submitting secrets.storeSecret ...")
		secretID, err = chain.StoreSecret(kp, *env, epoch, aad)
		if err != nil {
			return err
		}
		fmt.Printf("Stored on chain: secret_id=%s.\n", secretID)
	}

	secretEpoch, err := chain.SecretEpoch(secretID)
	if err != nil {
		return err
	}
	wire, err := chain.SecretPayload(secretID)
	if err != nil {
		return err
	}
	threshold, err := chain.ThresholdAtEpoch(secretEpoch)
	if err != nil {
		return err
	}
	sharedA, err := chain.SharedA()
	if err != nil {
		return err
	}
	nodes, err := chain.Nodes()
	if err != nil {
		return err
	}
	fmt.Printf("Committee: %d nodes, threshold t=%d.\n", len(nodes), threshold)

	committee := make([]mattersdk.CommitteeNode, 0, len(nodes))
	for _, n := range nodes {
		sc, err := chain.ShareCommitment(secretEpoch, n.Account)
		if err != nil {
			return err
		}
		committee = append(committee, mattersdk.CommitteeNode{Index: n.Index, Endpoint: n.Endpoint, ShareCommitment: sc})
	}

	blockHash, err := chain.FinalizedHead()
	if err != nil {
		return err
	}
	signer, err := mattersdk.SubstrateSigner(kp.PublicKey, func(p []byte) ([]byte, error) {
		return signature.Sign(p, kp.URI)
	})
	if err != nil {
		return err
	}

	fmt.Println("Collecting partial decryptions ...")
	recovered, err := mattersdk.Decrypt(mattersdk.NewHTTPTransport(), signer, mattersdk.DecryptParams{
		SecretID:  secretID,
		Epoch:     secretEpoch,
		BindingID: wire.BindingID,
		Aad:       aad,
		Capsule:   wire.Capsule,
		CT:        wire.CT,
		SharedA:   sharedA,
		BlockHash: blockHash,
		Threshold: threshold,
		Nodes:     committee,
	})
	if err != nil {
		return err
	}

	// Recovered plaintext is compared in process, never printed.
	defer mattersdk.Wipe(recovered)
	fmt.Printf("\nRecovered %d bytes\n", len(recovered))
	if existing == "" {
		if string(recovered) != secret {
			return fmt.Errorf("MISMATCH: recovered plaintext != original")
		}
		fmt.Println("Round trip verified ✔")
	}
	return nil
}
