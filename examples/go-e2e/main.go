// MatterVault end-to-end test against a LIVE chain + committee (Go) — the Go
// analogue of examples/e2e/run.ts: connect -> fetch context -> encrypt ->
// secrets.storeSecret (pays a fee) -> read back -> threshold-decrypt -> assert.
//
// Env:
//
//	MATTER_RPC_URL      ws(s) endpoint            (default: testnet)
//	MATTER_SIGNER_SEED  sr25519 SURI / 0x-seed    (falls back to TEST_KEY)
//	MATTER_SECRET       plaintext to seal         (default: a sample env line)
//	MATTER_SECRET_ID    decrypt an existing secret instead of storing a new one
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	mv "github.com/openmatter-network/matter-sdk/packages/go/mattervault"
)

const (
	defaultRPC    = "wss://node2.testnet.openmatter.network"
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

func run() error {
	rpcURL := getenv("MATTER_RPC_URL", defaultRPC)
	seed := os.Getenv("MATTER_SIGNER_SEED")
	if seed == "" {
		seed = os.Getenv("TEST_KEY")
	}
	if seed == "" {
		return fmt.Errorf("set MATTER_SIGNER_SEED or TEST_KEY (sr25519 SURI / 0x-seed)")
	}
	secret := getenv("MATTER_SECRET", defaultSecret)
	existing := os.Getenv("MATTER_SECRET_ID")
	aad := mv.AadEnvV1

	kp, err := signature.KeyringPairFromSecret(seed, ss58Format)
	if err != nil {
		return err
	}
	fmt.Printf("Account: %s\n", kp.Address)

	chain, err := mv.NewChainClient(rpcURL)
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

	var secretID uint64
	if existing != "" {
		secretID, err = strconv.ParseUint(existing, 10, 64)
		if err != nil {
			return err
		}
		fmt.Printf("Using existing secret %d.\n", secretID)
	} else {
		env, err := mv.Encrypt(jointPk, epoch, []byte(secret), mv.AadBytes(aad), nil)
		if err != nil {
			return err
		}
		fmt.Printf("Sealed %dB -> capsule %dB, proof %dB, ct %dB\n", len(secret), len(env.Capsule), len(env.Proof), len(env.CT))
		fmt.Println("Submitting secrets.storeSecret ...")
		secretID, err = chain.StoreSecret(kp, *env, epoch, aad)
		if err != nil {
			return err
		}
		fmt.Printf("Stored on chain: secret_id=%d.\n", secretID)
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

	committee := make([]mv.CommitteeNode, 0, len(nodes))
	for _, n := range nodes {
		sc, err := chain.ShareCommitment(secretEpoch, n.Account)
		if err != nil {
			return err
		}
		committee = append(committee, mv.CommitteeNode{Index: n.Index, Endpoint: n.Endpoint, ShareCommitment: sc})
	}

	blockHash, err := chain.FinalizedHead()
	if err != nil {
		return err
	}
	signer, err := mv.SubstrateSigner(kp.PublicKey, func(p []byte) ([]byte, error) {
		return signature.Sign(p, kp.URI)
	})
	if err != nil {
		return err
	}

	fmt.Println("Collecting partial decryptions ...")
	recovered, err := mv.Decrypt(mv.NewHTTPTransport(), signer, mv.DecryptParams{
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

	text := string(recovered)
	fmt.Printf("\nRecovered: %s\n", text)
	if existing == "" {
		if text != secret {
			return fmt.Errorf("MISMATCH: recovered plaintext != original")
		}
		fmt.Println("Round trip verified ✔")
	}
	return nil
}
