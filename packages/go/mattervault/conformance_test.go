package mattervault

// Cross-language conformance: the deterministic outputs (signing payload, Lagrange
// coefficient) must match the fixtures the Rust core generated. Run after building
// the FFI staticlib:
//
//	cargo build -p matter-vault-ffi --release
//	go test ./...

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

const vectorsRel = "../../../testvectors"

func load(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorsRel, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func secretID16(t *testing.T, dec string) [16]byte {
	t.Helper()
	n, ok := new(big.Int).SetString(dec, 10)
	if !ok {
		t.Fatalf("bad secret_id %q", dec)
	}
	var out [16]byte
	n.FillBytes(out[:])
	return out
}

func toU64(xs []int) []uint64 {
	out := make([]uint64, len(xs))
	for i, x := range xs {
		out[i] = uint64(x)
	}
	return out
}

func TestSigningPayloadConformance(t *testing.T) {
	var doc struct {
		Cases []struct {
			SecretID     string `json:"secret_id"`
			Subset       []int  `json:"subset"`
			BlockHashHex string `json:"block_hash_hex"`
			PayloadHex   string `json:"payload_hex"`
		} `json:"cases"`
	}
	load(t, "signing_payload.json", &doc)

	for _, c := range doc.Cases {
		bh, err := hex.DecodeString(c.BlockHashHex)
		if err != nil || len(bh) != 32 {
			t.Fatalf("block_hash: %v", err)
		}
		var blockHash [32]byte
		copy(blockHash[:], bh)

		got, err := SigningPayload(secretID16(t, c.SecretID), toU64(c.Subset), blockHash)
		if err != nil {
			t.Fatalf("SigningPayload: %v", err)
		}
		if hex.EncodeToString(got) != c.PayloadHex {
			t.Errorf("secret_id=%s: payload mismatch", c.SecretID)
		}
	}
}

func TestOpenSecretConformance(t *testing.T) {
	var doc struct {
		SharedAHex   string      `json:"shared_a_hex"`
		CapsuleHex   string      `json:"capsule_hex"`
		SecretID     json.Number `json:"secret_id"`
		Epoch        uint32      `json:"epoch"`
		BindingIDHex string      `json:"binding_id_hex"`
		AadHex       string      `json:"aad_hex"`
		CTHex        string      `json:"ct_hex"`
		ExpectedHex  string      `json:"expected_plaintext_hex"`
		Partials     []struct {
			PartialHex    string `json:"partial_hex"`
			ProofHex      string `json:"proof_hex"`
			CommitmentHex string `json:"commitment_hex"`
			LambdaHex     string `json:"lambda_hex"`
		} `json:"partials"`
	}
	load(t, "open_secret.json", &doc)

	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("hex: %v", err)
		}
		return b
	}

	partials := make([]PartialInput, len(doc.Partials))
	for i, p := range doc.Partials {
		partials[i] = PartialInput{
			Partial:    mustHex(p.PartialHex),
			Proof:      mustHex(p.ProofHex),
			Commitment: mustHex(p.CommitmentHex),
			Lambda:     mustHex(p.LambdaHex),
		}
	}

	got, err := OpenSecret(
		mustHex(doc.SharedAHex), mustHex(doc.CapsuleHex), secretID16(t, doc.SecretID.String()),
		doc.Epoch, mustHex(doc.BindingIDHex), mustHex(doc.AadHex), mustHex(doc.CTHex), partials,
	)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if hex.EncodeToString(got) != doc.ExpectedHex {
		t.Errorf("recovered plaintext mismatch")
	}
}

func TestLagrangeConformance(t *testing.T) {
	var doc struct {
		Cases []struct {
			Point     uint64 `json:"point"`
			Subset    []int  `json:"subset"`
			LambdaHex string `json:"lambda_hex"`
		} `json:"cases"`
	}
	load(t, "lagrange.json", &doc)

	for _, c := range doc.Cases {
		got, err := LagrangeFor(c.Point, toU64(c.Subset))
		if err != nil {
			t.Fatalf("LagrangeFor: %v", err)
		}
		if hex.EncodeToString(got) != c.LambdaHex {
			t.Errorf("point=%d: lambda mismatch", c.Point)
		}
	}
}
