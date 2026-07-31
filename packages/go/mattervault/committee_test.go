package mattervault

// Orchestration tests for Decrypt — the Go analogue of the TypeScript
// `decrypt.test.ts` and Python `test_orchestration.py` suites, which Go had no
// equivalent of. These run against a fixture-replaying fake, so they exercise
// quorum selection, request building, per-node Lagrange, fan-out, epoch
// detection, and aggregation without a socket.
//
// Requires the FFI staticlib:
//
//	cargo build -p matter-vault-ffi --release
//	go test ./...

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestDecryptRecoversSecretFromQuorum(t *testing.T) {
	fx := loadCommitteeFixture(t)
	transport := &fakeTransport{fx: fx, t: t}

	got, err := Decrypt(transport, &recordingSigner{}, fx.params(t))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if hex.EncodeToString(got) != fx.ExpectedHex {
		t.Error("recovered plaintext does not match the fixture")
	}
}

func TestDecryptSignsPerNodeWithThatNodesRecipientIndex(t *testing.T) {
	// MV-C1. Every request must be signed for the node it is addressed to, so a
	// signature harvested by one committee member cannot be replayed to a peer.
	// This property had no coverage in Go at all.
	fx := loadCommitteeFixture(t)
	signer := &recordingSigner{}

	if _, err := Decrypt(&fakeTransport{fx: fx, t: t}, signer, fx.params(t)); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(signer.recipientIndexes) != fx.threshold(t) {
		t.Fatalf("signed %d times, want %d (one per node in the quorum)",
			len(signer.recipientIndexes), fx.threshold(t))
	}

	// Each signature is bound to a distinct recipient...
	seen := map[uint64]bool{}
	for _, index := range signer.recipientIndexes {
		if seen[index] {
			t.Errorf("recipient index %d was signed for twice; a signature is replayable", index)
		}
		seen[index] = true
	}
	// ...and that recipient is a node actually in the subset.
	for _, node := range fx.Subset[:fx.threshold(t)] {
		if !seen[uint64(node)] {
			t.Errorf("no request was signed for node %d", node)
		}
	}

	// The subset handed to the signer must be the same for every request —
	// it is part of the signed transcript.
	for i, subset := range signer.subsets {
		if len(subset) != fx.threshold(t) {
			t.Errorf("request %d: subset has %d entries, want %d", i, len(subset), fx.threshold(t))
		}
		for j := range subset {
			if subset[j] != signer.subsets[0][j] {
				t.Errorf("request %d: subset differs from request 0", i)
			}
		}
	}
}

func TestDecryptPicksTheLowestIndexedSubset(t *testing.T) {
	fx := loadCommitteeFixture(t)
	params := fx.params(t)
	// Present the roster in reverse; selection must still be by index.
	for i, j := 0, len(params.Nodes)-1; i < j; i, j = i+1, j-1 {
		params.Nodes[i], params.Nodes[j] = params.Nodes[j], params.Nodes[i]
	}
	signer := &recordingSigner{}

	if _, err := Decrypt(&fakeTransport{fx: fx, t: t}, signer, params); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	subset := signer.subsets[0]
	for i := 1; i < len(subset); i++ {
		if subset[i-1] >= subset[i] {
			t.Fatalf("subset is not ascending: %v", subset)
		}
	}
}

func TestDecryptQuorumUnavailable(t *testing.T) {
	fx := loadCommitteeFixture(t)

	t.Run("too few nodes supplied", func(t *testing.T) {
		params := fx.params(t)
		params.Nodes = params.Nodes[:1]
		_, err := Decrypt(&fakeTransport{fx: fx, t: t}, &recordingSigner{}, params)
		if kind := decryptErrorKind(t, err); kind != "quorum" {
			t.Errorf("kind = %q, want %q", kind, "quorum")
		}
	})

	t.Run("nodes reachable but not active", func(t *testing.T) {
		_, err := Decrypt(&fakeTransport{fx: fx, t: t, unhealthy: true}, &recordingSigner{}, fx.params(t))
		if kind := decryptErrorKind(t, err); kind != "quorum" {
			t.Errorf("kind = %q, want %q", kind, "quorum")
		}
	})
}

func TestDecryptRejectsEpochRotation(t *testing.T) {
	// A node serving a different epoch means the committee rotated; the caller
	// must refetch state rather than aggregate across epochs.
	fx := loadCommitteeFixture(t)
	transport := &fakeTransport{fx: fx, t: t, servedEpoch: fx.Epoch + 7}

	_, err := Decrypt(transport, &recordingSigner{}, fx.params(t))
	if kind := decryptErrorKind(t, err); kind != "epoch" {
		t.Errorf("kind = %q, want %q", kind, "epoch")
	}
}

func TestDecryptTransportFailureIsTyped(t *testing.T) {
	fx := loadCommitteeFixture(t)
	transport := &fakeTransport{fx: fx, t: t, partialErr: errors.New("connection reset")}

	_, err := Decrypt(transport, &recordingSigner{}, fx.params(t))
	if kind := decryptErrorKind(t, err); kind != "transport" {
		t.Errorf("kind = %q, want %q", kind, "transport")
	}
}

func TestDecryptMalformedPartialIsTyped(t *testing.T) {
	fx := loadCommitteeFixture(t)
	transport := &fakeTransport{fx: fx, t: t, badPartial: "0xnothex"}

	_, err := Decrypt(transport, &recordingSigner{}, fx.params(t))
	if kind := decryptErrorKind(t, err); kind != "transport" {
		t.Errorf("kind = %q, want %q", kind, "transport")
	}
}

func TestDecryptPropagatesSignerFailure(t *testing.T) {
	fx := loadCommitteeFixture(t)
	sentinel := errors.New("hsm unavailable")

	_, err := Decrypt(&fakeTransport{fx: fx, t: t}, &recordingSigner{err: sentinel}, fx.params(t))
	if err == nil {
		t.Fatal("expected the signer failure to propagate")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("signer error was not propagated: %v", err)
	}
}

func TestDecryptRequestCarriesCanonicalFields(t *testing.T) {
	fx := loadCommitteeFixture(t)
	transport := &fakeTransport{fx: fx, t: t}

	if _, err := Decrypt(transport, &recordingSigner{}, fx.params(t)); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	for i, req := range transport.decryptCalls {
		if req.Auth != "substrate" {
			t.Errorf("request %d: auth = %q", i, req.Auth)
		}
		// secret_id crosses the wire as 16 big-endian bytes, hex-encoded.
		if want := 2 + 32; len(req.SecretID) != want {
			t.Errorf("request %d: secret_id is %d chars, want %d", i, len(req.SecretID), want)
		}
		if want := 2 + 64; len(req.BlockHash) != want {
			t.Errorf("request %d: block_hash is %d chars, want %d", i, len(req.BlockHash), want)
		}
		if len(req.Subset) != fx.threshold(t) {
			t.Errorf("request %d: subset has %d entries", i, len(req.Subset))
		}
		if req.LagrangeCoeff == "" || req.LagrangeCoeff == "0x" {
			t.Errorf("request %d: missing lagrange coefficient", i)
		}
	}
}
