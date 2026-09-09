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
	"strings"
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

// A per-node transport failure is a per-node *fault*, not the whole decrypt's
// verdict: the node is dropped and the subset re-formed (audit MV-H2, which the
// Rust SDK already implemented and this binding did not). When every node
// refuses, the run ends as "quorum" — naming each node and its reason — rather
// than as an opaque "transport" from whichever node happened to answer first.
func TestDecryptPerNodeTransportFailureExhaustsAsQuorum(t *testing.T) {
	fx := loadCommitteeFixture(t)
	transport := &fakeTransport{fx: fx, t: t, partialErr: errors.New("connection reset")}

	_, err := Decrypt(transport, &recordingSigner{}, fx.params(t))
	if kind := decryptErrorKind(t, err); kind != "quorum" {
		t.Fatalf("kind = %q, want %q", kind, "quorum")
	}
	var de *DecryptError
	if !errors.As(err, &de) {
		t.Fatalf("not a *DecryptError: %v", err)
	}
	if len(de.Faults) == 0 {
		t.Fatal("every dropped node must be accounted for")
	}
	for _, f := range de.Faults {
		if f.Stage != FaultPartialDecrypt {
			t.Errorf("node %d stage = %q, want %q", f.Index, f.Stage, FaultPartialDecrypt)
		}
		if !strings.Contains(f.Detail, "connection reset") {
			t.Errorf("node %d detail = %q, want the node's own reason", f.Index, f.Detail)
		}
	}
	// A caller that only logs err.Error() still gets the reasons.
	if !strings.Contains(err.Error(), "connection reset") {
		t.Errorf("reasons must survive into Error(): %v", err)
	}
}

// The 2026-09-09 testnet shape: one node unreachable at /health while the rest
// answer. The old code reported only a count, so working out *which* node was
// missing meant reading the committee's own logs.
func TestDecryptNamesTheNodeThatFailedHealth(t *testing.T) {
	fx := loadCommitteeFixture(t)
	params := fx.params(t)
	down := params.Nodes[0]
	transport := &fakeTransport{
		fx: fx, t: t,
		healthErrAt: map[string]error{down.Endpoint: errors.New("connection refused")},
	}

	_, err := Decrypt(transport, &recordingSigner{}, params)
	var de *DecryptError
	if !errors.As(err, &de) || de.Kind != "quorum" {
		t.Fatalf("want a quorum DecryptError, got %v", err)
	}
	found := false
	for _, f := range de.Faults {
		if f.Index == down.Index {
			found = true
			if f.Stage != FaultHealth {
				t.Errorf("stage = %q, want %q", f.Stage, FaultHealth)
			}
			if f.Endpoint != down.Endpoint {
				t.Errorf("endpoint = %q, want %q", f.Endpoint, down.Endpoint)
			}
		}
	}
	if !found {
		t.Fatalf("node %d must be named in the faults: %+v", down.Index, de.Faults)
	}
	if !strings.Contains(err.Error(), down.Endpoint) {
		t.Errorf("the endpoint must survive into Error(): %v", err)
	}
}

// Nothing was dropped — the caller supplied too few nodes. The bare count could
// never distinguish that from "nodes were dropped"; empty faults now does.
func TestDecryptTooFewNodesReportsNoFaults(t *testing.T) {
	fx := loadCommitteeFixture(t)
	params := fx.params(t)
	params.Nodes = params.Nodes[:1]

	_, err := Decrypt(&fakeTransport{fx: fx, t: t}, &recordingSigner{}, params)
	var de *DecryptError
	if !errors.As(err, &de) {
		t.Fatalf("not a *DecryptError: %v", err)
	}
	if len(de.Faults) != 0 {
		t.Errorf("no node failed, so no fault should be reported: %+v", de.Faults)
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
