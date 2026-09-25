package mattersdk

// Decrypt orchestration tests; doubles live in fakes_test.go.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
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
	// Each request is signed for its addressee, so a signature harvested by one
	// node cannot be replayed to a peer.
	fx := loadCommitteeFixture(t)
	signer := &recordingSigner{}

	if _, err := Decrypt(&fakeTransport{fx: fx, t: t}, signer, fx.params(t)); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(signer.recipientIndexes) != fx.threshold(t) {
		t.Fatalf("signed %d times, want %d (one per node in the quorum)",
			len(signer.recipientIndexes), fx.threshold(t))
	}

	seen := map[uint64]bool{}
	for _, index := range signer.recipientIndexes {
		if seen[index] {
			t.Errorf("recipient index %d was signed for twice; a signature is replayable", index)
		}
		seen[index] = true
	}
	for _, node := range fx.Subset[:fx.threshold(t)] {
		if !seen[uint64(node)] {
			t.Errorf("no request was signed for node %d", node)
		}
	}

	// The subset is part of the signed transcript: identical for every request.
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

func TestDecryptSignsAnIndexOrderedSubset(t *testing.T) {
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
	// Another epoch means the committee rotated; never aggregate across epochs.
	fx := loadCommitteeFixture(t)
	transport := &fakeTransport{fx: fx, t: t, servedEpoch: fx.Epoch + 7}

	_, err := Decrypt(transport, &recordingSigner{}, fx.params(t))
	if kind := decryptErrorKind(t, err); kind != "epoch" {
		t.Errorf("kind = %q, want %q", kind, "epoch")
	}
}

// A node's transport failure drops that node and re-forms the subset. When every
// node refuses, the error is "quorum" with each node's reason, not "transport".
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
	if !strings.Contains(err.Error(), "connection reset") {
		t.Errorf("reasons must survive into Error(): %v", err)
	}
}

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

// Empty Faults distinguishes "too few nodes supplied" from "nodes were dropped".
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

func TestChooseQuorumIsTDistinctNodesInIndexOrder(t *testing.T) {
	nodes := make([]CommitteeNode, 7)
	for i := range nodes {
		nodes[i] = CommitteeNode{Index: uint64(i + 1)}
	}
	r := rand.New(rand.NewPCG(7, 7))
	for range 100 {
		chosen := chooseQuorum(nodes, 4, r)
		if len(chosen) != 4 {
			t.Fatalf("chose %d nodes, want 4", len(chosen))
		}
		for i := 1; i < len(chosen); i++ {
			if chosen[i-1].Index >= chosen[i].Index {
				t.Fatalf("not sorted and distinct: %v", chosen)
			}
		}
	}
}

// A fixed lowest-index quorum puts the same node in every decrypt, turning one
// bad node into a standing tap or a standing denial.
func TestChooseQuorumIsNotTheFixedLowestIndices(t *testing.T) {
	nodes := make([]CommitteeNode, 5)
	for i := range nodes {
		nodes[i] = CommitteeNode{Index: uint64(i + 1)}
	}
	r := rand.New(rand.NewPCG(42, 42))
	hits := map[uint64]int{}
	distinct := map[string]bool{}
	for range 200 {
		chosen := chooseQuorum(nodes, 3, r)
		key := fmt.Sprint(chosen)
		distinct[key] = true
		for _, n := range chosen {
			hits[n.Index]++
		}
	}
	if len(distinct) < 2 {
		t.Fatalf("every quorum was the same: %v", distinct)
	}
	for index := uint64(1); index <= 5; index++ {
		// 3/5 of quorums on average; 60 of 200 is a loose floor.
		if hits[index] < 60 {
			t.Fatalf("node %d chosen only %d/200 times", index, hits[index])
		}
	}
}

func TestDecryptDropsANodeSpeakingAnotherProtocolVersion(t *testing.T) {
	fx := loadCommitteeFixture(t)
	params := fx.params(t)
	bad := params.Nodes[0].Endpoint
	transport := &fakeTransport{fx: fx, t: t, versionAt: map[string]uint16{bad: CryptoProtocolVersion() + 1}}

	_, err := Decrypt(transport, &recordingSigner{}, params)
	var de *DecryptError
	if !errors.As(err, &de) || de.Kind != "quorum" {
		t.Fatalf("want a quorum DecryptError, got %v", err)
	}
	if len(de.Faults) != 1 || de.Faults[0].Endpoint != bad || de.Faults[0].Stage != FaultProtocolVersion {
		t.Fatalf("want one protocol-version fault at %s, got %+v", bad, de.Faults)
	}
	if len(transport.decryptCalls) != 0 {
		t.Fatalf("a node on another protocol version must not be asked for a partial")
	}
}

func TestDecryptAcceptsANodeThatDoesNotReportAVersion(t *testing.T) {
	fx := loadCommitteeFixture(t)
	// fakeTransport reports version 0 unless told otherwise: an older node.
	got, err := Decrypt(&fakeTransport{fx: fx, t: t}, &recordingSigner{}, fx.params(t))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if want := mustDecodeHex(t, fx.ExpectedHex); string(got) != string(want) {
		t.Fatalf("recovered %x, want %x", got, want)
	}
}
