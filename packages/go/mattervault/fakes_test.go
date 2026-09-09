package mattervault

// Shared test doubles for the orchestration suite.
//
// The committee fixture (testvectors/open_secret.json) carries real partials
// from a real quorum, so a fake transport that replays them exercises quorum
// selection, request building, the per-node Lagrange computation, fan-out, and
// aggregation without a socket. This is the Go analogue of the TypeScript
// `FixtureCommittee` and the Python `_FakeTransport`.

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// committeeFixture is open_secret.json: one sealed secret plus the partials a
// real committee produced for it.
type committeeFixture struct {
	SharedAHex   string `json:"shared_a_hex"`
	CapsuleHex   string `json:"capsule_hex"`
	SecretID     string `json:"secret_id"`
	Epoch        uint32 `json:"epoch"`
	BindingIDHex string `json:"binding_id_hex"`
	AadHex       string `json:"aad_hex"`
	CTHex        string `json:"ct_hex"`
	ExpectedHex  string `json:"expected_plaintext_hex"`
	Subset       []int  `json:"subset"`
	Partials     []struct {
		PartialHex    string `json:"partial_hex"`
		ProofHex      string `json:"proof_hex"`
		CommitmentHex string `json:"commitment_hex"`
		LambdaHex     string `json:"lambda_hex"`
	} `json:"partials"`
	Meta struct {
		N string `json:"n"`
		T string `json:"t"`
	} `json:"meta"`
}

func loadCommitteeFixture(t *testing.T) *committeeFixture {
	t.Helper()
	var fx committeeFixture
	load(t, "open_secret.json", &fx)
	return &fx
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func (fx *committeeFixture) threshold(t *testing.T) int {
	t.Helper()
	n, err := strconv.Atoi(fx.Meta.T)
	if err != nil {
		t.Fatalf("meta.t %q: %v", fx.Meta.T, err)
	}
	return n
}

// nodes builds the committee roster, one endpoint per subset index. The
// endpoint encodes the index so the fake transport can answer with that node's
// partial — the same trick the TypeScript suite uses.
func (fx *committeeFixture) nodes(t *testing.T) []CommitteeNode {
	t.Helper()
	out := make([]CommitteeNode, len(fx.Subset))
	for i, index := range fx.Subset {
		out[i] = CommitteeNode{
			Index:           uint64(index),
			Endpoint:        fmt.Sprintf("http://node-%d", index),
			ShareCommitment: mustDecodeHex(t, fx.Partials[i].CommitmentHex),
		}
	}
	return out
}

// params builds a DecryptParams that should recover ExpectedHex.
func (fx *committeeFixture) params(t *testing.T) DecryptParams {
	t.Helper()
	secretID, err := ParseSecretID(fx.SecretID)
	if err != nil {
		t.Fatalf("secret_id %q: %v", fx.SecretID, err)
	}
	return DecryptParams{
		SecretID:  secretID,
		Epoch:     fx.Epoch,
		BindingID: mustDecodeHex(t, fx.BindingIDHex),
		Aad:       Aad(mustDecodeHex(t, fx.AadHex)),
		Capsule:   mustDecodeHex(t, fx.CapsuleHex),
		CT:        mustDecodeHex(t, fx.CTHex),
		SharedA:   mustDecodeHex(t, fx.SharedAHex),
		BlockHash: [32]byte{},
		Threshold: fx.threshold(t),
		Nodes:     fx.nodes(t),
	}
}

// fakeTransport replays fixture partials, keyed by the index in the endpoint.
type fakeTransport struct {
	fx *committeeFixture
	t  *testing.T

	// Overrides for the failure-path tests. Zero values mean "behave normally".
	unhealthy   bool
	servedEpoch uint32
	partialErr  error
	badPartial  string

	// Per-endpoint injection, for asserting that a fault names the right node.
	// healthErrAt errors the /health probe; refusePartialAt passes /health and
	// then refuses the real request — the shape that stranded a deployment while
	// every node looked healthy from outside.
	healthErrAt     map[string]error
	refusePartialAt map[string]error

	healthCalls  []string
	decryptCalls []PartialDecryptRequest
}

func (f *fakeTransport) Health(endpoint string) (Health, error) {
	f.healthCalls = append(f.healthCalls, endpoint)
	if err, ok := f.healthErrAt[endpoint]; ok {
		return Health{}, err
	}
	if f.unhealthy {
		return Health{Status: "joining", Epoch: f.fx.Epoch}, nil
	}
	return Health{Status: "active", Epoch: f.fx.Epoch}, nil
}

func (f *fakeTransport) PartialDecrypt(endpoint string, req PartialDecryptRequest) (PartialDecryptResponse, error) {
	f.decryptCalls = append(f.decryptCalls, req)
	if err, ok := f.refusePartialAt[endpoint]; ok {
		return PartialDecryptResponse{}, err
	}
	if f.partialErr != nil {
		return PartialDecryptResponse{}, f.partialErr
	}

	index := f.indexOf(endpoint)
	slot := -1
	for i, s := range f.fx.Subset {
		if s == index {
			slot = i
		}
	}
	if slot < 0 {
		return PartialDecryptResponse{}, fmt.Errorf("no fixture partial for node %d", index)
	}

	epoch := f.fx.Epoch
	if f.servedEpoch != 0 {
		epoch = f.servedEpoch
	}
	partial := "0x" + f.fx.Partials[slot].PartialHex
	if f.badPartial != "" {
		partial = f.badPartial
	}
	return PartialDecryptResponse{
		NodeIndex:   uint64(index),
		Partial:     partial,
		Proof:       "0x" + f.fx.Partials[slot].ProofHex,
		ServedEpoch: epoch,
	}, nil
}

func (f *fakeTransport) indexOf(endpoint string) int {
	f.t.Helper()
	parts := strings.Split(endpoint, "-")
	index, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		f.t.Fatalf("endpoint %q does not encode a node index: %v", endpoint, err)
	}
	return index
}

// recordingSigner returns well-formed auth and remembers what it was asked to
// authorize, so tests can assert on the per-node binding (MV-C1).
type recordingSigner struct {
	err error

	recipientIndexes []uint64
	subsets          [][]uint64
	secretIDs        []SecretID
	blockHashes      [][32]byte
}

func (s *recordingSigner) AuthScheme() string { return "substrate" }

func (s *recordingSigner) Authorize(secretID SecretID, subset []uint64, recipientIndex uint64, blockHash [32]byte) (RequestAuth, error) {
	if s.err != nil {
		return RequestAuth{}, s.err
	}
	s.recipientIndexes = append(s.recipientIndexes, recipientIndex)
	s.subsets = append(s.subsets, append([]uint64(nil), subset...))
	s.secretIDs = append(s.secretIDs, secretID)
	s.blockHashes = append(s.blockHashes, blockHash)
	return RequestAuth{
		Auth:      "substrate",
		Requester: "0x" + strings.Repeat("00", 32),
		Signature: "0x01" + strings.Repeat("00", 64),
	}, nil
}

// decryptErrorKind extracts the typed kind, failing the test if err is not a
// *DecryptError — branching on message text is exactly what the type prevents.
func decryptErrorKind(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	de, ok := err.(*DecryptError)
	if !ok {
		t.Fatalf("expected *DecryptError, got %T: %v", err, err)
	}
	return de.Kind
}

// fakeAgentKeys answers BudgetsApi_agent_key without a chain, keeping the three
// outcomes distinct: a grant, no grant, and a lookup that failed.
type fakeAgentKeys struct {
	delegation *Delegation
	err        error
	calls      [][]byte
}

func (f *fakeAgentKeys) AgentKey(key []byte) (*Delegation, error) {
	f.calls = append(f.calls, key)
	if f.err != nil {
		return nil, f.err
	}
	return f.delegation, nil
}
