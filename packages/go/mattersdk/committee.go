package mattersdk

import (
	cryptorand "crypto/rand"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
)

// CommitteeNode is one committee node with the chain-derived data a decryptor needs.
type CommitteeNode struct {
	Index           uint64
	Endpoint        string
	ShareCommitment []byte
}

// DecryptParams is everything needed to recover one secret; the caller supplies
// the chain-derived fields.
type DecryptParams struct {
	SecretID  SecretID
	Epoch     uint32
	BindingID []byte
	Aad       Aad
	Capsule   []byte
	CT        []byte
	SharedA   []byte
	BlockHash [32]byte
	Threshold int
	Nodes     []CommitteeNode
}

// FaultStage says where in the decrypt round trip a node stopped being usable.
type FaultStage string

const (
	// FaultHealth: the /health probe did not answer.
	FaultHealth FaultStage = "health"
	// FaultInactive: /health answered, but the node did not report itself active.
	FaultInactive FaultStage = "inactive"
	// FaultPartialDecrypt: /partial-decrypt did not answer.
	FaultPartialDecrypt FaultStage = "partial-decrypt"
	// FaultEpochMismatch: the node served a different epoch than the caller's
	// state is for, and too few nodes agreed with it to call it a rotation.
	FaultEpochMismatch FaultStage = "epoch-mismatch"
	// FaultProtocolVersion: /health reported a crypto protocol version this
	// SDK does not speak.
	FaultProtocolVersion FaultStage = "protocol-version"
)

// speaksOurProtocol reports whether a node's /health version is compatible. 0
// (field absent) is accepted: each proof's version tag still binds the transcript.
func speaksOurProtocol(reported uint16) bool {
	return reported == 0 || reported == CryptoProtocolVersion()
}

// chooseQuorum picks threshold of available uniformly at random, returned in
// index order (the signed subset's order). Random so no fixed node sees, or can
// deny, every decrypt.
func chooseQuorum(available []CommitteeNode, threshold int, r *rand.Rand) []CommitteeNode {
	shuffled := append([]CommitteeNode(nil), available...)
	r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	chosen := shuffled[:threshold]
	sort.Slice(chosen, func(i, j int) bool { return chosen[i].Index < chosen[j].Index })
	return chosen
}

// NodeFault is why one committee node did not contribute to a quorum. It never
// carries request material: no signature, auth fields, or partial.
type NodeFault struct {
	Index    uint64
	Endpoint string
	Stage    FaultStage
	// Detail is the underlying reason, already rendered.
	Detail string
}

// DecryptError is a typed decrypt failure; branch on Kind, not on message text.
type DecryptError struct {
	Kind string // "quorum" | "epoch" | "transport" | "crypto"
	Msg  string
	// Faults, for Kind == "quorum", lists which nodes were dropped and why.
	// Empty means the caller supplied too few nodes.
	Faults []NodeFault
}

func (e *DecryptError) Error() string { return e.Msg }

// summarizeFaults renders faults into the message, so a caller that only logs
// err.Error() still gets the reasons.
func summarizeFaults(faults []NodeFault) string {
	if len(faults) == 0 {
		return ""
	}
	parts := make([]string, 0, len(faults))
	for _, f := range faults {
		parts = append(parts, fmt.Sprintf("node %d (%s) %s: %s", f.Index, f.Endpoint, f.Stage, f.Detail))
	}
	return " — " + strings.Join(parts, "; ")
}

// quorumUnavailable builds the error both exhaustion paths return.
func quorumUnavailable(needed, found int, faults []NodeFault) *DecryptError {
	return &DecryptError{
		Kind:   "quorum",
		Msg:    fmt.Sprintf("quorum unavailable: need %d healthy nodes, found %d%s", needed, found, summarizeFaults(faults)),
		Faults: faults,
	}
}

// Decrypt recovers a secret by aggregating a threshold quorum of partial decryptions:
// health-probe -> pick Threshold active nodes at random -> sign once -> query each ->
// verify + aggregate + AEAD-open. The returned plaintext is sensitive.
func Decrypt(transport Transport, signer Signer, p DecryptParams) ([]byte, error) {
	// 1. Health-probe; keep the active nodes and record why others dropped out.
	var active []CommitteeNode
	var faults []NodeFault
	for _, node := range p.Nodes {
		h, err := transport.Health(node.Endpoint)
		switch {
		case err != nil:
			faults = append(faults, NodeFault{node.Index, node.Endpoint, FaultHealth, err.Error()})
		case !speaksOurProtocol(h.CryptoProtocolVersion):
			faults = append(faults, NodeFault{node.Index, node.Endpoint, FaultProtocolVersion,
				fmt.Sprintf("speaks crypto protocol v%d, this SDK speaks v%d", h.CryptoProtocolVersion, CryptoProtocolVersion())})
		case h.Status != "active":
			faults = append(faults, NodeFault{node.Index, node.Endpoint, FaultInactive,
				fmt.Sprintf("status %q, epoch %d, crypto protocol v%d", h.Status, h.Epoch, h.CryptoProtocolVersion)})
		default:
			active = append(active, node)
		}
	}
	if len(active) < p.Threshold {
		return nil, quorumUnavailable(p.Threshold, len(active), faults)
	}

	// 2. Form a quorum. A node that fails or serves a different epoch is dropped
	//    and the subset re-formed, so one node cannot deny the decrypt. A genuine
	//    rotation shows as Threshold nodes agreeing on a new served_epoch. Each
	//    fault removes a node, so the loop terminates.
	available := active
	rotatedVotes := map[uint32]int{}
	r := rand.New(rand.NewChaCha8(randomSeed()))

	for len(available) >= p.Threshold {
		chosen := chooseQuorum(available, p.Threshold, r)
		subset := make([]uint64, len(chosen))
		for i, n := range chosen {
			subset[i] = n.Index
		}

		// 3. Sign per node: the payload binds the node's index, so a signature
		//    cannot be replayed to a peer.
		partials := make([]PartialInput, 0, len(chosen))
		faulty := uint64(0)
		hasFaulty := false

		for _, node := range chosen {
			lambda, err := LagrangeFor(node.Index, subset)
			if err != nil {
				return nil, err
			}
			auth, err := signer.Authorize(p.SecretID, subset, node.Index, p.BlockHash)
			if err != nil {
				return nil, err
			}
			req := PartialDecryptRequest{
				SecretID:      p.SecretID.Hex(),
				Subset:        subset,
				LagrangeCoeff: toHex(lambda),
				Requester:     auth.Requester,
				BlockHash:     toHex(p.BlockHash[:]),
				Signature:     auth.Signature,
				Auth:          auth.Auth,
			}
			resp, err := transport.PartialDecrypt(node.Endpoint, req)
			if err != nil {
				// A per-node fault; the reason distinguishes a refusal after
				// /health from an unreachable node.
				faults = append(faults, NodeFault{node.Index, node.Endpoint, FaultPartialDecrypt, err.Error()})
				faulty, hasFaulty = node.Index, true
				break
			}

			// A different served_epoch from Threshold nodes is a real rotation
			// (fail so the caller refetches); from fewer, a misbehaving node to
			// drop. 0 means an older node serving the current epoch.
			if resp.ServedEpoch != 0 && resp.ServedEpoch != p.Epoch {
				rotatedVotes[resp.ServedEpoch]++
				if rotatedVotes[resp.ServedEpoch] >= p.Threshold {
					return nil, &DecryptError{Kind: "epoch", Msg: fmt.Sprintf(
						"secret served under epoch %d, state supplied for %d; refetch and retry", resp.ServedEpoch, p.Epoch)}
				}
				faults = append(faults, NodeFault{node.Index, node.Endpoint, FaultEpochMismatch,
					fmt.Sprintf("served epoch %d, state supplied for %d", resp.ServedEpoch, p.Epoch)})
				faulty, hasFaulty = node.Index, true
				break
			}

			partial, err := fromHex(resp.Partial)
			if err != nil {
				return nil, &DecryptError{Kind: "transport", Msg: "bad partial hex: " + err.Error()}
			}
			proof, err := fromHex(resp.Proof)
			if err != nil {
				return nil, &DecryptError{Kind: "transport", Msg: "bad proof hex: " + err.Error()}
			}
			partials = append(partials, PartialInput{Point: node.Index, Partial: partial, Proof: proof, Commitment: node.ShareCommitment})
		}

		if hasFaulty {
			remaining := make([]CommitteeNode, 0, len(available)-1)
			for _, n := range available {
				if n.Index != faulty {
					remaining = append(remaining, n)
				}
			}
			available = remaining
			continue
		}
		return openAndWrap(p, partials)
	}

	// Ran out of good nodes. If divergent served_epochs dominated, surface the
	// most common one as a rotation (refetch + retry); otherwise no quorum.
	bestEpoch, bestVotes := uint32(0), 0
	for epoch, votes := range rotatedVotes {
		if votes > bestVotes || (votes == bestVotes && epoch < bestEpoch) {
			bestEpoch, bestVotes = epoch, votes
		}
	}
	if bestVotes > 0 {
		return nil, &DecryptError{Kind: "epoch", Msg: fmt.Sprintf(
			"secret served under epoch %d, state supplied for %d; refetch and retry", bestEpoch, p.Epoch)}
	}
	return nil, quorumUnavailable(p.Threshold, len(available), faults)
}

// openAndWrap verifies, aggregates, and AEAD-opens in the shared core.
func openAndWrap(p DecryptParams, partials []PartialInput) ([]byte, error) {
	pt, err := OpenSecret(p.SharedA, p.Capsule, p.SecretID.Bytes(), p.Epoch, p.BindingID, AadBytes(p.Aad), p.CT, partials)
	if err != nil {
		return nil, &DecryptError{Kind: "crypto", Msg: err.Error()}
	}
	return pt, nil
}

// randomSeed draws a ChaCha8 seed from the OS, so quorum choice cannot be
// predicted from outside the process.
func randomSeed() [32]byte {
	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		// crypto/rand does not fail on a supported platform; if it does,
		// nothing else in this process is safe either.
		panic("matter-sdk: crypto/rand: " + err.Error())
	}
	return seed
}
