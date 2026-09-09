// Threshold-decrypt orchestration: form a quorum, sign once, fan out, open.
// The crypto stays in the shared core (via cgo); this is the networking + quorum
// shell, a direct port of packages/typescript/src/committee.ts.
package mattervault

import (
	"fmt"
	"sort"
	"strings"
)

// CommitteeNode is one committee node with the chain-derived data a decryptor needs.
type CommitteeNode struct {
	Index           uint64
	Endpoint        string
	ShareCommitment []byte
}

// DecryptParams is everything needed to recover one secret (chain-derived fields supplied by you).
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
)

// NodeFault is why one committee node did not contribute to a quorum.
//
// It carries the endpoint because "which nodes could this caller not reach" is
// the first question asked, and an index does not answer it when the caller and
// the operator are looking at different machines. It never carries request
// material — no signature, no auth fields, no partial.
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
	// Faults, for Kind == "quorum", says which nodes were dropped and why.
	// Without it this error reports only a count, and a count cannot distinguish
	// "the committee is down" from "this caller cannot reach two of them" from
	// "the partials do not verify" — three problems with three different fixes.
	// Empty means no node failed: the caller supplied too few to begin with.
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
// health-probe -> pick Threshold active nodes -> sign once -> query each ->
// verify + aggregate + AEAD-open. The returned plaintext is sensitive.
func Decrypt(transport Transport, signer Signer, p DecryptParams) ([]byte, error) {
	// 1. Health-probe; keep the active nodes.
	//
	//    Every node that drops out records why. This used to be
	//    `if err == nil && h.Status == "active"`, which discarded both the
	//    transport error and the not-active case, leaving only a count — and a
	//    count cannot tell an operator whether the committee is down or this
	//    caller simply cannot reach part of it.
	var active []CommitteeNode
	var faults []NodeFault
	for _, node := range p.Nodes {
		h, err := transport.Health(node.Endpoint)
		switch {
		case err != nil:
			faults = append(faults, NodeFault{node.Index, node.Endpoint, FaultHealth, err.Error()})
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

	// 2. Assemble a quorum. A node that fails or serves a *different* epoch is a
	//    per-node fault: drop it and re-form the subset from the remaining nodes,
	//    rather than letting one node deny the whole decrypt (audit MV-H2). A
	//    *genuine* rotation still surfaces as Threshold nodes agreeing on the
	//    same new served_epoch. Each fault removes a node, so the loop terminates.
	sort.Slice(active, func(i, j int) bool { return active[i].Index < active[j].Index })
	available := active
	rotatedVotes := map[uint32]int{}

	for len(available) >= p.Threshold {
		chosen := available[:p.Threshold]
		subset := make([]uint64, len(chosen))
		for i, n := range chosen {
			subset[i] = n.Index
		}

		// 3. Query each chosen node, signing per node so the payload binds that
		//    node's index — a signature can't be replayed by it to a peer (MV-C1).
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
				// Treat an unreachable/erroring node as a per-node fault — but
				// keep the reason: a node that passed /health and then refused
				// the real request is a different problem from one that was
				// never reachable.
				faults = append(faults, NodeFault{node.Index, node.Endpoint, FaultPartialDecrypt, err.Error()})
				faulty, hasFaulty = node.Index, true
				break
			}

			// A served_epoch that differs means this node is serving a different
			// key than the caller's state is for. If Threshold nodes agree on the
			// same new epoch it's a real rotation (fail loudly so the caller
			// refetches); otherwise it's one misbehaving node — drop it.
			// (0 = older node serving current.)
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
			partials = append(partials, PartialInput{Partial: partial, Proof: proof, Commitment: node.ShareCommitment, Lambda: lambda})
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

// openAndWrap runs step 5 — verify + aggregate + AEAD-open in the shared core.
func openAndWrap(p DecryptParams, partials []PartialInput) ([]byte, error) {
	pt, err := OpenSecret(p.SharedA, p.Capsule, p.SecretID.Bytes(), p.Epoch, p.BindingID, AadBytes(p.Aad), p.CT, partials)
	if err != nil {
		return nil, &DecryptError{Kind: "crypto", Msg: err.Error()}
	}
	return pt, nil
}
