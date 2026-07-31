// Threshold-decrypt orchestration: form a quorum, sign once, fan out, open.
// The crypto stays in the shared core (via cgo); this is the networking + quorum
// shell, a direct port of packages/typescript/src/committee.ts.
package mattervault

import (
	"fmt"
	"sort"
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

// DecryptError is a typed decrypt failure; branch on Kind, not on message text.
type DecryptError struct {
	Kind string // "quorum" | "epoch" | "transport" | "crypto"
	Msg  string
}

func (e *DecryptError) Error() string { return e.Msg }

// Decrypt recovers a secret by aggregating a threshold quorum of partial decryptions:
// health-probe -> pick Threshold active nodes -> sign once -> query each ->
// verify + aggregate + AEAD-open. The returned plaintext is sensitive.
func Decrypt(transport Transport, signer Signer, p DecryptParams) ([]byte, error) {
	// 1. Health-probe; keep the active nodes.
	var active []CommitteeNode
	for _, node := range p.Nodes {
		h, err := transport.Health(node.Endpoint)
		if err == nil && h.Status == "active" {
			active = append(active, node)
		}
	}
	if len(active) < p.Threshold {
		return nil, &DecryptError{"quorum", fmt.Sprintf("quorum unavailable: need %d healthy nodes, found %d", p.Threshold, len(active))}
	}

	// 2. Lowest-indexed Threshold nodes form the subset.
	sort.Slice(active, func(i, j int) bool { return active[i].Index < active[j].Index })
	chosen := active[:p.Threshold]
	subset := make([]uint64, len(chosen))
	for i, n := range chosen {
		subset[i] = n.Index
	}

	// 3. Query each chosen node, signing per node so the payload binds that
	//    node's index — a signature can't be replayed by it to a peer (MV-C1).
	partials := make([]PartialInput, 0, len(chosen))
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
			return nil, &DecryptError{"transport", err.Error()}
		}
		// A served_epoch that differs means a rotation: fail loudly. (0 = current.)
		if resp.ServedEpoch != 0 && resp.ServedEpoch != p.Epoch {
			return nil, &DecryptError{"epoch", fmt.Sprintf("secret served under epoch %d, state supplied for %d; refetch and retry", resp.ServedEpoch, p.Epoch)}
		}
		partial, err := fromHex(resp.Partial)
		if err != nil {
			return nil, &DecryptError{"transport", "bad partial hex: " + err.Error()}
		}
		proof, err := fromHex(resp.Proof)
		if err != nil {
			return nil, &DecryptError{"transport", "bad proof hex: " + err.Error()}
		}
		partials = append(partials, PartialInput{Partial: partial, Proof: proof, Commitment: node.ShareCommitment, Lambda: lambda})
	}

	// 5. Verify + aggregate + AEAD-open in the shared core.
	pt, err := OpenSecret(p.SharedA, p.Capsule, p.SecretID.Bytes(), p.Epoch, p.BindingID, AadBytes(p.Aad), p.CT, partials)
	if err != nil {
		return nil, &DecryptError{"crypto", err.Error()}
	}
	return pt, nil
}
