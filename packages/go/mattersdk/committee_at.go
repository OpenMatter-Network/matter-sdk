package mattersdk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

// EpochCommittee is the committee state a decrypt needs for one epoch: the
// DecryptParams fields that come from the chain.
type EpochCommittee struct {
	Epoch     uint32
	Threshold int
	SharedA   []byte
	// Nodes are the epoch's reachable members, sorted by DKG index.
	Nodes []CommitteeNode
	// BlockHash is the finalized head the request is anchored to.
	BlockHash [32]byte
}

// committeeMember is one seat of an epoch's committee snapshot.
type committeeMember struct {
	Account [32]byte
	Index   uint64
}

// CommitteeAt reads the committee a secret sealed at `epoch` must be decrypted
// with: that epoch's shared_a, threshold and seated members, joined with the
// registry's endpoints and each member's share commitment for the epoch. Use it
// with SecretEpoch; SharedA and Nodes describe only the current epoch.
func (c *ChainClient) CommitteeAt(epoch uint32) (EpochCommittee, error) {
	epochArg := u32le(epoch)

	sharedA, err := c.dkgSharedAAt(epochArg)
	if err != nil {
		return EpochCommittee{}, err
	}
	threshold, err := c.ThresholdAtEpoch(epoch)
	if err != nil {
		return EpochCommittee{}, fmt.Errorf("threshold at epoch %d: %w", epoch, err)
	}
	members, err := c.committeeMembersAt(epochArg)
	if err != nil {
		return EpochCommittee{}, err
	}
	registry, err := c.Nodes()
	if err != nil {
		return EpochCommittee{}, fmt.Errorf("committee registry: %w", err)
	}
	endpoints := make(map[[32]byte]string, len(registry))
	for _, node := range registry {
		var account [32]byte
		copy(account[:], node.Account)
		endpoints[account] = node.rawEndpoint
	}
	commitments := make(map[[32]byte][]byte, len(members))
	for _, member := range members {
		raw, err := c.stateCall("KgcApi_share_commitment", append(u32le(epoch), member.Account[:]...))
		if err != nil {
			return EpochCommittee{}, fmt.Errorf("share commitment at epoch %d: %w", epoch, err)
		}
		commitment, err := decodeOptionBytes(raw)
		if err != nil {
			return EpochCommittee{}, fmt.Errorf("share commitment at epoch %d: %w", epoch, err)
		}
		if commitment != nil {
			commitments[member.Account] = commitment
		}
	}
	nodes, err := assembleCommittee(members, endpoints, commitments, threshold, epoch)
	if err != nil {
		return EpochCommittee{}, err
	}
	head, err := c.FinalizedHead()
	if err != nil {
		return EpochCommittee{}, fmt.Errorf("finalized head: %w", err)
	}
	return EpochCommittee{Epoch: epoch, Threshold: threshold, SharedA: sharedA, Nodes: nodes, BlockHash: head}, nil
}

// dkgSharedAAt reads shared_a from KgcApi_dkg_output_at_epoch, an
// Option<(joint_pk, shared_a)>.
func (c *ChainClient) dkgSharedAAt(epochArg []byte) ([]byte, error) {
	raw, err := c.stateCall("KgcApi_dkg_output_at_epoch", epochArg)
	if err != nil {
		return nil, fmt.Errorf("DKG output: %w", err)
	}
	dec := scale.NewDecoder(bytes.NewReader(raw))
	flag, err := dec.ReadOneByte()
	if err != nil {
		return nil, fmt.Errorf("DKG output: %w", err)
	}
	if flag == 0 {
		return nil, fmt.Errorf("no DKG output at epoch %d", binary.LittleEndian.Uint32(epochArg))
	}
	var output struct {
		JointPk types.Bytes
		SharedA types.Bytes
	}
	if err := dec.Decode(&output); err != nil {
		return nil, fmt.Errorf("DKG output: %w", err)
	}
	return []byte(output.SharedA), nil
}

// committeeMembersAt reads KgcApi_committee_at_epoch, a Vec<(AccountId, u64)>.
func (c *ChainClient) committeeMembersAt(epochArg []byte) ([]committeeMember, error) {
	raw, err := c.stateCall("KgcApi_committee_at_epoch", epochArg)
	if err != nil {
		return nil, fmt.Errorf("committee: %w", err)
	}
	var rows []struct {
		Account  types.AccountID
		DkgIndex types.U64
	}
	if err := scale.NewDecoder(bytes.NewReader(raw)).Decode(&rows); err != nil {
		return nil, fmt.Errorf("committee: %w", err)
	}
	members := make([]committeeMember, len(rows))
	for i, row := range rows {
		members[i] = committeeMember{Account: row.Account, Index: uint64(row.DkgIndex)}
	}
	return members, nil
}

// assembleCommittee joins an epoch's committee with registry endpoints and share
// commitments, sorted by DKG index. Members without an absolute http(s) endpoint
// are dropped (the quorum tolerates n - t missing); a kept member without its
// commitment is an error, because its partial would be unverifiable.
func assembleCommittee(
	members []committeeMember,
	endpoints map[[32]byte]string,
	commitments map[[32]byte][]byte,
	threshold int,
	epoch uint32,
) ([]CommitteeNode, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("no committee seated at epoch %d", epoch)
	}
	nodes := make([]CommitteeNode, 0, len(members))
	for _, member := range members {
		endpoint, ok := absoluteHTTPEndpoint(endpoints[member.Account])
		if !ok {
			continue
		}
		commitment, ok := commitments[member.Account]
		if !ok {
			return nil, fmt.Errorf("share commitment missing for reachable node %d at epoch %d", member.Index, epoch)
		}
		nodes = append(nodes, CommitteeNode{Index: member.Index, Endpoint: endpoint, ShareCommitment: commitment})
	}
	if len(nodes) < threshold {
		return nil, fmt.Errorf("only %d of epoch %d's committee is reachable; need %d", len(nodes), epoch, threshold)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Index < nodes[j].Index })
	return nodes, nil
}

// absoluteHTTPEndpoint accepts only an absolute http(s) URL, trimming trailing
// slashes.
func absoluteHTTPEndpoint(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
		return "", false
	}
	return strings.TrimRight(s, "/"), true
}
