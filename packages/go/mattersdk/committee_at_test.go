package mattersdk

import (
	"bytes"
	"testing"
)

func memberAccount(n byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = n
	}
	return a
}

func testCommittee() []committeeMember {
	return []committeeMember{
		{Account: memberAccount(3), Index: 30},
		{Account: memberAccount(1), Index: 10},
		{Account: memberAccount(2), Index: 20},
	}
}

func testEndpoints() map[[32]byte]string {
	return map[[32]byte]string{
		memberAccount(1): "https://kgc1.example",
		memberAccount(2): "https://kgc2.example/",
		memberAccount(3): "https://kgc3.example",
	}
}

func testCommitments() map[[32]byte][]byte {
	return map[[32]byte][]byte{
		memberAccount(1): []byte("g1"),
		memberAccount(2): []byte("g2"),
		memberAccount(3): []byte("g3"),
	}
}

func nodeIndices(nodes []CommitteeNode) []uint64 {
	out := make([]uint64, len(nodes))
	for i, n := range nodes {
		out[i] = n.Index
	}
	return out
}

func TestAssembleCommitteeJoinsTheTablesAndSortsByDkgIndex(t *testing.T) {
	nodes, err := assembleCommittee(testCommittee(), testEndpoints(), testCommitments(), 2, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got := nodeIndices(nodes); len(got) != 3 || got[0] != 10 || got[1] != 20 || got[2] != 30 {
		t.Fatalf("indices %v, want [10 20 30]", got)
	}
	if nodes[1].Endpoint != "https://kgc2.example" {
		t.Errorf("trailing slash kept: %q", nodes[1].Endpoint)
	}
	if !bytes.Equal(nodes[1].ShareCommitment, []byte("g2")) {
		t.Errorf("commitment %q, want g2", nodes[1].ShareCommitment)
	}
}

func TestAssembleCommitteeDropsMembersWithoutAnAbsoluteHTTPEndpoint(t *testing.T) {
	endpoints := map[[32]byte]string{
		memberAccount(1): "https://kgc1.example",
		memberAccount(2): "ftp://kgc2.example",
		// memberAccount(3) is no longer in the registry.
	}
	nodes, err := assembleCommittee(testCommittee(), endpoints, testCommitments(), 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got := nodeIndices(nodes); len(got) != 1 || got[0] != 10 {
		t.Fatalf("indices %v, want [10]", got)
	}
}

func TestAssembleCommitteeRefusesAReachableMemberWithoutACommitment(t *testing.T) {
	commitments := testCommitments()
	delete(commitments, memberAccount(2))
	if _, err := assembleCommittee(testCommittee(), testEndpoints(), commitments, 2, 7); err == nil {
		t.Fatal("a reachable member without its share commitment is unverifiable and must fail")
	}
}

func TestAssembleCommitteeRefusesFewerReachableMembersThanTheThreshold(t *testing.T) {
	endpoints := map[[32]byte]string{memberAccount(1): "https://kgc1.example"}
	if _, err := assembleCommittee(testCommittee(), endpoints, testCommitments(), 2, 7); err == nil {
		t.Fatal("one reachable member cannot meet a threshold of two")
	}
}

func TestAssembleCommitteeRefusesAnEmptyCommittee(t *testing.T) {
	if _, err := assembleCommittee(nil, testEndpoints(), testCommitments(), 1, 7); err == nil {
		t.Fatal("an epoch with no seated committee must fail")
	}
}
