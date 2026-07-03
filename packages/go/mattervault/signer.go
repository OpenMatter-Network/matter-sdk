package mattervault

import "fmt"

// SCALE enum index of MultiSignature::Sr25519 (Ed25519=0, Sr25519=1, Ecdsa=2).
const multisignatureSr25519 = 0x01

// RequestAuth is the auth fields attached to a /partial-decrypt request.
type RequestAuth struct {
	Auth      string `json:"auth"`
	Requester string `json:"requester"`
	Signature string `json:"signature"`
}

// Signer authorizes a /partial-decrypt request without exposing its key. One
// request targets one node: recipientIndex is that node's 1-based dkg_index,
// folded into the signed payload so a signature can't be replayed to a peer
// (MV-C1). The shell calls this once per node in the quorum.
type Signer interface {
	AuthScheme() string
	Authorize(secretID uint64, subset []uint64, recipientIndex uint64, blockHash [32]byte) (RequestAuth, error)
}

type substrateSigner struct {
	requester string
	sign      func([]byte) ([]byte, error)
}

// SubstrateSigner builds a signer from a 32-byte account id and an sr25519 sign
// function. The sign callback is where your key lives — it receives the canonical
// payload bytes and returns the 64-byte signature; the key never enters the SDK.
func SubstrateSigner(accountID []byte, sign func([]byte) ([]byte, error)) (Signer, error) {
	if len(accountID) != 32 {
		return nil, fmt.Errorf("accountID must be 32 bytes, got %d", len(accountID))
	}
	return &substrateSigner{requester: toHex(accountID), sign: sign}, nil
}

func (s *substrateSigner) AuthScheme() string { return "substrate" }

func (s *substrateSigner) Authorize(secretID uint64, subset []uint64, recipientIndex uint64, blockHash [32]byte) (RequestAuth, error) {
	payloadID := secretIDBytes(secretID)
	payload, err := SigningPayload(payloadID, subset, blockHash, recipientIndex)
	if err != nil {
		return RequestAuth{}, err
	}
	sig, err := s.sign(payload)
	if err != nil {
		return RequestAuth{}, err
	}
	if len(sig) != 64 {
		return RequestAuth{}, fmt.Errorf("sr25519 signature must be 64 bytes, got %d", len(sig))
	}
	multisig := append([]byte{multisignatureSr25519}, sig...)
	return RequestAuth{Auth: "substrate", Requester: s.requester, Signature: toHex(multisig)}, nil
}
