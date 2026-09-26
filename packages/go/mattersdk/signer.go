package mattersdk

import "fmt"

// SCALE enum index of MultiSignature::Sr25519 (Ed25519=0, Sr25519=1, Ecdsa=2).
const multisignatureSr25519 = 0x01

// Length of a raw sr25519 signature, before MultiSignature framing.
const sr25519SignatureBytes = 64

// RequestAuth is the auth fields attached to a /partial-decrypt request. The
// Ethereum fields are set only by an Ethereum-auth (EIP-712) Signer; the
// Substrate path leaves them nil.
type RequestAuth struct {
	Auth      string `json:"auth"`
	Requester string `json:"requester"`
	Signature string `json:"signature"`
	// EthAddress is the 0x-prefixed Ethereum address that signed.
	EthAddress *string `json:"eth_address,omitempty"`
	// ValidUntil is the unix time after which the signature is refused.
	ValidUntil *uint64 `json:"valid_until,omitempty"`
	// EthSignature is the 0x-prefixed EIP-712 signature.
	EthSignature *string `json:"eth_signature,omitempty"`
}

// Signer authorizes a /partial-decrypt request without exposing its key.
// recipientIndex is the target node's 1-based dkg_index; it is signed so a
// signature cannot be replayed to a peer. Called once per node in the quorum.
type Signer interface {
	AuthScheme() string
	Authorize(secretID SecretID, subset []uint64, recipientIndex uint64, blockHash [32]byte) (RequestAuth, error)
}

type substrateSigner struct {
	requester string
	sign      func([]byte) ([]byte, error)
}

// SubstrateSigner builds a Signer from a 32-byte account id and an sr25519 sign
// callback, which receives the canonical payload and returns the 64-byte
// signature. The key never enters the SDK; use ApiKey for an in-process key.
func SubstrateSigner(accountID []byte, sign func([]byte) ([]byte, error)) (Signer, error) {
	if len(accountID) != 32 {
		return nil, fmt.Errorf("accountID must be 32 bytes, got %d", len(accountID))
	}
	return &substrateSigner{requester: toHex(accountID), sign: sign}, nil
}

func (s *substrateSigner) AuthScheme() string { return "substrate" }

func (s *substrateSigner) Authorize(secretID SecretID, subset []uint64, recipientIndex uint64, blockHash [32]byte) (RequestAuth, error) {
	payload, err := SigningPayload(secretID.Bytes(), subset, blockHash, recipientIndex)
	if err != nil {
		return RequestAuth{}, err
	}
	sig, err := s.sign(payload)
	if err != nil {
		return RequestAuth{}, err
	}
	if len(sig) != sr25519SignatureBytes {
		return RequestAuth{}, fmt.Errorf("sr25519 signature must be %d bytes, got %d", sr25519SignatureBytes, len(sig))
	}
	multisig := append([]byte{multisignatureSr25519}, sig...)
	return RequestAuth{Auth: "substrate", Requester: s.requester, Signature: toHex(multisig)}, nil
}
