package mattervault

// SubstrateSigner framing and input validation. The Go port of the assertions in
// the Rust `signer::tests` and Python `test_substrate_signer_frames_a_multisignature`.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func constantSigner(t *testing.T, sig []byte) Signer {
	t.Helper()
	s, err := SubstrateSigner(bytes.Repeat([]byte{0x01}, 32), func([]byte) ([]byte, error) {
		return sig, nil
	})
	if err != nil {
		t.Fatalf("SubstrateSigner: %v", err)
	}
	return s
}

func TestSubstrateSignerFramesAMultiSignature(t *testing.T) {
	signer := constantSigner(t, bytes.Repeat([]byte{0x07}, 64))

	auth, err := signer.Authorize(NewSecretID(42), []uint64{1, 2, 3}, 2, [32]byte{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.Auth != "substrate" {
		t.Errorf("auth = %q", auth.Auth)
	}

	// requester is the raw AccountId32: 0x + 64 hex chars, no length prefix.
	requester, err := hex.DecodeString(strings.TrimPrefix(auth.Requester, "0x"))
	if err != nil || len(requester) != 32 {
		t.Fatalf("requester is not 32 bytes: %q (%v)", auth.Requester, err)
	}

	// signature is a SCALE MultiSignature: 1-byte variant (Sr25519 = 1) + 64 bytes.
	sig, err := hex.DecodeString(strings.TrimPrefix(auth.Signature, "0x"))
	if err != nil {
		t.Fatalf("signature hex: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature is %d bytes, want 65", len(sig))
	}
	if sig[0] != multisignatureSr25519 {
		t.Errorf("variant byte = %#x, want %#x", sig[0], multisignatureSr25519)
	}
	if !bytes.Equal(sig[1:], bytes.Repeat([]byte{0x07}, 64)) {
		t.Error("signature body was altered during framing")
	}
}

func TestSubstrateSignerRejectsWrongSizedAccountID(t *testing.T) {
	for _, size := range []int{0, 31, 33, 64} {
		if _, err := SubstrateSigner(make([]byte, size), nil); err == nil {
			t.Errorf("accountID of %d bytes was accepted", size)
		}
	}
}

func TestSubstrateSignerRejectsWrongSizedSignature(t *testing.T) {
	for _, size := range []int{0, 63, 65, 128} {
		signer := constantSigner(t, make([]byte, size))
		if _, err := signer.Authorize(NewSecretID(1), []uint64{1}, 1, [32]byte{}); err == nil {
			t.Errorf("signature of %d bytes was accepted", size)
		}
	}
}

func TestSubstrateSignerPropagatesSignFailure(t *testing.T) {
	sentinel := errors.New("hsm rejected the request")
	signer, err := SubstrateSigner(make([]byte, 32), func([]byte) ([]byte, error) {
		return nil, sentinel
	})
	if err != nil {
		t.Fatalf("SubstrateSigner: %v", err)
	}
	if _, err := signer.Authorize(NewSecretID(1), []uint64{1}, 1, [32]byte{}); !errors.Is(err, sentinel) {
		t.Errorf("sign failure was not propagated: %v", err)
	}
}

func TestSubstrateSignerSignsADistinctPayloadPerRecipient(t *testing.T) {
	// MV-C1 at the signer level: the bytes handed to the key must differ per
	// recipient, so a captured signature is not valid at another node.
	var seen [][]byte
	signer, err := SubstrateSigner(make([]byte, 32), func(payload []byte) ([]byte, error) {
		seen = append(seen, append([]byte(nil), payload...))
		return make([]byte, 64), nil
	})
	if err != nil {
		t.Fatalf("SubstrateSigner: %v", err)
	}

	for _, recipient := range []uint64{1, 2, 3} {
		if _, err := signer.Authorize(NewSecretID(9), []uint64{1, 2, 3}, recipient, [32]byte{0xab}); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
	}
	for i := range seen {
		for j := i + 1; j < len(seen); j++ {
			if bytes.Equal(seen[i], seen[j]) {
				t.Errorf("recipients %d and %d were handed identical payloads", i, j)
			}
		}
	}
}
