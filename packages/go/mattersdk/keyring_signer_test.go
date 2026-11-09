package mattersdk

import (
	"bytes"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/vedhavyas/go-subkey/v2"
	"github.com/vedhavyas/go-subkey/v2/sr25519"
	"golang.org/x/crypto/blake2b"
)

// A committee request payload is verified raw by the node, however long it is,
// so KeyringSigner must never hash on its own: the SDK hashes extrinsic payloads
// before they reach it, and nothing else may be hashed.
func TestKeyringSignerSignsLongPayloadsVerbatim(t *testing.T) {
	signer := KeyringSigner{Pair: signature.TestKeyringPairAlice}
	payload := bytes.Repeat([]byte{0xab}, maxUnhashedPayloadBytes+44)

	sig, err := signer.SignExtrinsic(payload)
	if err != nil {
		t.Fatalf("SignExtrinsic: %v", err)
	}
	if len(sig) != sr25519SignatureBytes {
		t.Fatalf("signature is %d bytes, want %d", len(sig), sr25519SignatureBytes)
	}

	pair, err := subkey.DeriveKeyPair(sr25519.Scheme{}, signature.TestKeyringPairAlice.URI)
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	if !bytes.Equal(pair.Public(), signer.AccountID()) {
		t.Fatal("AccountID does not match the derived pair")
	}
	if !pair.Verify(payload, sig) {
		t.Error("signature does not verify over the raw payload")
	}
	digest := blake2b.Sum256(payload)
	if pair.Verify(digest[:], sig) {
		t.Error("signature verifies over the digest: the payload was hashed a second time")
	}
}
