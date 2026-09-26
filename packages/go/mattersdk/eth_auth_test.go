package mattersdk

import (
	"encoding/json"
	"strings"
	"testing"
)

// ethSigner stands in for a custom Ethereum-auth (EIP-712) signer.
type ethSigner struct{}

func (ethSigner) AuthScheme() string { return "ethereum" }

func (ethSigner) Authorize(SecretID, []uint64, uint64, [32]byte) (RequestAuth, error) {
	validUntil := uint64(1_900_000_000)
	address := "0x00000000000000000000000000000000000000aa"
	signature := "0x" + strings.Repeat("11", 65)
	return RequestAuth{
		Auth:         "ethereum",
		EthAddress:   &address,
		ValidUntil:   &validUntil,
		EthSignature: &signature,
	}, nil
}

func TestDecryptForwardsEthereumAuthFields(t *testing.T) {
	fx := loadCommitteeFixture(t)
	transport := &fakeTransport{fx: fx, t: t}
	if _, err := Decrypt(transport, ethSigner{}, fx.params(t)); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	for i, req := range transport.decryptCalls {
		if req.EthAddress == nil || req.ValidUntil == nil || req.EthSignature == nil {
			t.Fatalf("request %d dropped the Ethereum auth fields: %+v", i, req)
		}
		if *req.ValidUntil != 1_900_000_000 {
			t.Errorf("request %d: valid_until = %d", i, *req.ValidUntil)
		}
	}
}

func TestPartialDecryptRequestJSONMatchesTheWire(t *testing.T) {
	validUntil := uint64(42)
	address, signature := "0xaa", "0xbb"
	eth, err := json.Marshal(PartialDecryptRequest{
		Auth: "ethereum", EthAddress: &address, ValidUntil: &validUntil, EthSignature: &signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"eth_address":"0xaa"`, `"valid_until":42`, `"eth_signature":"0xbb"`} {
		if !strings.Contains(string(eth), want) {
			t.Errorf("%s missing %s", eth, want)
		}
	}

	// A Substrate request carries no Ethereum fields at all, as before.
	substrate, err := json.Marshal(PartialDecryptRequest{Auth: "substrate"})
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"eth_address", "valid_until", "eth_signature"} {
		if strings.Contains(string(substrate), absent) {
			t.Errorf("substrate request carries %s: %s", absent, substrate)
		}
	}
}
