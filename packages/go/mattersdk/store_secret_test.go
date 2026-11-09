package mattersdk

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/registry"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

func secretStored(id int64, owner []byte) Event {
	var account types.AccountID
	copy(account[:], owner)
	return Event{
		Pallet: "Secrets",
		Name:   "SecretStored",
		Fields: registry.DecodedFields{
			{Name: "secret_id", Value: types.NewU128(*big.NewInt(id))},
			{Name: "owner", Value: account},
		},
	}
}

// secretStoredAsDecoded shapes the event exactly as GSRPC's registry decodes it
// from the live runtime (seen on testnet spec 333): `AccountId32` is a one-field
// composite whose `[u8; 32]` arrives as a slice of U8.
func secretStoredAsDecoded(id int64, owner []byte) Event {
	elems := make([]interface{}, len(owner))
	for i, b := range owner {
		elems[i] = types.U8(b)
	}
	return Event{
		Pallet: "Secrets",
		Name:   "SecretStored",
		Fields: registry.DecodedFields{
			{Name: "secret_id", Value: types.NewU128(*big.NewInt(id))},
			{Name: "sp_core.crypto.AccountId32.owner", Value: registry.DecodedFields{
				{Name: "[u8; 32]", Value: elems},
			}},
		},
	}
}

func TestStoredSecretIDReadsTheOwnerAsTheRegistryDecodesIt(t *testing.T) {
	mine, theirs := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	events := []Event{
		secretStoredAsDecoded(7, theirs),
		secretStoredAsDecoded(9, mine),
	}
	id, found, err := storedSecretID(events, mine)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v: the registry's AccountId32 shape was not recognised", found, err)
	}
	if id != NewSecretID(9) {
		t.Errorf("id %s, want 9", id)
	}
	// A composite that is not account-shaped never matches.
	odd := secretStoredAsDecoded(11, mine)
	odd.Fields[1].Value = registry.DecodedFields{{Name: "[u8; 32]", Value: []interface{}{types.U8(1)}}}
	if _, found, _ := storedSecretID([]Event{odd}, mine); found {
		t.Error("a 1-byte composite matched a 32-byte owner")
	}
}

func TestStoredSecretIDMatchesTheOwnersEvent(t *testing.T) {
	mine, theirs := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	events := []Event{
		{Pallet: "System", Name: "ExtrinsicSuccess"},
		secretStored(7, theirs), // a concurrent store in the same block
		secretStored(9, mine),
	}
	id, found, err := storedSecretID(events, mine)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if id != NewSecretID(9) {
		t.Errorf("id %s, want 9: another account's store was taken", id)
	}
	if _, found, _ := storedSecretID(events[:2], mine); found {
		t.Error("no SecretStored for this owner must report not found")
	}
}

func TestStoreSecretCallCarriesTheLabel(t *testing.T) {
	meta := loadSpec330Metadata(t)
	chain := &ChainClient{meta: meta}
	call, err := chain.StoreSecretCall(EncryptedSecret{BindingID: []byte{1}, Capsule: []byte{2}, Proof: []byte{3}, CT: []byte{4}}, 5, "db-url", AadEnvV1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(call.Args, []byte("db-url")) {
		t.Error("the label is not in the encoded call")
	}
	decodesExactly(t, meta, call)
}
