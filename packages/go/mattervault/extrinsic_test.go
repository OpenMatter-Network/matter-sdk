package mattervault

// Signed-extrinsic assembly, against synthetic metadata so no blob or network is
// needed. The layout being asserted is a consensus contract: a wrong byte here
// produces an opaque "1010 outdated" from the node, or worse, a valid signature
// over something other than what we meant.

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"golang.org/x/crypto/blake2b"
)

// The extensions the live runtime declares, in metadata order (verified against
// testnet spec_version 308).
var liveExtensions = []string{
	"CheckNonZeroSender",
	"CheckSpecVersion",
	"CheckTxVersion",
	"CheckGenesis",
	"CheckMortality",
	"CheckNonce",
	"CheckWeight",
	"ChargeTransactionPayment",
	"CheckMetadataHash",
	"WeightReclaim",
}

// syntheticMetadata builds just enough V14 metadata to drive assembly: the
// signed-extension list is the only part PrepareExtrinsic reads.
func syntheticMetadata(identifiers ...string) *types.Metadata {
	exts := make([]types.SignedExtensionMetadataV14, len(identifiers))
	for i, id := range identifiers {
		exts[i] = types.SignedExtensionMetadataV14{Identifier: types.Text(id)}
	}
	meta := types.NewMetadataV14()
	meta.AsMetadataV14.Extrinsic.SignedExtensions = exts
	return meta
}

func testCall() types.Call {
	return types.Call{
		CallIndex: types.CallIndex{SectionIndex: 55, MethodIndex: 0},
		Args:      types.Args{0xde, 0xad, 0xbe, 0xef},
	}
}

func testContext() SigningContext {
	ctx := SigningContext{
		SpecVersion:        308,
		TransactionVersion: 9,
		Nonce:              7,
		Tip:                0,
	}
	for i := range ctx.GenesisHash {
		ctx.GenesisHash[i] = byte(i)
	}
	ctx.MortalityHash = ctx.GenesisHash // immortal era anchors to genesis
	return ctx
}

func TestPrepareMatchesTheVerifiedRuntimeLayout(t *testing.T) {
	// Pins the exact byte layout the previous hand-assembled implementation
	// produced, which is known to be accepted by this runtime. If the registry
	// ever reorders or drops a contribution, this fails.
	x, err := PrepareExtrinsic(syntheticMetadata(liveExtensions...), testCall(), testContext())
	if err != nil {
		t.Fatalf("PrepareExtrinsic: %v", err)
	}

	ctx := testContext()

	// extra: Era(immortal) ++ Compact(nonce) ++ Compact(tip) ++ CheckMetadataHash(Disabled)
	wantExtra := []byte{eraImmortal}
	wantExtra = append(wantExtra, compactUint(uint64(ctx.Nonce))...)
	wantExtra = append(wantExtra, compactUint(ctx.Tip)...)
	wantExtra = append(wantExtra, metadataHashDisabled)
	if !bytes.Equal(x.Extra, wantExtra) {
		t.Errorf("extra = %s, want %s", hex.EncodeToString(x.Extra), hex.EncodeToString(wantExtra))
	}

	// additional: SpecVersion ++ TxVersion ++ Genesis ++ MortalityAnchor ++ None
	wantAdditional := append([]byte{}, u32le(ctx.SpecVersion)...)
	wantAdditional = append(wantAdditional, u32le(ctx.TransactionVersion)...)
	wantAdditional = append(wantAdditional, ctx.GenesisHash[:]...)
	wantAdditional = append(wantAdditional, ctx.MortalityHash[:]...)
	wantAdditional = append(wantAdditional, optionNone)
	if !bytes.Equal(x.Additional, wantAdditional) {
		t.Errorf("additional = %s, want %s",
			hex.EncodeToString(x.Additional), hex.EncodeToString(wantAdditional))
	}
}

func TestPrepareFollowsMetadataOrderNotRegistrationOrder(t *testing.T) {
	// The runtime decides the order; the map must not impose its own.
	forward, err := PrepareExtrinsic(
		syntheticMetadata("CheckSpecVersion", "CheckTxVersion"), testCall(), testContext())
	if err != nil {
		t.Fatalf("PrepareExtrinsic: %v", err)
	}
	reversed, err := PrepareExtrinsic(
		syntheticMetadata("CheckTxVersion", "CheckSpecVersion"), testCall(), testContext())
	if err != nil {
		t.Fatalf("PrepareExtrinsic: %v", err)
	}
	if bytes.Equal(forward.Additional, reversed.Additional) {
		t.Error("additional data is order-insensitive; the metadata order is being ignored")
	}
}

func TestUnknownSignedExtensionRefusesToSign(t *testing.T) {
	// The whole reason this file exists: a runtime upgrade that adds an
	// extension must stop us, not be silently skipped.
	withNew := append(append([]string{}, liveExtensions...), "CheckSomethingNewIn309")

	_, err := PrepareExtrinsic(syntheticMetadata(withNew...), testCall(), testContext())
	if err == nil {
		t.Fatal("expected a refusal for an unregistered signed extension")
	}
	if !strings.Contains(err.Error(), "CheckSomethingNewIn309") {
		t.Errorf("error should name the offending extension: %v", err)
	}
}

func TestNoSignedExtensionsIsAnError(t *testing.T) {
	// Empty metadata means we failed to load it, not that the runtime has no
	// extensions. Signing on that basis would produce a garbage payload.
	if _, err := PrepareExtrinsic(syntheticMetadata(), testCall(), testContext()); err == nil {
		t.Error("expected an error when metadata declares no signed extensions")
	}
}

func TestCheckEraAliasProducesTheSameBytes(t *testing.T) {
	mortality, err := PrepareExtrinsic(syntheticMetadata("CheckMortality"), testCall(), testContext())
	if err != nil {
		t.Fatalf("CheckMortality: %v", err)
	}
	era, err := PrepareExtrinsic(syntheticMetadata("CheckEra"), testCall(), testContext())
	if err != nil {
		t.Fatalf("CheckEra: %v", err)
	}
	if !bytes.Equal(mortality.Extra, era.Extra) || !bytes.Equal(mortality.Additional, era.Additional) {
		t.Error("CheckEra and CheckMortality must contribute identical bytes")
	}
}

func TestSigningPayloadHashesOnlyWhenOversized(t *testing.T) {
	// The runtime blake2b-256-hashes payloads over 256 bytes before verifying.
	// Getting the threshold wrong produces a signature the node rejects.
	short := &UnsignedExtrinsic{Call: make([]byte, 10)}
	if got := short.SigningPayload(); len(got) != 10 {
		t.Errorf("short payload was altered: %d bytes", len(got))
	}

	atLimit := &UnsignedExtrinsic{Call: make([]byte, maxUnhashedPayloadBytes)}
	if got := atLimit.SigningPayload(); len(got) != maxUnhashedPayloadBytes {
		t.Errorf("payload at the limit should not be hashed: %d bytes", len(got))
	}

	oversized := &UnsignedExtrinsic{Call: bytes.Repeat([]byte{0xab}, maxUnhashedPayloadBytes+1)}
	got := oversized.SigningPayload()
	want := blake2b.Sum256(bytes.Repeat([]byte{0xab}, maxUnhashedPayloadBytes+1))
	if !bytes.Equal(got, want[:]) {
		t.Error("oversized payload was not blake2b-256-hashed")
	}
}

func TestSigningPayloadConcatenatesInOrder(t *testing.T) {
	x := &UnsignedExtrinsic{Call: []byte{1, 2}, Extra: []byte{3}, Additional: []byte{4, 5}}
	if got := x.SigningPayload(); !bytes.Equal(got, []byte{1, 2, 3, 4, 5}) {
		t.Errorf("payload = %v, want call ++ extra ++ additional", got)
	}
}

func TestAssembleFraming(t *testing.T) {
	x := &UnsignedExtrinsic{Call: []byte{0xca, 0xfe}, Extra: []byte{0x00, 0x1c}}
	accountID := bytes.Repeat([]byte{0xaa}, accountIDBytes)
	sig := bytes.Repeat([]byte{0x07}, sr25519SignatureBytes)

	full, err := x.Assemble(accountID, sig)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	// A compact length prefix, then the body.
	bodyLen := 2 + accountIDBytes + 1 + sr25519SignatureBytes + len(x.Extra) + len(x.Call)
	prefix := compactUint(uint64(bodyLen))
	if !bytes.HasPrefix(full, prefix) {
		t.Fatalf("missing compact length prefix")
	}
	body := full[len(prefix):]
	if len(body) != bodyLen {
		t.Fatalf("body is %d bytes, want %d", len(body), bodyLen)
	}

	if body[0] != extrinsicVersionSigned {
		t.Errorf("version byte = %#x, want %#x", body[0], extrinsicVersionSigned)
	}
	if body[1] != multiAddressID {
		t.Errorf("address variant = %#x, want %#x", body[1], multiAddressID)
	}
	if !bytes.Equal(body[2:2+accountIDBytes], accountID) {
		t.Error("account id was not written verbatim")
	}
	at := 2 + accountIDBytes
	if body[at] != multisignatureSr25519 {
		t.Errorf("signature variant = %#x, want %#x", body[at], multisignatureSr25519)
	}
	if !bytes.Equal(body[at+1:at+1+sr25519SignatureBytes], sig) {
		t.Error("signature was not written verbatim")
	}
	at += 1 + sr25519SignatureBytes
	if !bytes.Equal(body[at:at+len(x.Extra)], x.Extra) {
		t.Error("extra was not written after the signature")
	}
	if !bytes.Equal(body[at+len(x.Extra):], x.Call) {
		t.Error("call must come last")
	}
}

func TestAssembleRejectsWrongSizedInputs(t *testing.T) {
	x := &UnsignedExtrinsic{Call: []byte{0x01}}
	good := bytes.Repeat([]byte{0x07}, sr25519SignatureBytes)

	if _, err := x.Assemble(make([]byte, 31), good); err == nil {
		t.Error("a 31-byte account id was accepted")
	}
	if _, err := x.Assemble(make([]byte, accountIDBytes), make([]byte, 63)); err == nil {
		t.Error("a 63-byte signature was accepted")
	}
}
