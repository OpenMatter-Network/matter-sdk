package mattersdk

import (
	"fmt"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	codec "github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"golang.org/x/crypto/blake2b"
)

const (
	// Extrinsic format version 4 with the signed bit set.
	extrinsicVersionSigned = 0x84
	// SCALE index of MultiAddress::Id.
	multiAddressID = 0x00
	// SCALE index of Era::Immortal.
	eraImmortal = 0x00
	// SCALE index of CheckMetadataHash's `Mode::Disabled`, and of `Option::None`
	// for the digest it would otherwise contribute.
	metadataHashDisabled = 0x00
	optionNone           = 0x00
	// Signing payloads longer than this are blake2b-256-hashed first.
	maxUnhashedPayloadBytes = 256
	// Length of a substrate AccountId32.
	accountIDBytes = 32
)

// SigningContext is the chain and account state the signed extensions draw on.
type SigningContext struct {
	SpecVersion        uint32
	TransactionVersion uint32
	GenesisHash        [32]byte
	// MortalityHash equals GenesisHash for the immortal era this SDK uses.
	MortalityHash [32]byte
	Nonce         uint32
	Tip           uint64
}

// contributor supplies the bytes one signed extension adds to each segment:
// `extra` travels with the extrinsic, `additional` is signed but not transmitted.
// A nil function contributes nothing, which differs from an unknown extension.
type contributor struct {
	extra      func(SigningContext) []byte
	additional func(SigningContext) []byte
}

// signedExtensions maps a metadata extension identifier to its contributor.
// GSRPC's built-in signer assumes a fixed extension set; this walks the set the
// metadata declares instead. An unregistered identifier stops assembly: never
// sign bytes we cannot account for.
var signedExtensions = map[string]contributor{
	"CheckNonZeroSender": {},
	"CheckSpecVersion": {
		additional: func(ctx SigningContext) []byte { return u32le(ctx.SpecVersion) },
	},
	"CheckTxVersion": {
		additional: func(ctx SigningContext) []byte { return u32le(ctx.TransactionVersion) },
	},
	"CheckGenesis": {
		additional: func(ctx SigningContext) []byte { return ctx.GenesisHash[:] },
	},
	// Registered under both names (runtime source: CheckEra, metadata:
	// CheckMortality) so either spelling signs; the bytes are identical.
	"CheckMortality": {
		extra:      func(SigningContext) []byte { return []byte{eraImmortal} },
		additional: func(ctx SigningContext) []byte { return ctx.MortalityHash[:] },
	},
	"CheckEra": {
		extra:      func(SigningContext) []byte { return []byte{eraImmortal} },
		additional: func(ctx SigningContext) []byte { return ctx.MortalityHash[:] },
	},
	"CheckNonce": {
		extra: func(ctx SigningContext) []byte { return compactUint(uint64(ctx.Nonce)) },
	},
	"CheckWeight": {},
	"ChargeTransactionPayment": {
		extra: func(ctx SigningContext) []byte { return compactUint(ctx.Tip) },
	},
	// We do not supply a metadata digest, so the mode is Disabled and the
	// additional data is Option::None.
	"CheckMetadataHash": {
		extra:      func(SigningContext) []byte { return []byte{metadataHashDisabled} },
		additional: func(SigningContext) []byte { return []byte{optionNone} },
	},
	"WeightReclaim": {},
}

// Register an extension only alongside a runtime that declares it; a guessed
// entry would defeat the unknown-extension error.

// UnsignedExtrinsic is a call plus the two byte segments the runtime's signed
// extensions contribute, ready to be signed and assembled.
//
// The signature is passed to Assemble, keeping the key out of this file and
// letting conformance vectors pin framing with a fixed dummy signature.
type UnsignedExtrinsic struct {
	Call       []byte
	Extra      []byte
	Additional []byte
}

// PrepareExtrinsic builds the segments for `call` from the signed extensions the
// metadata declares, in order. It fails, naming the extension, on any extension
// this SDK does not know.
func PrepareExtrinsic(meta *types.Metadata, call types.Call, ctx SigningContext) (*UnsignedExtrinsic, error) {
	callBytes, err := codec.Encode(call)
	if err != nil {
		return nil, fmt.Errorf("encode call: %w", err)
	}

	declared := meta.AsMetadataV14.Extrinsic.SignedExtensions
	if len(declared) == 0 {
		return nil, fmt.Errorf("runtime metadata declares no signed extensions; cannot assemble a signed extrinsic")
	}

	x := &UnsignedExtrinsic{Call: callBytes}
	for _, ext := range declared {
		identifier := string(ext.Identifier)
		c, known := signedExtensions[identifier]
		if !known {
			return nil, fmt.Errorf(
				"runtime declares signed extension %q, which this SDK cannot contribute bytes for; "+
					"refusing to sign a payload it cannot account for (the runtime likely upgraded — "+
					"update packages/go/mattersdk/extrinsic.go)", identifier)
		}
		if c.extra != nil {
			x.Extra = append(x.Extra, c.extra(ctx)...)
		}
		if c.additional != nil {
			x.Additional = append(x.Additional, c.additional(ctx)...)
		}
	}
	return x, nil
}

// SigningPayload returns the exact bytes to sign: call ++ extra ++ additional,
// blake2b-256-hashed when longer than 256 bytes, as the runtime verifies.
// Hashing here keeps raw-sr25519 signers correct.
func (x *UnsignedExtrinsic) SigningPayload() []byte {
	raw := make([]byte, 0, len(x.Call)+len(x.Extra)+len(x.Additional))
	raw = append(raw, x.Call...)
	raw = append(raw, x.Extra...)
	raw = append(raw, x.Additional...)
	if len(raw) > maxUnhashedPayloadBytes {
		digest := blake2b.Sum256(raw)
		return digest[:]
	}
	return raw
}

// Assemble produces the length-prefixed signed extrinsic ready for
// `author_submitExtrinsic`:
//
//	version(0x84) ++ MultiAddress::Id(account) ++ MultiSignature::Sr25519(sig) ++ extra ++ call
func (x *UnsignedExtrinsic) Assemble(accountID, sig []byte) ([]byte, error) {
	if len(accountID) != accountIDBytes {
		return nil, fmt.Errorf("accountID must be %d bytes, got %d", accountIDBytes, len(accountID))
	}
	if len(sig) != sr25519SignatureBytes {
		return nil, fmt.Errorf("sr25519 signature must be %d bytes, got %d", sr25519SignatureBytes, len(sig))
	}

	body := make([]byte, 0, 2+len(accountID)+1+len(sig)+len(x.Extra)+len(x.Call))
	body = append(body, extrinsicVersionSigned, multiAddressID)
	body = append(body, accountID...)
	body = append(body, multisignatureSr25519)
	body = append(body, sig...)
	body = append(body, x.Extra...)
	body = append(body, x.Call...)

	return append(compactUint(uint64(len(body))), body...), nil
}
