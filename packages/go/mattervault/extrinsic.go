// Signed-extrinsic assembly for any call.
//
// GSRPC's own signer hardcodes the pre-CheckMetadataHash signed-extension set,
// so against this runtime — whose TxExtension adds
// `frame_metadata_hash_extension::CheckMetadataHash` and
// `frame_system::WeightReclaim` — its signing payload is misaligned and the node
// rejects the extrinsic. The previous fix hardcoded a replacement layout inside
// StoreSecret, which worked but would silently mis-sign the day the runtime adds
// an eleventh extension.
//
// Instead, walk the extensions the *metadata* declares and ask a contributor per
// identifier for its `extra` and `additionalSigned` bytes. An identifier with no
// registered contributor is a hard error: signing bytes we cannot account for is
// how you get an opaque "1010 outdated" at 3am, and a wrong signature over a
// funded account is not a failure worth being optimistic about.
package mattervault

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
	// The runtime blake2b-256-hashes a signing payload longer than this before
	// verifying it, so a signer must do the same.
	maxUnhashedPayloadBytes = 256
	// Length of a substrate AccountId32.
	accountIDBytes = 32
)

// SigningContext is the chain and account state the signed extensions draw on.
type SigningContext struct {
	SpecVersion        uint32
	TransactionVersion uint32
	GenesisHash        [32]byte
	// The block an extrinsic's mortality is anchored to. Equals GenesisHash for
	// the immortal era this SDK uses.
	MortalityHash [32]byte
	Nonce         uint32
	Tip           uint64
}

// contributor supplies the bytes one signed extension adds to each segment:
// `extra` travels with the extrinsic, `additional` is signed but not transmitted.
// A nil function contributes nothing — which is itself meaningful, and different
// from the extension being unknown.
type contributor struct {
	extra      func(SigningContext) []byte
	additional func(SigningContext) []byte
}

// signedExtensions maps a metadata extension identifier to its contributor.
//
// Registering an extension is a statement that we know what it signs. Anything
// absent here stops assembly rather than being skipped.
//
// Verified 2026-07-29 against the live testnet (spec_version 308, metadata V14):
// the runtime declares exactly CheckNonZeroSender, CheckSpecVersion,
// CheckTxVersion, CheckGenesis, CheckMortality, CheckNonce, CheckWeight,
// ChargeTransactionPayment, CheckMetadataHash, WeightReclaim — in that order.
var signedExtensions = map[string]contributor{
	// Checks the sender is not the zero account. Contributes nothing.
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
	// The runtime source calls this `frame_system::CheckEra`, but the metadata
	// emits `CheckMortality` — confirmed absent/present respectively in the live
	// V14 blob. Both spellings are registered because they denote identical
	// bytes, and a runtime that emitted the other name should not halt signing.
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
	// Block-weight accounting. Contributes nothing to either segment.
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
	// Returns unused weight after dispatch. Contributes nothing.
	"WeightReclaim": {},
}

// Deliberately absent: entries for extensions this runtime does not declare.
// Pre-registering guesses would defeat the purpose of the unknown-extension
// error — the SDK would confidently contribute bytes for an extension nobody
// verified. Add one only alongside a runtime that actually declares it.

// UnsignedExtrinsic is a call plus the two byte segments the runtime's signed
// extensions contribute, ready to be signed and assembled.
//
// The signature is supplied to Assemble rather than produced internally: it
// keeps the key out of this file, and it lets a conformance vector pin the
// framing with a fixed dummy signature despite sr25519 being non-deterministic.
type UnsignedExtrinsic struct {
	Call       []byte
	Extra      []byte
	Additional []byte
}

// PrepareExtrinsic builds the segments for `call` by walking the signed
// extensions this runtime's metadata declares, in metadata order.
//
// Returns an error naming the offending extension if the runtime declares one
// this SDK does not understand.
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
					"update packages/go/mattervault/extrinsic.go)", identifier)
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
// blake2b-256-hashed when longer than 256 bytes, matching what the runtime
// verifies. GSRPC's `signature.Sign` does this hashing internally; doing it here
// keeps any signer — including one that only offers raw sr25519 — correct.
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
