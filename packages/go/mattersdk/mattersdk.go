// Package mattersdk is the Go client for MatterSDK and the OpenMatter chain.
//
// Cryptography and API-key derivation run in the shared Rust core
// (crates/matter-sdk-ffi) via cgo, conformant with testvectors/. This package adds
// the committee HTTP client, quorum orchestration, the Signer abstraction, and a
// chain client that signs and submits extrinsics.
//
// The core is linked statically, so binaries need no Rust toolchain at run time.
// Building needs CGO_ENABLED=1 and a C compiler; on musl (e.g. Alpine) add -tags musl.
package mattersdk

// Link flags live in link_dev.go (monorepo) or a generated link.go (published
// module), never both: cgo concatenates every file's directives.

/*
#include "matter_sdk.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"math"
	"runtime"
	"unsafe"
)

// Error codes mirror the C ABI.
var (
	ErrInvalidArg = fmt.Errorf("matter-sdk: invalid argument")
	ErrCrypto     = fmt.Errorf("matter-sdk: cryptographic operation failed")
	// ErrBadAPIKey: a key is empty, malformed, or names an unsupported scheme.
	// The C boundary carries only codes, so the reason is not more specific.
	ErrBadAPIKey = fmt.Errorf("matter-sdk: api key is empty, malformed, or names an unsupported scheme")
	// ErrInternal is a bug inside the shared core: a panic caught at the C
	// boundary. Report it; retrying will not help.
	ErrInternal = fmt.Errorf("matter-sdk: internal error in the shared core")
)

// The C status codes, as plain Go values so the mapping is testable.
const (
	statusOK         = int32(C.MSDK_OK)
	statusInvalidArg = int32(C.MSDK_ERR_INVALID_ARG)
	statusCrypto     = int32(C.MSDK_ERR_CRYPTO)
	statusKey        = int32(C.MSDK_ERR_KEY)
	statusInternal   = int32(C.MSDK_ERR_INTERNAL)
)

func errFromCode(rc C.int32_t) error { return errFromStatus(int32(rc)) }

func errFromStatus(rc int32) error {
	switch rc {
	case statusOK:
		return nil
	case statusInvalidArg:
		return ErrInvalidArg
	case statusKey:
		return ErrBadAPIKey
	case statusInternal:
		return ErrInternal
	default:
		return ErrCrypto
	}
}

// CryptoProtocolVersion is the crypto protocol version the shared core speaks.
// A committee node reporting a different non-zero version in /health is
// dropped before it is asked for a partial.
func CryptoProtocolVersion() uint16 {
	return uint16(C.msdk_crypto_protocol_version())
}

// MaxCommitteeResponseBytes is the cap on a committee node's response body
// that every binding's transport enforces.
func MaxCommitteeResponseBytes() int64 {
	var out C.uint64_t
	if err := errFromCode(C.msdk_max_committee_response_bytes(&out)); err != nil {
		panic("matter-sdk: " + err.Error())
	}
	return int64(out)
}

// Wipe zeroes b in place. Defer it on a recovered plaintext: the core wipes its
// own copy before freeing it; this clears Go's copy.
func Wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// subsetPtr returns a C pointer to the first element of subset (or nil if empty).
// The slice must outlive the C call.
func subsetPtr(subset []uint64) *C.uint64_t {
	if len(subset) == 0 {
		return nil
	}
	return (*C.uint64_t)(unsafe.Pointer(&subset[0]))
}

// sizeToInt converts a C length to a Go one, refusing a value an int cannot
// hold rather than wrapping it.
func sizeToInt(n uint64) (int, bool) {
	if n > math.MaxInt {
		return 0, false
	}
	return int(n), true
}

// goBytesAndFree copies an MsdkBuf into a Go slice and releases (and wipes)
// the Rust buffer.
func goBytesAndFree(buf C.MsdkBuf) []byte {
	defer C.msdk_free(buf)
	if buf.ptr == nil || buf.len == 0 {
		return nil
	}
	n, ok := sizeToInt(uint64(buf.len))
	if !ok {
		// The core never returns a buffer this large; reaching here is a bug.
		panic(fmt.Sprintf("matter-sdk: core returned a %d-byte buffer", uint64(buf.len)))
	}
	out := make([]byte, n)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(buf.ptr)), n))
	return out
}

// SigningPayload returns the canonical bytes a requester signs for a
// /partial-decrypt request, binding (secretID, subset, blockHash,
// recipientIndex). recipientIndex is the responding node's 1-based dkg_index:
// sign once per node so a signature cannot be replayed to a peer.
func SigningPayload(secretID [16]byte, subset []uint64, blockHash [32]byte, recipientIndex uint64) ([]byte, error) {
	var out C.MsdkBuf
	rc := C.msdk_signing_payload(
		(*C.uint8_t)(&secretID[0]),
		subsetPtr(subset),
		C.size_t(len(subset)),
		(*C.uint8_t)(&blockHash[0]),
		C.uint64_t(recipientIndex),
		&out,
	)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	return goBytesAndFree(out), nil
}

// LagrangeFor returns the bincode Lagrange coefficient for point over subset.
func LagrangeFor(point uint64, subset []uint64) ([]byte, error) {
	var out C.MsdkBuf
	rc := C.msdk_lagrange_for(C.uint64_t(point), subsetPtr(subset), C.size_t(len(subset)), &out)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	return goBytesAndFree(out), nil
}

// EncryptedSecret is the four-blob envelope published on chain.
type EncryptedSecret struct {
	BindingID []byte
	Capsule   []byte
	Proof     []byte
	CT        []byte
}

// Encrypt seals secrets under the committee joint public key. A nil bindingID
// causes a random one to be generated (returned in the result).
func Encrypt(jointPk []byte, epoch uint32, secrets, aad, bindingID []byte) (*EncryptedSecret, error) {
	if len(jointPk) == 0 || len(secrets) == 0 {
		return nil, ErrInvalidArg
	}
	var out C.MsdkEnvelope
	rc := C.msdk_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&jointPk[0])), C.size_t(len(jointPk)),
		C.uint32_t(epoch),
		(*C.uint8_t)(unsafe.Pointer(&secrets[0])), C.size_t(len(secrets)),
		bytesPtr(aad), C.size_t(len(aad)),
		bytesPtr(bindingID), C.size_t(len(bindingID)),
		&out,
	)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	return &EncryptedSecret{
		BindingID: goBytesAndFree(out.binding_id),
		Capsule:   goBytesAndFree(out.capsule),
		Proof:     goBytesAndFree(out.proof),
		CT:        goBytesAndFree(out.ct),
	}, nil
}

func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// VerifyPlaintextProof checks a capsule's version-tagged plaintext proof up front.
func VerifyPlaintextProof(jointPk, capsule, proof, bindingID []byte, epoch uint32) (bool, error) {
	var valid C.uint8_t
	rc := C.msdk_verify_plaintext_proof(
		bytesPtr(jointPk), C.size_t(len(jointPk)),
		bytesPtr(capsule), C.size_t(len(capsule)),
		bytesPtr(proof), C.size_t(len(proof)),
		bytesPtr(bindingID), C.size_t(len(bindingID)),
		C.uint32_t(epoch), &valid,
	)
	if err := errFromCode(rc); err != nil {
		return false, err
	}
	return valid != 0, nil
}

// PartialInput is one collected committee partial, ready for OpenSecret.
type PartialInput struct {
	Point      uint64 // the responding node's 1-based dkg_index
	Partial    []byte // bincode PartialDecryption from the node
	Proof      []byte // bincode PartDecProof from the node
	Commitment []byte // bincode FeldmanCommitment read from chain, never from the node
}

// OpenSecret verifies the quorum, aggregates, and AEAD-opens the payload.
// secretID is the 16 big-endian id bytes. The core derives each Lagrange
// coefficient from the points and rejects a zero or repeated point.
//
// The returned plaintext is sensitive: never log it, and Wipe it when done.
// The core's own copy is wiped before it is freed.
func OpenSecret(sharedA, capsule []byte, secretID [16]byte, epoch uint32, bindingID, aad, ct []byte, partials []PartialInput) ([]byte, error) {
	// Pin every Go buffer we hand to C inside the MsdkPartialInput array: cgo
	// forbids passing Go memory that contains unpinned Go pointers.
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pin := func(b []byte) *C.uint8_t {
		if len(b) == 0 {
			return nil
		}
		pinner.Pin(&b[0])
		return (*C.uint8_t)(unsafe.Pointer(&b[0]))
	}

	cParts := make([]C.MsdkPartialInput, len(partials))
	for i := range partials {
		p := partials[i]
		cParts[i] = C.MsdkPartialInput{
			point:          C.uint64_t(p.Point),
			partial:        pin(p.Partial),
			partial_len:    C.size_t(len(p.Partial)),
			proof:          pin(p.Proof),
			proof_len:      C.size_t(len(p.Proof)),
			commitment:     pin(p.Commitment),
			commitment_len: C.size_t(len(p.Commitment)),
		}
	}
	var partsPtr *C.MsdkPartialInput
	if len(cParts) > 0 {
		pinner.Pin(&cParts[0])
		partsPtr = &cParts[0]
	}

	var out C.MsdkBuf
	rc := C.msdk_open_secret(
		bytesPtr(sharedA), C.size_t(len(sharedA)),
		bytesPtr(capsule), C.size_t(len(capsule)),
		(*C.uint8_t)(&secretID[0]), C.uint32_t(epoch),
		bytesPtr(bindingID), C.size_t(len(bindingID)),
		bytesPtr(aad), C.size_t(len(aad)),
		bytesPtr(ct), C.size_t(len(ct)),
		partsPtr, C.size_t(len(cParts)),
		&out,
	)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	return goBytesAndFree(out), nil
}
