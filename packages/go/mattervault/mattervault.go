// Package mattervault is the Go binding for MatterVault.
//
// SCAFFOLD — proof-of-binding. The crypto calls below are wired through cgo to
// the one shared Rust core (crates/matter-vault-ffi); the full committee client,
// quorum orchestration, and Signer abstraction are tracked in docs/parity.md and
// not yet implemented. What IS implemented here (Encrypt, SigningPayload,
// LagrangeFor) calls real core crypto and must match the Rust/TS bindings against
// testvectors/.
//
// Build prerequisites:
//
//	cargo build -p matter-vault-ffi --release   # produces target/release/libmatter_vault_ffi.a
//	go test ./...
package mattervault

/*
#cgo CFLAGS: -I${SRCDIR}/../../../crates/matter-vault-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -lmatter_vault_ffi -lm
#include "matter_vault.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// Error codes mirror the C ABI.
var (
	ErrInvalidArg = fmt.Errorf("matter-vault: invalid argument")
	ErrCrypto     = fmt.Errorf("matter-vault: cryptographic operation failed")
)

func errFromCode(rc C.int32_t) error {
	switch rc {
	case C.MV_OK:
		return nil
	case C.MV_ERR_INVALID_ARG:
		return ErrInvalidArg
	default:
		return ErrCrypto
	}
}

// subsetPtr returns a C pointer to the first element of subset (or nil if empty).
// The slice must outlive the C call.
func subsetPtr(subset []uint64) *C.uint64_t {
	if len(subset) == 0 {
		return nil
	}
	return (*C.uint64_t)(unsafe.Pointer(&subset[0]))
}

// goBytesAndFree copies an MvBuf into a Go slice and releases the Rust buffer.
func goBytesAndFree(buf C.MvBuf) []byte {
	defer C.mv_free(buf)
	if buf.ptr == nil || buf.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
}

// SigningPayload returns the canonical bytes a requester signs for a
// /partial-decrypt request, binding (secretID, subset, blockHash).
func SigningPayload(secretID [16]byte, subset []uint64, blockHash [32]byte) ([]byte, error) {
	var out C.MvBuf
	rc := C.mv_signing_payload(
		(*C.uint8_t)(&secretID[0]),
		subsetPtr(subset),
		C.size_t(len(subset)),
		(*C.uint8_t)(&blockHash[0]),
		&out,
	)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	return goBytesAndFree(out), nil
}

// LagrangeFor returns the bincode Lagrange coefficient for point over subset.
func LagrangeFor(point uint64, subset []uint64) ([]byte, error) {
	var out C.MvBuf
	rc := C.mv_lagrange_for(C.uint64_t(point), subsetPtr(subset), C.size_t(len(subset)), &out)
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
	var out C.MvEnvelope
	rc := C.mv_encrypt(
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
	rc := C.mv_verify_plaintext_proof(
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
	Partial    []byte // bincode PartialDecryption from the node
	Proof      []byte // bincode PartDecProof from the node
	Commitment []byte // bincode FeldmanCommitment read from chain
	Lambda     []byte // bincode Lagrange coefficient for the node over the subset
}

// OpenSecret verifies the quorum, aggregates, and AEAD-opens the payload. The
// returned plaintext is sensitive (Go has no zeroizing buffer) — keep it
// short-lived and never log it. secretID is the 16 big-endian id bytes.
func OpenSecret(sharedA, capsule []byte, secretID [16]byte, epoch uint32, bindingID, aad, ct []byte, partials []PartialInput) ([]byte, error) {
	// Pin every Go buffer we hand to C inside the MvPartialInput array: cgo
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

	cParts := make([]C.MvPartialInput, len(partials))
	for i := range partials {
		p := partials[i]
		cParts[i] = C.MvPartialInput{
			partial:        pin(p.Partial),
			partial_len:    C.size_t(len(p.Partial)),
			proof:          pin(p.Proof),
			proof_len:      C.size_t(len(p.Proof)),
			commitment:     pin(p.Commitment),
			commitment_len: C.size_t(len(p.Commitment)),
			lambda:         pin(p.Lambda),
			lambda_len:     C.size_t(len(p.Lambda)),
		}
	}
	var partsPtr *C.MvPartialInput
	if len(cParts) > 0 {
		pinner.Pin(&cParts[0])
		partsPtr = &cParts[0]
	}

	var out C.MvBuf
	rc := C.mv_open_secret(
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
