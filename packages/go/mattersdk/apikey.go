package mattersdk

/*
#include "matter_sdk.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// ApiKey is an OpenMatter API key: parse once, then sign. Parsing and sr25519
// derivation run in the Rust core (vectors: testvectors/api_keys.json).
//
// # Guarantees
//
//   - Key material stays in Rust memory; the only outputs are the public account
//     id and signatures.
//   - String and Format render "ApiKey(sr25519, 0x…, <redacted>)", so the key
//     cannot reach a log through %v, %s, or %+v.
//   - MarshalJSON refuses, so the key cannot reach encoding/json output.
//
// Guardrails constrain accidents, not attackers: anything that can read the
// process can read the key. See docs/secure-signing.md.
//
// # Lifetime
//
// Close releases the Rust-side key and zeroizes its buffers. The finalizer is
// only a backstop; call Close when the key is short-lived.
type ApiKey struct {
	handle *C.MsdkApiKey
	// Public and immutable, so cached.
	accountID []byte
	scheme    string
}

// NewApiKey parses a 0x 32-byte mini-secret, a BIP39 mnemonic, or an sr25519
// SURI with derivation junctions, each optionally prefixed with "sr25519:".
// Surrounding whitespace is ignored. A phrase-less URI (which would derive from
// the public development phrase) is rejected, and a secp256k1: key is reported
// as unsupported. The returned error never contains key material.
func NewApiKey(key string) (*ApiKey, error) {
	raw := []byte(key)
	var ptr *C.uint8_t
	if len(raw) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&raw[0]))
	}

	var handle *C.MsdkApiKey
	rc := C.msdk_apikey_parse(ptr, C.size_t(len(raw)), &handle)
	runtime.KeepAlive(raw)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, ErrBadAPIKey
	}

	k := &ApiKey{handle: handle}
	runtime.SetFinalizer(k, (*ApiKey).Close)

	// cgo functions cannot be passed as values, so these reads are not shared
	// through a helper.
	var accountBuf C.MsdkBuf
	if err := errFromCode(C.msdk_apikey_account_id(k.handle, &accountBuf)); err != nil {
		k.Close()
		return nil, err
	}
	k.accountID = goBytesAndFree(accountBuf)

	var schemeBuf C.MsdkBuf
	if err := errFromCode(C.msdk_apikey_scheme(k.handle, &schemeBuf)); err != nil {
		k.Close()
		return nil, err
	}
	k.scheme = string(goBytesAndFree(schemeBuf))

	return k, nil
}

// AccountID returns the 32-byte on-chain account id this key controls.
// The returned slice is a copy; mutating it does not affect the key.
func (k *ApiKey) AccountID() []byte {
	return append([]byte(nil), k.accountID...)
}

// AccountIDHex returns the account id as 0x + 64 lowercase hex characters.
func (k *ApiKey) AccountIDHex() string { return toHex(k.accountID) }

// Scheme returns the signature scheme token, e.g. "sr25519".
func (k *ApiKey) Scheme() string { return k.scheme }

// Sign returns the raw 64-byte sr25519 signature over msg, with no framing.
func (k *ApiKey) Sign(msg []byte) ([]byte, error) {
	if k.handle == nil {
		return nil, fmt.Errorf("matter-sdk: api key is closed")
	}
	var ptr *C.uint8_t
	if len(msg) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	var out C.MsdkBuf
	rc := C.msdk_apikey_sign(k.handle, ptr, C.size_t(len(msg)), &out)
	runtime.KeepAlive(msg)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	return goBytesAndFree(out), nil
}

// SignExtrinsic implements ExtrinsicSigner. An oversized payload arrives
// already hashed, so it is signed verbatim.
func (k *ApiKey) SignExtrinsic(payload []byte) ([]byte, error) { return k.Sign(payload) }

// Signer adapts the key to the committee Signer interface for /partial-decrypt.
func (k *ApiKey) Signer() (Signer, error) {
	return SubstrateSigner(k.accountID, k.Sign)
}

// Close releases the Rust-side key and zeroizes its buffers. Idempotent; later
// use of the key returns an error.
func (k *ApiKey) Close() {
	if k.handle != nil {
		C.msdk_apikey_free(k.handle)
		k.handle = nil
		runtime.SetFinalizer(k, nil)
	}
}

// String is redacted: it never renders key material.
func (k *ApiKey) String() string {
	return fmt.Sprintf("ApiKey(%s, %s, <redacted>)", k.scheme, k.AccountIDHex())
}

// Format routes every fmt verb through the redacted String.
func (k *ApiKey) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte(k.String()))
}

// MarshalJSON always fails: serializing a credential is almost always a
// mistake, and a redacted placeholder would hide it.
func (k *ApiKey) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("matter-sdk: refusing to serialize an ApiKey; remove it from the value being encoded")
}
