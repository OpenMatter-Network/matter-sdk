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

// ApiKey is an OpenMatter API key: parse once, then sign.
//
// Parsing and sr25519 derivation happen in the shared Rust core, so this
// binding agrees byte-for-byte with every other on testvectors/api_keys.json —
// including the parts that are easy to get wrong natively: applying SURI
// junctions, refusing a phrase-less URI that would fall back to the public
// development phrase, and reporting a reserved secp256k1: scheme as unsupported
// rather than malformed.
//
// # Guarantees
//
//   - The key material stays in Rust memory. There is no accessor for it; the
//     only outputs are the public account id and signatures.
//   - String and Format render "ApiKey(sr25519, 0x…, <redacted>)", so the key
//     cannot reach a log line through %v, %s, or %+v.
//   - MarshalJSON refuses, so the key cannot reach a structured log or a config
//     dump through encoding/json.
//
// Guardrails constrain accidents, not attackers: anything that can read the
// process can read the key. See docs/secure-signing.md for the trade against an
// HSM- or KMS-backed Signer.
//
// # Lifetime
//
// Close releases the Rust-side key and wipes its zeroizing buffers. A finalizer
// is also set, so a forgotten key is eventually released — but finalizers run at
// the garbage collector's discretion, so call Close when the key is short-lived.
type ApiKey struct {
	handle *C.MvApiKey
	// Cached because they are public, immutable, and wanted on every request.
	accountID []byte
	scheme    string
}

// NewApiKey parses a 0x 32-byte mini-secret, a BIP39 mnemonic, or an sr25519
// SURI with derivation junctions — each optionally prefixed with "sr25519:".
//
// Surrounding whitespace is tolerated, since keys arrive from environment
// variables and files. The returned error never contains key material.
func NewApiKey(key string) (*ApiKey, error) {
	raw := []byte(key)
	var ptr *C.uint8_t
	if len(raw) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&raw[0]))
	}

	var handle *C.MvApiKey
	rc := C.mv_apikey_parse(ptr, C.size_t(len(raw)), &handle)
	runtime.KeepAlive(raw)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, ErrBadAPIKey
	}

	k := &ApiKey{handle: handle}
	runtime.SetFinalizer(k, (*ApiKey).Close)

	// Read the two public, immutable attributes once. cgo functions cannot be
	// passed as Go values, so these are spelled out rather than shared through a
	// helper.
	var accountBuf C.MvBuf
	if err := errFromCode(C.mv_apikey_account_id(k.handle, &accountBuf)); err != nil {
		k.Close()
		return nil, err
	}
	k.accountID = goBytesAndFree(accountBuf)

	var schemeBuf C.MvBuf
	if err := errFromCode(C.mv_apikey_scheme(k.handle, &schemeBuf)); err != nil {
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
		return nil, fmt.Errorf("matter-vault: api key is closed")
	}
	var ptr *C.uint8_t
	if len(msg) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	var out C.MvBuf
	rc := C.mv_apikey_sign(k.handle, ptr, C.size_t(len(msg)), &out)
	runtime.KeepAlive(msg)
	if err := errFromCode(rc); err != nil {
		return nil, err
	}
	return goBytesAndFree(out), nil
}

// SignExtrinsic satisfies ExtrinsicSigner, so an ApiKey can sign and submit any
// call. The payload arrives already hashed when oversized, so it is signed
// verbatim.
func (k *ApiKey) SignExtrinsic(payload []byte) ([]byte, error) { return k.Sign(payload) }

// Signer adapts the key to the committee Signer interface, so the same key both
// submits extrinsics and authorizes /partial-decrypt requests.
func (k *ApiKey) Signer() (Signer, error) {
	return SubstrateSigner(k.accountID, k.Sign)
}

// Close releases the Rust-side key and wipes its buffers. Safe to call more than
// once; using the key afterwards returns an error.
func (k *ApiKey) Close() {
	if k.handle != nil {
		C.mv_apikey_free(k.handle)
		k.handle = nil
		runtime.SetFinalizer(k, nil)
	}
}

// String is redacted: it never renders key material.
func (k *ApiKey) String() string {
	return fmt.Sprintf("ApiKey(%s, %s, <redacted>)", k.scheme, k.AccountIDHex())
}

// Format routes every fmt verb — including %v and %+v — through the redacted
// String, so a struct containing an ApiKey cannot print it.
func (k *ApiKey) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte(k.String()))
}

// MarshalJSON refuses rather than emitting the key.
//
// Returning an error rather than a redacted string is deliberate: serializing a
// credential is almost always a mistake, and a silent placeholder would let it
// pass code review. The error names the field so the caller can remove it.
func (k *ApiKey) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("matter-vault: refusing to serialize an ApiKey; remove it from the value being encoded")
}
