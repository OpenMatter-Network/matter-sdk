package mattersdk

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
)

// SecretID is an on-chain secret identifier, a u128. It is a comparable value
// type whose zero value is valid, and it never truncates.
type SecretID struct {
	hi, lo uint64
}

// NewSecretID builds an id from a uint64, for the common small-id case.
func NewSecretID(v uint64) SecretID { return SecretID{lo: v} }

// SecretIDFromBytes reads a big-endian 16-byte id — the signing-payload form.
func SecretIDFromBytes(b [16]byte) SecretID {
	return SecretID{
		hi: binary.BigEndian.Uint64(b[0:8]),
		lo: binary.BigEndian.Uint64(b[8:16]),
	}
}

// ParseSecretID accepts a decimal string (the testvectors form) or `0x` hex.
func ParseSecretID(s string) (SecretID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return SecretID{}, fmt.Errorf("empty secret id")
	}

	base := 10
	if body, ok := strings.CutPrefix(s, "0x"); ok {
		s, base = body, 16
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok || n.Sign() < 0 {
		return SecretID{}, fmt.Errorf("invalid secret id %q", s)
	}
	if n.BitLen() > 128 {
		return SecretID{}, fmt.Errorf("secret id %q exceeds u128", s)
	}

	var b [16]byte
	n.FillBytes(b[:])
	return SecretIDFromBytes(b), nil
}

// Bytes renders the id as 16 big-endian bytes: the signing-payload form, and
// what the committee reconstructs and verifies.
func (s SecretID) Bytes() [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], s.hi)
	binary.BigEndian.PutUint64(b[8:16], s.lo)
	return b
}

// LEBytes renders the id as 16 little-endian bytes: the SCALE form a runtime-API
// argument takes.
func (s SecretID) LEBytes() [16]byte {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], s.lo)
	binary.LittleEndian.PutUint64(b[8:16], s.hi)
	return b
}

// Hex renders `0x` + 32 hex characters, the wire form of `secret_id`.
func (s SecretID) Hex() string {
	b := s.Bytes()
	return toHex(b[:])
}

// String renders the id in decimal, matching the testvectors representation.
func (s SecretID) String() string { return s.bigInt().String() }

// IsUint64 reports whether the id fits in a uint64.
func (s SecretID) IsUint64() bool { return s.hi == 0 }

// Uint64 returns the id as a uint64. Panics if it does not fit; check IsUint64
// first.
func (s SecretID) Uint64() uint64 {
	if !s.IsUint64() {
		panic(fmt.Sprintf("secret id %s exceeds uint64", s))
	}
	return s.lo
}

// BigInt returns the id as a big.Int, for the codec types that require one.
func (s SecretID) BigInt() *big.Int {
	b := s.Bytes()
	return new(big.Int).SetBytes(b[:])
}

func (s SecretID) bigInt() *big.Int { return s.BigInt() }

// MarshalText renders the decimal form, so JSON never rounds it through float64.
func (s SecretID) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses the decimal or hex form.
func (s *SecretID) UnmarshalText(b []byte) error {
	parsed, err := ParseSecretID(string(b))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}
