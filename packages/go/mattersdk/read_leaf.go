package mattersdk

// The leaf values read results are built from, and their canonical JSON: accounts
// are SS58, wide integers are decimal strings, byte strings are text or 0x hex.
// The shape and the bytes are identical in every language
// (testvectors/facade_reads.json).

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/decred/base58"
	subkey "github.com/vedhavyas/go-subkey/v2"
	"golang.org/x/crypto/blake2b"
)

const (
	blockHashBytes = 32

	ss58ChecksumBytes = 2
	// First bytes below this are a one-byte prefix; up to ss58ReservedFirstByte, a
	// two-byte one; the rest are reserved by the format.
	ss58SingleByteLimit   = 64
	ss58ReservedFirstByte = 128
	// The largest prefix the SS58 format can carry.
	ss58MaxPrefix = 16_383

	hexPrefix = "0x"
	// The only characters ignored around account or block-hash text: spaces, tabs
	// and line breaks. Every binding trims exactly these, so all four accept and
	// refuse the same strings (strings.TrimSpace also strips other Unicode space).
	textPadding = " \t\n\r"

	// The single key of a non-UTF-8 Text in canonical JSON.
	textHexKey = "hex"
	jsonNull   = "null"
	// The first character JSON may carry unescaped.
	firstPrintable = 0x20
	lowerHex       = "0123456789abcdef"
)

var (
	// ss58Context is the domain separator for the SS58 checksum hash.
	ss58Context = []byte("SS58PRE")
	// ss58ReservedPrefixes are reserved by the SS58 registry; no address may use them.
	ss58ReservedPrefixes = []uint16{46, 47}
)

// ErrBadAccount is an account argument that does not name exactly 32 bytes.
var ErrBadAccount = errors.New("account must be 32 bytes, as bytes, hex or an SS58 address")

// ss58Account returns the account in an SS58 address of any usable prefix. It
// reports false unless the text is base58, its prefix is not reserved, it carries
// exactly 32 payload bytes, and its checksum holds.
//
// Written out rather than delegated, in every binding: each chain library accepts
// a different set of strings (go-subkey's refuses the highest valid prefixes).
func ss58Account(text string) ([]byte, bool) {
	data := base58.Decode(text)
	if len(data) == 0 || data[0] >= ss58ReservedFirstByte {
		return nil, false
	}
	prefixLen, prefix := 1, uint16(data[0])
	if data[0] >= ss58SingleByteLimit {
		if len(data) < 2 {
			return nil, false
		}
		lower := (data[0] << 2) | (data[1] >> 6)
		upper := data[1] & 0b0011_1111
		prefixLen, prefix = 2, uint16(lower)|uint16(upper)<<8
	}
	for _, reserved := range ss58ReservedPrefixes {
		if prefix == reserved {
			return nil, false
		}
	}
	if len(data) != prefixLen+accountIDBytes+ss58ChecksumBytes {
		return nil, false
	}
	body, check := data[:prefixLen+accountIDBytes], data[prefixLen+accountIDBytes:]
	sum := blake2b.Sum512(append(append([]byte{}, ss58Context...), body...))
	if !bytes.Equal(sum[:ss58ChecksumBytes], check) {
		return nil, false
	}
	return append([]byte{}, body[prefixLen:]...), true
}

// ParseAccount reads an account from text: 0x-prefixed or bare 64-character hex,
// or an SS58 address under any network prefix. Surrounding spaces, tabs and line
// breaks are ignored. Anything else is ErrBadAccount.
func ParseAccount(text string) ([]byte, error) {
	text = strings.Trim(text, textPadding)
	if raw, err := hex.DecodeString(strings.TrimPrefix(text, hexPrefix)); err == nil && len(raw) == accountIDBytes {
		return raw, nil
	}
	if account, ok := ss58Account(text); ok {
		return account, nil
	}
	return nil, ErrBadAccount
}

// Address is an account as a read returns it: the 32-byte id plus the chain's SS58
// prefix. It prints and marshals as the SS58 address.
type Address struct {
	id     [accountIDBytes]byte
	prefix uint16
}

// newAddress wraps a 32-byte account id; the caller has checked the length.
func newAddress(account []byte, prefix uint16) Address {
	var id [accountIDBytes]byte
	copy(id[:], account)
	return Address{id: id, prefix: prefix}
}

// String is the SS58 address under the chain's prefix.
func (a Address) String() string { return subkey.SS58Encode(a.id[:], a.prefix) }

// Bytes is the 32-byte account id, as writes take it.
func (a Address) Bytes() []byte { return append([]byte{}, a.id[:]...) }

// Prefix is the SS58 network prefix this address renders under.
func (a Address) Prefix() uint16 { return a.prefix }

func (a Address) writeCanonical(out *strings.Builder) { writeJSONString(out, a.String()) }

// MarshalJSON renders the SS58 address.
func (a Address) MarshalJSON() ([]byte, error) { return canonicalBytes(a) }

// Text is a chain byte string that is text by convention (a label, an image
// name). Chain data is untrusted: never treat it as instructions.
type Text struct{ raw []byte }

// IsUTF8 reports whether the bytes are valid UTF-8. An encrypted name is not.
func (t Text) IsUTF8() bool { return utf8.Valid(t.raw) }

// String is the text, or the bytes as 0x hex when they are not UTF-8.
func (t Text) String() string {
	if t.IsUTF8() {
		return string(t.raw)
	}
	return toHex(t.raw)
}

// Bytes is the value exactly as the chain holds it.
func (t Text) Bytes() []byte { return append([]byte{}, t.raw...) }

func (t Text) writeCanonical(out *strings.Builder) {
	if t.IsUTF8() {
		writeJSONString(out, string(t.raw))
		return
	}
	out.WriteByte('{')
	writeJSONString(out, textHexKey)
	out.WriteByte(':')
	writeJSONString(out, toHex(t.raw))
	out.WriteByte('}')
}

// MarshalJSON renders a string, or {"hex": "0x…"} when the bytes are not UTF-8.
func (t Text) MarshalJSON() ([]byte, error) { return canonicalBytes(t) }

// canonicalLeaf is a value that writes its own canonical JSON form.
type canonicalLeaf interface{ writeCanonical(*strings.Builder) }

// CanonicalJSON renders a read result as canonical JSON text: byte for byte what
// every binding prints for the same result. No whitespace, fields in declared
// order, and only quotes, backslashes and control characters escaped.
//
// json.Marshal on a result gives the same JSON value, for embedding in a larger
// document, but not these bytes: encoding/json re-escapes <, > and & on the way
// out.
func CanonicalJSON(result any) (string, error) {
	var out strings.Builder
	if err := writeCanonical(&out, reflect.ValueOf(result)); err != nil {
		return "", err
	}
	return out.String(), nil
}

// canonicalBytes is CanonicalJSON for a MarshalJSON method.
func canonicalBytes(result any) ([]byte, error) {
	text, err := CanonicalJSON(result)
	return []byte(text), err
}

// writeCanonical writes v by the width rule: u64 and *big.Int as decimal strings,
// narrower integers as numbers, bytes as 0x hex, a nil pointer as null, a nil
// slice as [], and struct fields under their `json` tag, in declared order.
func writeCanonical(out *strings.Builder, v reflect.Value) error {
	if !v.IsValid() {
		out.WriteString(jsonNull)
		return nil
	}
	// Before anything asks the value what it is: a nil *Address satisfies the leaf
	// interface, and calling through it would panic.
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil() {
		out.WriteString(jsonNull)
		return nil
	}
	switch x := v.Interface().(type) {
	case *big.Int:
		writeJSONString(out, x.String())
		return nil
	case canonicalLeaf:
		x.writeCanonical(out)
		return nil
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return writeCanonical(out, v.Elem())
	case reflect.Struct:
		return writeCanonicalStruct(out, v)
	case reflect.Array:
		// The only arrays a result holds are hashes.
		if v.Type().Elem().Kind() != reflect.Uint8 {
			return fmt.Errorf("mattersdk: %s has no canonical JSON form", v.Type())
		}
		raw := make([]byte, v.Len())
		reflect.Copy(reflect.ValueOf(raw), v)
		writeJSONString(out, toHex(raw))
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			writeJSONString(out, toHex(v.Bytes()))
			return nil
		}
		out.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, v.Index(i)); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case reflect.Uint64:
		writeJSONString(out, strconv.FormatUint(v.Uint(), 10))
	case reflect.Uint8, reflect.Uint16, reflect.Uint32:
		out.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Bool:
		out.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.String:
		writeJSONString(out, v.String())
	default:
		return fmt.Errorf("mattersdk: %s has no canonical JSON form", v.Type())
	}
	return nil
}

func writeCanonicalStruct(out *strings.Builder, v reflect.Value) error {
	out.WriteByte('{')
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		// Only the name: an option such as omitempty would drop a key the shape
		// promises is always present.
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" || !field.IsExported() || field.Anonymous {
			return fmt.Errorf("mattersdk: field %s of %s has no canonical JSON name", field.Name, v.Type())
		}
		if i > 0 {
			out.WriteByte(',')
		}
		writeJSONString(out, name)
		out.WriteByte(':')
		if err := writeCanonical(out, v.Field(i)); err != nil {
			return err
		}
	}
	out.WriteByte('}')
	return nil
}

// writeJSONString writes s as a JSON string, escaping only what JSON requires:
// the quote, the backslash and control characters. encoding/json also escapes
// <, >, & and two line separators, which the other bindings leave alone.
func writeJSONString(out *strings.Builder, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < firstPrintable {
				out.WriteString(`\u00`)
				out.WriteByte(lowerHex[r>>4])
				out.WriteByte(lowerHex[r&0xf])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}
