package mattersdk

// A strict SCALE reader for read results. Decoders say what they expect, field by
// field, and must consume every byte: a value whose layout the runtime has changed
// fails here instead of decoding into something plausible and wrong.
//
// The reader keeps the first failure and returns zero values after it, so a
// decoder reads straight through and checks once, in finish.

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

const (
	compactModeMask = 0b11
	compactModeBits = 2
	// Compact modes, by the low two bits of the first byte.
	compactOneByte   = 0
	compactTwoBytes  = 1
	compactFourBytes = 2
	// The big-integer mode's first byte carries (byte count - 4) above the mode bits.
	compactBigMinBytes = 4

	scaleBoolFalse  = 0
	scaleBoolTrue   = 1
	scaleOptionNone = 0
	scaleOptionSome = 1

	u128Bytes = 16
)

// The largest value each fixed-width compact mode may carry; a larger mode for it
// is not canonical.
var (
	compactOneByteMax  = big.NewInt(1<<6 - 1)
	compactTwoByteMax  = big.NewInt(1<<14 - 1)
	compactFourByteMax = big.NewInt(1<<30 - 1)
)

// The widest value of each integer type a compact may carry.
var (
	u32Max  = new(big.Int).SetUint64(1<<32 - 1)
	u64Max  = new(big.Int).SetUint64(1<<64 - 1)
	u128Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
)

// scaleReader reads one value's fields in wire order. target names the source in
// errors.
type scaleReader struct {
	data   []byte
	offset int
	target string
	err    error
}

func newScaleReader(target string, data []byte) *scaleReader {
	return &scaleReader{data: data, target: target}
}

func (r *scaleReader) fail(format string, args ...any) {
	if r.err != nil {
		return
	}
	r.err = chainErrorf(KindChain, r.target,
		"%s: the value does not have the layout this SDK decodes: %s",
		r.target, fmt.Sprintf(format, args...))
}

func (r *scaleReader) remaining() int { return len(r.data) - r.offset }

// fixed returns the next n bytes exactly as stored, or n zero bytes after a failure.
func (r *scaleReader) fixed(n int) []byte {
	if r.err == nil && n > r.remaining() {
		r.fail("needs %d more bytes at offset %d, has %d", n, r.offset, r.remaining())
	}
	if r.err != nil {
		return make([]byte, n)
	}
	out := r.data[r.offset : r.offset+n]
	r.offset += n
	return out
}

func (r *scaleReader) u8() uint8   { return r.fixed(1)[0] }
func (r *scaleReader) u16() uint16 { return binary.LittleEndian.Uint16(r.fixed(2)) }
func (r *scaleReader) u32() uint32 { return binary.LittleEndian.Uint32(r.fixed(4)) }
func (r *scaleReader) u64() uint64 { return binary.LittleEndian.Uint64(r.fixed(8)) }

// u128 is never nil.
func (r *scaleReader) u128() *big.Int { return littleEndianInt(r.fixed(u128Bytes)) }

func littleEndianInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i, b := range le {
		be[len(le)-1-i] = b
	}
	return new(big.Int).SetBytes(be)
}

func (r *scaleReader) boolean() bool {
	switch b := r.u8(); b {
	case scaleBoolFalse:
		return false
	case scaleBoolTrue:
		return true
	default:
		r.fail("a bool is 0 or 1, found %d", b)
		return false
	}
}

// compact reads a compact-encoded unsigned integer no wider than widest, refusing
// any encoding longer than needed: the reference codec refuses both. Never nil.
func (r *scaleReader) compact(widest *big.Int) *big.Int {
	if r.err == nil && r.remaining() == 0 {
		r.fail("needs a compact integer, has no bytes left")
	}
	if r.err != nil {
		return new(big.Int)
	}
	value := r.compactValue()
	if r.err == nil && value.Cmp(widest) > 0 {
		r.fail("a compact integer of %s is wider than its type", value)
	}
	if r.err != nil {
		return new(big.Int)
	}
	return value
}

func (r *scaleReader) compactValue() *big.Int {
	switch r.data[r.offset] & compactModeMask {
	case compactOneByte:
		return big.NewInt(int64(r.u8() >> compactModeBits))
	case compactTwoBytes:
		return r.canonical(big.NewInt(int64(r.u16()>>compactModeBits)), compactOneByteMax)
	case compactFourBytes:
		return r.canonical(big.NewInt(int64(r.u32()>>compactModeBits)), compactTwoByteMax)
	default:
		body := r.fixed(int(r.u8()>>compactModeBits) + compactBigMinBytes)
		if r.err == nil && body[len(body)-1] == 0 {
			r.fail("a compact integer has a leading zero byte")
		}
		return r.canonical(littleEndianInt(body), compactFourByteMax)
	}
}

// canonical returns value, which a shorter mode could not have carried.
func (r *scaleReader) canonical(value, shorterModeMax *big.Int) *big.Int {
	if r.err == nil && value.Cmp(shorterModeMax) <= 0 {
		r.fail("a compact integer is not in its shortest form")
	}
	return value
}

func (r *scaleReader) compactU32() uint32 { return uint32(r.compact(u32Max).Uint64()) }
func (r *scaleReader) compactU64() uint64 { return r.compact(u64Max).Uint64() }

// compactU128 is never nil.
func (r *scaleReader) compactU128() *big.Int { return r.compact(u128Max) }

// length reads a compact length, checked against what is left so garbage cannot
// ask for gigabytes.
func (r *scaleReader) length() int {
	n := int64(r.compactU32())
	if r.err == nil && n > int64(r.remaining()) {
		r.fail("a length of %d runs past the input (%d bytes left)", n, r.remaining())
	}
	if r.err != nil {
		return 0
	}
	return int(n)
}

// bytes reads a length-prefixed byte string (Vec<u8>, BoundedVec<u8>).
func (r *scaleReader) bytes() []byte { return r.fixed(r.length()) }

// isSome reads an Option's tag: the caller reads the value only when it is true.
func (r *scaleReader) isSome() bool {
	switch tag := r.u8(); tag {
	case scaleOptionNone:
		return false
	case scaleOptionSome:
		return true
	default:
		r.fail("an option tag is 0 or 1, found %d", tag)
		return false
	}
}

// finish asserts the value ended where the layout says it does, and reports the
// first failure of the whole read.
func (r *scaleReader) finish() error {
	if r.err == nil && r.remaining() != 0 {
		r.fail("%d bytes left over", r.remaining())
	}
	return r.err
}

// readVec reads a length-prefixed sequence; item reads one element. Never nil.
func readVec[T any](r *scaleReader, item func(*scaleReader) T) []T {
	n := r.length()
	out := make([]T, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, item(r))
	}
	return out
}

// decodeStrict decodes data as exactly what read reads: nothing missing, nothing
// left over.
func decodeStrict[T any](target string, data []byte, read func(*scaleReader) T) (T, error) {
	r := newScaleReader(target, data)
	value := read(r)
	if err := r.finish(); err != nil {
		var zero T
		return zero, err
	}
	return value, nil
}
