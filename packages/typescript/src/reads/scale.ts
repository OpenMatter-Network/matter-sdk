// A strict SCALE reader for read results. Decoders say what they expect, field
// by field, and must consume every byte: a value whose layout the runtime has
// changed fails here instead of decoding into something plausible and wrong.

import { ClientError } from "../errors.js";

const COMPACT_MODE_MASK = 0b11;
const COMPACT_MODE_BITS = 2n;
/** Compact modes, by the low two bits of the first byte. */
const enum CompactMode {
  OneByte = 0,
  TwoBytes = 1,
  FourBytes = 2,
  BigInteger = 3,
}
/** The big-integer mode's first byte carries `byte count - 4` above the mode bits. */
const COMPACT_BIG_MIN_BYTES = 4;
/** The largest value each fixed-width mode may carry; a larger mode for it is not canonical. */
const COMPACT_ONE_BYTE_MAX = (1n << 6n) - 1n;
const COMPACT_TWO_BYTE_MAX = (1n << 14n) - 1n;
const COMPACT_FOUR_BYTE_MAX = (1n << 30n) - 1n;

const U32_MAX = (1n << 32n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;

const BOOL_FALSE = 0;
const BOOL_TRUE = 1;
const OPTION_NONE = 0;
const OPTION_SOME = 1;

/** Reads one value's fields in wire order. `target` names the source in errors. */
export class ScaleReader {
  readonly #bytes: Uint8Array;
  readonly #target: string;
  #offset = 0;

  constructor(bytes: Uint8Array, target: string) {
    this.#bytes = bytes;
    this.#target = target;
  }

  #fail(why: string): ClientError {
    return ClientError.chain(
      this.#target,
      `the value does not have the layout this SDK decodes: ${why}`,
    );
  }

  /** The next `length` bytes, exactly as stored. */
  fixed(length: number): Uint8Array {
    const end = this.#offset + length;
    if (end > this.#bytes.length) {
      throw this.#fail(`needs ${length} more bytes at offset ${this.#offset}, has ${this.#bytes.length - this.#offset}`);
    }
    const slice = this.#bytes.slice(this.#offset, end);
    this.#offset = end;
    return slice;
  }

  /** A little-endian unsigned integer of `length` bytes. */
  #unsigned(length: number): bigint {
    return this.fixed(length).reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
  }

  u8(): number {
    return Number(this.#unsigned(1));
  }

  u16(): number {
    return Number(this.#unsigned(2));
  }

  u32(): number {
    return Number(this.#unsigned(4));
  }

  u64(): bigint {
    return this.#unsigned(8);
  }

  u128(): bigint {
    return this.#unsigned(16);
  }

  bool(): boolean {
    const byte = this.u8();
    if (byte === BOOL_FALSE) return false;
    if (byte === BOOL_TRUE) return true;
    throw this.#fail(`a bool is 0 or 1, found ${byte}`);
  }

  /**
   * A compact-encoded unsigned integer no wider than `max`, refusing any encoding
   * longer than needed: the reference codec refuses both, so this does too.
   */
  #compact(max: bigint): bigint {
    const first = this.#bytes[this.#offset];
    if (first === undefined) throw this.#fail("needs a compact integer, has no bytes left");
    const value = this.#compactValue(first);
    if (value > max) throw this.#fail(`a compact integer of ${value} is wider than its type`);
    return value;
  }

  #compactValue(first: number): bigint {
    switch (first & COMPACT_MODE_MASK) {
      case CompactMode.OneByte:
        return this.#unsigned(1) >> COMPACT_MODE_BITS;
      case CompactMode.TwoBytes:
        return this.#canonical(this.#unsigned(2) >> COMPACT_MODE_BITS, COMPACT_ONE_BYTE_MAX);
      case CompactMode.FourBytes:
        return this.#canonical(this.#unsigned(4) >> COMPACT_MODE_BITS, COMPACT_TWO_BYTE_MAX);
      default: {
        const length = (this.u8() >> Number(COMPACT_MODE_BITS)) + COMPACT_BIG_MIN_BYTES;
        const body = this.fixed(length);
        if (body[length - 1] === 0) throw this.#fail("a compact integer has a leading zero byte");
        const value = body.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
        return this.#canonical(value, COMPACT_FOUR_BYTE_MAX);
      }
    }
  }

  /** `value`, which a shorter mode could not have carried. */
  #canonical(value: bigint, shorterModeMax: bigint): bigint {
    if (value <= shorterModeMax) throw this.#fail("a compact integer is not in its shortest form");
    return value;
  }

  /** A `Compact<u32>`: a number, like every integer up to 32 bits. */
  compactU32(): number {
    return Number(this.#compact(U32_MAX));
  }

  compactU64(): bigint {
    return this.#compact(U64_MAX);
  }

  compactU128(): bigint {
    return this.#compact(U128_MAX);
  }

  /** A compact length, checked against what is left so garbage cannot ask for gigabytes. */
  #length(): number {
    const length = this.compactU32();
    const remaining = this.#bytes.length - this.#offset;
    if (length > remaining) {
      throw this.#fail(`a length of ${length} runs past the input (${remaining} bytes left)`);
    }
    return length;
  }

  /** A length-prefixed byte string (`Vec<u8>`, `BoundedVec<u8>`). */
  bytes(): Uint8Array {
    return this.fixed(this.#length());
  }

  /** A length-prefixed sequence; `item` reads one element. */
  vec<T>(item: (reader: ScaleReader) => T): T[] {
    return Array.from({ length: this.#length() }, () => item(this));
  }

  /** An `Option<T>`; `undefined` is `None`. */
  option<T>(item: (reader: ScaleReader) => T): T | undefined {
    const tag = this.u8();
    if (tag === OPTION_NONE) return undefined;
    if (tag === OPTION_SOME) return item(this);
    throw this.#fail(`an option tag is 0 or 1, found ${tag}`);
  }

  /** Assert the value ended where the layout says it does. */
  finish(): void {
    const left = this.#bytes.length - this.#offset;
    if (left !== 0) throw this.#fail(`${left} bytes left over`);
  }
}

/** Decode `bytes` as exactly what `read` reads: nothing missing, nothing left over. */
export function decodeStrict<T>(
  target: string,
  bytes: Uint8Array,
  read: (reader: ScaleReader) => T,
): T {
  const reader = new ScaleReader(bytes, target);
  const value = read(reader);
  reader.finish();
  return value;
}

/** A little-endian unsigned integer of `length` bytes: how SCALE writes `u32` and `u128`. */
function unsignedBytes(value: bigint, length: number): Uint8Array {
  return Uint8Array.from({ length }, (_unused, index) => Number((value >> BigInt(8 * index)) & 0xffn));
}

export function encodeU32(value: number): Uint8Array {
  return unsignedBytes(BigInt(value), 4);
}

export function encodeU128(value: bigint): Uint8Array {
  return unsignedBytes(value, 16);
}

/** A compact length in its shortest form. Lengths here never reach the big-integer mode. */
function encodeCompactLength(length: number): Uint8Array {
  const value = BigInt(length);
  if (value <= COMPACT_ONE_BYTE_MAX) return unsignedBytes(value << COMPACT_MODE_BITS, 1);
  if (value <= COMPACT_TWO_BYTE_MAX) {
    return unsignedBytes((value << COMPACT_MODE_BITS) | BigInt(CompactMode.TwoBytes), 2);
  }
  if (value <= COMPACT_FOUR_BYTE_MAX) {
    return unsignedBytes((value << COMPACT_MODE_BITS) | BigInt(CompactMode.FourBytes), 4);
  }
  throw new RangeError(`${length} bytes is too long to encode`);
}

/** A length-prefixed byte string (`Vec<u8>`). */
export function encodeBytes(bytes: Uint8Array): Uint8Array {
  return concatBytes(encodeCompactLength(bytes.length), bytes);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  return Uint8Array.from(parts.flatMap((part) => Array.from(part)));
}
