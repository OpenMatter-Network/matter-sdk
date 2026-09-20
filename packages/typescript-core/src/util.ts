// Hex + numeric framing helpers shared across the package. These mirror the
// core's `wire` module byte-for-byte so the TS and Rust sides agree.

/** Encode bytes as a `"0x"`-prefixed lowercase hex string. */
export function toHex(bytes: Uint8Array): string {
  let s = "0x";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Decode a `"0x"`-prefixed (or bare) hex string into bytes. */
export function fromHex(s: string): Uint8Array {
  const h = s.startsWith("0x") ? s.slice(2) : s;
  if (h.length % 2 !== 0) throw new Error(`odd-length hex: ${s}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Render a `u128` secret id as `"0x"` + 32 hex chars (16 big-endian bytes). */
export function secretIdToHex(secretId: bigint): string {
  if (secretId < 0n || secretId >= 1n << 128n) throw new Error("secret_id out of u128 range");
  const bytes = new Uint8Array(16);
  let v = secretId;
  for (let i = 15; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return toHex(bytes);
}

/** Coerce a subset of node indices to the `BigUint64Array` the wasm expects. */
export function subsetBig(subset: Array<bigint | number>): BigUint64Array {
  return BigUint64Array.from(subset.map((x) => BigInt(x)));
}
