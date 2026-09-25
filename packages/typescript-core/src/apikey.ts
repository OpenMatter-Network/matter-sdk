import type { KeySigner } from "./signer.js";
import { wasm } from "./wasm.js";

/** Signature schemes an API key can carry. `secp256k1` is reserved, not yet supported. */
export type KeyScheme = "sr25519";

/**
 * An OpenMatter API key: parse once, then sign.
 *
 * - **Redacted.** `toString()`, `toJSON()` and Node `inspect` render
 *   `ApiKey(sr25519, 0x…, <redacted>)`.
 * - **No accessor for the secret.** It stays in wasm memory; the only outputs
 *   are the account id and signatures.
 *
 * Guardrails constrain accidents, not attackers: anything that can read the
 * process can read the key. See `docs/secure-signing.md` for an HSM/KMS-backed
 * {@link KeySigner} instead.
 *
 * The key is not wiped automatically (JS has no destructors). Call
 * {@link ApiKey.free} when a short-lived key is done.
 *
 * @example
 * ```ts
 * const key = new ApiKey(process.env.MATTER_API_KEY!);
 * console.log(key.accountIdHex);   // 0x46ebddef…
 * console.log(`${key}`);           // ApiKey(sr25519, 0x46ebddef…, <redacted>)
 * ```
 */
export class ApiKey implements KeySigner {
  readonly #inner: InstanceType<typeof wasm.ApiKey>;

  /**
   * Parse a `0x` 32-byte mini-secret, a BIP39 mnemonic, or an sr25519 SURI,
   * each optionally prefixed with `"sr25519:"`.
   *
   * @throws if the key is empty, names an unsupported scheme (`secp256k1:` is
   * reserved), is malformed, or fails derivation. The message never contains
   * key material.
   */
  constructor(key: string) {
    this.#inner = new wasm.ApiKey(key);
  }

  get scheme(): KeyScheme {
    return this.#inner.scheme as KeyScheme;
  }

  /** The 32-byte on-chain account id this key controls. */
  get accountId(): Uint8Array {
    return this.#inner.accountId;
  }

  /** The same account id as `0x` + 64 lowercase hex characters. */
  get accountIdHex(): string {
    return this.#inner.accountIdHex;
  }

  /** Sign `message`, returning the raw 64-byte sr25519 signature (no framing). */
  sign(message: Uint8Array): Uint8Array {
    return this.#inner.sign(message);
  }

  /** Drop the Rust-side key and wipe its zeroizing buffers. Later use throws. */
  free(): void {
    this.#inner.free();
  }

  /** Redacted. Never renders the key. */
  toString(): string {
    return this.#inner.toString();
  }

  /** Redacted, so `JSON.stringify(key)` cannot serialize key material. */
  toJSON(): string {
    return this.#inner.toJSON();
  }

  /** Redacted, so `console.log(key)` in Node cannot print key material. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.#inner.toString();
  }
}
