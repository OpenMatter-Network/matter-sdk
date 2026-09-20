// OpenMatter API-key ingestion.
//
// Parsing and sr25519 derivation happen in the shared Rust core (via wasm), not
// in `@polkadot/util-crypto`, so this package agrees byte-for-byte with every
// other binding on `testvectors/api_keys.json`. Only the *framing* of a
// signature into request auth fields is TypeScript's job — see `signer.ts`.

import type { KeySigner } from "./signer.js";
import { wasm } from "./wasm.js";

/** Signature schemes an API key can carry. `secp256k1` is reserved, not yet supported. */
export type KeyScheme = "sr25519";

/**
 * An OpenMatter API key: parse once, then sign.
 *
 * ## Guarantees
 *
 * - **Redacted.** `toString()` and `toJSON()` render `ApiKey(sr25519, 0x…, <redacted>)`,
 *   so the key cannot reach a log line, a `JSON.stringify`, or an error report.
 * - **No accessor for the secret.** The material stays in wasm memory; the only
 *   outputs are the public account id and signatures.
 *
 * Guardrails constrain accidents, not attackers — anything that can read the
 * process can read the key. See `docs/secure-signing.md` for the trade against a
 * {@link KeySigner} backed by an HSM or KMS.
 *
 * ## Lifetime
 *
 * JavaScript has no destructors, so the Rust-side key is *not* wiped
 * automatically. Call {@link ApiKey.free} when done (or use `using` — the wasm
 * class implements `Symbol.dispose`) if the key is short-lived. A key held for
 * the life of the process needs no special handling.
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
   * Parse a `0x` 32-byte mini-secret, a BIP39 mnemonic, or an sr25519 SURI with
   * derivation junctions — each optionally prefixed with `"sr25519:"`.
   *
   * @throws if the key is empty, names an unsupported scheme (`secp256k1:` is
   * reserved but unimplemented), is malformed, or fails derivation. The thrown
   * message never contains key material.
   */
  constructor(key: string) {
    this.#inner = new wasm.ApiKey(key);
  }

  /** The signature scheme this key signs with. */
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

  /**
   * Drop the Rust-side key and let its zeroizing buffers wipe. Using the key
   * afterwards throws. Idempotent in the sense that the wasm binding tolerates
   * a double free.
   */
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
