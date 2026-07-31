// Request authorization: who signs a `/partial-decrypt`, and how it is framed.
//
// Two shapes, answering different questions:
//
//   * `KeySigner` — "here is an account and a way to sign bytes." The SDK
//     derives the framing via `partialDecryptAuth`, so the transcript rules live
//     here and cannot drift per integration. An `ApiKey` is one, and so is an
//     HSM/KMS adapter.
//   * `Signer` — "here are the finished auth fields." The implementor owns the
//     framing. This is the general seam, and the one the Ethereum/EIP-712 path
//     needs: an EIP-712 signer has no 32-byte substrate account id and signs
//     structured typed data rather than raw bytes.
//
// This mirrors the Rust split (`matter_vault_key::KeySigner` vs
// `matter_vault::Signer`) so the two languages describe the same seam.

import { signingPayload } from "./crypto.js";
import { toHex } from "./util.js";

export type AuthScheme = "substrate" | "ethereum";

/** Auth fields attached to a `/partial-decrypt` request (see the wire types). */
export interface RequestAuth {
  auth: AuthScheme;
  /** `0x` + SCALE `AccountId` (Substrate) or empty (Ethereum). */
  requester: string;
  /** `0x` + SCALE `MultiSignature` (Substrate) or empty (Ethereum). */
  signature: string;
  eth_address?: string;
  valid_until?: number;
  eth_signature?: string;
}

/** Per-request context handed to a {@link Signer}. One request targets one node. */
export interface SigningRequest {
  secretId: bigint;
  subset: number[];
  /** The 1-based `dkg_index` of the node this request is addressed to (MV-C1). */
  recipientIndex: number;
  blockHash: Uint8Array;
  validUntil?: number;
}

/** Something that authorizes a request without exposing its key to the SDK. */
export interface Signer {
  authScheme(): AuthScheme;
  authorize(req: SigningRequest): Promise<RequestAuth>;
}

/**
 * An on-chain identity plus the ability to sign raw bytes — the only thing an
 * HSM, KMS, or remote-signer integration needs to provide. Every protocol
 * framing the SDK needs is derived from it, so the rules cannot drift per
 * integration. An {@link ApiKey} implements this.
 */
export interface KeySigner {
  readonly accountId: Uint8Array;
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** SCALE enum index of `MultiSignature::Sr25519` (`Ed25519=0, Sr25519=1, Ecdsa=2`). */
const MULTISIGNATURE_SR25519 = 0x01;

/** Length of a raw sr25519 signature, before `MultiSignature` framing. */
const SR25519_SIGNATURE_BYTES = 64;

/** Length of a substrate `AccountId32`. */
const ACCOUNT_ID_BYTES = 32;

/**
 * Frame a signature over `req` as Substrate auth fields.
 *
 * This is the single implementation of the Substrate `/partial-decrypt`
 * transcript: an sr25519 signature over the canonical signing payload, wrapped
 * as a SCALE `MultiSignature`, with the raw `AccountId32` as `requester`. Every
 * key-backed signer routes through here, so the framing cannot diverge between
 * an API key, an HSM adapter, and a test double.
 */
export async function partialDecryptAuth(
  signer: KeySigner,
  req: SigningRequest,
): Promise<RequestAuth> {
  const { accountId } = signer;
  if (accountId.length !== ACCOUNT_ID_BYTES) {
    throw new Error(`accountId must be ${ACCOUNT_ID_BYTES} bytes, got ${accountId.length}`);
  }
  const payload = signingPayload(req.secretId, req.subset, req.blockHash, req.recipientIndex);
  const sig = await signer.sign(payload);
  if (sig.length !== SR25519_SIGNATURE_BYTES) {
    throw new Error(`sr25519 signature must be ${SR25519_SIGNATURE_BYTES} bytes, got ${sig.length}`);
  }
  const multisig = new Uint8Array(1 + SR25519_SIGNATURE_BYTES);
  multisig[0] = MULTISIGNATURE_SR25519;
  multisig.set(sig, 1);
  return { auth: "substrate", requester: toHex(accountId), signature: toHex(multisig) };
}

/**
 * Adapt a {@link KeySigner} — an {@link ApiKey}, an HSM/KMS client, a wallet —
 * into a {@link Signer} the committee client accepts.
 */
export function keySigner(signer: KeySigner): Signer {
  return {
    authScheme: () => "substrate",
    authorize: (req) => partialDecryptAuth(signer, req),
  };
}

/**
 * Build a Substrate signer from a 32-byte account id and an sr25519 signing
 * function. The `sign` callback is where your key lives (a `@polkadot` keyring
 * pair, a wallet, an HSM/KMS adapter) — it receives the canonical payload bytes
 * and returns the 64-byte signature. The key behind this signer never enters
 * the SDK.
 *
 * Equivalent to `keySigner({ accountId, sign })`; kept because it reads better
 * when the key is a closure rather than an object.
 */
export function substrateSigner(
  accountId: Uint8Array,
  sign: (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>,
): Signer {
  if (accountId.length !== ACCOUNT_ID_BYTES) throw new Error("accountId must be 32 bytes");
  return keySigner({ accountId, sign });
}
