import { signingPayload } from "./crypto.js";
import { toHex } from "./util.js";

/**
 * How a `/partial-decrypt` request is authorized. `substrate`: an sr25519
 * `MultiSignature` (every signer shipped here). `ethereum`: EIP-712, accepted by
 * the wire protocol but only via a custom {@link Signer}.
 */
export type AuthScheme = "substrate" | "ethereum";

/** Auth fields attached to a `/partial-decrypt` request. */
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
  /** The 1-based `dkg_index` of the node this request is addressed to. */
  recipientIndex: number;
  blockHash: Uint8Array;
  validUntil?: number;
}

/**
 * Authorizes a request without exposing its key to the SDK; the implementor
 * owns the framing (needed for EIP-712, which has no substrate account and
 * signs typed data). Mirrors Rust `matter_sdk::Signer`.
 */
export interface Signer {
  authScheme(): AuthScheme;
  authorize(req: SigningRequest): Promise<RequestAuth>;
}

/**
 * An on-chain identity plus raw-byte signing: all an HSM, KMS, or remote signer
 * must provide. The SDK derives all framing. {@link ApiKey} implements this.
 */
export interface KeySigner {
  readonly accountId: Uint8Array;
  sign(message: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** SCALE enum index of `MultiSignature::Sr25519` (`Ed25519=0, Sr25519=1, Ecdsa=2`). */
const MULTISIGNATURE_SR25519 = 0x01;

/** Length of a raw sr25519 signature, before `MultiSignature` framing. */
const SR25519_SIGNATURE_BYTES = 64;

const ACCOUNT_ID_BYTES = 32;

/**
 * Frame a signature over `req` as Substrate auth fields: an sr25519 signature over
 * the canonical signing payload, wrapped as a SCALE `MultiSignature`, with the raw
 * `AccountId32` as `requester`. Every key-backed signer routes through here.
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

/** Adapt a {@link KeySigner} (API key, HSM/KMS client, wallet) into a {@link Signer}. */
export function keySigner(signer: KeySigner): Signer {
  return {
    authScheme: () => "substrate",
    authorize: (req) => partialDecryptAuth(signer, req),
  };
}

/**
 * Build a Substrate signer from a 32-byte account id and a `sign` callback that
 * returns the 64-byte sr25519 signature over the payload. The key never enters
 * the SDK. Equivalent to `keySigner({ accountId, sign })`.
 */
export function substrateSigner(
  accountId: Uint8Array,
  sign: (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>,
): Signer {
  if (accountId.length !== ACCOUNT_ID_BYTES) throw new Error("accountId must be 32 bytes");
  return keySigner({ accountId, sign });
}
