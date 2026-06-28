// The bring-your-own-signer abstraction. Your key never enters the SDK: you
// provide something that signs the canonical payload, and the SDK frames the
// result into the request's auth fields.

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

/** Per-request context handed to a {@link Signer}. */
export interface SigningRequest {
  secretId: bigint;
  subset: number[];
  blockHash: Uint8Array;
  validUntil?: number;
}

/** Something that authorizes a request without exposing its key to the SDK. */
export interface Signer {
  authScheme(): AuthScheme;
  authorize(req: SigningRequest): Promise<RequestAuth>;
}

/** SCALE enum index of `MultiSignature::Sr25519` (`Ed25519=0, Sr25519=1, Ecdsa=2`). */
const MULTISIGNATURE_SR25519 = 0x01;

/**
 * Build a Substrate signer from a 32-byte account id and an sr25519 signing
 * function. The `sign` callback is where your key lives (a `@polkadot` keyring
 * pair, a wallet, an HSM/KMS adapter) — it receives the canonical payload bytes
 * and returns the 64-byte signature. The key never enters the SDK.
 */
export function substrateSigner(
  accountId: Uint8Array,
  sign: (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>,
): Signer {
  if (accountId.length !== 32) throw new Error("accountId must be 32 bytes");
  const requester = toHex(accountId);
  return {
    authScheme: () => "substrate",
    async authorize(req: SigningRequest): Promise<RequestAuth> {
      const payload = signingPayload(req.secretId, req.subset, req.blockHash);
      const sig = await sign(payload);
      if (sig.length !== 64) throw new Error(`sr25519 signature must be 64 bytes, got ${sig.length}`);
      const multisig = new Uint8Array(65);
      multisig[0] = MULTISIGNATURE_SR25519;
      multisig.set(sig, 1);
      return { auth: "substrate", requester, signature: toHex(multisig) };
    },
  };
}
