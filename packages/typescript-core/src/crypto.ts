// Type-shaping wrappers over the wasm core; no cryptography here.

import { Aad, aadBytes } from "./aad.js";
import type { EncryptedSecret, PartialInput } from "./types.js";
import { secretIdToHex, subsetBig, toHex } from "./util.js";
import { wasm } from "./wasm.js";

/**
 * Seal a secret under the committee joint public key.
 *
 * @param jointPk bincode `PublicKey` from the chain's `KgcApi::joint_pk()`
 * @param epoch current DKG epoch
 * @param plaintext the secret bytes (e.g. `KEY=VALUE` lines)
 * @param aad an {@link Aad} tag (or raw bytes) the secret is bound to
 * @param bindingId optional label; 32 random bytes are generated if omitted
 */
export function encrypt(
  jointPk: Uint8Array,
  epoch: number,
  plaintext: Uint8Array,
  aad: Aad | Uint8Array,
  bindingId?: Uint8Array,
): EncryptedSecret {
  const env = wasm.encryptSecret(jointPk, epoch, plaintext, aadBytes(aad), bindingId);
  // Copy the getters out before the wasm object is GC'd.
  return { bindingId: env.bindingId, capsule: env.capsule, proof: env.proof, ct: env.ct };
}

/**
 * Canonical bytes a requester signs for a `/partial-decrypt` request.
 * `recipientIndex` is the target node's 1-based `dkg_index`: sign once per node
 * so a signature can't be replayed to another node in the subset.
 */
export function signingPayload(
  secretId: bigint,
  subset: Array<bigint | number>,
  blockHash: Uint8Array,
  recipientIndex: bigint | number,
): Uint8Array {
  return wasm.partialDecryptSigningPayload(
    secretIdToHex(secretId),
    subsetBig(subset),
    toHex(blockHash),
    BigInt(recipientIndex),
  );
}

/** Bincode Lagrange coefficient `λ` for `point` over `subset`. */
export function lagrangeFor(point: bigint | number, subset: Array<bigint | number>): Uint8Array {
  return wasm.lagrangeFor(BigInt(point), subsetBig(subset));
}

/** Verify a capsule's ZKPoPlaintext proof up front (before contacting a node). */
export function verifyPlaintextProof(
  jointPk: Uint8Array,
  capsule: Uint8Array,
  taggedProof: Uint8Array,
  bindingId: Uint8Array,
  epoch: number,
): boolean {
  return wasm.verifyPlaintextProof(jointPk, capsule, taggedProof, bindingId, epoch);
}

/** The crypto protocol version the core speaks; `decrypt` drops nodes reporting another. */
export function cryptoProtocolVersion(): number {
  return wasm.cryptoProtocolVersion();
}

/** The cap on a committee node's response body, in bytes. */
export function maxCommitteeResponseBytes(): number {
  return wasm.maxCommitteeResponseBytes();
}

/**
 * Verify the collected quorum's proofs, aggregate, and AEAD-open the payload.
 *
 * The core's copy of the plaintext is wiped; never log the returned array and
 * {@link wipe} it when done.
 */
export function openSecret(args: {
  sharedA: Uint8Array;
  capsule: Uint8Array;
  secretId: bigint;
  epoch: number;
  bindingId: Uint8Array;
  aad: Aad | Uint8Array;
  ct: Uint8Array;
  partials: PartialInput[];
}): Uint8Array {
  return wasm.openSecret(
    args.sharedA,
    args.capsule,
    secretIdToHex(args.secretId),
    args.epoch,
    args.bindingId,
    aadBytes(args.aad),
    args.ct,
    args.partials,
  );
}
