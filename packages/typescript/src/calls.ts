// Ready-to-submit on-chain call arguments. The builders take an Aad tag so a
// secret can't be stored under a different AAD than it was sealed with.
//
// These are for callers who submit with their own Substrate client
// (@polkadot/api). @openmatter-network/matter-client can submit them for you —
// see its MatterClient, which is the shorter path for most callers.

import { Aad, aadBytes } from "./aad.js";
import type { EncryptedSecret } from "./types.js";

/** Arguments for `secrets.storeSecret(payload, epoch, label, aad)`. */
export interface StoreSecret {
  payload: EncryptedSecret;
  epoch: number;
  label: Uint8Array;
  aad: Uint8Array;
}

/** Build store args, deriving the AAD bytes from the registry tag used at seal time. */
export function storeSecret(
  payload: EncryptedSecret,
  epoch: number,
  label: Uint8Array | string,
  aad: Aad,
): StoreSecret {
  return {
    payload,
    epoch,
    label: typeof label === "string" ? new TextEncoder().encode(label) : label,
    aad: aadBytes(aad),
  };
}

/** Arguments for `secrets.rotateSecret(secret_id, payload, epoch, aad)`. */
export interface RotateSecret {
  secretId: bigint;
  payload: EncryptedSecret;
  epoch: number;
  aad: Uint8Array;
}

/** Build rotate args from the registry AAD tag used at seal time. */
export function rotateSecret(
  secretId: bigint,
  payload: EncryptedSecret,
  epoch: number,
  aad: Aad,
): RotateSecret {
  return { secretId, payload, epoch, aad: aadBytes(aad) };
}

/**
 * Who a secret is granted to.
 *
 * The chain's `GrantTarget<AccountId>` is an **enum**, not a bare account id.
 * Earlier versions of this builder emitted a raw 32-byte grantee, which the
 * runtime cannot decode — the call data was dead on arrival. Nothing caught it
 * because no end-to-end test exercised `grant`.
 */
export type GrantTarget =
  /** Another user or a resource node, named by account. */
  | { readonly User: Uint8Array }
  /**
   * A deployment: authorizes whichever resource is currently assigned to it, so
   * the owner need not name an account that only exists after assignment.
   */
  | { readonly Deployment: bigint };

const ACCOUNT_ID_BYTES = 32;

/** A grant target naming an account. */
export function grantToUser(account: Uint8Array): GrantTarget {
  if (account.length !== ACCOUNT_ID_BYTES) {
    throw new Error(`account must be ${ACCOUNT_ID_BYTES} bytes, got ${account.length}`);
  }
  return { User: account };
}

/** A grant target naming a deployment. */
export function grantToDeployment(deployment: bigint): GrantTarget {
  return { Deployment: deployment };
}

/** Arguments for `secrets.grantAccess(secret_id, target)`. */
export interface GrantAccess {
  secretId: bigint;
  target: GrantTarget;
}

/** Build grant args for a principal. */
export function grantAccess(secretId: bigint, target: GrantTarget): GrantAccess {
  return { secretId, target };
}

/**
 * Arguments for `secrets.revokeAccess(secret_id, target)`.
 *
 * Revocation is how a leaked signer is contained, so it is a first-class call
 * rather than something callers have to hand-roll.
 */
export interface RevokeAccess {
  secretId: bigint;
  target: GrantTarget;
}

/** Build revoke args. The target must match the grant exactly, or this is a no-op. */
export function revokeAccess(secretId: bigint, target: GrantTarget): RevokeAccess {
  return { secretId, target };
}

/** Arguments for `secrets.deleteSecret(secret_id)`. Owner only, irreversible. */
export interface DeleteSecret {
  secretId: bigint;
}

/** Build delete args. */
export function deleteSecret(secretId: bigint): DeleteSecret {
  return { secretId };
}
