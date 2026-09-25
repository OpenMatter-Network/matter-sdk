// On-chain call arguments for callers submitting with their own Substrate client;
// `@openmatter-network/matter-sdk`'s MatterClient submits them for you. Builders
// take an `Aad` tag so a secret is stored under the AAD it was sealed with.

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

/** Who a secret is granted to: the chain's `GrantTarget<AccountId>` enum. */
export type GrantTarget =
  /** Another user or a resource node, named by account. */
  | { readonly User: Uint8Array }
  /** A deployment: authorizes whichever resource is currently assigned to it. */
  | { readonly Deployment: bigint };

const ACCOUNT_ID_BYTES = 32;

/** A grant target naming a 32-byte account id. */
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

export function grantAccess(secretId: bigint, target: GrantTarget): GrantAccess {
  return { secretId, target };
}

/** Arguments for `secrets.revokeAccess(secret_id, target)`. */
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

export function deleteSecret(secretId: bigint): DeleteSecret {
  return { secretId };
}
