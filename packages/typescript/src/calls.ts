// Ready-to-submit on-chain call arguments. The SDK never submits transactions or
// holds keys — you submit these with your own Substrate client (@polkadot/api).
// The builders take an Aad tag so a secret can't be stored under a different AAD
// than it was sealed with.

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

/** Arguments for `secrets.grantAccess(secret_id, grantee)`. */
export interface GrantAccess {
  secretId: bigint;
  grantee: Uint8Array;
}

/** Build grant args; `grantee` is the 32-byte account id being authorized. */
export function grantAccess(secretId: bigint, grantee: Uint8Array): GrantAccess {
  if (grantee.length !== 32) throw new Error("grantee must be a 32-byte account id");
  return { secretId, grantee };
}
