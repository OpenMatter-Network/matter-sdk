/**
 * MatterVault — TypeScript SDK.
 *
 * Seal secrets under the matter-kgc committee and recover them through a signed,
 * threshold `/partial-decrypt` quorum. The cryptography — and key derivation —
 * run in a shared wasm core (the same core the Rust SDK uses); this package adds
 * the committee client, the quorum orchestration, the signer seam, and the
 * on-chain call builders.
 *
 * You choose where your key lives: an {@link ApiKey} the SDK holds under
 * documented guardrails, or a {@link KeySigner}/{@link Signer} you implement
 * over an HSM, KMS, or wallet. See `docs/secure-signing.md`.
 *
 * @example
 * ```ts
 * import { ApiKey, encrypt, decrypt, FetchTransport, keySigner, Aad } from "@openmatter-network/matter-vault";
 *
 * const env = encrypt(jointPk, epoch, new TextEncoder().encode("API_KEY=swordfish"), Aad.EnvV1);
 * // submit storeSecret(env, epoch, "prod", Aad.EnvV1) with your chain client...
 *
 * const key = new ApiKey(process.env.MATTER_API_KEY!);
 * const plaintext = await decrypt(new FetchTransport(), keySigner(key), {
 *   secretId, epoch, bindingId: env.bindingId, aad: Aad.EnvV1,
 *   capsule: env.capsule, ct: env.ct, sharedA, blockHash, threshold, nodes,
 * });
 * ```
 */

export { Aad, aadBytes } from "./aad.js";
export { encrypt, signingPayload, lagrangeFor, verifyPlaintextProof, openSecret } from "./crypto.js";
export type { EncryptedSecret, PartialInput } from "./types.js";
export { ApiKey } from "./apikey.js";
export type { KeyScheme } from "./apikey.js";
export { substrateSigner, keySigner, partialDecryptAuth } from "./signer.js";
export type { Signer, KeySigner, SigningRequest, RequestAuth, AuthScheme } from "./signer.js";
export {
  decrypt,
  DecryptError,
  FetchTransport,
} from "./committee.js";
export type {
  CommitteeNode,
  DecryptParams,
  DecryptErrorKind,
  FaultStage,
  NodeFault,
  Transport,
  Health,
  PartialDecryptRequest,
  PartialDecryptResponse,
} from "./committee.js";
export {
  storeSecret,
  rotateSecret,
  grantAccess,
  revokeAccess,
  deleteSecret,
  grantToUser,
  grantToDeployment,
} from "./calls.js";
export type {
  StoreSecret,
  RotateSecret,
  GrantAccess,
  RevokeAccess,
  DeleteSecret,
  GrantTarget,
} from "./calls.js";
export { toHex, fromHex, secretIdToHex } from "./util.js";
