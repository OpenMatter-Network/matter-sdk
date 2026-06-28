/**
 * MatterVault — TypeScript SDK.
 *
 * Seal secrets under the matter-kgc committee and recover them through a signed,
 * threshold `/partial-decrypt` quorum. The cryptography runs in a shared wasm core
 * (the same core the Rust SDK uses); this package adds the committee client, the
 * quorum orchestration, the bring-your-own-{@link Signer}, and the on-chain call
 * builders. You submit transactions with your own Substrate client.
 *
 * @example
 * ```ts
 * import { encrypt, decrypt, FetchTransport, substrateSigner, Aad, storeSecret } from "@openmatter-network/matter-vault";
 *
 * const env = encrypt(jointPk, epoch, new TextEncoder().encode("API_KEY=swordfish"), Aad.EnvV1);
 * // submit storeSecret(env, epoch, "prod", Aad.EnvV1) with your chain client...
 *
 * const signer = substrateSigner(accountId, (payload) => pair.sign(payload)); // key stays in `pair`
 * const plaintext = await decrypt(new FetchTransport(), signer, {
 *   secretId, epoch, bindingId: env.bindingId, aad: Aad.EnvV1,
 *   capsule: env.capsule, ct: env.ct, sharedA, blockHash, threshold, nodes,
 * });
 * ```
 */

export { Aad, aadBytes } from "./aad.js";
export { encrypt, signingPayload, lagrangeFor, verifyPlaintextProof, openSecret } from "./crypto.js";
export type { EncryptedSecret, PartialInput } from "./types.js";
export { substrateSigner } from "./signer.js";
export type { Signer, SigningRequest, RequestAuth, AuthScheme } from "./signer.js";
export {
  decrypt,
  DecryptError,
  FetchTransport,
} from "./committee.js";
export type {
  CommitteeNode,
  DecryptParams,
  DecryptErrorKind,
  Transport,
  Health,
  PartialDecryptRequest,
  PartialDecryptResponse,
} from "./committee.js";
export { storeSecret, rotateSecret, grantAccess } from "./calls.js";
export type { StoreSecret, RotateSecret, GrantAccess } from "./calls.js";
export { toHex, fromHex, secretIdToHex } from "./util.js";
