// Type-resolution smoke test, compiled (never run) by scripts/smoke-npm.sh under
// `moduleResolution: nodenext` — the strictest reader of a package's `exports` map.
//
// If the published types failed to resolve, every import below would silently become
// `any` and a plain usage check would still pass. The @ts-expect-error lines are what
// make this bite: with `any` types they are unused, and an unused expectation is an error.
import { Aad, encrypt, type EncryptedSecret } from "@openmatter-network/matter-sdk-core";
import { MatterClient, type MatterConfig } from "@openmatter-network/matter-sdk";

declare const jointPk: Uint8Array;
declare const config: MatterConfig;

const sealed: EncryptedSecret = encrypt(jointPk, 1, new Uint8Array(), Aad.EnvV1);
export const capsuleLength: number = sealed.capsule.length;
export const client: typeof MatterClient = MatterClient;
export const network: MatterConfig = config;

// @ts-expect-error the epoch is a number, not a string
encrypt(jointPk, "1", new Uint8Array(), Aad.EnvV1);
// @ts-expect-error EncryptedSecret has no such field
export const missing = sealed.noSuchField;
