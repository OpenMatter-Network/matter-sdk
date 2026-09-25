// Type-resolution smoke test, compiled (never run) by scripts/smoke-npm.sh under nodenext.
// The @ts-expect-error lines fail the build if the types silently resolve to `any`.
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
