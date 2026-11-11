// OpenMatter Login: a 32-byte seed sealed under the committee key, owned on
// chain by the seed's own account, and released only to the holder of a
// sign-in token for the `(app, issuer, subject)` registered for it.
//
// The byte contract lives in the wasm core (pinned by testvectors/login.json);
// this file is the client shell around it. It holds no chain client: the caller
// submits `register_login` and reads `LoginsApi_login_for` with its own, using
// the argument and decoding helpers here. See docs/login.md.
//
// A sign-in token is a bearer credential for up to ten minutes. Nothing here
// logs one, and no error message contains one.

import { decrypt } from "./committee.js";
import type { DecryptParams, LoginTransport, Transport } from "./committee.js";
import { sealFor } from "./crypto.js";
import { LoginAccountMismatch, LoginError, redactToken } from "./loginwire.js";
import type { AttestLoginRequest, AttestLoginResponse, LoginAttestationFault } from "./loginwire.js";
import { partialDecryptAuth } from "./signer.js";
import type { Signer } from "./signer.js";
import type { EncryptedSecret } from "./types.js";
import { fromHex, toHex, wipe } from "./util.js";
import { wasm } from "./wasm.js";

/** The generation of a login that has never been rotated. */
export const LOGIN_FIRST_GENERATION = 0;
/** Bytes of a login seed (an sr25519 mini-secret). */
export const LOGIN_SEED_BYTES = 32;
/** The runtime API (by `state_call` name) that answers {@link loginForArgs}. */
export const LOGIN_FOR_RUNTIME_API = "LoginsApi_login_for";

const ID_BYTES = 32;
const SR25519_SIGNATURE_BYTES = 64;
const ENCODER = new TextEncoder();

function requireLength(name: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) {
    throw new LoginError("invalid-input", `${name} must be ${expected} bytes, got ${bytes.length}`);
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

// ---- The byte contract ------------------------------------------------------

/**
 * Who a login belongs to: 32 bytes binding the app and a token's `iss` and
 * `sub`. The same person in two apps has two unrelated identities. The
 * audience is not part of it.
 */
export function loginIdentity(appId: Uint8Array, issuer: string, subject: string): Uint8Array {
  return wasm.loginIdentity(appId, ENCODER.encode(issuer), ENCODER.encode(subject));
}

/**
 * The `nonce` to request a sign-in token with, so the token is only usable
 * with the sr25519 key `requester` (32 bytes). 64 lowercase hex characters.
 */
export function loginNonce(requester: Uint8Array): string {
  return wasm.loginNonce(requester);
}

/** The 32-byte hash an attestation carries of a sealed seed envelope. */
export function loginPayloadHash(
  bindingId: Uint8Array,
  capsule: Uint8Array,
  proof: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  return wasm.loginPayloadHash(bindingId, capsule, proof, ct);
}

/**
 * The bytes a committee node signs to attest a registration, and the session
 * key signs to ask for it. Every byte argument is 32 bytes; `generation` is
 * {@link LOGIN_FIRST_GENERATION} for a first registration.
 */
export function loginAttestationPayload(
  genesis: Uint8Array,
  appId: Uint8Array,
  identity: Uint8Array,
  account: Uint8Array,
  payloadHash: Uint8Array,
  generation: number,
): Uint8Array {
  return wasm.loginAttestationPayload(genesis, appId, identity, account, payloadHash, generation);
}

/** The AAD a login seed is sealed under, for `appId` and `identity` (32 bytes each). */
export function loginSeedAad(appId: Uint8Array, identity: Uint8Array): Uint8Array {
  return wasm.loginSeedAad(appId, identity);
}

/** The 32-byte account id the login seed `seed` (32 bytes) controls. */
export function loginAccount(seed: Uint8Array): Uint8Array {
  return wasm.loginAccount(seed);
}

// ---- The sign-in token ------------------------------------------------------

/** The claims of an ID token a login client reads. See {@link decodeIdTokenClaims}. */
export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud?: string | string[];
  nonce?: string;
  iat?: number;
  exp?: number;
}

const malformedToken = (why: string) => new LoginError("token-malformed", `sign-in token is malformed: ${why}`);

function base64UrlDecode(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw malformedToken("payload is not base64url");
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  try {
    return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  } catch {
    throw malformedToken("payload is not base64url");
  }
}

function optionalClaim<T>(claims: Record<string, unknown>, name: string, is: (v: unknown) => v is T): T | undefined {
  const value = claims[name];
  if (value === undefined || value === null) return undefined;
  if (!is(value)) throw malformedToken(`claim "${name}" has the wrong type`);
  return value;
}

const isString = (v: unknown): v is string => typeof v === "string";
const isNumber = (v: unknown): v is number => typeof v === "number";
const isAudience = (v: unknown): v is string | string[] => isString(v) || (Array.isArray(v) && v.every(isString));

/**
 * Read the claims of an ID token **without verifying anything**: not the
 * signature, not the issuer, not the expiry. The committee verifies the token;
 * a client needs `iss` and `sub` only to compute its {@link loginIdentity}.
 * Never make an access decision from the result.
 *
 * @throws LoginError `token-malformed` if it is not a three-segment JWT whose
 * payload is a JSON object with string `iss` and `sub`. The message never
 * contains any part of the token.
 */
export function decodeIdTokenClaims(idToken: string): IdTokenClaims {
  const segments = idToken.split(".");
  if (segments.length !== 3) throw malformedToken("expected three dot-separated segments");
  const bytes = base64UrlDecode(segments[1]!);
  const claims = (() => {
    try {
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
    } catch {
      throw malformedToken("payload is not UTF-8 JSON");
    }
  })();
  if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
    throw malformedToken("payload is not a JSON object");
  }
  const record = claims as Record<string, unknown>;
  const [iss, sub] = [optionalClaim(record, "iss", isString), optionalClaim(record, "sub", isString)];
  if (iss === undefined || sub === undefined) throw malformedToken('claims "iss" and "sub" are required');
  return {
    iss,
    sub,
    aud: optionalClaim(record, "aud", isAudience),
    nonce: optionalClaim(record, "nonce", isString),
    iat: optionalClaim(record, "iat", isNumber),
    exp: optionalClaim(record, "exp", isNumber),
  };
}

/**
 * The key a sign-in is made with: a fresh sr25519 key per sign-in (the
 * "session key") and the token whose `nonce` is `loginNonce(requester)`.
 * The key owns nothing on chain and can be thrown away afterwards.
 */
export interface LoginSession {
  /** The identity provider's ID token (compact JWS). */
  idToken: string;
  /** The session key's 32-byte sr25519 public key. */
  requester: Uint8Array;
  /** Sign exactly the bytes given; return the raw 64-byte sr25519 signature. */
  sign(payload: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** Refuse locally what every node would refuse: a token minted for another key. */
function requireTokenBoundTo(session: Pick<LoginSession, "idToken" | "requester">): void {
  requireLength("requester", session.requester, ID_BYTES);
  if (decodeIdTokenClaims(session.idToken).nonce !== loginNonce(session.requester)) {
    throw new LoginError(
      "nonce-mismatch",
      "sign-in token is not bound to this session key: its nonce claim must be loginNonce(requester)",
    );
  }
}

/**
 * A {@link Signer} for OpenMatter Login: every answer carries the sign-in
 * token and the app id beside an sr25519 signature by the session key, and the
 * request builder forwards them as `auth: "oidc"`, `id_token`, `app_id`.
 *
 * Use it with {@link openLogin}. The token is held in a closure: it appears in
 * the answers `authorize` returns and nowhere else.
 *
 * @throws LoginError `nonce-mismatch` if the token was minted for another key,
 * `token-malformed` if it cannot be decoded, `invalid-input` on a wrong width.
 */
export function oidcSigner(args: LoginSession & { appId: Uint8Array }): Signer {
  const { appId, idToken, requester, sign } = args;
  requireLength("appId", appId, ID_BYTES);
  requireTokenBoundTo(args);
  const appIdHex = toHex(appId);
  return {
    authScheme: () => "oidc",
    authorize: async (req) => ({
      ...(await partialDecryptAuth({ accountId: requester, sign }, req)),
      auth: "oidc",
      id_token: idToken,
      app_id: appIdHex,
    }),
  };
}

// ---- Registration -----------------------------------------------------------

/** Everything a first registration is made of. See {@link prepareLoginRegistration}. */
export interface LoginRegistration {
  appId: Uint8Array;
  /** The account the seed controls; it signs `register_login` and owns the secret. */
  account: Uint8Array;
  /** The DKG epoch the seed was sealed under. */
  epoch: number;
  /** `loginIdentity(appId, issuer, subject)`. */
  identity: Uint8Array;
  /** The seed, sealed for `account` under `loginSeedAad(appId, identity)`. */
  envelope: EncryptedSecret;
  /** `loginPayloadHash` of `envelope`. */
  payloadHash: Uint8Array;
  /** The bytes the session key signs for `/attest-login`, and each node signs back. */
  attestationPayload: Uint8Array;
}

/**
 * Seal a new login seed and derive everything its registration needs. Pure:
 * no network.
 *
 * @param args.issuer the token's `iss` claim, byte for byte
 * @param args.subject the token's `sub` claim
 * @param args.account the account `seed` controls ({@link loginAccount})
 * @param args.jointPk bincode `PublicKey` from the chain's `KgcApi::joint_pk()`
 * @param args.seed 32 fresh random bytes; wipe your copy when done
 * @param args.genesis the chain's 32-byte genesis hash
 * @throws LoginAccountMismatch if `seed` does not control `account`: the chain
 * would refuse the envelope, or worse, register a key nobody holds.
 */
export function prepareLoginRegistration(args: {
  appId: Uint8Array;
  issuer: string;
  subject: string;
  account: Uint8Array;
  jointPk: Uint8Array;
  epoch: number;
  seed: Uint8Array;
  genesis: Uint8Array;
}): LoginRegistration {
  const { appId, account, epoch, genesis } = args;
  requireLength("seed", args.seed, LOGIN_SEED_BYTES);
  if (!sameBytes(loginAccount(args.seed), account)) {
    throw new LoginAccountMismatch("the seed does not control the account it is being registered for");
  }
  const identity = loginIdentity(appId, args.issuer, args.subject);
  const envelope = sealFor(account, args.jointPk, epoch, args.seed, loginSeedAad(appId, identity));
  const payloadHash = loginPayloadHash(envelope.bindingId, envelope.capsule, envelope.proof, envelope.ct);
  const attestationPayload = loginAttestationPayload(
    genesis,
    appId,
    identity,
    account,
    payloadHash,
    LOGIN_FIRST_GENERATION,
  );
  return { appId, account, epoch, identity, envelope, payloadHash, attestationPayload };
}

/**
 * The `/attest-login` body for `registration`, signed by the session key so a
 * captured token cannot be attested for another account or envelope.
 */
export async function attestLoginRequest(
  registration: Pick<LoginRegistration, "appId" | "account" | "payloadHash" | "attestationPayload">,
  session: LoginSession,
): Promise<AttestLoginRequest> {
  requireTokenBoundTo(session);
  const signature = await session.sign(registration.attestationPayload);
  requireLength("sr25519 signature", signature, SR25519_SIGNATURE_BYTES);
  return {
    app_id: toHex(registration.appId),
    id_token: session.idToken,
    account: toHex(registration.account),
    payload_hash: toHex(registration.payloadHash),
    requester: toHex(session.requester),
    signature: toHex(signature),
  };
}

/** One committee node's signature over a registration's attestation payload. */
export interface LoginAttestation {
  /** The node's 32-byte seated account. */
  nodeAccount: Uint8Array;
  /** Its 64-byte sr25519 signature. */
  signature: Uint8Array;
}

function attestationOf(response: AttestLoginResponse): LoginAttestation {
  const [nodeAccount, signature] = [fromHex(response.node_account), fromHex(response.signature)];
  requireLength("node_account", nodeAccount, ID_BYTES);
  requireLength("node signature", signature, SR25519_SIGNATURE_BYTES);
  return { nodeAccount, signature };
}

function faultOf(endpoint: string, reason: unknown, idToken: string): LoginAttestationFault {
  const detail = redactToken(reason instanceof Error ? reason.message : String(reason), idToken);
  return reason instanceof LoginError && reason.kind !== "invalid-input"
    ? { endpoint, kind: reason.kind, status: reason.status, detail }
    : { endpoint, kind: "transport", detail };
}

/**
 * Ask every node in `nodes` to attest `request`, in parallel, and resolve as
 * soon as `threshold` **distinct** nodes have signed; a slow node does not
 * delay success.
 *
 * Signatures are not verified here: the chain verifies each against the
 * seated committee when `register_login` is dispatched. A node account that
 * answers twice is counted once.
 *
 * @throws LoginError `already-registered` as soon as any node answers 409 —
 * read the login record and sign in instead; `attestations` when fewer than
 * `threshold` nodes signed, with one `faults` entry per node that did not
 * (each keeps its HTTP status: `401`/`403` means the token was refused, `503`
 * that the node could not check).
 */
export async function collectLoginAttestations(
  transport: Pick<LoginTransport, "attestLogin">,
  nodes: ReadonlyArray<{ endpoint: string }>,
  request: AttestLoginRequest,
  threshold: number,
): Promise<LoginAttestation[]> {
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new LoginError("invalid-input", `threshold must be a positive integer, got ${threshold}`);
  }
  const tooFew = (got: number, faults: LoginAttestationFault[]) =>
    new LoginError(
      "attestations",
      `need ${threshold} attestations, got ${got} from ${nodes.length} nodes` +
        (faults.length ? " — " + faults.map((f) => `${f.endpoint}: ${f.detail}`).join("; ") : ""),
      { faults },
    );
  if (nodes.length < threshold) throw tooFew(0, []);

  return new Promise<LoginAttestation[]>((resolve, reject) => {
    // Shared by the per-node callbacks below; nothing else touches them.
    const signed = new Map<string, LoginAttestation>();
    const faults = new Map<number, LoginAttestationFault>();
    let outstanding = nodes.length;
    let settled = false;
    const settle = (finish: () => void) => {
      if (!settled) {
        settled = true;
        finish();
      }
    };
    const answered = () => {
      outstanding -= 1;
      if (signed.size >= threshold) {
        settle(() => resolve([...signed.values()].slice(0, threshold)));
      } else if (outstanding === 0) {
        const inNodeOrder = [...faults.entries()].sort(([a], [b]) => a - b).map(([, fault]) => fault);
        settle(() => reject(tooFew(signed.size, inNodeOrder)));
      }
    };

    nodes.forEach(({ endpoint }, position) => {
      // `then` on a resolved value, so a transport that throws synchronously is a fault too.
      Promise.resolve()
        .then(() => transport.attestLogin(endpoint, request))
        .then(attestationOf)
        .then(
          (attestation) => {
            const key = toHex(attestation.nodeAccount);
            if (signed.has(key)) {
              faults.set(position, { endpoint, kind: "transport", detail: `node account ${key} already counted` });
            } else {
              signed.set(key, attestation);
            }
          },
          (reason: unknown) => {
            if (reason instanceof LoginError && reason.kind === "already-registered") {
              settle(() => reject(reason));
            }
            faults.set(position, faultOf(endpoint, reason, request.id_token));
          },
        )
        .then(answered);
    });
  });
}

/** Arguments for `logins.registerLogin(app_id, identity, payload, epoch, attestations)`. */
export interface RegisterLogin {
  appId: Uint8Array;
  identity: Uint8Array;
  payload: EncryptedSecret;
  epoch: number;
  /** `Vec<(AccountId, [u8; 64])>`: at least the committee threshold. */
  attestations: Array<[nodeAccount: Uint8Array, signature: Uint8Array]>;
}

/**
 * Build `register_login` args. Submit the call **signed by the registration's
 * account** (the seed's own) with your chain client.
 */
export function registerLogin(
  registration: Pick<LoginRegistration, "appId" | "identity" | "envelope" | "epoch">,
  attestations: readonly LoginAttestation[],
): RegisterLogin {
  return {
    appId: registration.appId,
    identity: registration.identity,
    payload: registration.envelope,
    epoch: registration.epoch,
    attestations: attestations.map((a) => [a.nodeAccount, a.signature]),
  };
}

// ---- The login record -------------------------------------------------------

/** The chain's record of one registered login (`LoginsApi_login_for`). */
export interface LoginRecord {
  /** The account the sealed seed controls. */
  account: Uint8Array;
  /** The sealed secret holding the seed. */
  secretId: bigint;
  /** `0` until the login is rotated. */
  generation: number;
}

/** The `0x` argument bytes for a `state_call` of {@link LOGIN_FOR_RUNTIME_API}. */
export function loginForArgs(appId: Uint8Array, identity: Uint8Array): string {
  requireLength("appId", appId, ID_BYTES);
  requireLength("identity", identity, ID_BYTES);
  return toHex(appId) + toHex(identity).slice(2);
}

const U128_BYTES = 16;
const U32_BYTES = 4;
const RECORD_BYTES = ID_BYTES + U128_BYTES + U32_BYTES;

function littleEndian(bytes: Uint8Array): bigint {
  return bytes.reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
}

/**
 * Decode the SCALE `Option<LoginRecord>` that {@link LOGIN_FOR_RUNTIME_API}
 * returns: `null` when the identity has no login in the app.
 *
 * @throws LoginError `invalid-input` on bytes that are not exactly that shape.
 */
export function decodeLoginRecord(result: Uint8Array | string): LoginRecord | null {
  const bytes = typeof result === "string" ? fromHex(result) : result;
  const [tag, body] = [bytes[0], bytes.subarray(1)];
  if (tag === 0 && body.length === 0) return null;
  if (tag !== 1 || body.length !== RECORD_BYTES) {
    throw new LoginError("invalid-input", `not a SCALE Option<LoginRecord> (${bytes.length} bytes)`);
  }
  return {
    account: body.slice(0, ID_BYTES),
    secretId: littleEndian(body.subarray(ID_BYTES, ID_BYTES + U128_BYTES)),
    generation: Number(littleEndian(body.subarray(ID_BYTES + U128_BYTES))),
  };
}

// ---- Sign-in ----------------------------------------------------------------

/**
 * What {@link openLogin} needs: {@link DecryptParams} for the record's secret,
 * with the AAD replaced by the identity it must have been sealed under.
 */
export type OpenLoginParams = Omit<DecryptParams, "aad"> & {
  appId: Uint8Array;
  /** `loginIdentity(appId, iss, sub)` for the token's claims. */
  identity: Uint8Array;
  /** The login record's `account`, which the recovered seed must control. */
  account: Uint8Array;
};

/**
 * Sign in: recover the login seed from a committee quorum, authorized by the
 * sign-in token `signer` carries (an {@link oidcSigner}).
 *
 * The seed is opened under `loginSeedAad(appId, identity)` — never a
 * caller-supplied AAD — and returned only if it controls `params.account`.
 * Never log it, and {@link wipe} it when done.
 *
 * @throws DecryptError as `decrypt` does (a refused token shows as per-node
 * `partial-decrypt 401`/`403` faults under `kind: "quorum"`);
 * LoginAccountMismatch if the recovered bytes are not the recorded account's
 * key; LoginError `invalid-input` if `signer` is not an oidc signer.
 */
export async function openLogin(
  transport: Transport,
  signer: Signer,
  params: OpenLoginParams,
): Promise<Uint8Array> {
  if (signer.authScheme() !== "oidc") {
    throw new LoginError("invalid-input", 'openLogin needs a signer whose authScheme is "oidc" (see oidcSigner)');
  }
  requireLength("account", params.account, ID_BYTES);
  const { appId, identity, account, ...secret } = params;
  const seed = await decrypt(transport, signer, { ...secret, aad: loginSeedAad(appId, identity) });
  if (seed.length !== LOGIN_SEED_BYTES || !sameBytes(loginAccount(seed), account)) {
    wipe(seed);
    throw new LoginAccountMismatch("the recovered seed does not control the account in the login record");
  }
  return seed;
}
