// The `/attest-login` wire: body shapes, how a refusal's HTTP status is named,
// and the login error type. No networking here; `FetchTransport` uses it.

/** `POST /attest-login` request body. Every field is `0x` hex except `id_token`. */
export interface AttestLoginRequest {
  /** The 32-byte id of the app the token signs in to. */
  app_id: string;
  /** The identity provider's ID token (compact JWS). Never log it. */
  id_token: string;
  /** The 32-byte account being registered for the identity. */
  account: string;
  /** The 32-byte `loginPayloadHash` of the sealed seed envelope. */
  payload_hash: string;
  /** The 32-byte sr25519 public key the token's `nonce` is bound to. */
  requester: string;
  /** `requester`'s 64-byte sr25519 signature over the attestation payload. */
  signature: string;
}

/** `POST /attest-login` response body. */
export interface AttestLoginResponse {
  /** `0x` + the responding node's 32-byte seated account. */
  node_account: string;
  /** `0x` + that account's 64-byte sr25519 signature over the attestation payload. */
  signature: string;
  crypto_protocol_version?: number;
}

/**
 * Distinct login failure causes, so callers branch on `.kind`, never on text.
 *
 * - `already-registered`: the identity has a login (HTTP 409). Sign in instead.
 * - `token-refused`: a node refused the sign-in token or the request signature
 *   (401/403). Another node will say the same; get a new token.
 * - `rate-limited`: 429. Back off.
 * - `unavailable`: the node could not check (503, e.g. it cannot fetch the
 *   issuer's signing keys). Another node may answer.
 * - `transport`: any other status, an unreachable node, or a malformed or
 *   oversized response.
 * - `attestations`: fewer than the threshold of nodes attested; see `faults`.
 * - `token-malformed`: the token is not a decodable JWT with `iss` and `sub`.
 * - `nonce-mismatch`: the token's `nonce` is not `loginNonce(requester)`, so
 *   no node would accept it with this key.
 * - `account-mismatch`: a seed does not control the account it was sealed for
 *   or recorded under ({@link LoginAccountMismatch}).
 * - `invalid-input`: a caller-supplied value has the wrong shape.
 */
export type LoginErrorKind =
  | "already-registered"
  | "token-refused"
  | "rate-limited"
  | "unavailable"
  | "transport"
  | "attestations"
  | "token-malformed"
  | "nonce-mismatch"
  | "account-mismatch"
  | "invalid-input";

/** Why one committee node did not attest. Never carries the token. */
export interface LoginAttestationFault {
  endpoint: string;
  kind: LoginErrorKind;
  /** The node's HTTP status, when it answered with one. */
  status?: number;
  /** The underlying reason, already rendered. */
  detail: string;
}

/** A typed OpenMatter Login failure. Its message never contains a sign-in token. */
export class LoginError extends Error {
  /** The refusing node's HTTP status, when the failure is one node's answer. */
  readonly status?: number;
  /** For `kind === "attestations"`, one entry per node that did not attest. */
  readonly faults: readonly LoginAttestationFault[];

  constructor(
    readonly kind: LoginErrorKind,
    message: string,
    details: { status?: number; faults?: readonly LoginAttestationFault[] } = {},
  ) {
    super(message);
    this.name = "LoginError";
    this.status = details.status;
    this.faults = details.faults ?? [];
  }
}

/**
 * A login seed does not control the account it belongs to. On registration the
 * chain would refuse the envelope; on sign-in the recovered bytes are not the
 * key of the recorded account and must not be used.
 */
export class LoginAccountMismatch extends LoginError {
  constructor(message: string) {
    super("account-mismatch", message);
    this.name = "LoginAccountMismatch";
  }
}

const KIND_BY_STATUS: Readonly<Record<number, LoginErrorKind>> = {
  401: "token-refused",
  403: "token-refused",
  409: "already-registered",
  429: "rate-limited",
  503: "unavailable",
};

/** What a node's non-2xx answer to `/attest-login` means. */
export function attestStatusKind(status: number): LoginErrorKind {
  return KIND_BY_STATUS[status] ?? "transport";
}

const REDACTED = "<redacted>";

/**
 * `text` with every occurrence of `idToken` (and of each of its three
 * segments) replaced, so text that originates outside the SDK — a node's
 * response body, a `fetch` error — can be quoted in a message.
 */
export function redactToken(text: string, idToken: string): string {
  const needles = [idToken, ...idToken.split(".")].filter((needle) => needle.length >= MIN_REDACTED_SEGMENT);
  return needles.reduce((out, needle) => out.split(needle).join(REDACTED), text);
}

/** Shorter fragments (an empty signature segment, `a`) would shred ordinary text. */
const MIN_REDACTED_SEGMENT = 8;
