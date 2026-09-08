// Typed client failures. Branch on `kind`, never on message text — the same
// convention `DecryptError` already establishes in @openmatter-network/matter-vault.

export type ClientErrorKind =
  /** The client has no signer, so it cannot submit or authorize. */
  | "read-only"
  /** The connection configuration is inconsistent. */
  | "config"
  /** A chain read or submission failed. */
  | "chain"
  /** A signing client was pointed at mainnet without explicit confirmation. */
  | "mainnet-not-confirmed"
  /** The endpoint serves a different network than the config selected. */
  | "wrong-network"
  /** A submitted extrinsic did not finalize within the budget. */
  | "finality-timeout"
  /** A member-tied API key was asked for a call its scopes do not cover. */
  | "not-permitted"
  /** The call is admitted to no API key, whatever its scopes. */
  | "never-admitted"
  /** A delegated call landed, but the call it wrapped failed. */
  | "dispatch"
  /** The key's proxy is gone, or now points at a different member. */
  | "key-revoked"
  /** The call is within the key's scopes, but nobody would pay for it. */
  | "unsponsored";

/** A typed client failure. */
export class ClientError extends Error {
  readonly kind: ClientErrorKind;
  /** The `pallet.item` involved, when the failure has one. */
  readonly target?: string;

  constructor(kind: ClientErrorKind, message: string, target?: string) {
    super(message);
    this.name = "ClientError";
    this.kind = kind;
    this.target = target;
  }

  static readOnly(): ClientError {
    return new ClientError(
      "read-only",
      "this client is read-only: build it with an api key or a signer to submit",
    );
  }

  static config(detail: string): ClientError {
    return new ClientError("config", `configuration error: ${detail}`);
  }

  static chain(target: string, detail: string): ClientError {
    return new ClientError("chain", `chain error at ${target}: ${detail}`, target);
  }

  static mainnetNotConfirmed(chainName: string, detectedVia: string): ClientError {
    return new ClientError(
      "mainnet-not-confirmed",
      `refusing to build a signing client against mainnet "${chainName}" ` +
        `(detected via ${detectedVia}) without explicit confirmation: set ` +
        `MATTER_CONFIRM=yes or pass confirmMainnet: true. ` +
        "This client can spend real funds",
    );
  }

  static wrongNetwork(expected: string, actual: string): ClientError {
    return new ClientError(
      "wrong-network",
      `expected the ${expected} network but the endpoint serves "${actual}"`,
    );
  }

  /**
   * The key's scopes do not cover this call. Caught before submission — the
   * chain would refuse it too, but a balance-less delegated key is refused in
   * the *pool*, for want of funds, so the chain's own answer names neither the
   * call nor the missing scope.
   */
  static notPermitted(target: string, required: string, held: string): ClientError {
    return new ClientError(
      "not-permitted",
      `key lacks ${required} for ${target}; it holds ${held}`,
      target,
    );
  }

  /**
   * No API key may make this call, whatever its scopes: token movement,
   * staking, governance, sudo, root-only and provider-signed calls, org
   * lifecycle, and the roster calls a key would otherwise use to widen itself.
   */
  static neverAdmitted(target: string): ClientError {
    return new ClientError(
      "never-admitted",
      `${target} is never admitted to an api key; sign it with the member's own key`,
      target,
    );
  }

  /**
   * A delegated call landed and the outer `proxy.proxy` succeeded, but the call
   * it wrapped failed. This is the error a direct dispatch would have produced;
   * `proxy.proxy` reports it as an event rather than a dispatch error.
   */
  static dispatch(target: string, detail: string): ClientError {
    return new ClientError("dispatch", `${target} failed under delegation: ${detail}`, target);
  }

  static keyRevoked(target: string): ClientError {
    return new ClientError(
      "key-revoked",
      `this key's proxy is gone or now points at a different member, so ${target} was ` +
        "refused; mint a new key or have the member re-authorize this one",
      target,
    );
  }

  static unsponsored(target: string, principal: string): ClientError {
    return new ClientError(
      "unsponsored",
      `${target} is within this key's scopes, but nobody would pay for it: ` +
        `${principal} and their billing org must cover the fee`,
      target,
    );
  }

  static finalityTimeout(target: string, waitedMs: number): ClientError {
    return new ClientError(
      "finality-timeout",
      `${target} did not finalize within ${waitedMs}ms; it may still land, so ` +
        "check the chain before resubmitting",
      target,
    );
  }
}
