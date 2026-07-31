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
  | "finality-timeout";

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

  static finalityTimeout(target: string, waitedMs: number): ClientError {
    return new ClientError(
      "finality-timeout",
      `${target} did not finalize within ${waitedMs}ms; it may still land, so ` +
        "check the chain before resubmitting",
      target,
    );
  }
}
