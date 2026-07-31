// The seam between MatterClient and the underlying chain library.
//
// The same pattern `Transport` already establishes for the committee: one narrow
// interface, so the client is testable without a node and `@polkadot/api` stays
// swappable (dedot and polkadot-api are each roughly an order of magnitude
// smaller). @polkadot/api is the default because it is what the e2e harness and
// the dashboard already prove works against this runtime's CheckMetadataHash and
// WeightReclaim signed extensions.

import type { ChainProperties } from "./network.js";

/** The outcome of a submitted extrinsic, after finalization. */
export interface TxReceipt {
  /** Hash of the extrinsic. */
  readonly txHash: string;
  /** Hash of the finalized block containing it. */
  readonly blockHash: string;
  /** `[pallet, event]` names emitted by this extrinsic, in order. */
  readonly events: ReadonlyArray<readonly [string, string]>;
}

/** Whether `pallet.event` was emitted. */
export function emitted(receipt: TxReceipt, pallet: string, event: string): boolean {
  return receipt.events.some(([p, e]) => p === pallet && e === event);
}

/**
 * What the client needs from a chain library. Everything above this boundary —
 * the guards, the amount arithmetic, the façades — is a pure function of the
 * properties and the responses.
 */
export interface ChainBackend {
  /** Chain identity and unit metadata, read once at connect. */
  properties(): Promise<ChainProperties>;

  /**
   * Sign and submit `pallet.call(args)`, resolving only once **finalized**.
   *
   * Finalization, not inclusion: the committee authorizes a partial-decrypt
   * against a finalized block, so resolving earlier yields an HTTP 403. That was
   * a real bug in the TypeScript harness before it was fixed.
   */
  submit(pallet: string, call: string, args: unknown[]): Promise<TxReceipt>;

  /** Read a storage entry. `undefined` means absent, which is normal. */
  query(pallet: string, entry: string, keys: unknown[]): Promise<unknown>;

  /** Call a runtime API by its `state_call` name. */
  runtimeApi(method: string, argsHex: string): Promise<string>;

  /** Read a pallet constant from the live metadata. */
  constant(pallet: string, name: string): unknown;

  /** Whether this backend can sign. */
  canSign(): boolean;

  /**
   * SS58-encode an account id with the chain's own prefix.
   *
   * On the backend because SS58 needs base58 and blake2b, which live in the chain
   * library rather than the light package.
   */
  encodeAddress(accountId: Uint8Array): string;

  /** Release the connection. */
  disconnect(): Promise<void>;
}
