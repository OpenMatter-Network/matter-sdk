// The seam between MatterClient and the chain library, so the client is
// testable without a node and `@polkadot/api` stays swappable.

import type { ChainProperties } from "./network.js";
import type { ScopeSet } from "./scopes.js";

/**
 * Who this client's signature speaks for.
 *
 * `delegated`: a member-tied API key (runtime spec >= 322) holding a scoped
 * proxy on its minting member; every call runs as that member. Any key without
 * such a proxy is `direct`.
 */
export type Mode =
  | { readonly kind: "direct" }
  | {
      readonly kind: "delegated";
      /** The member every call runs as, and who pays for it. */
      readonly principal: Uint8Array;
      /** What the chain says this key may do. */
      readonly scopes: ScopeSet;
    };

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

/** What the client needs from a chain library. */
export interface ChainBackend {
  /** Chain identity and unit metadata, read once at connect. */
  properties(): Promise<ChainProperties>;

  /** Who this backend's signature speaks for, resolved at connect. Absent means `direct`. */
  mode?(): Mode;

  /** Who `key` acts for and what it may do; `undefined` when it holds no scoped proxy. */
  agentKey?(key: Uint8Array): Promise<readonly [Uint8Array, ScopeSet] | undefined>;

  /**
   * Sign and submit `pallet.call(args)`, resolving only once **finalized**: the
   * committee authorizes against finalized blocks, so resolving on inclusion
   * yields HTTP 403 on a following decrypt.
   */
  submit(pallet: string, call: string, args: unknown[]): Promise<TxReceipt>;

  /** Read a storage entry; `undefined` when absent. */
  query(pallet: string, entry: string, keys: unknown[]): Promise<unknown>;

  /** Call a runtime API by its `state_call` name. */
  runtimeApi(method: string, argsHex: string): Promise<string>;

  /** Read a pallet constant from the live metadata. */
  constant(pallet: string, name: string): unknown;

  canSign(): boolean;

  /** SS58-encode an account id with the chain's own prefix. */
  encodeAddress(accountId: Uint8Array): string;

  disconnect(): Promise<void>;
}
