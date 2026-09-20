// What a re-read of the chain's grant says about the one a client holds.
//
// Split out from the backend so the decision can be tested without a node: the
// rest of the delegated failure path needs @polkadot/api, this does not.

import type { ScopeSet } from "./scopes.js";

/** The grant a delegated client was built with. */
export interface Grant {
  readonly principal: Uint8Array;
  readonly scopes: ScopeSet;
}

/** How a fresh grant compares to the held one. */
export type Refresh =
  /** The same principal with the same scopes. */
  | { readonly outcome: "unchanged" }
  /** Still this member, but the scopes moved. */
  | { readonly outcome: "rescoped"; readonly scopes: ScopeSet }
  /** Revoked, or rebound to a different member. */
  | { readonly outcome: "gone" };

const sameAccount = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

/**
 * Compare a fresh grant against the one held.
 *
 * Note what "gone" does *not* license: falling back to direct signing. A revoked
 * key that started signing as itself would fail the next call for want of funds
 * it was never meant to hold, and the caller would read "cannot pay fees"
 * instead of "your key was revoked".
 */
export function afterRefresh(
  previous: Grant,
  fresh: readonly [Uint8Array, ScopeSet] | undefined,
): Refresh {
  if (fresh === undefined) return { outcome: "gone" };
  const [principal, scopes] = fresh;
  if (!sameAccount(principal, previous.principal)) return { outcome: "gone" };
  if (scopes.bits !== previous.scopes.bits) return { outcome: "rescoped", scopes };
  return { outcome: "unchanged" };
}

/** Substrate's "Invalid Transaction" JSON-RPC error code. */
const POOL_REJECTION_CODE = 1010;

/**
 * Markers for a pool rejection when the JSON-RPC code is unavailable. The same
 * list the Rust client uses, so the bindings agree on what one looks like.
 */
const POOL_REJECTION_MARKERS = ["1010", "Inability to pay", "InvalidTransaction"];

/**
 * Whether the node refused a transaction at validation rather than the runtime
 * refusing it at dispatch.
 *
 * A balance-less key whose call the runtime will not admit is not sponsored at
 * fee time, so it is refused here, before any block. That is why a revoked key
 * reports "cannot pay fees" and never `Proxy.NotProxy`.
 */
export function isPoolRejection(cause: unknown): boolean {
  if (cause === undefined || cause === null) return false;
  const code = (cause as { code?: unknown }).code;
  if (typeof code === "number" && code === POOL_REJECTION_CODE) return true;
  const text = cause instanceof Error ? cause.message : String(cause);
  return POOL_REJECTION_MARKERS.some((marker) => text.includes(marker));
}
