// Pure delegated-grant decisions, testable without a node.

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
 * "gone" must never fall back to direct signing: the caller would see "cannot
 * pay fees" instead of "key revoked".
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

/** Pool-rejection markers when the JSON-RPC code is unavailable. Must match the Rust client. */
const POOL_REJECTION_MARKERS = ["1010", "Inability to pay", "InvalidTransaction"];

/**
 * Whether the node refused a transaction at pool validation rather than at
 * dispatch. A revoked, balance-less key is refused here ("cannot pay fees"),
 * never with `Proxy.NotProxy`.
 */
export function isPoolRejection(cause: unknown): boolean {
  if (cause === undefined || cause === null) return false;
  const code = (cause as { code?: unknown }).code;
  if (typeof code === "number" && code === POOL_REJECTION_CODE) return true;
  const text = cause instanceof Error ? cause.message : String(cause);
  return POOL_REJECTION_MARKERS.some((marker) => text.includes(marker));
}
