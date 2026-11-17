// Where a read's bytes come from. A domain module names its sources and holds a
// pure decoder; `Snapshot` is the only fetch, and it reads every source at one
// block, so a result never mixes two.

import { toHex } from "@openmatter-network/matter-sdk-core";

import { ClientError } from "../errors.js";
import { bytesFromHex, trimPadding } from "./leaf.js";

const FINALIZED_HEAD = "chain_getFinalizedHead";
const QUERY_STORAGE_AT = "state_queryStorageAt";
const STATE_CALL = "state_call";
const BLOCK_HASH_BYTES = 32;
/** The length of an account id. */
export const ACCOUNT_ID_BYTES = 32;
const NOT_AN_ACCOUNT = "account must be 32 bytes, as bytes, hex or an SS58 address";

/**
 * What reads need from a chain library, below any decoding. A backend that
 * offers it supports every façade read.
 */
export interface RawReads {
  /** One JSON-RPC request, answered with its raw JSON result. */
  rpc(method: string, params: readonly unknown[]): Promise<unknown>;
  /** The raw key `pallet.entry(keys)` is stored under, from the live metadata. */
  storageKey(pallet: string, entry: string, keys: readonly unknown[]): Uint8Array;
  /** A pallet constant's SCALE bytes, from the live metadata. */
  constant(pallet: string, name: string): Uint8Array;
  /**
   * `pallet.call(args)` as it would be submitted, SCALE-encoded: the call
   * itself, or wrapped in `Proxy.proxy` to run as `principal` when one is given.
   * `args` are what `tx` takes.
   */
  callData(pallet: string, call: string, args: readonly unknown[], principal?: Uint8Array): Uint8Array;
  /** The 32-byte account in an SS58 address of any usable prefix; `undefined` if it is not one. */
  ss58Decode(text: string): Uint8Array | undefined;
}

/** A pallet constant, as the runtime metadata spells it. */
export interface ConstantEntry {
  readonly pallet: string;
  readonly name: string;
}

/** A storage entry, as the runtime metadata spells it. */
export interface StorageEntry {
  readonly pallet: string;
  readonly entry: string;
}

/** `Pallet.Entry`: how errors and the read catalogue name a storage source. */
export function targetOf(entry: StorageEntry): string {
  return `${entry.pallet}.${entry.entry}`;
}

/** One storage value to fetch: an entry and its map keys (none for a plain value). */
export interface StorageRequest {
  readonly entry: StorageEntry;
  readonly keys: readonly unknown[];
}

/** A block hash from bytes or hex. Throws `TypeError` unless it is 32 bytes. */
export function blockHash(block: Uint8Array | string): Uint8Array {
  const bytes = typeof block === "string" ? bytesFromHex(trimPadding(block)) : block;
  if (!(bytes instanceof Uint8Array) || bytes.length !== BLOCK_HASH_BYTES) {
    throw new TypeError("a block hash is 32 bytes, as bytes or hex");
  }
  // A copy: the caller may reuse its buffer after pinning.
  return bytes.slice();
}

/**
 * An account from bytes or text: `0x`-prefixed or bare 64-character hex, or an
 * SS58 address under any network prefix, ignoring surrounding spaces, tabs and
 * line breaks. Throws `TypeError` unless it names exactly 32 bytes.
 */
export function accountIdOf(reads: RawReads, who: Uint8Array | string): Uint8Array {
  if (typeof who !== "string") {
    if (!(who instanceof Uint8Array) || who.length !== ACCOUNT_ID_BYTES) {
      throw new TypeError(NOT_AN_ACCOUNT);
    }
    return who.slice();
  }
  const text = trimPadding(who);
  const fromHex = bytesFromHex(text);
  const account = fromHex?.length === ACCOUNT_ID_BYTES ? fromHex : reads.ss58Decode(text);
  if (account === undefined) throw new TypeError(NOT_AN_ACCOUNT);
  return account;
}

function rpcFailure(method: string, cause: unknown): ClientError {
  return ClientError.chain(method, cause instanceof Error ? cause.message : String(cause));
}

/** One JSON-RPC request; a refusal is a chain error naming the method. */
export async function request(
  reads: RawReads,
  method: string,
  params: readonly unknown[],
): Promise<unknown> {
  try {
    return await reads.rpc(method, params);
  } catch (cause) {
    throw rpcFailure(method, cause);
  }
}

/** One block's state. Every source of a read goes through the same snapshot. */
export class Snapshot {
  readonly #reads: RawReads;
  readonly #at: Uint8Array;

  constructor(reads: RawReads, at: Uint8Array) {
    this.#reads = reads;
    this.#at = at;
  }

  /** The block this snapshot reads at. */
  get at(): Uint8Array {
    return this.#at.slice();
  }

  /**
   * Call the runtime API `api` (`Trait_method`) with SCALE-encoded `args` at
   * this snapshot's block, returning its SCALE-encoded answer. A failure names
   * the API, not the transport: that is what the caller asked for.
   */
  async call(api: string, args: Uint8Array): Promise<Uint8Array> {
    let answer: unknown;
    try {
      answer = await this.#reads.rpc(STATE_CALL, [api, toHex(args), toHex(this.#at)]);
    } catch (cause) {
      throw rpcFailure(api, cause);
    }
    const bytes = typeof answer === "string" ? bytesFromHex(answer) : undefined;
    if (bytes === undefined) {
      throw ClientError.chain(api, "the node answered with something that is not hex");
    }
    return bytes;
  }

  /** One JSON-RPC request whose only parameter is this snapshot's block. */
  async requestHere(method: string): Promise<unknown> {
    return request(this.#reads, method, [toHex(this.#at)]);
  }

  /**
   * Fetch several storage values in one request. The result is in request
   * order; `undefined` is a value the chain does not store.
   */
  async storage(requests: readonly StorageRequest[]): Promise<Array<Uint8Array | undefined>> {
    const keys = requests.map(({ entry, keys: mapKeys }) =>
      toHex(this.#reads.storageKey(entry.pallet, entry.entry, mapKeys)),
    );
    const sets = await request(this.#reads, QUERY_STORAGE_AT, [keys, toHex(this.#at)]);
    const answers = new Map(
      (Array.isArray(sets) ? sets : []).flatMap((set: { changes?: unknown }) =>
        Array.isArray(set.changes) ? (set.changes as Array<[string, string | null]>) : [],
      ),
    );
    return requests.map((req, index) => {
      const key = keys[index] as string;
      if (!answers.has(key)) {
        throw ClientError.chain(
          targetOf(req.entry),
          `the node's ${QUERY_STORAGE_AT} answer left this key out`,
        );
      }
      const value = answers.get(key);
      if (value === null || value === undefined) return undefined;
      const bytes = bytesFromHex(value);
      if (bytes === undefined) {
        throw ClientError.chain(targetOf(req.entry), "the node answered with something that is not hex");
      }
      return bytes;
    });
  }
}

/** Resolve `pin` to a block, asking the node only when it is not given. */
export async function snapshot(reads: RawReads, pin: Uint8Array | undefined): Promise<Snapshot> {
  if (pin !== undefined) return new Snapshot(reads, pin);
  const head = await request(reads, FINALIZED_HEAD, []);
  const bytes = typeof head === "string" ? bytesFromHex(head) : undefined;
  if (bytes === undefined || bytes.length !== BLOCK_HASH_BYTES) {
    throw ClientError.chain(FINALIZED_HEAD, "the node did not answer with a block hash");
  }
  return new Snapshot(reads, bytes);
}
