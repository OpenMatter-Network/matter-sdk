// testvectors/facade_reads.json (emitted from Rust) and a chain that replays one
// of its cases: the read catalogue, run through the real façades.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { Metadata, TypeRegistry } from "@polkadot/types";
import {
  decorateConstants,
  decorateExtrinsics,
  decorateStorage,
} from "@polkadot/types/metadata/decorate";

import {
  AccountsFacade,
  FeesFacade,
  NetworkFacade,
  ScopeSet,
  type ChainProperties,
  type FacadeHost,
  type RawReads,
} from "../src/index.js";
import {
  buildCall,
  constantBytes,
  ss58Decode,
  ss58Encode,
  storageKey,
  type StorageKeyCreator,
} from "../src/polkadot.js";

const vectorsDir = resolve(import.meta.dirname, "../../../testvectors");

/**
 * One JSON-RPC request and how the node answered: its `result` (which may be
 * `null`), or the `error` it refused with.
 */
export interface Exchange {
  method: string;
  params: unknown[];
  result?: unknown;
  error?: string;
}

/** A transcript: what a pinned read asks, and how it must end. */
export interface ReadCase {
  name: string;
  args: Record<string, unknown>;
  at: string;
  exchanges: Exchange[];
  /** The result as a JSON value; absent when the read must fail. */
  expected?: unknown;
  /** The result as exactly the canonical bytes. */
  expected_json?: string;
  /** The source a failing read's chain error must name. */
  error?: { target: string };
  /** Who the reading client would sign as, and for which member; absent for a read-only client. */
  client?: ClientIdentity;
}

/** A case's client: bare-hex account ids, `null` where there is none. */
export interface ClientIdentity {
  signer: string | null;
  principal: string | null;
}

/** One argument of a call a case names: wide integers as decimal strings. */
export interface CallArg {
  name: string;
  type: string;
  value: string;
}

export interface ReadRow {
  facade: string;
  method: string;
  args: Array<{ name: string; type: string }>;
  sources: Array<{ kind: string; name: string }>;
  result: string;
  /** Whether the read is about one block, and so can be pinned to it. */
  pinnable: boolean;
  /** Whether the read returns nothing when there is nothing to return. */
  nullable: boolean;
  cases: ReadCase[];
}

export interface ReasonTable {
  source: string;
  groups: Array<{ index: number; pallet: string; reasons: Array<{ index: number; name: string }> }>;
}

export const readFixture = JSON.parse(
  readFileSync(resolve(vectorsDir, "facade_reads.json"), "utf8"),
) as {
  pin_method: string;
  chain: { ss58_prefix: number; existential_deposit: string };
  accounts: {
    accepted: Array<{ text: string; account_hex: string }>;
    refused: string[];
    addresses: Array<{ account_hex: string; prefix: number; address: string }>;
  };
  scale: {
    valid: Array<{ type: string; hex: string; value: string }>;
    invalid: Array<{ type: string; hex: string; why: string }>;
  };
  tables: {
    hold_reasons: ReasonTable;
    freeze_reasons: ReasonTable;
    lock_reasons: string[];
    dispatch_classes: string[];
  };
  reads: ReadRow[];
};

type Encodable = { toU8a(): Uint8Array };
type Constants = Record<string, Record<string, Encodable>>;
type Calls = Record<string, Record<string, (...args: never[]) => Encodable>>;

/** `api.query`, `api.consts` and `api.tx` as @polkadot builds them from the spec-330 metadata, without a socket. */
function spec330(): {
  storage: Record<string, Record<string, StorageKeyCreator>>;
  constants: Constants;
  calls: Calls;
} {
  const registry = new TypeRegistry();
  const metadata = new Metadata(
    registry,
    new Uint8Array(readFileSync(resolve(vectorsDir, "spec330_metadata.scale"))),
  );
  registry.setMetadata(metadata);
  return {
    storage: decorateStorage(registry, metadata.asLatest, metadata.version) as unknown as Record<
      string,
      Record<string, StorageKeyCreator>
    >,
    constants: decorateConstants(registry, metadata.asLatest, metadata.version) as unknown as Constants,
    calls: decorateExtrinsics(registry, metadata.asLatest, metadata.version) as unknown as Calls,
  };
}

const { storage, constants, calls } = spec330();

/** The finalized head a chain with no transcript reports. */
export const FIXTURE_HEAD = `0x${"f1".repeat(32)}`;
const FINALIZED_HEAD = "chain_getFinalizedHead";

/**
 * A chain that replays one case's transcript. It answers a request only as the
 * transcript recorded that exact request, reports the case's block as its
 * finalized head unless the transcript says otherwise, takes storage keys and
 * constants from the real spec-330 metadata, and records every request, so a
 * test can assert that the read asked exactly what was recorded.
 */
export class FixtureChain implements RawReads {
  readonly requests: Array<Pick<Exchange, "method" | "params">> = [];
  readonly #exchanges: readonly Exchange[];
  readonly #head: string;

  constructor(testCase?: Pick<ReadCase, "at" | "exchanges">) {
    this.#exchanges = testCase?.exchanges ?? [];
    this.#head = testCase === undefined ? FIXTURE_HEAD : `0x${testCase.at}`;
  }

  async rpc(method: string, params: readonly unknown[]): Promise<unknown> {
    this.requests.push({ method, params: [...params] });
    const recorded = this.#exchanges.find(
      (exchange) => exchange.method === method && isDeepStrictEqual(exchange.params, [...params]),
    );
    if (recorded === undefined) {
      if (method === FINALIZED_HEAD) return this.#head;
      throw new Error(`the transcript has no answer for ${method}(${JSON.stringify(params)})`);
    }
    if (recorded.error !== undefined) throw new Error(recorded.error);
    return recorded.result;
  }

  constant(pallet: string, name: string): Uint8Array {
    return constantBytes((p, n) => constants[p]?.[n], pallet, name);
  }

  storageKey(pallet: string, entry: string, keys: readonly unknown[]): Uint8Array {
    return storageKey((p, e) => storage[p]?.[e], pallet, entry, keys);
  }

  callData(pallet: string, call: string, args: readonly unknown[], principal?: Uint8Array): Uint8Array {
    return buildCall((p, c) => calls[p]?.[c], pallet, call, args, principal).toU8a();
  }

  ss58Decode(text: string): Uint8Array | undefined {
    return ss58Decode(text);
  }
}

/** The chain facts the fixture's cases were emitted under. */
export const fixtureProperties: ChainProperties = {
  genesisHash: `0x${"00".repeat(32)}`,
  chainName: "MatterChain Fake",
  specVersion: 330,
  tokenSymbol: "MTR-Test",
  ss58Prefix: readFixture.chain.ss58_prefix,
  tokenDecimalsDeclared: 18,
  tokenDecimalsEffective: 18,
  existentialDeposit: BigInt(readFixture.chain.existential_deposit),
};

function accountBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

/**
 * A façade host that reads from `chain` and refuses to submit. With a `client`
 * it has that identity: who would sign, and for which member.
 */
export function readingHost(chain: RawReads, client?: ClientIdentity): FacadeHost {
  const signer = client?.signer ?? null;
  const principal = client?.principal ?? null;
  return {
    ...(signer === null ? {} : { accountId: accountBytes(signer) }),
    ...(principal === null
      ? {}
      : { mode: { kind: "delegated", principal: accountBytes(principal), scopes: ScopeSet.ALL } }),
    async tx() {
      throw new Error("a read must not submit an extrinsic");
    },
    backend: {
      reads: chain,
      encodeAddress: (accountId) => ss58Encode(accountId, fixtureProperties.ss58Prefix),
    },
    properties: fixtureProperties,
  };
}

/** The façades that have reads, by fixture name. */
export function readFacadeFor(name: string, host: FacadeHost): object {
  switch (name) {
    case "accounts":
      return new AccountsFacade(host);
    case "network":
      return new NetworkFacade(host);
    case "fees":
      return new FeesFacade(host);
    default:
      throw new Error(`the read fixture names an unknown façade: ${name}`);
  }
}

/** The fixture's snake_case method name as TypeScript spells it. */
export function toCamel(text: string): string {
  return text.replace(/_([a-z0-9])/g, (_all, ch: string) => ch.toUpperCase());
}

/**
 * A case's arguments as a caller passes them, in the row's order. Wide integers
 * travel as decimal strings in the fixture: JSON numbers cannot carry 64 bits.
 */
export function argsOf(row: ReadRow, args: Record<string, unknown>): unknown[] {
  return row.args.map(({ name, type }) => {
    const value = args[name];
    switch (type) {
      case "account":
      case "string":
        return value;
      case "u64":
      case "u128":
        return BigInt(value as string);
      case "call_args":
        return (value as CallArg[]).map(callArg);
      default:
        throw new Error(`the fixture names an argument type this test does not convert: ${type}`);
    }
  });
}

/** One argument of a call as this binding's `tx` takes it. */
function callArg({ type, value }: CallArg): unknown {
  switch (type) {
    case "u128":
      return BigInt(value);
    default:
      throw new Error(`the fixture names a call argument type this test does not convert: ${type}`);
  }
}
