// The @polkadot/api ChainBackend. Imported lazily by MatterClient.

import { ApiPromise, WsProvider } from "@polkadot/api";
import type { Metadata } from "@polkadot/types";
import type { Signer as PolkadotSigner, SignerPayloadJSON } from "@polkadot/types/types";
import { compactStripLength, u8aConcat, u8aEq, u8aToHex } from "@polkadot/util";
import { base58Decode, blake2AsU8a, encodeAddress } from "@polkadot/util-crypto";
import type { KeySigner } from "@openmatter-network/matter-sdk-core";

import { decimalsFromExistentialDeposit } from "./amount.js";
import type { ChainBackend, Mode, ReceiptEvent, TxReceipt } from "./backend.js";
import { defaultLogger, type ClientLogger } from "./logger.js";
import { afterRefresh, isPoolRejection } from "./delegation.js";
import { ClientError } from "./errors.js";
import type { ChainProperties } from "./network.js";
import { bytesFromHex } from "./reads/leaf.js";
import { ACCOUNT_ID_BYTES, snapshot, type RawReads } from "./reads/source.js";
import { requiredScopes, ScopeSet } from "./scopes.js";

/** SCALE enum index of `MultiSignature::Sr25519`. */
const MULTISIGNATURE_SR25519 = 1;

/**
 * Substrate signs an extrinsic payload verbatim up to this length and its
 * blake2b-256 digest beyond it. The runtime verifies the same way, so the SDK
 * applies the rule before a `KeySigner` sees the bytes: a signer signs exactly
 * what it is given, in every language.
 */
export const MAX_UNHASHED_SIGNING_PAYLOAD_BYTES = 256;

/** The constant every address this client renders is encoded under. */
const SS58_PREFIX_TARGET = "System.SS58Prefix";
/** Domain separator for the SS58 checksum hash. */
const SS58_CONTEXT = new TextEncoder().encode("SS58PRE");
const SS58_CHECKSUM_BYTES = 2;
const SS58_HASH_BITS = 512;
/** First bytes below this are a one-byte prefix; up to the reserved bound, a two-byte one. */
const SS58_SINGLE_BYTE_LIMIT = 64;
const SS58_RESERVED_FIRST_BYTE = 128;
/** Prefixes the SS58 registry reserves; no address may use them. */
const SS58_RESERVED_PREFIXES: readonly number[] = [46, 47];

/** Rendered `describeDispatchError` prefix for a revoked or rebound key. */
const NOT_PROXY_PREFIX = "proxy.NotProxy";
/** `Proxy.proxy`, as @polkadot indexes it. */
const PROXY_PALLET = "proxy";
const PROXY_CALL = "proxy";
/** The `MultiAddress` variant that carries a 32-byte account id. */
const MULTI_ADDRESS_ID = "Id";

/** Runtime API mapping a key to its principal; absent before runtime spec 322. */
const AGENT_KEY_TRAIT = "BudgetsApi";
const AGENT_KEY_METHOD = "agent_key";

/** Overrides the principal a key acts for when the chain's pointer is stale. */
const PRINCIPAL_ENV = "MATTER_PRINCIPAL";

/** The RPC a finalized-head read fails at, for error targets. */
const FINALIZED_HEAD_RPC = "chain_getFinalizedHead";

export class PolkadotBackend implements ChainBackend {
  readonly #api: ApiPromise;
  readonly #signer: KeySigner | undefined;
  /** Pallet index -> name as metadata spells it, for receipts. */
  readonly #palletNames: ReadonlyMap<number, string>;
  readonly #ss58Prefix: number;
  #mode: Mode = { kind: "direct" };

  /** Block-pinned raw reads over the same connection. */
  readonly reads: RawReads;

  private constructor(api: ApiPromise, provider: WsProvider, signer: KeySigner | undefined) {
    this.#api = api;
    this.#signer = signer;
    this.#palletNames = palletNamesByIndex(api.runtimeMetadata);
    this.#ss58Prefix = ss58PrefixOf(api);
    this.reads = {
      // The provider, not `api.rpc`: reads decode the raw answer themselves.
      rpc: (method, params) => provider.send(method, [...params]),
      storageKey: (pallet, entry, keys) =>
        storageKey((p, e) => api.query[p]?.[e]?.creator as StorageKeyCreator | undefined, pallet, entry, keys),
      constant: (pallet, name) => constantBytes((p, n) => api.consts[p]?.[n], pallet, name),
      callData: (pallet, call, args, principal) =>
        buildCall((p, c) => api.tx[p]?.[c], pallet, call, args, principal).method.toU8a(),
      ss58Decode,
    };
  }

  static async connect(
    url: string,
    signer: KeySigner | undefined,
    logger: ClientLogger = defaultLogger,
  ): Promise<PolkadotBackend> {
    const provider = new WsProvider(url);
    let api: ApiPromise;
    try {
      api = await ApiPromise.create({ provider, noInitWarn: true });
    } catch (cause) {
      throw ClientError.chain(url, cause instanceof Error ? cause.message : String(cause));
    }
    let backend: PolkadotBackend;
    try {
      backend = new PolkadotBackend(api, provider, signer);
    } catch (cause) {
      // The runtime lacks something the backend needs: do not leave the socket open.
      await api.disconnect();
      throw cause;
    }
    if (signer !== undefined) {
      backend.#mode = await resolveMode(api, signer.accountId, logger);
      if (backend.#mode.kind === "delegated") {
        logger.info(
          `acting for ${backend.encodeAddress(backend.#mode.principal)} ` +
            `with scopes ${backend.#mode.scopes.toString()}`,
        );
      }
    }
    return backend;
  }

  mode(): Mode {
    return this.#mode;
  }

  async agentKey(key: Uint8Array): Promise<readonly [Uint8Array, ScopeSet] | undefined> {
    return agentKey(this.#api, key);
  }

  canSign(): boolean {
    return this.#signer !== undefined;
  }

  encodeAddress(accountId: Uint8Array): string {
    return ss58Encode(accountId, this.#ss58Prefix);
  }

  async properties(): Promise<ChainProperties> {
    const api = this.#api;
    const [chainName, properties] = await Promise.all([
      api.rpc.system.chain(),
      api.rpc.system.properties(),
    ]);

    const existentialDeposit = (api.consts["balances"]?.["existentialDeposit"] as unknown as {
      toString(): string;
    } | undefined)?.toString();
    if (existentialDeposit === undefined) {
      throw ClientError.chain(
        "Balances.ExistentialDeposit",
        "constant missing from the runtime metadata",
      );
    }
    const ed = BigInt(existentialDeposit);

    const declaredList = properties.tokenDecimals.unwrapOr(undefined);
    const tokenDecimalsDeclared = declaredList?.[0]?.toNumber() ?? 0;
    const symbolList = properties.tokenSymbol.unwrapOr(undefined);

    return {
      genesisHash: api.genesisHash.toHex(),
      chainName: chainName.toString(),
      specVersion: api.runtimeVersion.specVersion.toNumber(),
      tokenSymbol: symbolList?.[0]?.toString() ?? "",
      ss58Prefix: this.#ss58Prefix,
      tokenDecimalsDeclared,
      tokenDecimalsEffective: decimalsFromExistentialDeposit(ed) ?? tokenDecimalsDeclared,
      existentialDeposit: ed,
    };
  }

  async submit(pallet: string, call: string, args: unknown[]): Promise<TxReceipt> {
    const signer = this.#signer;
    if (signer === undefined) throw ClientError.readOnly();

    const target = `${pallet}.${call}`;
    const principal = this.#mode.kind === "delegated" ? this.#mode.principal : undefined;
    const extrinsic = buildCall((p, c) => this.#api.tx[p]?.[c], pallet, call, args, principal);
    const address = this.#api.createType("AccountId32", signer.accountId).toString();

    // Sign via KeySigner, never a keyring pair: the key may live in an HSM.
    await extrinsic.signAsync(address, { signer: keySignerAdapter(this.#api, signer) });

    // Resolve on finalization, not inclusion; see ChainBackend.submit.
    return new Promise<TxReceipt>((resolve, reject) => {
      extrinsic
        .send((result) => {
          if (result.dispatchError !== undefined) {
            const dispatchError = result.dispatchError;
            this.#classifyDispatchFailure(target, dispatchError).then(reject).catch(reject);
            return;
          }
          if (!result.status.isFinalized) return;

          // `dispatchError` only covers the outer `proxy.proxy`; the wrapped
          // call's outcome is in its `ProxyExecuted` event.
          if (this.#mode.kind === "delegated") {
            const failure = wrappedFailure(this.#api, result.events);
            if (failure !== undefined) {
              reject(ClientError.dispatch(target, failure));
              return;
            }
          }

          resolve({
            txHash: extrinsic.hash.toHex(),
            blockHash: result.status.asFinalized.toHex(),
            events: receiptEvents(result.events, this.#palletNames),
          });
        })
        .catch((cause: unknown) => {
          this.#classifySubmissionFailure(target, pallet, call, args, cause)
            .then(reject)
            .catch(reject);
        });
    });
  }

  /**
   * Classify a pool rejection. Its message cannot distinguish "delegation gone"
   * from "nobody can pay", so re-read the grant and let the chain decide.
   */
  async #classifySubmissionFailure(
    target: string,
    pallet: string,
    call: string,
    args: unknown[],
    cause: unknown,
  ): Promise<ClientError> {
    const detail = cause instanceof Error ? cause.message : String(cause);
    if (this.#mode.kind !== "delegated" || !isPoolRejection(cause)) {
      return ClientError.chain(target, detail);
    }

    const refreshed = await this.#refreshDelegation();
    if (refreshed === undefined) return ClientError.chain(target, detail);
    if (refreshed.outcome === "gone") return ClientError.keyRevoked(target);
    if (refreshed.outcome === "rescoped") {
      const required = requiredScopes(pallet, call, args);
      if (required !== null && !refreshed.scopes.isSuperset(required)) {
        return ClientError.notPermitted(
          target,
          required.toString(),
          refreshed.scopes.toString(),
        );
      }
    }
    return ClientError.unsponsored(target, this.encodeAddress(this.#mode.principal));
  }

  /** On `Proxy.NotProxy`, confirm revocation against the chain before reporting it. */
  async #classifyDispatchFailure(
    target: string,
    dispatchError: { isModule: boolean; asModule: unknown; toString(): string },
  ): Promise<ClientError> {
    const detail = describeDispatchError(this.#api, dispatchError);
    if (this.#mode.kind !== "delegated" || !detail.startsWith(NOT_PROXY_PREFIX)) {
      return ClientError.chain(target, detail);
    }
    const refreshed = await this.#refreshDelegation();
    if (refreshed?.outcome === "gone") return ClientError.keyRevoked(target);
    return ClientError.chain(target, detail);
  }

  /**
   * Re-read the chain's grant, updating cached scopes if they moved; `undefined`
   * if the lookup failed. A *gone* grant leaves the mode delegated (never falls
   * back to direct signing).
   */
  async #refreshDelegation(): Promise<ReturnType<typeof afterRefresh> | undefined> {
    if (this.#mode.kind !== "delegated" || this.#signer === undefined) return undefined;
    const previous = { principal: this.#mode.principal, scopes: this.#mode.scopes };
    try {
      const fresh = await agentKey(this.#api, this.#signer.accountId);
      const refreshed = afterRefresh(previous, fresh);
      if (refreshed.outcome === "rescoped") {
        this.#mode = { ...this.#mode, scopes: refreshed.scopes };
      }
      return refreshed;
    } catch {
      return undefined;
    }
  }

  async query(pallet: string, entry: string, keys: unknown[]): Promise<unknown> {
    const storageAt = async (block: Uint8Array): Promise<StorageAt> =>
      (await this.#api.at(block)).query as unknown as StorageAt;
    return queryFinalized(this.reads, storageAt, pallet, entry, keys);
  }

  async runtimeApi(method: string, argsHex: string): Promise<string> {
    return runtimeApiFinalized(this.reads, method, argsHex);
  }

  async finalizedHead(): Promise<Uint8Array> {
    try {
      return (await this.#api.rpc.chain.getFinalizedHead()).toU8a();
    } catch (cause) {
      throw ClientError.chain(
        FINALIZED_HEAD_RPC,
        cause instanceof Error ? cause.message : String(cause),
      );
    }
  }

  constant(pallet: string, name: string): unknown {
    const value = this.#api.consts[toMemberName(pallet)]?.[toMemberName(name)];
    if (value === undefined) {
      throw ClientError.chain(`${pallet}.${name}`, "no such constant in the live metadata");
    }
    return value;
  }

  async disconnect(): Promise<void> {
    await this.#api.disconnect();
  }
}

/**
 * Resolve who `accountId` acts for.
 *
 * `MATTER_PRINCIPAL` wins, with `ScopeSet.ALL`: local scope checks are disabled
 * and only the runtime enforces. Otherwise ask the chain via `agentKey`.
 */
async function resolveMode(
  api: ApiPromise,
  accountId: Uint8Array,
  logger: ClientLogger,
): Promise<Mode> {
  const override = readPrincipalOverride(api);
  if (override !== undefined) {
    logger.warn(
      "MATTER_PRINCIPAL is set, so this client acts for that account " +
        "without asking the chain. Local scope checking is disabled; the runtime " +
        "still enforces.",
    );
    return { kind: "delegated", principal: override, scopes: ScopeSet.ALL };
  }

  const resolved = await agentKey(api, accountId);
  if (resolved === undefined) return { kind: "direct" };
  const [principal, scopes] = resolved;
  return { kind: "delegated", principal, scopes };
}

/**
 * `BudgetsApi_agent_key(key)`: who `key` acts for and what it may do.
 * `undefined` when the runtime lacks the API or the key is unregistered.
 */
async function agentKey(
  api: ApiPromise,
  key: Uint8Array,
): Promise<readonly [Uint8Array, ScopeSet] | undefined> {
  // Checked in metadata, not inferred from an RPC error.
  const defined = api.runtimeMetadata.asLatest.apis?.some(
    (trait) =>
      trait.name.toString() === AGENT_KEY_TRAIT &&
      trait.methods.some((m) => m.name.toString() === AGENT_KEY_METHOD),
  );
  if (defined !== true) return undefined;

  const raw = await api.rpc.state.call(
    `${AGENT_KEY_TRAIT}_${AGENT_KEY_METHOD}`,
    u8aToHex(key),
  );
  const decoded = api.createType("Option<(AccountId32, u32)>", raw);
  if (decoded.isNone) return undefined;

  const [principal, bits] = decoded.unwrap();
  return [principal.toU8a(), ScopeSet.fromBits(bits.toNumber())] as const;
}

/** `MATTER_PRINCIPAL` (`0x`-hex or SS58, registry-validated) as account bytes, if set. */
function readPrincipalOverride(api: ApiPromise): Uint8Array | undefined {
  const raw = globalThis.process?.env?.[PRINCIPAL_ENV]?.trim();
  if (raw === undefined || raw === "") return undefined;
  try {
    return api.createType("AccountId32", raw).toU8a();
  } catch (cause) {
    throw ClientError.config(
      `${PRINCIPAL_ENV} is neither 0x-prefixed hex nor a valid SS58 address: ` +
        (cause instanceof Error ? cause.message : String(cause)),
    );
  }
}

/** Pallet index -> pallet name as the runtime metadata spells it (`NominationPools`). */
export function palletNamesByIndex(metadata: Metadata): Map<number, string> {
  return new Map(
    metadata.asLatest.pallets.map((pallet) => [pallet.index.toNumber(), pallet.name.toString()]),
  );
}

/** The slice of @polkadot's `GenericEvent` that a receipt reads. */
interface EmittedEvent {
  index: Uint8Array;
  section: string;
  method: string;
  data: readonly { toPrimitive(): unknown }[];
  meta: { fields: readonly { name: { isSome: boolean; unwrap(): { toString(): string } } }[] };
}

/**
 * A receipt's `[pallet, event, fields]` entries. @polkadot's `event.section` is
 * lowerCamel (`secrets`); receipts use the metadata name (`Secrets`), as every
 * other binding does, resolved from the event's pallet index. Fields are keyed
 * by the runtime's own names (`secret_id`, not @polkadot's `secretId`), as
 * Python and Go key them, and positionally (`"0"`, `"1"`) for unnamed fields.
 */
export function receiptEvents(
  events: readonly { event: EmittedEvent }[],
  palletNames: ReadonlyMap<number, string>,
): ReceiptEvent[] {
  return events.map(({ event }) => [
    palletNames.get(event.index[0]!) ?? event.section,
    event.method,
    eventFields(event),
  ] as const);
}

/**
 * An event's fields as plain values: integers as numbers, or decimal strings
 * beyond 2^53; accounts as SS58 strings; bytes as hex.
 */
function eventFields(event: EmittedEvent): Readonly<Record<string, unknown>> {
  return Object.fromEntries(
    event.data.map((value, i) => {
      const name = event.meta.fields[i]?.name;
      return [name?.isSome === true ? name.unwrap().toString() : String(i), value.toPrimitive()];
    }),
  );
}

/**
 * `args` for @polkadot's `api.tx` / `api.query`: every `Uint8Array`, at any
 * depth of plain arrays and objects, as `0x`-hex.
 *
 * @polkadot reads a raw `Uint8Array` given to a `Bytes` (`Vec<u8>`,
 * `BoundedVec<u8>`) codec as SCALE that already carries its length prefix, so
 * the first byte is taken for a compact length and the value is rejected or
 * silently truncated. Hex is read as the value itself by every codec, including
 * fixed-size ones (`AccountId32`, `H256`, `[u8; N]`). Anything that is not plain
 * data (a @polkadot codec instance, for one) is passed through as is.
 */
export function toChainArgs(args: readonly unknown[]): unknown[] {
  return args.map(toChainValue);
}

function toChainValue(value: unknown): unknown {
  if (value instanceof Uint8Array) return u8aToHex(value);
  if (Array.isArray(value)) return value.map(toChainValue);
  if (isPlainObject(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, toChainValue(inner)]));
  }
  return value;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** The bytes a `KeySigner` signs for an extrinsic payload: see {@link MAX_UNHASHED_SIGNING_PAYLOAD_BYTES}. */
export function extrinsicSigningBytes(payload: Uint8Array): Uint8Array {
  return payload.length > MAX_UNHASHED_SIGNING_PAYLOAD_BYTES ? blake2AsU8a(payload) : payload;
}

/** What {@link keySignerAdapter} needs from an `ApiPromise` or a `TypeRegistry`. */
export interface PayloadTypes {
  createType(
    type: "ExtrinsicPayload",
    value: SignerPayloadJSON,
    options: { version: number },
  ): { toU8a(isBare?: boolean | Record<string, boolean>): Uint8Array };
}

/**
 * Adapt a {@link KeySigner} into the `Signer` @polkadot's `signAsync` takes.
 * The SDK derives all framing: it rebuilds the canonical payload bytes, applies
 * Substrate's hashing rule, and wraps the raw 64-byte signature as
 * `MultiSignature::Sr25519`. The signer never sees a keyring pair.
 */
export function keySignerAdapter(types: PayloadTypes, signer: KeySigner): PolkadotSigner {
  return {
    signPayload: async (payload) => {
      const raw = types.createType("ExtrinsicPayload", payload, { version: payload.version });
      const signature = await signer.sign(extrinsicSigningBytes(raw.toU8a({ method: true })));
      const framed = new Uint8Array(1 + signature.length);
      framed[0] = MULTISIGNATURE_SR25519;
      framed.set(signature, 1);
      return { id: 1, signature: u8aToHex(framed) };
    },
  };
}

/** The runtime's `System.SS58Prefix`: consensus-backed, unlike `system_properties.ss58Format`. */
function ss58PrefixOf(api: ApiPromise): number {
  const prefix = (api.consts["system"]?.["ss58Prefix"] as { toNumber(): number } | undefined)?.toNumber();
  if (prefix === undefined) {
    throw ClientError.chain(SS58_PREFIX_TARGET, "constant missing from the runtime metadata");
  }
  return prefix;
}

/** `accountId` as an SS58 address under `prefix`. */
export function ss58Encode(accountId: Uint8Array, prefix: number): string {
  return encodeAddress(accountId, prefix);
}

/**
 * The account in an SS58 address of any usable prefix, or `undefined` unless the
 * text is base58, its prefix is not reserved, it carries exactly 32 payload
 * bytes, and its checksum holds.
 *
 * Written out rather than delegated, in every binding: @polkadot's decoder
 * passes any hex through as an "address", and each chain library accepts a
 * different set of strings.
 */
export function ss58Decode(text: string): Uint8Array | undefined {
  let data: Uint8Array;
  try {
    data = base58Decode(text);
  } catch {
    return undefined;
  }
  const first = data[0];
  if (first === undefined || first >= SS58_RESERVED_FIRST_BYTE) return undefined;
  const prefixLength = first < SS58_SINGLE_BYTE_LIMIT ? 1 : 2;
  const second = data[1] ?? 0;
  const prefix =
    prefixLength === 1
      ? first
      : (((first << 2) | (second >> 6)) & 0xff) | ((second & 0b0011_1111) << 8);
  const bodyLength = prefixLength + ACCOUNT_ID_BYTES;
  if (
    SS58_RESERVED_PREFIXES.includes(prefix) ||
    data.length !== bodyLength + SS58_CHECKSUM_BYTES
  ) {
    return undefined;
  }
  const body = data.subarray(0, bodyLength);
  const checksum = blake2AsU8a(u8aConcat(SS58_CONTEXT, body), SS58_HASH_BITS).subarray(
    0,
    SS58_CHECKSUM_BYTES,
  );
  return u8aEq(checksum, data.subarray(bodyLength)) ? body.slice(prefixLength) : undefined;
}

/**
 * What builds a call from its arguments: `api.tx.pallet.call`, and equally an
 * entry of `decorateExtrinsics` over offline metadata.
 */
export type CallCreator<Built> = (...args: never[]) => Built;

/**
 * Build `pallet.call(args)` as it is submitted: the call itself, or wrapped in
 * `Proxy.proxy(principal, None, call)` so it runs as `principal` when one is
 * given. The one place a call is built, so what is priced is what is signed.
 * `creatorFor` takes the names as @polkadot indexes them (camelCase).
 */
export function buildCall<Built>(
  creatorFor: (pallet: string, call: string) => CallCreator<Built> | undefined,
  pallet: string,
  call: string,
  args: readonly unknown[],
  principal?: Uint8Array,
): Built {
  const target = `${pallet}.${call}`;
  const creator = creatorFor(toMemberName(pallet), toMemberName(call));
  if (creator === undefined) {
    throw ClientError.chain(
      target,
      "no such call in the live runtime metadata (was the runtime upgraded?)",
    );
  }
  // Delegated: never sign as the key itself.
  const wrap = principal === undefined ? undefined : creatorFor(PROXY_PALLET, PROXY_CALL);
  if (principal !== undefined && wrap === undefined) {
    throw ClientError.chain("Proxy.proxy", "this runtime exposes no proxy pallet");
  }
  try {
    const inner = creator(...(toChainArgs(args) as never[]));
    return wrap === undefined || principal === undefined
      ? inner
      : wrap(...([{ [MULTI_ADDRESS_ID]: u8aToHex(principal) }, null, inner] as never[]));
  } catch (cause) {
    throw ClientError.chain(
      target,
      `argument encoding: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
}

/**
 * A pallet constant's SCALE bytes. `constantFor` takes the names as @polkadot
 * indexes them (camelCase): `api.consts.pallet.name`, and equally an entry of
 * `decorateConstants` over offline metadata.
 */
export function constantBytes(
  constantFor: (pallet: string, name: string) => { toU8a(): Uint8Array } | undefined,
  pallet: string,
  name: string,
): Uint8Array {
  const constant = constantFor(toMemberName(pallet), toMemberName(name));
  if (constant === undefined) {
    throw ClientError.chain(`${pallet}.${name}`, "no such constant in the live runtime metadata");
  }
  return constant.toU8a();
}

/**
 * What builds a storage key from map keys: `api.query.pallet.entry.creator`, and
 * equally an entry of `decorateStorage` over offline metadata. It returns the
 * key with a compact length in front.
 */
export type StorageKeyCreator = (...keys: never[]) => Uint8Array;

/**
 * The raw key `pallet.entry(keys)` is stored under. `creatorFor` takes the
 * names as @polkadot indexes them (camelCase).
 */
export function storageKey(
  creatorFor: (pallet: string, entry: string) => StorageKeyCreator | undefined,
  pallet: string,
  entry: string,
  keys: readonly unknown[],
): Uint8Array {
  const creator = creatorFor(toMemberName(pallet), toMemberName(entry));
  if (creator === undefined) {
    throw ClientError.chain(
      `${pallet}.${entry}`,
      "no such storage entry in the live runtime metadata",
    );
  }
  return compactStripLength(creator(...(toChainArgs(keys) as never[])))[1];
}

/** A block's storage, as `(await api.at(block)).query` exposes it. */
export type StorageAt = Record<
  string,
  Record<string, ((...keys: never[]) => Promise<unknown>) | undefined> | undefined
>;

/**
 * Read `pallet.entry(keys)` at the latest finalized block, so the answer cannot
 * be reverted and a write that has returned is visible. `storageAt` gives a
 * block's storage. An entry the runtime does not have is a chain error naming it.
 */
export async function queryFinalized(
  reads: RawReads,
  storageAt: (block: Uint8Array) => Promise<StorageAt>,
  pallet: string,
  entry: string,
  keys: readonly unknown[],
): Promise<unknown> {
  const view = await snapshot(reads, undefined);
  const storage = await storageAt(view.at);
  const item = storage[toMemberName(pallet)]?.[toMemberName(entry)];
  if (item === undefined) {
    throw ClientError.chain(
      `${pallet}.${entry}`,
      "no such storage entry in the live runtime metadata",
    );
  }
  return storedValue(await item(...(toChainArgs(keys) as never[])));
}

/**
 * Call the runtime API `method` with hex-encoded SCALE arguments at the latest
 * finalized block, returning its SCALE answer as hex.
 */
export async function runtimeApiFinalized(
  reads: RawReads,
  method: string,
  argsHex: string,
): Promise<string> {
  const args = bytesFromHex(argsHex);
  if (args === undefined) throw ClientError.chain(method, "the arguments are not hex");
  const view = await snapshot(reads, undefined);
  return u8aToHex(await view.call(method, args));
}

/**
 * A storage read's value, or `undefined` when the key holds nothing: an absent
 * optional entry, or the storage default @polkadot substitutes for an absent
 * entry. A stored zero or empty value is returned, matching the other bindings.
 */
export function storedValue<T>(value: T): T | undefined {
  const codec = value as unknown as { isNone?: boolean; isStorageFallback?: boolean };
  if (codec.isNone === true || codec.isStorageFallback === true) return undefined;
  return value;
}

/** The wrapped call's error from `Proxy.ProxyExecuted`, or `undefined` if it succeeded. */
function wrappedFailure(api: ApiPromise, events: readonly { event: unknown }[]): string | undefined {
  for (const { event } of events) {
    const e = event as {
      section: string;
      method: string;
      data: readonly unknown[];
    };
    if (e.section !== "proxy" || e.method !== "ProxyExecuted") continue;
    const result = e.data[0] as { isErr?: boolean; asErr?: unknown } | undefined;
    if (result?.isErr !== true) return undefined;
    return describeDispatchError(
      api,
      result.asErr as { isModule: boolean; asModule: unknown; toString(): string },
    );
  }
  return undefined;
}

/**
 * Metadata name -> @polkadot's camelCase member name. Handles both PascalCase
 * (`ExistentialDeposit`) and snake_case (`store_secret`).
 */
function toMemberName(text: string): string {
  const camel = text.replace(/_([a-z0-9])/g, (_all, ch: string) => ch.toUpperCase());
  return camel.charAt(0).toLowerCase() + camel.slice(1);
}

/** Render a `DispatchError` as `section.Name: docs` where possible. */
function describeDispatchError(api: ApiPromise, error: { isModule: boolean; asModule: unknown; toString(): string }): string {
  if (!error.isModule) return error.toString();
  try {
    const meta = api.registry.findMetaError(error.asModule as never);
    return `${meta.section}.${meta.name}: ${meta.docs.join(" ").trim()}`;
  } catch {
    return error.toString();
  }
}
