// The @polkadot/api implementation of ChainBackend.
//
// Imported lazily by MatterClient, so the guards and the amount arithmetic can be
// unit-tested — and a caller can inject their own backend — without pulling in
// @polkadot/api.

import { ApiPromise, WsProvider } from "@polkadot/api";
import type { KeySigner } from "@openmatter-network/matter-vault";

import { decimalsFromExistentialDeposit } from "./amount.js";
import type { ChainBackend, Mode, TxReceipt } from "./backend.js";
import { defaultLogger, type ClientLogger } from "./logger.js";
import { afterRefresh, isPoolRejection } from "./delegation.js";
import { ClientError } from "./errors.js";
import type { ChainProperties } from "./network.js";
import { requiredScopes, ScopeSet } from "./scopes.js";

/** SCALE enum index of `MultiSignature::Sr25519`. */
const MULTISIGNATURE_SR25519 = 1;

/** ss58 prefix to assume when the node does not report one. */
const DEFAULT_SS58_PREFIX = 42;

/** The runtime API mapping a key to its principal. Its absence from metadata is
 * how a chain older than the scoped-key runtime is detected. */
/**
 * pallet-proxy's complaint that no definition matches this (key, member) pair —
 * a revoked or rebound key, in practice. Matched on the rendered prefix because
 * that is what describeDispatchError produces.
 */
const NOT_PROXY_PREFIX = "proxy.NotProxy";

const AGENT_KEY_TRAIT = "BudgetsApi";
const AGENT_KEY_METHOD = "agent_key";

/** Names the principal a key acts for when the chain's own pointer is stale. */
const PRINCIPAL_ENV = "MATTER_PRINCIPAL";

export class PolkadotBackend implements ChainBackend {
  readonly #api: ApiPromise;
  readonly #signer: KeySigner | undefined;
  #mode: Mode = { kind: "direct" };

  private constructor(api: ApiPromise, signer: KeySigner | undefined) {
    this.#api = api;
    this.#signer = signer;
  }

  static async connect(
    url: string,
    signer: KeySigner | undefined,
    logger: ClientLogger = defaultLogger,
  ): Promise<PolkadotBackend> {
    let api: ApiPromise;
    try {
      api = await ApiPromise.create({ provider: new WsProvider(url), noInitWarn: true });
    } catch (cause) {
      throw ClientError.chain(url, cause instanceof Error ? cause.message : String(cause));
    }
    const backend = new PolkadotBackend(api, signer);
    if (signer !== undefined) {
      backend.#mode = await resolveMode(api, signer.accountId, logger);
      if (backend.#mode.kind === "delegated") {
        // Said once, and worth saying: a key that was meant to be delegated but
        // resolved direct is the first thing anyone debugging an unexplained
        // fee rejection needs to see. SS58, because that is the form the
        // dashboard showed whoever minted the key.
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
    // `createType("AccountId32", …).toString()` applies the registry's ss58 prefix,
    // which @polkadot sets from the chain's own system_properties at connect — so
    // this matches what the other bindings render without hardcoding 42.
    return this.#api.createType("AccountId32", accountId).toString();
  }

  async properties(): Promise<ChainProperties> {
    const api = this.#api;
    const [chainName, properties] = await Promise.all([
      api.rpc.system.chain(),
      api.rpc.system.properties(),
    ]);

    // The consensus-backed decimal count: ED === 10 ** (d - 3). The chain-spec's
    // tokenDecimals is presentational and can disagree.
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
      ss58Prefix: properties.ss58Format.unwrapOr(undefined)?.toNumber() ?? DEFAULT_SS58_PREFIX,
      tokenDecimalsDeclared,
      tokenDecimalsEffective: decimalsFromExistentialDeposit(ed) ?? tokenDecimalsDeclared,
      existentialDeposit: ed,
    };
  }

  async submit(pallet: string, call: string, args: unknown[]): Promise<TxReceipt> {
    const signer = this.#signer;
    if (signer === undefined) throw ClientError.readOnly();

    const target = `${pallet}.${call}`;
    const section = this.#api.tx[toMemberName(pallet)];
    const method = section?.[toMemberName(call)];
    if (method === undefined) {
      throw ClientError.chain(
        target,
        "no such call in the live runtime metadata (was the runtime upgraded?)",
      );
    }

    // Under a member-tied key nothing is signed as the key itself: the key has
    // no authority and no balance, so a direct call is refused in the pool for
    // want of fees. Everything goes through `proxy.proxy(member, null, call)`
    // and runs as the member.
    const inner = method(...(args as never[]));
    let extrinsic = inner;
    if (this.#mode.kind === "delegated") {
      const wrap = this.#api.tx["proxy"]?.["proxy"];
      if (wrap === undefined) {
        // A delegated client on a chain with no pallet-proxy cannot act at all,
        // and saying so beats a TypeError from an undefined call.
        throw ClientError.chain("Proxy.proxy", "this runtime exposes no proxy pallet");
      }
      extrinsic = wrap(
        // MultiAddress::Id — @polkadot encodes the variant from a raw account.
        this.#api.createType("AccountId32", this.#mode.principal),
        null,
        inner,
      );
    }
    const address = this.#api.createType("AccountId32", signer.accountId).toString();

    // Sign through our own signer rather than handing @polkadot a keyring pair:
    // the key may live in an HSM, and our `sign` is allowed to fail.
    await extrinsic.signAsync(address, {
      signer: {
        signPayload: async (payload) => {
          const raw = this.#api.createType("ExtrinsicPayload", payload, {
            version: payload.version,
          });
          const signature = await signer.sign(raw.toU8a({ method: true }));
          const framed = new Uint8Array(1 + signature.length);
          framed[0] = MULTISIGNATURE_SR25519;
          framed.set(signature, 1);
          return { id: 1, signature: u8aToHex(framed) };
        },
      },
    });

    // Resolve on FINALIZATION, not inclusion: the committee authorizes against
    // the finalized head, so resolving earlier yields an HTTP 403. That was a
    // real bug in the e2e harness before it was fixed.
    return new Promise<TxReceipt>((resolve, reject) => {
      extrinsic
        .send((result) => {
          if (result.dispatchError !== undefined) {
            const dispatchError = result.dispatchError;
            this.#classifyDispatchFailure(target, dispatchError).then(reject).catch(reject);
            return;
          }
          if (!result.status.isFinalized) return;

          // `proxy.proxy` succeeds as an extrinsic even when the call it
          // wrapped failed — `result.dispatchError` above only ever sees the
          // outer one — so without this every delegated failure reads as a win.
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
            events: result.events.map(
              ({ event }) => [event.section, event.method] as const,
            ),
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
   * Explain a submission the node refused at validation.
   *
   * A pool rejection has two indistinguishable causes — the delegation is gone,
   * or nobody can pay — and the message names neither. So rather than guess from
   * text, re-read the grant and let the chain's answer decide.
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
      // The scopes moved under us. If the call is now out of scope, name the
      // missing one with the fresh set rather than blaming the payer.
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

  /**
   * Refine an outer dispatch failure that names a revoked proxy.
   *
   * `Proxy.NotProxy` means pallet-proxy found no definition for this
   * (key, member) pair, which in practice means the key was revoked or rebound
   * since connect. Confirm that against the chain before saying so.
   */
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
   * Re-read the chain's grant, updating the cached scopes if they moved.
   *
   * `undefined` means the lookup itself failed, so nothing new is known.
   * A grant that is *gone* deliberately leaves the mode delegated: a revoked key
   * that fell back to direct signing would fail the next call for want of funds
   * it was never meant to hold.
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
    const target = `${pallet}.${entry}`;
    const section = this.#api.query[toMemberName(pallet)];
    const item = section?.[toMemberName(entry)];
    if (item === undefined) {
      throw ClientError.chain(target, "no such storage entry in the live runtime metadata");
    }
    const value = await item(...(keys as never[]));
    // Absence is normal control flow, so it surfaces as undefined rather than an
    // error or an empty-but-truthy codec value.
    const maybe = value as unknown as { isNone?: boolean; isEmpty?: boolean };
    if (maybe.isNone === true || maybe.isEmpty === true) return undefined;
    return value;
  }

  async runtimeApi(method: string, argsHex: string): Promise<string> {
    try {
      const result = await this.#api.rpc.state.call(method, argsHex);
      return result.toHex();
    } catch (cause) {
      throw ClientError.chain(method, cause instanceof Error ? cause.message : String(cause));
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
 * Ask the chain who `account` acts for.
 *
 * `MATTER_PRINCIPAL` first: the escape hatch for a key whose pointer is stale
 * while its proxy still stands. The chain cannot then report the scopes either,
 * so it assumes the full set — the local pre-flight check turns off and the
 * runtime's filter decides alone. Assuming the empty set would refuse every call
 * locally and make the override useless, so the override is loud rather than
 * narrow.
 *
 * Then metadata: a pre-322 chain simply does not define the runtime API, and
 * that is a fact held locally. Guessing it from the shape of an RPC error would
 * be worse in every way.
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
 * `BudgetsApi_agent_key(key)` — who `key` acts for and what it may do.
 *
 * `undefined` covers both "this chain has no such runtime API" (a runtime older
 * than scoped keys) and "the chain has it and says this key is not registered".
 * To a caller both mean the same thing: there is no scoped proxy here.
 */
async function agentKey(
  api: ApiPromise,
  key: Uint8Array,
): Promise<readonly [Uint8Array, ScopeSet] | undefined> {
  // Asked of metadata rather than inferred from an error: a pre-scoped-key chain
  // simply does not define the method, and that is a fact held locally.
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

/**
 * `MATTER_PRINCIPAL` as raw account bytes, if set.
 *
 * Decoded through the registry rather than by hand, so `0x`-hex and SS58 are
 * both accepted and both validated the same way the chain would.
 */
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

/**
 * The wrapped call's own error, or `undefined` if it succeeded.
 *
 * `Proxy.ProxyExecuted` carries a `DispatchResult`, which is where a delegated
 * call's real outcome lives — the outer extrinsic's success says only that the
 * proxy dispatched something.
 */
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
 * Metadata name -> the identifier @polkadot indexes it under.
 *
 * Metadata is inconsistent about case and @polkadot normalizes it away: pallets
 * and constants are PascalCase (`Secrets`, `ExistentialDeposit`), storage entries
 * are PascalCase (`NextSecretId`), and calls are snake_case (`store_secret`) —
 * but every one of them is reached camelCased. Both transformations are needed,
 * and applying only one silently fails to resolve at run time.
 */
function toMemberName(text: string): string {
  const camel = text.replace(/_([a-z0-9])/g, (_all, ch: string) => ch.toUpperCase());
  return camel.charAt(0).toLowerCase() + camel.slice(1);
}

function u8aToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/**
 * Turn a `DispatchError` into the pallet's own error name where possible. The raw
 * codec renders as an opaque index pair, which is useless in a log.
 */
function describeDispatchError(api: ApiPromise, error: { isModule: boolean; asModule: unknown; toString(): string }): string {
  if (!error.isModule) return error.toString();
  try {
    const meta = api.registry.findMetaError(error.asModule as never);
    return `${meta.section}.${meta.name}: ${meta.docs.join(" ").trim()}`;
  } catch {
    return error.toString();
  }
}
