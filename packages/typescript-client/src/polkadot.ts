// The @polkadot/api implementation of ChainBackend.
//
// Imported lazily by MatterClient, so the guards and the amount arithmetic can be
// unit-tested — and a caller can inject their own backend — without pulling in
// @polkadot/api.

import { ApiPromise, WsProvider } from "@polkadot/api";
import type { KeySigner } from "@openmatter-network/matter-vault";

import { decimalsFromExistentialDeposit } from "./amount.js";
import type { ChainBackend, TxReceipt } from "./backend.js";
import { ClientError } from "./errors.js";
import type { ChainProperties } from "./network.js";

/** SCALE enum index of `MultiSignature::Sr25519`. */
const MULTISIGNATURE_SR25519 = 1;

/** ss58 prefix to assume when the node does not report one. */
const DEFAULT_SS58_PREFIX = 42;

export class PolkadotBackend implements ChainBackend {
  readonly #api: ApiPromise;
  readonly #signer: KeySigner | undefined;

  private constructor(api: ApiPromise, signer: KeySigner | undefined) {
    this.#api = api;
    this.#signer = signer;
  }

  static async connect(url: string, signer: KeySigner | undefined): Promise<PolkadotBackend> {
    try {
      const api = await ApiPromise.create({ provider: new WsProvider(url), noInitWarn: true });
      return new PolkadotBackend(api, signer);
    } catch (cause) {
      throw ClientError.chain(url, cause instanceof Error ? cause.message : String(cause));
    }
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

    const extrinsic = method(...(args as never[]));
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
            reject(ClientError.chain(target, describeDispatchError(this.#api, result.dispatchError)));
            return;
          }
          if (!result.status.isFinalized) return;

          resolve({
            txHash: extrinsic.hash.toHex(),
            blockHash: result.status.asFinalized.toHex(),
            events: result.events.map(
              ({ event }) => [event.section, event.method] as const,
            ),
          });
        })
        .catch((cause: unknown) =>
          reject(
            ClientError.chain(target, cause instanceof Error ? cause.message : String(cause)),
          ),
        );
    });
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
