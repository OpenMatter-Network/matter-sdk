import { ApiKey, type KeySigner } from "@openmatter-network/matter-sdk-core";

import {
  decimalsFromExistentialDeposit,
  formatAmount,
  oneToken,
  parseAmount,
} from "./amount.js";
import type { ChainBackend, Mode, TxReceipt } from "./backend.js";
import { ClientError } from "./errors.js";
import { defaultLogger, type ClientLogger } from "./logger.js";
import {
  DeploymentsFacade,
  KeysFacade,
  OrgsFacade,
  ResourcesFacade,
  SecretsFacade,
  StakingFacade,
} from "./facade.js";
import { ScopeSet, requiredScopes } from "./scopes.js";
import {
  CONFIRM_ENV,
  CONFIRM_VALUE,
  Network,
  decimalsDisagree,
  defaultRpcUrl,
  detectMainnet,
  type ChainProperties,
} from "./network.js";

/** How to connect. */
export interface MatterConfig {
  /** Which network. Default `Network.Testnet`. */
  network?: Network;
  /** Overrides the network's default endpoint. Required for `Network.Custom`. */
  rpcUrl?: string;
  /** Allow a signing client on mainnet. Also set by `MATTER_CONFIRM=yes`. Default `false`. */
  confirmMainnet?: boolean;
  /** How long to wait for a submitted extrinsic to finalize. Default 120s. */
  finalityTimeoutMs?: number;
  /** Inject a backend instead of connecting one (e.g. for tests). */
  backend?: ChainBackend;
  /**
   * Receives connect diagnostics (delegation principal, decimals mismatch).
   * Default: console. Pass no-ops to silence.
   */
  logger?: ClientLogger;
}


const DEFAULT_FINALITY_TIMEOUT_MS = 120_000;

/**
 * A client for the OpenMatter chain and the matter-kgc committee.
 *
 * No builder by design: named constructors make "API key or signer" unambiguous.
 *
 * @example
 * ```ts
 * const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));
 * await client.tx("Staking", "chill", []);
 * const account = await client.query("System", "Account", [client.accountId]);
 * ```
 */
export class MatterClient {
  readonly #backend: ChainBackend;
  readonly #properties: ChainProperties;
  readonly #signer: KeySigner | undefined;
  readonly #finalityTimeoutMs: number;

  private constructor(
    backend: ChainBackend,
    properties: ChainProperties,
    signer: KeySigner | undefined,
    finalityTimeoutMs: number,
  ) {
    this.#backend = backend;
    this.#properties = properties;
    this.#signer = signer;
    this.#finalityTimeoutMs = finalityTimeoutMs;
  }

  /**
   * Connect read-only. Queries work; anything that submits throws
   * `ClientError` with `kind === "read-only"`.
   */
  static async connect(config: MatterConfig = {}): Promise<MatterClient> {
    return MatterClient.#build(config, undefined);
  }

  /**
   * Connect with an OpenMatter API key.
   *
   * The key is held in process under the guarantees documented on `ApiKey`. For
   * HSM/KMS keys, prefer {@link connectWithSigner}; see `docs/secure-signing.md`.
   */
  static async connectWithApiKey(
    key: ApiKey | string,
    config: MatterConfig = {},
  ): Promise<MatterClient> {
    const apiKey = typeof key === "string" ? new ApiKey(key) : key;
    return MatterClient.#build(config, apiKey);
  }

  /** Connect with a signer you own (HSM, KMS, remote signer). Recommended for production. */
  static async connectWithSigner(
    signer: KeySigner,
    config: MatterConfig = {},
  ): Promise<MatterClient> {
    return MatterClient.#build(config, signer);
  }

  /**
   * Connect from `MATTER_API_KEY` (else `MATTER_SIGNER_SEED`), `MATTER_RPC_URL`,
   * `MATTER_NETWORK` and `MATTER_CONFIRM`. Connects read-only when no key is set.
   */
  static async fromEnv(config: MatterConfig = {}): Promise<MatterClient> {
    const env = process.env;
    const networkName = env["MATTER_NETWORK"] ?? Network.Testnet;
    if (networkName !== Network.Testnet && networkName !== Network.Mainnet) {
      throw ClientError.config(
        `MATTER_NETWORK must be "testnet" or "mainnet", got "${networkName}"`,
      );
    }

    const resolved: MatterConfig = {
      ...config,
      network: config.network ?? networkName,
      rpcUrl: config.rpcUrl ?? env["MATTER_RPC_URL"],
    };

    for (const name of ["MATTER_API_KEY", "MATTER_SIGNER_SEED"] as const) {
      const value = env[name];
      if (value !== undefined && value.trim() !== "") {
        return MatterClient.connectWithApiKey(new ApiKey(value), resolved);
      }
    }
    return MatterClient.connect(resolved);
  }

  static async #build(
    config: MatterConfig,
    signer: KeySigner | undefined,
  ): Promise<MatterClient> {
    const network = config.network ?? Network.Testnet;
    const logger = config.logger ?? defaultLogger;
    const backend =
      config.backend ?? (await MatterClient.#connectBackend(config, network, signer, logger));
    const properties = await backend.properties();

    if (decimalsDisagree(properties)) {
      logger.warn(
        `${properties.chainName} reports tokenDecimals=` +
          `${properties.tokenDecimalsDeclared} in its chain spec but is executing a ` +
          `runtime whose ExistentialDeposit implies ${properties.tokenDecimalsEffective}. ` +
          `Using ${properties.tokenDecimalsEffective} for all arithmetic.`,
      );
    }

    const client = new MatterClient(
      backend,
      properties,
      signer,
      config.finalityTimeoutMs ?? DEFAULT_FINALITY_TIMEOUT_MS,
    );
    client.#enforceNetworkGuards(network, config.confirmMainnet ?? false);
    return client;
  }

  static async #connectBackend(
    config: MatterConfig,
    network: Network,
    signer: KeySigner | undefined,
    logger: ClientLogger,
  ): Promise<ChainBackend> {
    const url = config.rpcUrl ?? defaultRpcUrl(network);
    if (url === undefined) {
      throw ClientError.config("Network.Custom requires a rpcUrl");
    }
    // Lazy so an injected backend never loads @polkadot/api.
    const { PolkadotBackend } = await import("./polkadot.js");
    return PolkadotBackend.connect(url, signer, logger);
  }

  /**
   * Refuse a testnet config on a mainnet endpoint, and a signing mainnet client
   * without confirmation. Checks what the endpoint serves, not the config.
   */
  #enforceNetworkGuards(network: Network, confirmMainnet: boolean): void {
    const { isMainnet, detectedVia } = detectMainnet(this.#properties);

    if (network === Network.Testnet && isMainnet) {
      throw ClientError.wrongNetwork("testnet", this.#properties.chainName);
    }

    // Read-only mainnet access needs no confirmation.
    if (!isMainnet || this.#signer === undefined) return;

    const confirmed = confirmMainnet || process.env[CONFIRM_ENV] === CONFIRM_VALUE;
    if (confirmed) return;
    throw ClientError.mainnetNotConfirmed(this.#properties.chainName, detectedVia);
  }

  /** Chain identity and unit metadata, read once at connect. */
  get properties(): ChainProperties {
    return this.#properties;
  }

  /** The signing identity's 32-byte account id, or `undefined` if read-only. */
  get accountId(): Uint8Array | undefined {
    return this.#signer?.accountId;
  }

  /** The signing identity's account id as `0x` hex, or `undefined`. */
  get accountIdHex(): string | undefined {
    const id = this.accountId;
    if (id === undefined) return undefined;
    return `0x${Array.from(id, (b) => b.toString(16).padStart(2, "0")).join("")}`;
  }

  /** The signing identity's SS58 address (chain-reported prefix), or `undefined` if read-only. */
  get address(): string | undefined {
    const id = this.accountId;
    return id === undefined ? undefined : this.#backend.encodeAddress(id);
  }

  /** The signer backing this client, for the committee path. */
  get signer(): KeySigner | undefined {
    return this.#signer;
  }

  /** The underlying backend, for anything this surface does not cover. */
  get backend(): ChainBackend {
    return this.#backend;
  }

  /** Parse a decimal token amount into plancks, at this chain's effective decimals. */
  parseAmount(text: string): bigint {
    return parseAmount(text, this.#properties.tokenDecimalsEffective);
  }

  /** Render plancks as a decimal string, at this chain's effective decimals. */
  formatAmount(plancks: bigint): string {
    return formatAmount(plancks, this.#properties.tokenDecimalsEffective);
  }

  /** One whole token in plancks, on this chain. */
  oneToken(): bigint {
    return oneToken(this.#properties.tokenDecimalsEffective);
  }

  /**
   * Sign and submit `pallet.call(args)`, resolved by name against live metadata,
   * waiting for finalization. Throws `finality-timeout` after `finalityTimeoutMs`.
   */
  async tx(pallet: string, call: string, args: unknown[]): Promise<TxReceipt> {
    if (this.#signer === undefined) throw ClientError.readOnly();

    const target = `${pallet}.${call}`;
    this.#refuseIfOutOfScope(pallet, call, args, target);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(
        () => reject(ClientError.finalityTimeout(target, this.#finalityTimeoutMs)),
        this.#finalityTimeoutMs,
      );
    });

    try {
      return await Promise.race([this.#backend.submit(pallet, call, args), timeout]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /**
   * Refuse, before submitting, a call this client's key cannot make. A courtesy
   * for clearer errors, not a boundary: the runtime enforces scopes.
   */
  #refuseIfOutOfScope(pallet: string, call: string, args: unknown[], target: string): void {
    const mode = this.mode;
    if (mode.kind !== "delegated") return;

    // Never admitted inside a proxy: nesting would launder authority through a batch.
    if (pallet === "Proxy" || pallet === "Utility" || pallet === "EthSigning") {
      throw ClientError.neverAdmitted(target);
    }

    const required = requiredScopes(pallet, call, args);
    if (required === null) throw ClientError.neverAdmitted(target);
    if (!mode.scopes.isSuperset(required)) {
      throw ClientError.notPermitted(target, required.toString(), mode.scopes.toString());
    }
  }

  /** Who this client's signature speaks for; see {@link Mode}. */
  get mode(): Mode {
    return this.#backend.mode?.() ?? { kind: "direct" };
  }

  /** The member this client acts for, or `undefined` when it acts as itself. */
  get principal(): Uint8Array | undefined {
    const mode = this.mode;
    return mode.kind === "delegated" ? mode.principal : undefined;
  }

  /** The member's SS58 address, or `undefined` when this client acts as itself. */
  get principalAddress(): string | undefined {
    const principal = this.principal;
    return principal === undefined ? undefined : this.#backend.encodeAddress(principal);
  }

  /**
   * Who `key` acts for and what it may do, per the chain; `undefined` if it holds
   * no scoped proxy. Works on a read-only client.
   */
  async agentKey(key: Uint8Array): Promise<readonly [Uint8Array, ScopeSet] | undefined> {
    if (this.#backend.agentKey === undefined) {
      throw ClientError.config("this backend cannot resolve an api key's grant");
    }
    return this.#backend.agentKey(key);
  }

  /** What this client's key may do, or `undefined` without a scoped proxy. */
  get scopes(): ScopeSet | undefined {
    const mode = this.mode;
    return mode.kind === "delegated" ? mode.scopes : undefined;
  }

  /**
   * Read a storage entry. `keys` are the map keys, empty for a plain value.
   * `undefined` means absent (e.g. an unfunded account's `System.Account`).
   */
  async query(pallet: string, entry: string, keys: unknown[] = []): Promise<unknown> {
    return this.#backend.query(pallet, entry, keys);
  }

  /** Call a runtime API by its `state_call` name, e.g. `"KgcApi_dkg_epoch"`. */
  async runtimeApi(method: string, argsHex = "0x"): Promise<string> {
    return this.#backend.runtimeApi(method, argsHex);
  }

  /** Read a pallet constant from the live metadata. */
  constant(pallet: string, name: string): unknown {
    return this.#backend.constant(pallet, name);
  }

  /** Secrets: store, rotate, share, and delete secrets. */
  get secrets(): SecretsFacade {
    return new SecretsFacade(this);
  }

  /** Deployments (`pallet-jobs`): request compute, wire networking, bind secrets. */
  get deployments(): DeploymentsFacade {
    return new DeploymentsFacade(this);
  }

  /** Resources: register capacity, price it, control who may use it. */
  get resources(): ResourcesFacade {
    return new ResourcesFacade(this);
  }

  /** Staking on MatterChain, including nomination pools. */
  get staking(): StakingFacade {
    return new StakingFacade(this);
  }

  /** Organizations and budgets. */
  get orgs(): OrgsFacade {
    return new OrgsFacade(this);
  }

  /** Minting and revoking member-tied API keys; see {@link KeysFacade}. */
  get keys(): KeysFacade {
    return new KeysFacade(this);
  }

  async disconnect(): Promise<void> {
    await this.#backend.disconnect();
  }
}
