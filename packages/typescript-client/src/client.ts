// The OpenMatter client: one key, every pallet.
//
// Mirrors the Rust MatterClient — four named constructors, a generic
// metadata-driven surface, plancks-only amounts, and a mainnet guard that checks
// what the *endpoint* serves rather than what the caller configured.

import { ApiKey, type KeySigner } from "@openmatter-network/matter-vault";

import {
  decimalsFromExistentialDeposit,
  formatAmount,
  oneToken,
  parseAmount,
} from "./amount.js";
import type { ChainBackend, TxReceipt } from "./backend.js";
import { ClientError } from "./errors.js";
import {
  DeploymentsFacade,
  OrgsFacade,
  ResourcesFacade,
  SecretsFacade,
  StakingFacade,
} from "./facade.js";
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
  /**
   * In-code acknowledgement that this client may spend real funds. Also
   * satisfiable with `MATTER_CONFIRM=yes`. Default `false`.
   */
  confirmMainnet?: boolean;
  /** How long to wait for a submitted extrinsic to finalize. Default 120s. */
  finalityTimeoutMs?: number;
  /**
   * Inject a backend instead of connecting one. The seam that makes this client
   * testable without a node.
   */
  backend?: ChainBackend;
}

const DEFAULT_FINALITY_TIMEOUT_MS = 120_000;

/**
 * A client for the OpenMatter chain and the MatterVault committee.
 *
 * Four named constructors, four distinct intents. There is deliberately no
 * builder: a builder would let you set both an API key and a signer and defer
 * "which wins?" to run time.
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

  // --- constructors -------------------------------------------------------

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
   * production keys in an HSM or KMS, prefer {@link connectWithSigner} — see
   * `docs/secure-signing.md`.
   */
  static async connectWithApiKey(
    key: ApiKey | string,
    config: MatterConfig = {},
  ): Promise<MatterClient> {
    const apiKey = typeof key === "string" ? new ApiKey(key) : key;
    return MatterClient.#build(config, apiKey);
  }

  /**
   * Connect with a signer you own — an HSM, a KMS, a remote signing service. The
   * recommended production path.
   */
  static async connectWithSigner(
    signer: KeySigner,
    config: MatterConfig = {},
  ): Promise<MatterClient> {
    return MatterClient.#build(config, signer);
  }

  /**
   * Connect from the environment: `MATTER_API_KEY` (falling back to
   * `MATTER_SIGNER_SEED`, for parity with the e2e harnesses), `MATTER_RPC_URL`,
   * `MATTER_NETWORK`, `MATTER_CONFIRM`.
   *
   * With no key in the environment this connects read-only rather than throwing,
   * so the same code path serves read-only tooling.
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
    const backend = config.backend ?? (await MatterClient.#connectBackend(config, network, signer));
    const properties = await backend.properties();

    if (decimalsDisagree(properties)) {
      // Loud once, then trust the runtime. Quiet success, loud surprise.
      console.warn(
        `WARNING: ${properties.chainName} reports tokenDecimals=` +
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
  ): Promise<ChainBackend> {
    const url = config.rpcUrl ?? defaultRpcUrl(network);
    if (url === undefined) {
      throw ClientError.config("Network.Custom requires a rpcUrl");
    }
    // Imported lazily so the guards and arithmetic can be unit-tested — and a
    // caller can inject a backend — without pulling in @polkadot/api.
    const { PolkadotBackend } = await import("./polkadot.js");
    return PolkadotBackend.connect(url, signer);
  }

  /**
   * Two guards, both about not spending real money by accident.
   *
   * The checks are on what the *endpoint* actually serves, not on the configured
   * network — pointing `Network.Testnet` at a mainnet URL must still trip, which
   * is exactly the hole a config-flag check would leave open.
   */
  #enforceNetworkGuards(network: Network, confirmMainnet: boolean): void {
    const { isMainnet, detectedVia } = detectMainnet(this.#properties);

    // A typo'd URL should fail before it costs anything.
    if (network === Network.Testnet && isMainnet) {
      throw ClientError.wrongNetwork("testnet", this.#properties.chainName);
    }

    // Read-only mainnet access needs no confirmation.
    if (!isMainnet || this.#signer === undefined) return;

    const confirmed = confirmMainnet || process.env[CONFIRM_ENV] === CONFIRM_VALUE;
    if (confirmed) return;
    throw ClientError.mainnetNotConfirmed(this.#properties.chainName, detectedVia);
  }

  // --- identity and properties -------------------------------------------

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

  /**
   * The signing identity's SS58 address, or `undefined` if read-only.
   *
   * Uses the prefix the chain reports rather than a constant, so the same key
   * prints the same address here as in the Rust, Python, and Go clients.
   */
  get address(): string | undefined {
    const id = this.accountId;
    return id === undefined ? undefined : this.#backend.encodeAddress(id);
  }

  /** The signer backing this client, for the committee path. */
  get signer(): KeySigner | undefined {
    return this.#signer;
  }

  /**
   * The underlying backend, for anything this surface does not cover.
   *
   * Exposed deliberately: a client that cannot be escaped from is a client that
   * blocks work. Using it is not a bug report.
   */
  get backend(): ChainBackend {
    return this.#backend;
  }

  // --- amounts ------------------------------------------------------------

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

  // --- the generic surface ------------------------------------------------

  /**
   * Sign and submit `pallet.call(args)`, waiting for finalization.
   *
   * Resolution is by name against the live metadata, so this reaches every pallet
   * the runtime exposes — including ones added after this SDK shipped.
   */
  async tx(pallet: string, call: string, args: unknown[]): Promise<TxReceipt> {
    if (this.#signer === undefined) throw ClientError.readOnly();

    const target = `${pallet}.${call}`;
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
   * Read a storage entry. `keys` are the map keys, empty for a plain value.
   * `undefined` means the entry is absent, which is normal control flow — an
   * unfunded account has no `System.Account` row.
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

  // --- curated façades ----------------------------------------------------
  //
  // Lazily constructed getters rather than fields, so adding a call touches only
  // the façade's own file. If a new façade call ever forces a change to
  // ClientError or MatterConfig, the seam has leaked — treat that as a design
  // bug, not a routine edit.

  /** Secrets: store, rotate, share, and delete MatterVault secrets. */
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

  /** Release the connection. */
  async disconnect(): Promise<void> {
    await this.#backend.disconnect();
  }
}
