// Network selection and the chain properties read at connect.

/** Which OpenMatter network to talk to. */
export const Network = {
  /** The public testnet. The default. */
  Testnet: "testnet",
  /** Mainnet. Signing clients require explicit confirmation. */
  Mainnet: "mainnet",
  /** Anything else (a local dev node, a fork). Requires an explicit `rpcUrl`. */
  Custom: "custom",
} as const;

export type Network = (typeof Network)[keyof typeof Network];

/** Default RPC endpoint per network. */
export const TESTNET_RPC = "wss://node2.testnet.openmatter.network";
export const MAINNET_RPC = "wss://node1.mainnet.openmatter.network";

/**
 * Genesis hash of the public testnet, read with `chain_getBlockHash(0)` on
 * 2026-07-29. The only spoof-resistant network signal currently pinned.
 */
export const TESTNET_GENESIS =
  "0xd87ca10ad40194ff37525c0b5fc5997d94010107a399d03bf5672c0a7b30f058";

/**
 * Fallback network signal while the mainnet genesis hash is unpinned: mainnet
 * mints `MTR`, testnet `MTR-Test`. From `chainspecs/*-spec.json`.
 */
export const MAINNET_TOKEN_SYMBOL = "MTR";

/** Environment variable that satisfies the mainnet confirmation guard. */
export const CONFIRM_ENV = "MATTER_CONFIRM";
export const CONFIRM_VALUE = "yes";

export function defaultRpcUrl(network: Network): string | undefined {
  if (network === Network.Testnet) return TESTNET_RPC;
  if (network === Network.Mainnet) return MAINNET_RPC;
  return undefined;
}

/**
 * Chain identity and unit metadata, read once at connect.
 *
 * Both decimal counts are exposed on purpose, because they can disagree.
 */
export interface ChainProperties {
  /** `chain_getBlockHash(0)`, `0x`-prefixed. */
  readonly genesisHash: string;
  /** `system_chain`, e.g. `"MatterChain Testnet"`. */
  readonly chainName: string;
  /** The live runtime's `spec_version`. */
  readonly specVersion: number;
  /** `system_properties.tokenSymbol`, e.g. `"MTR-Test"`. */
  readonly tokenSymbol: string;
  /** `system_properties.ss58Format`, defaulting to 42. */
  readonly ss58Prefix: number;

  /**
   * `system_properties.tokenDecimals` — **presentational**. Served from the
   * node's chain-spec file, not the runtime, so it can be stale or ahead of the
   * deployed wasm. Use it for display parity with explorers; never for arithmetic.
   */
  readonly tokenDecimalsDeclared: number;

  /**
   * Decimals implied by the live runtime's own `Balances.ExistentialDeposit`
   * (`ED === 10 ** (d - 3)`) — **consensus-backed**, and what every conversion
   * here uses.
   *
   * The distinction is not academic: matter-node changed `UNIT` from `10**12` to
   * `10**18` with no storage migration, so a node serving a stale chain spec
   * reports 18 while executing a 12-decimal runtime.
   */
  readonly tokenDecimalsEffective: number;

  /** The raw `Balances.ExistentialDeposit`, in plancks. */
  readonly existentialDeposit: bigint;
}

/** Whether the node's chain spec disagrees with the runtime it is executing. */
export function decimalsDisagree(properties: ChainProperties): boolean {
  return properties.tokenDecimalsDeclared !== properties.tokenDecimalsEffective;
}

/**
 * Whether this endpoint serves mainnet, and how that was decided.
 *
 * Genesis hash is the only spoof-resistant signal, but the mainnet hash is not
 * yet pinned (its RPC was unreachable when this was written), so the token symbol
 * stands in.
 */
export function detectMainnet(
  properties: ChainProperties,
): { isMainnet: boolean; detectedVia: "genesis-hash" | "token-symbol" } {
  if (properties.genesisHash === TESTNET_GENESIS) {
    return { isMainnet: false, detectedVia: "genesis-hash" };
  }
  return {
    isMainnet: properties.tokenSymbol === MAINNET_TOKEN_SYMBOL,
    detectedVia: "token-symbol",
  };
}
