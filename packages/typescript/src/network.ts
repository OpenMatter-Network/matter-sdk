/** Which OpenMatter network to talk to. */
export const Network = {
  /** The public testnet (default). */
  Testnet: "testnet",
  /** Mainnet. Signing clients require explicit confirmation. */
  Mainnet: "mainnet",
  /** Anything else (a local dev node, a fork). Requires an explicit `rpcUrl`. */
  Custom: "custom",
} as const;

export type Network = (typeof Network)[keyof typeof Network];

/** Testnet's default RPC endpoint. Must match `testvectors/networks.json`. */
export const TESTNET_RPC = "wss://node2.testnet.openmatter.network";
/** Mainnet's default RPC endpoint. Must match `testvectors/networks.json`. */
export const MAINNET_RPC = "wss://node2.mainnet.openmatter.network";

/** Genesis hash of the public testnet; the only spoof-resistant network signal pinned. */
export const TESTNET_GENESIS =
  "0xd87ca10ad40194ff37525c0b5fc5997d94010107a399d03bf5672c0a7b30f058";

/** Fallback mainnet signal while its genesis hash is unpinned (testnet uses `MTR-Test`). */
export const MAINNET_TOKEN_SYMBOL = "MTR";

/** Environment variable that satisfies the mainnet confirmation guard. */
export const CONFIRM_ENV = "MATTER_CONFIRM";
/** The value {@link CONFIRM_ENV} must hold to confirm a signing mainnet client. */
export const CONFIRM_VALUE = "yes";

/** The default RPC endpoint for `network`; `undefined` for `custom`. */
export function defaultRpcUrl(network: Network): string | undefined {
  if (network === Network.Testnet) return TESTNET_RPC;
  if (network === Network.Mainnet) return MAINNET_RPC;
  return undefined;
}

/** Chain identity and unit metadata, read once at connect. The two decimal counts can disagree. */
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
   * `system_properties.tokenDecimals`: **presentational**, from the node's chain
   * spec, possibly stale. Never use it for arithmetic.
   */
  readonly tokenDecimalsDeclared: number;

  /**
   * Decimals implied by the runtime's `Balances.ExistentialDeposit`
   * (`ED === 10 ** (d - 3)`): **consensus-backed**; every conversion uses this.
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
 * Whether this endpoint serves mainnet, and how that was decided. Token symbol
 * stands in until the mainnet genesis hash is pinned.
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
