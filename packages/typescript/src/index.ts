/**
 * OpenMatter TypeScript client: every MatterChain pallet, resolved from live
 * metadata.
 *
 * Re-exports all of `@openmatter-network/matter-sdk-core` (the light,
 * zero-dependency package for sealing and recovering secrets) and adds the
 * chain client, built on `@polkadot/api`.
 *
 * @example
 * ```ts
 * import { MatterClient, ApiKey } from "@openmatter-network/matter-sdk";
 *
 * const client = await MatterClient.connectWithApiKey(new ApiKey(process.env.MATTER_API_KEY!));
 *
 * // Any pallet, resolved from live metadata.
 * await client.tx("Staking", "bond", [client.parseAmount("10"), { Staked: null }]);
 *
 * // Reads and runtime APIs go through the same surface.
 * const account = await client.query("System", "Account", [client.accountId]);
 * const epoch = await client.runtimeApi("KgcApi_dkg_epoch");
 * ```
 *
 * Defaults to testnet; a signing client refuses mainnet without explicit
 * confirmation. See `docs/secure-signing.md` for the in-process key threat model.
 */

export * from "@openmatter-network/matter-sdk-core";

export { MatterClient } from "./client.js";
export type { MatterConfig } from "./client.js";
export { ClientError } from "./errors.js";
export { defaultLogger } from "./logger.js";
export type { ClientLogger } from "./logger.js";
export type { ClientErrorKind } from "./errors.js";
export { emitted } from "./backend.js";
export type { Mode } from "./backend.js";
export { Access, Scope, ScopeSet, requiredScopes } from "./scopes.js";
export type { ChainBackend, TxReceipt } from "./backend.js";
export {
  DeploymentsFacade,
  KeysFacade,
  OrgsFacade,
  ResourcesFacade,
  SecretsFacade,
  StakingFacade,
} from "./facade.js";
export type { FacadeHost } from "./facade.js";
export {
  AmountError,
  decimalsFromExistentialDeposit,
  formatAmount,
  oneToken,
  parseAmount,
} from "./amount.js";
export {
  CONFIRM_ENV,
  CONFIRM_VALUE,
  MAINNET_RPC,
  MAINNET_TOKEN_SYMBOL,
  Network,
  TESTNET_GENESIS,
  TESTNET_RPC,
  decimalsDisagree,
  defaultRpcUrl,
  detectMainnet,
} from "./network.js";
export type { ChainProperties } from "./network.js";
