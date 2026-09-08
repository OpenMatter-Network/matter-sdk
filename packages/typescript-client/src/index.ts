/**
 * OpenMatter — TypeScript client.
 *
 * One `apiKey` in, a client that can do anything that account is entitled to on
 * MatterChain: request deployments, manage resources, stake, run org budgets,
 * govern — every pallet the runtime exposes, resolved from live metadata rather
 * than vendored types.
 *
 * This package re-exports the whole of `@openmatter-network/matter-vault`, so a
 * chain consumer imports one package name. `matter-vault` remains the light,
 * zero-runtime-dependency package for browsers that only seal and recover
 * secrets; this one adds `@polkadot/api`.
 *
 * @example
 * ```ts
 * import { MatterClient, ApiKey, Aad } from "@openmatter-network/matter-client";
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
 * Defaults are testnet, and a *signing* client refuses to touch mainnet without
 * explicit confirmation. See `docs/secure-signing.md` for what holding a key in
 * process does and does not protect against.
 */

// The full light-package surface, so chain consumers need one import.
export * from "@openmatter-network/matter-vault";

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
