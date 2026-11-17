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
export { emitted, requireEvent } from "./backend.js";
export type { Mode, ReceiptEvent } from "./backend.js";
export { Access, Scope, ScopeSet, requiredScopes } from "./scopes.js";
export type { ChainBackend, TxReceipt } from "./backend.js";
export {
  AccountsFacade,
  DeploymentsFacade,
  FeesFacade,
  KeysFacade,
  NetworkFacade,
  OrgsFacade,
  ResourcesFacade,
  SecretsFacade,
  StakingFacade,
  secretIdFromReceipt,
} from "./facade.js";
export type { FacadeHost } from "./facade.js";
export { LockReasons } from "./reads/accounts.js";
export type { AccountBalance, BalanceLock, BalanceReason } from "./reads/accounts.js";
export { DispatchClass } from "./reads/fees.js";
export type { BilledTo, FeeEstimate, Weight } from "./reads/fees.js";
export type {
  Block,
  BlockHeader,
  NetworkInfo,
  NetworkTiming,
  NodeStatus,
} from "./reads/network.js";
export { canonicalJson, toJson } from "./reads/leaf.js";
export type { Text } from "./reads/leaf.js";
export type { RawReads } from "./reads/source.js";
export {
  AgentKeyKind,
  KeyPrincipal,
  MIN_TRANSFER_SPEC_VERSION,
  OrgRole,
  TransferActor,
  TransferRefusal,
  UnmovableKind,
  oldAccountHoldsNothing,
  planAccountTransfer,
  planSecretCleanup,
  toSudoBatch,
} from "./admin/accountTransfer.js";
export type {
  AgentKeyFacts,
  Allowance,
  CallTree,
  OldSecretFacts,
  OrgTransferFacts,
  PersonalHoldings,
  ProjectTransferFacts,
  TransferFacts,
  TransferPlan,
  TransferStep,
  Unmovable,
} from "./admin/accountTransfer.js";
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
