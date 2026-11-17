// Account reads: what an account holds and how much of it can move.

import { ClientError } from "../errors.js";
import { textFromBytes, type Text } from "./leaf.js";
import { decodeStrict, type ScaleReader } from "./scale.js";
import { targetOf, type StorageEntry, type StorageRequest } from "./source.js";

const ACCOUNT: StorageEntry = { pallet: "System", entry: "Account" };
const HOLDS: StorageEntry = { pallet: "Balances", entry: "Holds" };
const FREEZES: StorageEntry = { pallet: "Balances", entry: "Freezes" };
const LOCKS: StorageEntry = { pallet: "Balances", entry: "Locks" };

/** One pallet's reasons inside a runtime-composed reason enum, by enum index. */
export interface ReasonGroup {
  readonly index: number;
  readonly pallet: string;
  readonly reasons: ReadonlyMap<number, string>;
}

function group(index: number, pallet: string, reasons: ReadonlyArray<[number, string]>): ReasonGroup {
  return { index, pallet, reasons: new Map(reasons) };
}

/** `RuntimeHoldReason` as the runtime lays it out. */
export const HOLD_REASONS: readonly ReasonGroup[] = [
  group(10, "Staking", [[0, "Staking"]]),
  group(21, "Preimage", [[0, "Preimage"]]),
  group(27, "Council", [[0, "ProposalSubmission"]]),
  group(28, "TechnicalCommittee", [[0, "ProposalSubmission"]]),
  group(43, "AssetRewards", [[0, "PoolCreation"]]),
  group(45, "DelegatedStaking", [[0, "StakingDelegation"]]),
];

/** `RuntimeFreezeReason` as the runtime lays it out. */
export const FREEZE_REASONS: readonly ReasonGroup[] = [
  group(43, "AssetRewards", [[0, "Staked"]]),
  group(44, "NominationPools", [[0, "PoolMinBalance"]]),
];

/** Which withdrawals a legacy lock blocks. */
export enum LockReasons {
  /** Paying transaction fees. */
  Fee = "Fee",
  /** Everything except fees. */
  Misc = "Misc",
  /** Any withdrawal. */
  All = "All",
}

/** `pallet_balances::Reasons`, by enum index. */
export const LOCK_REASONS: readonly LockReasons[] = [LockReasons.Fee, LockReasons.Misc, LockReasons.All];
const LOCK_ID_BYTES = 8;

/** An amount on hold or frozen, and why. */
export interface BalanceReason {
  /** `Pallet.Reason`, e.g. `Staking.Staking`. */
  readonly reason: string;
  /** Plancks. */
  readonly amount: bigint;
}

/** A legacy balance lock. */
export interface BalanceLock {
  /** The locking pallet's eight-byte id, padding included. */
  readonly id: Text;
  /** Plancks. */
  readonly amount: bigint;
  /** Which withdrawals the lock blocks. */
  readonly reasons: LockReasons;
}

/** What an account holds, and how much of it can move. Amounts are plancks. */
export interface AccountBalance {
  /** The account read, as SS58 under the chain's prefix. */
  readonly account: string;
  /**
   * Whether the chain stores the account at all. `false` means never funded or
   * reaped; every amount is then zero.
   */
  readonly exists: boolean;
  /** Not on hold. Still subject to freezes, so not all of it can move. */
  readonly free: bigint;
  /** On hold: staked, or bonded as a deposit. */
  readonly reserved: bigint;
  /** The largest freeze; freezes overlap rather than add up. */
  readonly frozen: bigint;
  /** `free + reserved`. */
  readonly total: bigint;
  /** What a transfer may move if the account is allowed to be reaped. Fees are not deducted. */
  readonly transferable: bigint;
  /** What a transfer may move while keeping the account alive. Fees are not deducted. */
  readonly transferableKeepAlive: bigint;
  /** What makes up `reserved`. */
  readonly holds: readonly BalanceReason[];
  /** What makes up `frozen`. */
  readonly freezes: readonly BalanceReason[];
  /** Locks from pallets that predate freezes. */
  readonly locks: readonly BalanceLock[];
}

/** `frame_system::AccountInfo`, the fields a balance needs. */
interface AccountInfo {
  readonly consumers: number;
  readonly providers: number;
  readonly free: bigint;
  readonly reserved: bigint;
  readonly frozen: bigint;
}

const NO_ACCOUNT: AccountInfo = { consumers: 0, providers: 0, free: 0n, reserved: 0n, frozen: 0n };
const U128_MAX = (1n << 128n) - 1n;

function readAccountInfo(reader: ScaleReader): AccountInfo {
  reader.u32(); // nonce
  const consumers = reader.u32();
  const providers = reader.u32();
  reader.u32(); // sufficients
  const free = reader.u128();
  const reserved = reader.u128();
  const frozen = reader.u128();
  reader.u128(); // flags: a bitfield, not an amount
  return { consumers, providers, free, reserved, frozen };
}

function readReasons(
  table: readonly ReasonGroup[],
  entry: StorageEntry,
  raw: Uint8Array | undefined,
): BalanceReason[] {
  if (raw === undefined) return [];
  return decodeStrict(targetOf(entry), raw, (reader) =>
    reader.vec((item) => {
      const pallet = item.u8();
      const reason = item.u8();
      const amount = item.u128();
      const found = table.find((candidate) => candidate.index === pallet);
      const name = found?.reasons.get(reason);
      if (found === undefined || name === undefined) {
        throw ClientError.chain(
          targetOf(entry),
          `reason (${pallet}, ${reason}) is not one this SDK knows; the runtime has added it since`,
        );
      }
      return { reason: `${found.pallet}.${name}`, amount };
    }),
  );
}

function readLocks(raw: Uint8Array | undefined): BalanceLock[] {
  if (raw === undefined) return [];
  return decodeStrict(targetOf(LOCKS), raw, (reader) =>
    reader.vec((item) => {
      const id = textFromBytes(item.fixed(LOCK_ID_BYTES));
      const amount = item.u128();
      const index = item.u8();
      const reasons = LOCK_REASONS[index];
      if (reasons === undefined) {
        throw ClientError.chain(targetOf(LOCKS), `lock reasons ${index} is not a variant this SDK knows`);
      }
      return { id, amount, reasons };
    }),
  );
}

function saturatingSub(left: bigint, right: bigint): bigint {
  return left > right ? left - right : 0n;
}

/**
 * `fungible::Inspect::reducible_balance` at `Fortitude::Polite`, as
 * `pallet_balances` computes it. Freezes apply to the total, so held funds
 * count against them first; the existential deposit is kept back only when the
 * account must stay alive.
 */
function reducible(info: AccountInfo, keepExistentialDeposit: boolean, existentialDeposit: bigint): bigint {
  const frozenBeyondHolds = saturatingSub(info.frozen, info.reserved);
  const untouchable =
    keepExistentialDeposit && existentialDeposit > frozenBeyondHolds ? existentialDeposit : frozenBeyondHolds;
  return saturatingSub(info.free, untouchable);
}

/** The entries a balance read needs, in the order `decodeBalance` takes their values. */
export function balanceRequests(accountId: Uint8Array): StorageRequest[] {
  return [ACCOUNT, HOLDS, FREEZES, LOCKS].map((entry) => ({ entry, keys: [accountId] }));
}

/**
 * Build the balance from raw storage values in `balanceRequests` order. Pure:
 * the same bytes always give the same result, which is what the shared vectors
 * replay. `undefined` is an entry the chain does not store.
 */
export function decodeBalance(
  account: string,
  existentialDeposit: bigint,
  values: ReadonlyArray<Uint8Array | undefined>,
): AccountBalance {
  const [rawInfo, rawHolds, rawFreezes, rawLocks] = values;
  const info =
    rawInfo === undefined ? NO_ACCOUNT : decodeStrict(targetOf(ACCOUNT), rawInfo, readAccountInfo);
  // `Expendable` still needs the deposit when this balance is the account's
  // only provider and something depends on the account existing.
  const providerIsNeeded = info.free > 0n && info.consumers > 0 && info.providers <= 1;
  const total = info.free + info.reserved;

  return {
    account,
    exists: rawInfo !== undefined,
    free: info.free,
    reserved: info.reserved,
    frozen: info.frozen,
    total: total > U128_MAX ? U128_MAX : total,
    transferable: reducible(info, providerIsNeeded, existentialDeposit),
    transferableKeepAlive: reducible(info, true, existentialDeposit),
    holds: readReasons(HOLD_REASONS, HOLDS, rawHolds),
    freezes: readReasons(FREEZE_REASONS, FREEZES, rawFreezes),
    locks: readLocks(rawLocks),
  };
}
