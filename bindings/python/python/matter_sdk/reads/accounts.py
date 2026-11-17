"""Account reads: what an account holds and how much of it can move."""

import enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from ._leaf import Text, read_error, text, text_from_bytes, wide
from ._scale import ScaleReader, decode_strict
from ._source import StorageEntry, StorageRequest

_ACCOUNT = StorageEntry("System", "Account")
_HOLDS = StorageEntry("Balances", "Holds")
_FREEZES = StorageEntry("Balances", "Freezes")
_LOCKS = StorageEntry("Balances", "Locks")

#: One runtime-composed reason enum: pallet index -> (pallet, reason index -> reason).
_ReasonTable = Dict[int, Tuple[str, Dict[int, str]]]

#: ``RuntimeHoldReason`` as the runtime lays it out.
_HOLD_REASONS: _ReasonTable = {
    10: ("Staking", {0: "Staking"}),
    21: ("Preimage", {0: "Preimage"}),
    27: ("Council", {0: "ProposalSubmission"}),
    28: ("TechnicalCommittee", {0: "ProposalSubmission"}),
    43: ("AssetRewards", {0: "PoolCreation"}),
    45: ("DelegatedStaking", {0: "StakingDelegation"}),
}

#: ``RuntimeFreezeReason`` as the runtime lays it out.
_FREEZE_REASONS: _ReasonTable = {
    43: ("AssetRewards", {0: "Staked"}),
    44: ("NominationPools", {0: "PoolMinBalance"}),
}

_LOCK_ID_BYTES = 8
_U128_MAX = (1 << 128) - 1


class LockReasons(enum.Enum):
    """Which withdrawals a legacy lock blocks."""

    #: Paying transaction fees.
    FEE = "Fee"
    #: Everything except fees.
    MISC = "Misc"
    #: Any withdrawal.
    ALL = "All"


#: ``pallet_balances::Reasons``, by enum index.
_LOCK_REASONS = (LockReasons.FEE, LockReasons.MISC, LockReasons.ALL)


@dataclass(frozen=True)
class BalanceReason:
    """An amount on hold or frozen, and why."""

    #: ``Pallet.Reason``, e.g. ``Staking.Staking``.
    reason: str
    #: Plancks.
    amount: int = wide()


@dataclass(frozen=True)
class BalanceLock:
    """A legacy balance lock."""

    #: The locking pallet's eight-byte id, padding included.
    id: Text = text()
    #: Plancks.
    amount: int = wide()
    #: Which withdrawals the lock blocks.
    reasons: LockReasons


@dataclass(frozen=True)
class AccountBalance:
    """What an account holds, and how much of it can move. Amounts are plancks."""

    #: The account read, as SS58 under the chain's prefix.
    account: str
    #: Whether the chain stores the account at all. ``False`` means never funded
    #: or reaped; every amount is then zero.
    exists: bool
    #: Not on hold. Still subject to freezes, so not all of it can move.
    free: int = wide()
    #: On hold: staked, or bonded as a deposit.
    reserved: int = wide()
    #: The largest freeze; freezes overlap rather than add up.
    frozen: int = wide()
    #: ``free + reserved``.
    total: int = wide()
    #: What a transfer may move if the account is allowed to be reaped. Fees are
    #: not deducted.
    transferable: int = wide()
    #: What a transfer may move while keeping the account alive. Fees are not
    #: deducted.
    transferable_keep_alive: int = wide()
    #: What makes up ``reserved``.
    holds: Tuple[BalanceReason, ...]
    #: What makes up ``frozen``.
    freezes: Tuple[BalanceReason, ...]
    #: Locks from pallets that predate freezes.
    locks: Tuple[BalanceLock, ...]


@dataclass(frozen=True)
class _AccountInfo:
    """``frame_system::AccountInfo``, the fields a balance needs."""

    consumers: int = 0
    providers: int = 0
    free: int = 0
    reserved: int = 0
    frozen: int = 0


def _read_account_info(reader: ScaleReader) -> _AccountInfo:
    reader.u32()  # nonce
    consumers = reader.u32()
    providers = reader.u32()
    reader.u32()  # sufficients
    free = reader.u128()
    reserved = reader.u128()
    frozen = reader.u128()
    reader.u128()  # flags: a bitfield, not an amount
    return _AccountInfo(consumers, providers, free, reserved, frozen)


def _read_reasons(
    table: _ReasonTable, entry: StorageEntry, raw: Optional[bytes]
) -> Tuple[BalanceReason, ...]:
    def one(reader: ScaleReader) -> BalanceReason:
        pallet, reason, amount = reader.u8(), reader.u8(), reader.u128()
        name, reasons = table.get(pallet, ("", {}))
        if reason not in reasons:
            raise read_error(
                entry.target,
                f"reason ({pallet}, {reason}) is not one this SDK knows; "
                "the runtime has added it since",
            )
        return BalanceReason(reason=f"{name}.{reasons[reason]}", amount=amount)

    if raw is None:
        return ()
    return tuple(decode_strict(entry.target, raw, lambda reader: reader.vec(one)))


def _read_locks(raw: Optional[bytes]) -> Tuple[BalanceLock, ...]:
    def one(reader: ScaleReader) -> BalanceLock:
        lock_id = text_from_bytes(reader.fixed(_LOCK_ID_BYTES))  # not length-prefixed
        amount = reader.u128()
        index = reader.u8()
        if index >= len(_LOCK_REASONS):
            raise read_error(
                _LOCKS.target, f"lock reasons {index} is not a variant this SDK knows"
            )
        return BalanceLock(id=lock_id, amount=amount, reasons=_LOCK_REASONS[index])

    if raw is None:
        return ()
    return tuple(decode_strict(_LOCKS.target, raw, lambda reader: reader.vec(one)))


def _reducible(info: _AccountInfo, keep_existential_deposit: bool, existential_deposit: int) -> int:
    """``fungible::Inspect::reducible_balance`` at ``Fortitude::Polite``, as
    ``pallet_balances`` computes it. Freezes apply to the total, so held funds
    count against them first; the existential deposit is kept back only when the
    account must stay alive."""
    frozen_beyond_holds = max(info.frozen - info.reserved, 0)
    untouchable = (
        max(frozen_beyond_holds, existential_deposit)
        if keep_existential_deposit
        else frozen_beyond_holds
    )
    return max(info.free - untouchable, 0)


def balance_requests(account_id: bytes) -> List[StorageRequest]:
    """The entries a balance read needs, in the order :func:`decode_balance`
    takes their values."""
    return [StorageRequest(entry, (account_id,)) for entry in (_ACCOUNT, _HOLDS, _FREEZES, _LOCKS)]


def decode_balance(
    account: str, existential_deposit: int, values: Sequence[Optional[bytes]]
) -> AccountBalance:
    """Build the balance from raw storage values in :func:`balance_requests`
    order. Pure: the same bytes always give the same result, which is what the
    shared vectors replay. ``None`` is an entry the chain does not store."""
    raw_info, raw_holds, raw_freezes, raw_locks = values
    info = (
        _AccountInfo()
        if raw_info is None
        else decode_strict(_ACCOUNT.target, raw_info, _read_account_info)
    )
    # ``Expendable`` still needs the deposit when this balance is the account's
    # only provider and something depends on the account existing.
    provider_is_needed = info.free > 0 and info.consumers > 0 and info.providers <= 1

    return AccountBalance(
        account=account,
        exists=raw_info is not None,
        free=info.free,
        reserved=info.reserved,
        frozen=info.frozen,
        total=min(info.free + info.reserved, _U128_MAX),
        transferable=_reducible(info, provider_is_needed, existential_deposit),
        transferable_keep_alive=_reducible(info, True, existential_deposit),
        holds=_read_reasons(_HOLD_REASONS, _HOLDS, raw_holds),
        freezes=_read_reasons(_FREEZE_REASONS, _FREEZES, raw_freezes),
        locks=_read_locks(raw_locks),
    )
