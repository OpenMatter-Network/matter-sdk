//! Account reads: what an account holds and how much of it can move.

use matter_sdk_key::AccountId;
use parity_scale_codec::Decode;
use serde::Serialize;
use subxt::dynamic::Value;

use super::leaf::{decimal, Address, Text};
use super::{decode_strict, StorageEntry, StorageRequest};
use crate::error::{Result, SdkError};

pub(in crate::chain) const ACCOUNT: StorageEntry = StorageEntry::new("System", "Account");
pub(in crate::chain) const HOLDS: StorageEntry = StorageEntry::new("Balances", "Holds");
pub(in crate::chain) const FREEZES: StorageEntry = StorageEntry::new("Balances", "Freezes");
pub(in crate::chain) const LOCKS: StorageEntry = StorageEntry::new("Balances", "Locks");

/// One pallet's reasons inside a runtime-composed reason enum:
/// `(pallet index, pallet, [(reason index, reason)])`.
pub(in crate::chain) type ReasonGroup = (u8, &'static str, &'static [(u8, &'static str)]);

/// `RuntimeHoldReason` as the runtime lays it out.
pub(in crate::chain) const HOLD_REASONS: &[ReasonGroup] = &[
    (10, "Staking", &[(0, "Staking")]),
    (21, "Preimage", &[(0, "Preimage")]),
    (27, "Council", &[(0, "ProposalSubmission")]),
    (28, "TechnicalCommittee", &[(0, "ProposalSubmission")]),
    (43, "AssetRewards", &[(0, "PoolCreation")]),
    (45, "DelegatedStaking", &[(0, "StakingDelegation")]),
];

/// `RuntimeFreezeReason` as the runtime lays it out.
pub(in crate::chain) const FREEZE_REASONS: &[ReasonGroup] = &[
    (43, "AssetRewards", &[(0, "Staked")]),
    (44, "NominationPools", &[(0, "PoolMinBalance")]),
];

/// `frame_system::AccountInfo`.
#[derive(Decode)]
struct AccountInfoWire {
    _nonce: u32,
    consumers: u32,
    providers: u32,
    _sufficients: u32,
    data: AccountDataWire,
}

/// `pallet_balances::AccountData`. `flags` is a bitfield, not an amount.
#[derive(Decode)]
struct AccountDataWire {
    free: u128,
    reserved: u128,
    frozen: u128,
    _flags: u128,
}

/// One `IdAmount` under a runtime-composed reason: two enum index bytes, then
/// the amount.
#[derive(Decode)]
struct ReasonedAmountWire {
    pallet: u8,
    reason: u8,
    amount: u128,
}

/// `pallet_balances::BalanceLock`; `reasons` is an index into [`LOCK_REASONS`].
#[derive(Decode)]
struct LockWire {
    id: [u8; 8],
    amount: u128,
    reasons: u8,
}

/// What an account holds, and how much of it can move. Amounts are plancks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AccountBalance {
    /// The account read.
    pub account: Address,
    /// Whether the chain stores the account at all. `false` means never funded
    /// or reaped; every amount is then zero.
    pub exists: bool,
    /// Not on hold. Still subject to freezes, so not all of it can move.
    #[serde(with = "decimal")]
    pub free: u128,
    /// On hold: staked, or bonded as a deposit.
    #[serde(with = "decimal")]
    pub reserved: u128,
    /// The largest freeze; freezes overlap rather than add up.
    #[serde(with = "decimal")]
    pub frozen: u128,
    /// `free + reserved`.
    #[serde(with = "decimal")]
    pub total: u128,
    /// What a transfer may move if the account is allowed to be reaped. Fees
    /// are not deducted.
    #[serde(with = "decimal")]
    pub transferable: u128,
    /// What a transfer may move while keeping the account alive. Fees are not
    /// deducted.
    #[serde(with = "decimal")]
    pub transferable_keep_alive: u128,
    /// What makes up `reserved`.
    pub holds: Vec<BalanceReason>,
    /// What makes up `frozen`.
    pub freezes: Vec<BalanceReason>,
    /// Locks from pallets that predate freezes.
    pub locks: Vec<BalanceLock>,
}

/// An amount on hold or frozen, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BalanceReason {
    /// `Pallet.Reason`, e.g. `Staking.Staking`.
    pub reason: String,
    /// Plancks.
    #[serde(with = "decimal")]
    pub amount: u128,
}

/// A legacy balance lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BalanceLock {
    /// The locking pallet's eight-byte id, padding included.
    pub id: Text,
    /// Plancks.
    #[serde(with = "decimal")]
    pub amount: u128,
    /// Which withdrawals the lock blocks.
    pub reasons: LockReasons,
}

/// Which withdrawals a legacy lock blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum LockReasons {
    /// Paying transaction fees.
    Fee,
    /// Everything except fees.
    Misc,
    /// Any withdrawal.
    All,
}

/// `pallet_balances::Reasons`, by enum index.
pub(in crate::chain) const LOCK_REASONS: [LockReasons; 3] =
    [LockReasons::Fee, LockReasons::Misc, LockReasons::All];

/// The entries a balance read needs, in the order [`decode_balance`] takes
/// their values.
pub(in crate::chain) fn balance_requests(who: AccountId) -> [StorageRequest; 4] {
    [ACCOUNT, HOLDS, FREEZES, LOCKS].map(|entry| StorageRequest {
        entry,
        keys: vec![Value::from_bytes(who.as_bytes())],
    })
}

/// Raw storage values, in [`balance_requests`] order. `None` is an entry the
/// chain does not store.
pub(in crate::chain) type BalanceValues = [Option<Vec<u8>>; 4];

fn reason_name(
    table: &[ReasonGroup],
    entry: StorageEntry,
    wire: &ReasonedAmountWire,
) -> Result<String> {
    table
        .iter()
        .find(|(pallet, ..)| *pallet == wire.pallet)
        .and_then(|(_, pallet, reasons)| {
            reasons
                .iter()
                .find(|(reason, _)| *reason == wire.reason)
                .map(|(_, reason)| format!("{pallet}.{reason}"))
        })
        .ok_or_else(|| SdkError::Chain {
            target: entry.target(),
            detail: format!(
                "reason ({}, {}) is not one this SDK knows; the runtime has added it since",
                wire.pallet, wire.reason
            ),
        })
}

fn decode_reasons(
    table: &[ReasonGroup],
    entry: StorageEntry,
    raw: Option<&[u8]>,
) -> Result<Vec<BalanceReason>> {
    let wire: Vec<ReasonedAmountWire> = raw
        .map(|bytes| decode_strict(&entry.target(), bytes))
        .transpose()?
        .unwrap_or_default();
    wire.iter()
        .map(|item| {
            Ok(BalanceReason {
                reason: reason_name(table, entry, item)?,
                amount: item.amount,
            })
        })
        .collect()
}

fn decode_locks(raw: Option<&[u8]>) -> Result<Vec<BalanceLock>> {
    let wire: Vec<LockWire> = raw
        .map(|bytes| decode_strict(&LOCKS.target(), bytes))
        .transpose()?
        .unwrap_or_default();
    wire.into_iter()
        .map(|lock| {
            let reasons =
                LOCK_REASONS
                    .get(usize::from(lock.reasons))
                    .ok_or_else(|| SdkError::Chain {
                        target: LOCKS.target(),
                        detail: format!(
                            "lock reasons {} is not a variant this SDK knows",
                            lock.reasons
                        ),
                    })?;
            Ok(BalanceLock {
                id: Text::from_bytes(lock.id.to_vec()),
                amount: lock.amount,
                reasons: *reasons,
            })
        })
        .collect()
}

/// `fungible::Inspect::reducible_balance` at `Fortitude::Polite`, as
/// `pallet_balances` computes it. Freezes apply to the total, so held funds
/// count against them first; the existential deposit is kept back only when the
/// account must stay alive.
fn reducible(
    data: &AccountDataWire,
    keep_existential_deposit: bool,
    existential_deposit: u128,
) -> u128 {
    let frozen_beyond_holds = data.frozen.saturating_sub(data.reserved);
    let untouchable = if keep_existential_deposit {
        frozen_beyond_holds.max(existential_deposit)
    } else {
        frozen_beyond_holds
    };
    data.free.saturating_sub(untouchable)
}

/// Build the balance from raw storage. Pure: the same bytes always give the
/// same result, which is what the shared vectors replay.
pub(in crate::chain) fn decode_balance(
    account: Address,
    existential_deposit: u128,
    [info, holds, freezes, locks]: &BalanceValues,
) -> Result<AccountBalance> {
    // Sources decode in request order, so when two are malformed every binding
    // reports the same one.
    let info: Option<AccountInfoWire> = info
        .as_deref()
        .map(|bytes| decode_strict(&ACCOUNT.target(), bytes))
        .transpose()?;
    let holds = decode_reasons(HOLD_REASONS, HOLDS, holds.as_deref())?;
    let freezes = decode_reasons(FREEZE_REASONS, FREEZES, freezes.as_deref())?;
    let locks = decode_locks(locks.as_deref())?;

    let exists = info.is_some();
    let info = info.unwrap_or(AccountInfoWire {
        _nonce: 0,
        consumers: 0,
        providers: 0,
        _sufficients: 0,
        data: AccountDataWire {
            free: 0,
            reserved: 0,
            frozen: 0,
            _flags: 0,
        },
    });
    let data = &info.data;
    // `Expendable` still needs the deposit when this balance is the account's
    // only provider and something depends on the account existing.
    let provider_is_needed = data.free > 0 && info.consumers > 0 && info.providers <= 1;

    Ok(AccountBalance {
        account,
        exists,
        free: data.free,
        reserved: data.reserved,
        frozen: data.frozen,
        total: data.free.saturating_add(data.reserved),
        transferable: reducible(data, provider_is_needed, existential_deposit),
        transferable_keep_alive: reducible(data, true, existential_deposit),
        holds,
        freezes,
        locks,
    })
}

#[cfg(test)]
pub(in crate::chain) mod tests {
    use parity_scale_codec::Encode;
    use serde_json::json;

    use super::*;
    use crate::chain::read::testing::{ALICE, ALICE_SS58, ED, TOKEN};
    use crate::chain::test_metadata;

    fn alice() -> Address {
        Address::new(AccountId(ALICE), 42)
    }

    /// `AccountInfo` in wire order. Every field is distinct so a swapped pair
    /// shows up in the result.
    fn account_info(
        consumers: u32,
        providers: u32,
        free: u128,
        reserved: u128,
        frozen: u128,
    ) -> Vec<u8> {
        (
            7u32,
            consumers,
            providers,
            0u32,
            (free, reserved, frozen, 1u128 << 127),
        )
            .encode()
    }

    fn only_account(info: Vec<u8>) -> BalanceValues {
        [Some(info), None, None, None]
    }

    #[test]
    fn a_funded_account_decodes_to_the_documented_shape() {
        let values: BalanceValues = [
            Some(account_info(1, 1, 5 * TOKEN, 3 * TOKEN, 4 * TOKEN)),
            Some(vec![(10u8, 0u8, 3 * TOKEN)].encode()),
            Some(vec![(44u8, 0u8, 4 * TOKEN)].encode()),
            Some(vec![(*b"staking ", 2 * TOKEN, 2u8)].encode()),
        ];
        let balance = decode_balance(alice(), ED, &values).unwrap();

        // Written out by hand: this literal is the contract the other three
        // languages are held to.
        assert_eq!(
            serde_json::to_value(&balance).unwrap(),
            json!({
                "account": ALICE_SS58,
                "exists": true,
                "free": "5000000000000000000",
                "reserved": "3000000000000000000",
                "frozen": "4000000000000000000",
                "total": "8000000000000000000",
                "transferable": "4000000000000000000",
                "transferable_keep_alive": "4000000000000000000",
                "holds": [{"reason": "Staking.Staking", "amount": "3000000000000000000"}],
                "freezes": [{"reason": "NominationPools.PoolMinBalance", "amount": "4000000000000000000"}],
                "locks": [{"id": "staking ", "amount": "2000000000000000000", "reasons": "All"}],
            })
        );
    }

    #[test]
    fn an_account_the_chain_does_not_store_reads_as_zeros_not_an_error() {
        let balance = decode_balance(alice(), ED, &[None, None, None, None]).unwrap();
        assert!(!balance.exists);
        assert_eq!(
            (
                balance.free,
                balance.total,
                balance.transferable,
                balance.transferable_keep_alive
            ),
            (0, 0, 0, 0)
        );
        assert!(balance.holds.is_empty() && balance.freezes.is_empty() && balance.locks.is_empty());
    }

    #[test]
    fn held_funds_count_against_a_freeze_before_free_funds_do() {
        // frozen 4, reserved 3: only 1 of the freeze lands on `free`.
        let balance = decode_balance(
            alice(),
            ED,
            &only_account(account_info(0, 1, 5 * TOKEN, 3 * TOKEN, 4 * TOKEN)),
        )
        .unwrap();
        assert_eq!(balance.transferable, 4 * TOKEN);
    }

    #[test]
    fn the_existential_deposit_is_kept_back_only_when_the_account_must_live() {
        let read = |consumers, providers| {
            decode_balance(
                alice(),
                ED,
                &only_account(account_info(consumers, providers, TOKEN, 0, 0)),
            )
            .unwrap()
        };

        // Nothing depends on the account: all of it may leave.
        assert_eq!(read(0, 1).transferable, TOKEN);
        // Something does, and this balance is the only provider.
        assert_eq!(read(1, 1).transferable, TOKEN - ED);
        // Another provider keeps it alive.
        assert_eq!(read(1, 2).transferable, TOKEN);
        // Keep-alive always holds the deposit back.
        assert_eq!(read(0, 1).transferable_keep_alive, TOKEN - ED);
    }

    #[test]
    fn a_freeze_larger_than_the_balance_leaves_nothing_rather_than_underflowing() {
        let balance = decode_balance(
            alice(),
            ED,
            &only_account(account_info(0, 1, TOKEN, 0, 9 * TOKEN)),
        )
        .unwrap();
        assert_eq!(balance.transferable, 0);
        assert_eq!(balance.transferable_keep_alive, 0);
    }

    #[test]
    fn a_value_with_bytes_left_over_is_an_error_not_a_guess() {
        let mut info = account_info(0, 1, TOKEN, 0, 0);
        info.push(0);
        let err = decode_balance(alice(), ED, &only_account(info)).unwrap_err();
        assert!(
            matches!(&err, SdkError::Chain { target, .. } if target == "System.Account"),
            "{err:?}"
        );
    }

    #[test]
    fn a_reason_the_sdk_does_not_know_is_an_error_naming_the_entry() {
        let values: BalanceValues = [
            Some(account_info(0, 1, TOKEN, 0, 0)),
            Some(vec![(99u8, 0u8, TOKEN)].encode()),
            None,
            None,
        ];
        let err = decode_balance(alice(), ED, &values).unwrap_err();
        assert!(
            matches!(&err, SdkError::Chain { target, .. } if target == "Balances.Holds"),
            "{err:?}"
        );
    }

    /// A [`ReasonGroup`] with owned names, so a table and the metadata compare.
    type OwnedReasonGroup = (u8, String, Vec<(u8, String)>);

    /// The reason enum behind a `Vec<IdAmount>` storage value, read from metadata.
    fn runtime_reasons(entry: StorageEntry) -> Vec<OwnedReasonGroup> {
        /// A type's index in the metadata registry.
        type TypeId = u32;
        let metadata = test_metadata();
        let types = metadata.types();
        let resolve = |id: TypeId| &types.resolve(id).expect("type in registry").type_def;
        let variants = |id: TypeId| match resolve(id) {
            scale_info::TypeDef::Variant(v) => v.variants.clone(),
            other => panic!("expected an enum, found {other:?}"),
        };
        let only_field = |id: TypeId| match resolve(id) {
            scale_info::TypeDef::Composite(c) => c.fields[0].ty.id,
            scale_info::TypeDef::Sequence(s) => s.type_param.id,
            other => panic!("expected a wrapper, found {other:?}"),
        };

        let value_ty = metadata
            .pallet_by_name(entry.pallet)
            .and_then(|p| p.storage())
            .and_then(|s| s.entry_by_name(entry.entry))
            .expect("entry in metadata")
            .entry_type()
            .value_ty();
        // BoundedVec { Vec<IdAmount { id, amount }> }
        let id_amount = only_field(only_field(value_ty));
        let reason_enum = only_field(id_amount);
        variants(reason_enum)
            .into_iter()
            .map(|pallet| {
                let reasons = variants(pallet.fields[0].ty.id)
                    .into_iter()
                    .map(|r| (r.index, r.name))
                    .collect();
                (pallet.index, pallet.name, reasons)
            })
            .collect()
    }

    fn as_owned(table: &[ReasonGroup]) -> Vec<OwnedReasonGroup> {
        table
            .iter()
            .map(|(index, pallet, reasons)| {
                let reasons = reasons.iter().map(|(i, r)| (*i, r.to_string())).collect();
                (*index, pallet.to_string(), reasons)
            })
            .collect()
    }

    #[test]
    fn the_reason_tables_are_the_runtimes() {
        assert_eq!(as_owned(HOLD_REASONS), runtime_reasons(HOLDS));
        assert_eq!(as_owned(FREEZE_REASONS), runtime_reasons(FREEZES));
    }
}
