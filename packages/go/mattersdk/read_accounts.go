package mattersdk

// Account reads: what an account holds and how much of it can move.

import "math/big"

var (
	systemAccount   = storageEntry{"System", "Account"}
	balancesHolds   = storageEntry{"Balances", "Holds"}
	balancesFreezes = storageEntry{"Balances", "Freezes"}
	balancesLocks   = storageEntry{"Balances", "Locks"}
)

// reasonGroup is one pallet's reasons inside a runtime-composed reason enum, by
// enum index.
type reasonGroup struct {
	pallet  string
	reasons map[uint8]string
}

// holdReasons is RuntimeHoldReason as the runtime lays it out, by pallet index.
var holdReasons = map[uint8]reasonGroup{
	10: {"Staking", map[uint8]string{0: "Staking"}},
	21: {"Preimage", map[uint8]string{0: "Preimage"}},
	27: {"Council", map[uint8]string{0: "ProposalSubmission"}},
	28: {"TechnicalCommittee", map[uint8]string{0: "ProposalSubmission"}},
	43: {"AssetRewards", map[uint8]string{0: "PoolCreation"}},
	45: {"DelegatedStaking", map[uint8]string{0: "StakingDelegation"}},
}

// freezeReasons is RuntimeFreezeReason as the runtime lays it out, by pallet index.
var freezeReasons = map[uint8]reasonGroup{
	43: {"AssetRewards", map[uint8]string{0: "Staked"}},
	44: {"NominationPools", map[uint8]string{0: "PoolMinBalance"}},
}

// LockReasons says which withdrawals a legacy lock blocks.
type LockReasons string

const (
	// LockReasonsFee blocks paying transaction fees.
	LockReasonsFee LockReasons = "Fee"
	// LockReasonsMisc blocks everything except fees.
	LockReasonsMisc LockReasons = "Misc"
	// LockReasonsAll blocks any withdrawal.
	LockReasonsAll LockReasons = "All"
)

// lockReasonsByIndex is pallet_balances::Reasons, by enum index.
var lockReasonsByIndex = []LockReasons{LockReasonsFee, LockReasonsMisc, LockReasonsAll}

const lockIDBytes = 8

// BalanceReason is an amount on hold or frozen, and why.
type BalanceReason struct {
	// Reason is Pallet.Reason, e.g. Staking.Staking.
	Reason string `json:"reason"`
	// Amount is in plancks.
	Amount *big.Int `json:"amount"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (r BalanceReason) MarshalJSON() ([]byte, error) { return canonicalBytes(r) }

// BalanceLock is a legacy balance lock.
type BalanceLock struct {
	// ID is the locking pallet's eight-byte id, padding included.
	ID Text `json:"id"`
	// Amount is in plancks.
	Amount *big.Int `json:"amount"`
	// Reasons says which withdrawals the lock blocks.
	Reasons LockReasons `json:"reasons"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (l BalanceLock) MarshalJSON() ([]byte, error) { return canonicalBytes(l) }

// AccountBalance is what an account holds, and how much of it can move. Amounts
// are plancks and never nil.
type AccountBalance struct {
	// Account is the account read.
	Account Address `json:"account"`
	// Exists reports whether the chain stores the account at all. False means
	// never funded or reaped; every amount is then zero.
	Exists bool `json:"exists"`
	// Free is not on hold. It is still subject to freezes, so not all of it can move.
	Free *big.Int `json:"free"`
	// Reserved is on hold: staked, or bonded as a deposit.
	Reserved *big.Int `json:"reserved"`
	// Frozen is the largest freeze; freezes overlap rather than add up.
	Frozen *big.Int `json:"frozen"`
	// Total is Free + Reserved.
	Total *big.Int `json:"total"`
	// Transferable is what a transfer may move if the account is allowed to be
	// reaped. Fees are not deducted.
	Transferable *big.Int `json:"transferable"`
	// TransferableKeepAlive is what a transfer may move while keeping the account
	// alive. Fees are not deducted.
	TransferableKeepAlive *big.Int `json:"transferable_keep_alive"`
	// Holds make up Reserved.
	Holds []BalanceReason `json:"holds"`
	// Freezes make up Frozen.
	Freezes []BalanceReason `json:"freezes"`
	// Locks are from pallets that predate freezes.
	Locks []BalanceLock `json:"locks"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (b AccountBalance) MarshalJSON() ([]byte, error) { return canonicalBytes(b) }

// accountInfo is frame_system::AccountInfo, the fields a balance needs.
type accountInfo struct {
	consumers, providers   uint32
	free, reserved, frozen *big.Int
}

func readAccountInfo(r *scaleReader) accountInfo {
	r.u32() // nonce
	consumers := r.u32()
	providers := r.u32()
	r.u32() // sufficients
	free := r.u128()
	reserved := r.u128()
	frozen := r.u128()
	r.u128() // flags: a bitfield, not an amount
	return accountInfo{consumers, providers, free, reserved, frozen}
}

func readReasons(table map[uint8]reasonGroup, entry storageEntry, value stored) ([]BalanceReason, error) {
	if !value.found {
		return []BalanceReason{}, nil
	}
	return decodeStrict(entry.target(), value.raw, func(r *scaleReader) []BalanceReason {
		return readVec(r, func(r *scaleReader) BalanceReason {
			pallet, reason, amount := r.u8(), r.u8(), r.u128()
			name, known := table[pallet].reasons[reason]
			if !known {
				r.fail("reason (%d, %d) is not one this SDK knows; the runtime has added it since", pallet, reason)
			}
			return BalanceReason{Reason: table[pallet].pallet + "." + name, Amount: amount}
		})
	})
}

func readLocks(value stored) ([]BalanceLock, error) {
	if !value.found {
		return []BalanceLock{}, nil
	}
	return decodeStrict(balancesLocks.target(), value.raw, func(r *scaleReader) []BalanceLock {
		return readVec(r, func(r *scaleReader) BalanceLock {
			id := Text{raw: append([]byte{}, r.fixed(lockIDBytes)...)}
			amount := r.u128()
			index := int(r.u8())
			if index >= len(lockReasonsByIndex) {
				r.fail("lock reasons %d is not a variant this SDK knows", index)
				return BalanceLock{}
			}
			return BalanceLock{ID: id, Amount: amount, Reasons: lockReasonsByIndex[index]}
		})
	})
}

func saturatingSub(left, right *big.Int) *big.Int {
	if left.Cmp(right) <= 0 {
		return new(big.Int)
	}
	return new(big.Int).Sub(left, right)
}

// reducible is fungible::Inspect::reducible_balance at Fortitude::Polite, as
// pallet_balances computes it. Freezes apply to the total, so held funds count
// against them first; the existential deposit is kept back only when the account
// must stay alive.
func reducible(info accountInfo, keepExistentialDeposit bool, existentialDeposit *big.Int) *big.Int {
	untouchable := saturatingSub(info.frozen, info.reserved)
	if keepExistentialDeposit && existentialDeposit.Cmp(untouchable) > 0 {
		untouchable = existentialDeposit
	}
	return saturatingSub(info.free, untouchable)
}

// balanceRequests lists the entries a balance read needs, in the order
// decodeBalance takes their values.
func balanceRequests(account []byte) []storageRequest {
	entries := []storageEntry{systemAccount, balancesHolds, balancesFreezes, balancesLocks}
	requests := make([]storageRequest, len(entries))
	for i, entry := range entries {
		requests[i] = storageRequest{entry: entry, keys: [][]byte{account}}
	}
	return requests
}

// decodeBalance builds the balance from raw storage values in balanceRequests
// order. Pure: the same bytes always give the same result, which is what the
// shared vectors replay.
func decodeBalance(account Address, existentialDeposit *big.Int, values []stored) (AccountBalance, error) {
	rawInfo, rawHolds, rawFreezes, rawLocks := values[0], values[1], values[2], values[3]

	info := accountInfo{free: new(big.Int), reserved: new(big.Int), frozen: new(big.Int)}
	if rawInfo.found {
		decoded, err := decodeStrict(systemAccount.target(), rawInfo.raw, readAccountInfo)
		if err != nil {
			return AccountBalance{}, err
		}
		info = decoded
	}
	holds, err := readReasons(holdReasons, balancesHolds, rawHolds)
	if err != nil {
		return AccountBalance{}, err
	}
	freezes, err := readReasons(freezeReasons, balancesFreezes, rawFreezes)
	if err != nil {
		return AccountBalance{}, err
	}
	locks, err := readLocks(rawLocks)
	if err != nil {
		return AccountBalance{}, err
	}

	// Expendable still needs the deposit when this balance is the account's only
	// provider and something depends on the account existing.
	providerIsNeeded := info.free.Sign() > 0 && info.consumers > 0 && info.providers <= 1
	total := new(big.Int).Add(info.free, info.reserved)
	if total.Cmp(u128Max) > 0 {
		// A copy: the caller owns every amount in the result.
		total = new(big.Int).Set(u128Max)
	}

	return AccountBalance{
		Account:               account,
		Exists:                rawInfo.found,
		Free:                  info.free,
		Reserved:              info.reserved,
		Frozen:                info.frozen,
		Total:                 total,
		Transferable:          reducible(info, providerIsNeeded, existentialDeposit),
		TransferableKeepAlive: reducible(info, true, existentialDeposit),
		Holds:                 holds,
		Freezes:               freezes,
		Locks:                 locks,
	}, nil
}
