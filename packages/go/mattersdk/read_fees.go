package mattersdk

// Fee reads: what a call would cost, and who would be charged for it.

import (
	"math"
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

const (
	apiQueryCallInfo = "TransactionPaymentCallApi_query_call_info"
	apiFeePayer      = "PaymasterApi_fee_payer"

	// extrinsicOverheadBytes is what signing adds around a call: the length
	// prefix, version byte, signer address, signature, and the signed extensions'
	// bytes. An upper bound for an sr25519 signature on a mortal extrinsic with no
	// tip, so an estimate never undercounts the length fee.
	extrinsicOverheadBytes = 112

	orgIDBytes = 32
)

// DispatchClass is how the runtime schedules a call.
type DispatchClass string

const (
	// DispatchClassNormal is an ordinary call.
	DispatchClassNormal DispatchClass = "Normal"
	// DispatchClassOperational is an operational call, which has space reserved in
	// every block.
	DispatchClassOperational DispatchClass = "Operational"
	// DispatchClassMandatory is a call the block cannot be built without.
	DispatchClassMandatory DispatchClass = "Mandatory"
)

// dispatchClassesByIndex is frame_support::dispatch::DispatchClass, by enum index.
var dispatchClassesByIndex = []DispatchClass{
	DispatchClassNormal, DispatchClassOperational, DispatchClassMandatory,
}

// Weight is the computation a call is allowed.
type Weight struct {
	// RefTime is execution time, in picoseconds on reference hardware.
	RefTime uint64 `json:"ref_time"`
	// ProofSize is the bytes of state proof the call may need.
	ProofSize uint64 `json:"proof_size"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (w Weight) MarshalJSON() ([]byte, error) { return canonicalBytes(w) }

// BilledTo is the organization a fee is booked against, and for which member.
type BilledTo struct {
	// Org is the organization whose treasury pays.
	Org [32]byte `json:"org"`
	// Member is the member the spend counts against.
	Member Address `json:"member"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (b BilledTo) MarshalJSON() ([]byte, error) { return canonicalBytes(b) }

// FeeEstimate is what a call would cost, and who would be charged for it.
type FeeEstimate struct {
	// Pallet is the pallet of the call priced.
	Pallet string `json:"pallet"`
	// Call is the call priced.
	Call string `json:"call"`
	// PartialFee is the fee the chain would charge, in plancks, with no tip.
	// Governance fee overrides are already applied.
	PartialFee *big.Int `json:"partial_fee"`
	// Weight is the computation the call is allowed.
	Weight Weight `json:"weight"`
	// DispatchClass is how the runtime schedules the call.
	DispatchClass DispatchClass `json:"dispatch_class"`
	// EncodedLen is the extrinsic length the fee was computed for: the encoded
	// call plus an upper bound on what signing adds.
	EncodedLen uint32 `json:"encoded_len"`
	// WrappedInProxy reports whether the call was priced as this client would
	// submit it for a member: wrapped in proxy.proxy.
	WrappedInProxy bool `json:"wrapped_in_proxy"`
	// Signer is the account that would sign: this client's. Nil for a read-only
	// client.
	Signer *Address `json:"signer"`
	// Payer is the account the fee would be taken from. Nil when the runtime
	// cannot say: the client has no signer, or the call is one whose sponsorship
	// the runtime does not answer for. Never read nil as "the signer pays".
	Payer *Address `json:"payer"`
	// BilledTo is the organization the fee is booked against, when one pays.
	BilledTo *BilledTo `json:"billed_to"`
}

// MarshalJSON renders the canonical JSON value; see CanonicalJSON for the bytes.
func (e FeeEstimate) MarshalJSON() ([]byte, error) { return canonicalBytes(e) }

// dispatchInfo is the fee, weight and dispatch class from query_call_info's
// answer.
type dispatchInfo struct {
	partialFee *big.Int
	weight     Weight
	class      DispatchClass
}

// priced is what the client knows about the call before asking the chain.
type priced struct {
	pallet, call   string
	encodedLen     uint32
	wrappedInProxy bool
	signer         *Address
}

// callInfoArgs returns the length the fee is computed for, and query_call_info's
// arguments: the call as the runtime decodes it, then that length.
func callInfoArgs(call []byte) (uint32, []byte, error) {
	if len(call) > math.MaxUint32-extrinsicOverheadBytes {
		return 0, nil, chainErrorf(KindChain, apiQueryCallInfo,
			"%s: the call is too long to be an extrinsic", apiQueryCallInfo)
	}
	encodedLen := uint32(len(call)) + extrinsicOverheadBytes
	length, err := codec.Encode(types.NewU32(encodedLen))
	if err != nil {
		return 0, nil, wrapChainError(KindChain, apiQueryCallInfo, err, "%s: %v", apiQueryCallInfo, err)
	}
	return encodedLen, append(append([]byte{}, call...), length...), nil
}

// feePayerArgs is fee_payer's arguments: who signs, the call as bytes, the fee
// and the tip. An estimate assumes no tip: the SDK never adds one.
func feePayerArgs(signer, call []byte, fee *big.Int) ([]byte, error) {
	noTip := types.NewU128(*new(big.Int))
	args := append([]byte{}, signer...)
	for _, part := range []any{types.NewBytes(call), types.NewU128(*fee), noTip} {
		encoded, err := codec.Encode(part)
		if err != nil {
			return nil, wrapChainError(KindChain, apiFeePayer, err, "%s: %v", apiFeePayer, err)
		}
		args = append(args, encoded...)
	}
	return args, nil
}

// decodeDispatchInfo reads the fee and weight from query_call_info's answer. Pure.
func decodeDispatchInfo(raw []byte) (dispatchInfo, error) {
	type wire struct {
		weight     Weight
		class      uint8
		partialFee *big.Int
	}
	read, err := decodeStrict(apiQueryCallInfo, raw, func(r *scaleReader) wire {
		return wire{
			weight:     Weight{RefTime: r.compactU64(), ProofSize: r.compactU64()},
			class:      r.u8(),
			partialFee: r.u128(),
		}
	})
	if err != nil {
		return dispatchInfo{}, err
	}
	if int(read.class) >= len(dispatchClassesByIndex) {
		return dispatchInfo{}, chainErrorf(KindChain, apiQueryCallInfo,
			"%s: dispatch class %d is not a variant this SDK knows", apiQueryCallInfo, read.class)
	}
	return dispatchInfo{
		partialFee: read.partialFee,
		weight:     read.weight,
		class:      dispatchClassesByIndex[read.class],
	}, nil
}

// payerWire is fee_payer's answer: the payer, and the (org, member) the spend is
// booked against when an organization pays.
type payerWire struct {
	known   bool
	account []byte
	booked  bool
	org     [orgIDBytes]byte
	member  []byte
}

func readPayer(r *scaleReader) payerWire {
	if !r.isSome() {
		return payerWire{}
	}
	answer := payerWire{known: true, account: r.fixed(accountIDBytes)}
	if !r.isSome() {
		return answer
	}
	answer.booked = true
	copy(answer.org[:], r.fixed(orgIDBytes))
	answer.member = r.fixed(accountIDBytes)
	return answer
}

// decodeEstimate builds the estimate from what was priced and the runtime's two
// answers. payer is fee_payer's raw answer, nil when there was no signer to ask
// about. Pure.
func decodeEstimate(call priced, info dispatchInfo, payer []byte, prefix uint16) (FeeEstimate, error) {
	estimate := FeeEstimate{
		Pallet:         call.pallet,
		Call:           call.call,
		PartialFee:     info.partialFee,
		Weight:         info.weight,
		DispatchClass:  info.class,
		EncodedLen:     call.encodedLen,
		WrappedInProxy: call.wrappedInProxy,
		Signer:         call.signer,
	}
	if payer == nil {
		return estimate, nil
	}
	answer, err := decodeStrict(apiFeePayer, payer, readPayer)
	if err != nil {
		return FeeEstimate{}, err
	}
	if answer.known {
		account := newAddress(answer.account, prefix)
		estimate.Payer = &account
	}
	if answer.booked {
		estimate.BilledTo = &BilledTo{Org: answer.org, Member: newAddress(answer.member, prefix)}
	}
	return estimate, nil
}
