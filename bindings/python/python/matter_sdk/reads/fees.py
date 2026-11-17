"""Fee reads: what a call would cost, and who would be charged for it."""

import enum
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..hexutil import to_hex
from ._leaf import read_error, wide
from ._scale import ScaleReader, decode_strict, encode_byte_string, encode_u32, encode_u128

QUERY_CALL_INFO = "TransactionPaymentCallApi_query_call_info"
FEE_PAYER = "PaymasterApi_fee_payer"

#: What signing adds around a call: the length prefix, version byte, signer
#: address, signature, and the signed extensions' bytes. An upper bound for an
#: sr25519 signature on a mortal extrinsic with no tip, so an estimate never
#: undercounts the length fee.
EXTRINSIC_OVERHEAD_BYTES = 112

#: An estimate assumes no tip: the SDK never adds one.
_NO_TIP = 0
_U32_MAX = (1 << 32) - 1
_ACCOUNT_BYTES = 32
_ORG_BYTES = 32


class DispatchClass(enum.Enum):
    """How the runtime schedules a call."""

    #: An ordinary call.
    NORMAL = "Normal"
    #: An operational call, which has space reserved in every block.
    OPERATIONAL = "Operational"
    #: A call the block cannot be built without.
    MANDATORY = "Mandatory"


#: ``frame_support::dispatch::DispatchClass``, by enum index.
DISPATCH_CLASSES: Tuple[DispatchClass, ...] = (
    DispatchClass.NORMAL,
    DispatchClass.OPERATIONAL,
    DispatchClass.MANDATORY,
)


@dataclass(frozen=True)
class Weight:
    """The computation a call is allowed."""

    #: Execution time, in picoseconds on reference hardware.
    ref_time: int = wide()
    #: Bytes of state proof the call may need.
    proof_size: int = wide()


@dataclass(frozen=True)
class BilledTo:
    """The organization a fee is booked against, and for which member."""

    #: The organization whose treasury pays, as ``0x`` hex.
    org: str
    #: The member the spend counts against.
    member: str


@dataclass(frozen=True)
class FeeEstimate:
    """What a call would cost, and who would be charged for it."""

    #: The pallet of the call priced.
    pallet: str
    #: The call priced.
    call: str
    #: The fee the chain would charge, in plancks, with no tip. Governance fee
    #: overrides are already applied.
    partial_fee: int = wide()
    #: The computation the call is allowed.
    weight: Weight
    #: How the runtime schedules the call.
    dispatch_class: DispatchClass
    #: The extrinsic length the fee was computed for: the encoded call plus an
    #: upper bound on what signing adds.
    encoded_len: int
    #: Whether the call was priced as this client would submit it for a member:
    #: wrapped in ``Proxy.proxy``.
    wrapped_in_proxy: bool
    #: The account that would sign: this client's. ``None`` for a read-only
    #: client.
    signer: Optional[str]
    #: The account the fee would be taken from. ``None`` when the runtime cannot
    #: say: the client has no signer, or the call is one whose sponsorship the
    #: runtime does not answer for. Never read ``None`` as "the signer pays".
    payer: Optional[str]
    #: The organization the fee is booked against, when one pays.
    billed_to: Optional[BilledTo]


@dataclass(frozen=True)
class DispatchInfo:
    """The fee, weight and dispatch class from ``query_call_info``'s answer."""

    partial_fee: int
    weight: Weight
    dispatch_class: DispatchClass


@dataclass(frozen=True)
class Priced:
    """What the client knows about the call before asking the chain."""

    pallet: str
    call: str
    encoded_len: int
    wrapped_in_proxy: bool
    signer: Optional[str]


def call_info_args(call: bytes) -> Tuple[int, bytes]:
    """The length the fee is computed for, and ``query_call_info``'s arguments:
    the call as the runtime decodes it, then that length."""
    encoded_len = len(call) + EXTRINSIC_OVERHEAD_BYTES
    if encoded_len > _U32_MAX:
        raise read_error(QUERY_CALL_INFO, "the call is too long to be an extrinsic")
    return encoded_len, bytes(call) + encode_u32(encoded_len)


def fee_payer_args(signer: bytes, call: bytes, fee: int) -> bytes:
    """``fee_payer``'s arguments: who signs, the call as bytes, the fee and the
    tip."""
    return bytes(signer) + encode_byte_string(call) + encode_u128(fee) + encode_u128(_NO_TIP)


def _read_dispatch_info(reader: ScaleReader) -> DispatchInfo:
    weight = Weight(ref_time=reader.compact_u64(), proof_size=reader.compact_u64())
    index = reader.u8()
    if index >= len(DISPATCH_CLASSES):
        raise read_error(
            QUERY_CALL_INFO, f"dispatch class {index} is not a variant this SDK knows"
        )
    return DispatchInfo(
        partial_fee=reader.u128(), weight=weight, dispatch_class=DISPATCH_CLASSES[index]
    )


def decode_dispatch_info(raw: bytes) -> DispatchInfo:
    """The fee and weight from ``query_call_info``'s answer. Pure."""
    return decode_strict(QUERY_CALL_INFO, raw, _read_dispatch_info)


def _read_booked(reader: ScaleReader) -> Tuple[bytes, bytes]:
    return reader.fixed(_ORG_BYTES), reader.fixed(_ACCOUNT_BYTES)


def _read_payer(reader: ScaleReader) -> Tuple[bytes, Optional[Tuple[bytes, bytes]]]:
    return reader.fixed(_ACCOUNT_BYTES), reader.option(_read_booked)


def decode_estimate(
    priced: Priced,
    info: DispatchInfo,
    payer: Optional[bytes],
    address: Callable[[bytes], str],
) -> FeeEstimate:
    """Build the estimate from what was priced and the runtime's two answers.
    ``payer`` is ``fee_payer``'s raw answer, ``None`` when there was no signer to
    ask about. Pure."""
    answer = (
        None
        if payer is None
        else decode_strict(FEE_PAYER, payer, lambda reader: reader.option(_read_payer))
    )
    account, booked = answer if answer is not None else (None, None)
    return FeeEstimate(
        pallet=priced.pallet,
        call=priced.call,
        partial_fee=info.partial_fee,
        weight=info.weight,
        dispatch_class=info.dispatch_class,
        encoded_len=priced.encoded_len,
        wrapped_in_proxy=priced.wrapped_in_proxy,
        signer=priced.signer,
        payer=None if account is None else address(account),
        billed_to=(
            None if booked is None else BilledTo(org=to_hex(booked[0]), member=address(booked[1]))
        ),
    )
