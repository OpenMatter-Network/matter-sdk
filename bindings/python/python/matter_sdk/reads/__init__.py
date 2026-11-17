"""Friendly reads of chain state: one call answers one question, with the
pallet, storage key and SCALE layout hidden.

A read has four parts. A domain module names its **sources** and holds a **pure
decoder** from raw bytes to a typed result; :class:`~._source.Snapshot` is the
only **fetch**, and it reads every source at one block; the **façade method** in
``facade.py`` wires the three together.

Decoders are strict: a value must have exactly the layout this SDK knows, so a
runtime that has changed it fails loudly at the read instead of returning
something plausible and wrong. Nothing here needs the ``[sdk]`` extra.
"""

from ._leaf import Text, canonical_json, to_json
from .accounts import AccountBalance, BalanceLock, BalanceReason, LockReasons
from .fees import BilledTo, DispatchClass, FeeEstimate, Weight
from .network import Block, BlockHeader, NetworkInfo, NetworkTiming, NodeStatus

__all__ = [
    "AccountBalance",
    "BalanceLock",
    "BalanceReason",
    "BilledTo",
    "Block",
    "BlockHeader",
    "DispatchClass",
    "FeeEstimate",
    "LockReasons",
    "NetworkInfo",
    "NetworkTiming",
    "NodeStatus",
    "Text",
    "Weight",
    "canonical_json",
    "to_json",
]
