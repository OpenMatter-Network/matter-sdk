"""The bring-your-own-signer abstraction.

The key behind *this* signer never enters the SDK: you provide a function that signs
payload, and the SDK frames the result into the request's auth fields.
"""

from typing import Callable, List, Protocol, runtime_checkable

from ._native import signing_payload
from .hexutil import to_hex

# SCALE enum index of MultiSignature::Sr25519 (Ed25519=0, Sr25519=1, Ecdsa=2).
_MULTISIGNATURE_SR25519 = 0x01


@runtime_checkable
class Signer(Protocol):
    """Authorizes a /partial-decrypt request without exposing its key."""

    def auth_scheme(self) -> str: ...

    def authorize(
        self, secret_id: int, subset: List[int], recipient_index: int, block_hash: bytes
    ) -> dict: ...


class _SubstrateSigner:
    def __init__(self, account_id: bytes, sign: Callable[[bytes], bytes]) -> None:
        if len(account_id) != 32:
            raise ValueError("account_id must be 32 bytes")
        self._requester = to_hex(account_id)
        self._sign = sign

    def auth_scheme(self) -> str:
        return "substrate"

    def authorize(
        self, secret_id: int, subset: List[int], recipient_index: int, block_hash: bytes
    ) -> dict:
        # recipient_index is the responding node's 1-based dkg_index: sign once
        # per node so the signature can't be replayed to a peer (MV-C1).
        payload = signing_payload(secret_id, list(subset), bytes(block_hash), recipient_index)
        sig = self._sign(payload)
        if len(sig) != 64:
            raise ValueError(f"sr25519 signature must be 64 bytes, got {len(sig)}")
        multisig = bytes([_MULTISIGNATURE_SR25519]) + bytes(sig)
        return {"auth": "substrate", "requester": self._requester, "signature": to_hex(multisig)}


def substrate_signer(account_id: bytes, sign: Callable[[bytes], bytes]) -> Signer:
    """Build a Substrate signer from a 32-byte account id and an sr25519 sign fn.

    ``sign`` is where your key lives (a keyring pair, wallet, HSM/KMS adapter): it
    receives the canonical payload bytes and returns the 64-byte signature.
    """
    return _SubstrateSigner(account_id, sign)
