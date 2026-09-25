"""Type stubs for the compiled core (``bindings/python/src/lib.rs``)."""

from typing import List, Optional, Tuple

CRYPTO_PROTOCOL_VERSION: int
"""The crypto protocol version the core speaks, as a node reports it in ``/health``."""

MAX_COMMITTEE_RESPONSE_BYTES: int
"""Maximum committee response body size, in bytes, every transport enforces."""

def encrypt(
    joint_pk: bytes,
    epoch: int,
    plaintext: bytes,
    aad: bytes,
    binding_id: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Seal ``plaintext``, returning ``(binding_id, capsule, proof, ct)``."""

def signing_payload(secret_id: int, subset: List[int], block_hash: bytes, recipient_index: int) -> bytes:
    """The canonical bytes a requester signs for one node's ``/partial-decrypt`` request."""

def lagrange_for(point: int, subset: List[int]) -> bytes:
    """The bincode Lagrange coefficient for ``point`` over ``subset``."""

def verify_plaintext_proof(joint_pk: bytes, capsule: bytes, tagged_proof: bytes, binding_id: bytes, epoch: int) -> bool:
    """Verify a capsule's ZKPoPlaintext proof up front."""

def open_secret(
    shared_a: bytes,
    capsule: bytes,
    secret_id: int,
    epoch: int,
    binding_id: bytes,
    aad: bytes,
    ct: bytes,
    partials: List[Tuple[int, bytes, bytes, bytes]],
) -> bytearray:
    """Verify, aggregate, and AEAD-open; returns a wipeable buffer.

    ``partials`` are ``(point, partial, proof, commitment)``.
    """

class ApiKey:
    """An OpenMatter API key. The secret never crosses into Python."""

    def __init__(self, key: str) -> None: ...
    @property
    def scheme(self) -> str: ...
    @property
    def account_id(self) -> bytes: ...
    @property
    def account_id_hex(self) -> str: ...
    def sign(self, message: bytes) -> bytes: ...
