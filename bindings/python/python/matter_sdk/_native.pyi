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
    """Seal ``plaintext`` under a binding id you choose, returning ``(binding_id, capsule, proof, ct)``.

    For a secret you will store, use :func:`seal_for`: the default binding id here is a
    random label that commits to no owner.
    """

def seal_for(
    joint_pk: bytes,
    epoch: int,
    plaintext: bytes,
    aad: bytes,
    *,
    owner: bytes,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Seal ``plaintext`` for the 32-byte account ``owner`` that will own the secret.

    The binding id commits to ``owner``, so the chain accepts the envelope only as that
    account's secret. ``owner`` is the account the store is dispatched as, not
    necessarily the key that signs it.
    """

def binding_id_for(owner: bytes, salt: bytes) -> bytes:
    """The owner-bound binding id for ``owner`` (32 bytes) under ``salt`` (31 bytes)."""

def binding_commits_to(owner: bytes, binding_id: bytes) -> bool:
    """Whether ``binding_id`` is an owner-bound binding id committing to ``owner``."""

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
