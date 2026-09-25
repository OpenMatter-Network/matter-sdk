"""OpenMatter API-key ingestion.

Parsing and sr25519 derivation run in the shared Rust core, never in
``substrate-interface``; signature framing is in ``signer.py``.
"""

from typing import Callable, Optional

from ._native import ApiKey as _NativeApiKey

__all__ = ["ApiKey", "api_key_from_env"]

# Read in order. Never argv: it would land in shell history and `ps` output.
_ENV_VARS = ("MATTER_API_KEY", "MATTER_SIGNER_SEED")


class ApiKey:
    """An OpenMatter API key: parse once, then sign.

    Accepts a ``0x`` 32-byte mini-secret, a BIP39 mnemonic, or an sr25519 SURI
    with derivation junctions, each optionally prefixed ``"sr25519:"``; surrounding
    whitespace is ignored. Raises ``ValueError`` on a bad key, never echoing it.

    Guarantees, enforced by the underlying Rust type:

    * **Redacted.** ``repr`` and ``str`` render ``ApiKey(sr25519, 0x…, <redacted>)``.
    * **Not picklable, not copyable.** ``__reduce__``, ``__copy__``, and
      ``__deepcopy__`` all raise.
    * **No accessor for the secret.** It stays in Rust memory; the only outputs
      are the public account id and signatures.

    These guard against accidents, not attackers: anything that can read the
    process can read the key. See ``docs/secure-signing.md`` for HSM/KMS signers.

    >>> key = ApiKey("bottom drive obey lake curtain smoke basket hold race lonely fit walk")
    >>> key.account_id_hex
    '0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a'
    >>> "<redacted>" in repr(key)
    True
    """

    __slots__ = ("_inner",)

    def __init__(self, key: str) -> None:
        self._inner = _NativeApiKey(key)

    @property
    def scheme(self) -> str:
        """The signature scheme token, e.g. ``"sr25519"``."""
        return self._inner.scheme

    @property
    def account_id(self) -> bytes:
        """The 32-byte on-chain account id this key controls."""
        return self._inner.account_id

    @property
    def account_id_hex(self) -> str:
        """The account id as ``0x`` + 64 lowercase hex characters."""
        return self._inner.account_id_hex

    def sign(self, message: bytes) -> bytes:
        """The raw 64-byte sr25519 signature over ``message``, with no framing."""
        return self._inner.sign(message)

    def signer(self):
        """This key as a committee :class:`~matter_sdk.signer.Signer`."""
        from .signer import substrate_signer

        return substrate_signer(self.account_id, self.sign)

    def __repr__(self) -> str:
        return repr(self._inner)

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError(
            "refusing to pickle an ApiKey; pass the key string through your "
            "secret manager instead"
        )

    def __copy__(self):
        raise TypeError("refusing to copy an ApiKey")

    def __deepcopy__(self, memo):
        raise TypeError("refusing to deep-copy an ApiKey")


def api_key_from_env(getenv: Optional[Callable[[str], Optional[str]]] = None) -> Optional[ApiKey]:
    """Read an :class:`ApiKey` from ``MATTER_API_KEY``, falling back to
    ``MATTER_SIGNER_SEED``.

    Returns ``None`` when neither is set (or is only whitespace); the caller
    decides whether a key was required. ``getenv`` is injectable for tests.
    """
    if getenv is None:
        import os

        getenv = os.environ.get

    for var in _ENV_VARS:
        value = getenv(var)
        if value and value.strip():
            return ApiKey(value)
    return None
