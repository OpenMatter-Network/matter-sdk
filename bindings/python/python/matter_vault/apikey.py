"""OpenMatter API-key ingestion.

Parsing and sr25519 derivation happen in the shared Rust core (via the compiled
``_native`` extension), not in ``substrate-interface``, so this binding agrees
byte-for-byte with every other on ``testvectors/api_keys.json``. Only the
*framing* of a signature into request auth fields is Python's job — see
``signer.py``.

Deriving natively is exactly where this binding drifted: ``ChainClient``
branched on the ``0x`` prefix and routed hex SURIs to ``create_from_seed``, which
ignores derivation junctions and silently returns the **root** account.
"""

from typing import Callable, Optional

from ._native import ApiKey as _NativeApiKey

__all__ = ["ApiKey", "api_key_from_env"]

# The environment variables a key is read from, in order. Never argv: it would
# land in shell history and `ps` output. MATTER_SIGNER_SEED is accepted for
# parity with the existing e2e harnesses.
_ENV_VARS = ("MATTER_API_KEY", "MATTER_SIGNER_SEED")


class ApiKey:
    """An OpenMatter API key: parse once, then sign.

    Accepts a ``0x`` 32-byte mini-secret, a BIP39 mnemonic, or an sr25519 SURI
    with derivation junctions — each optionally prefixed with ``"sr25519:"``.
    Surrounding whitespace is tolerated, since keys arrive from environment
    variables and files.

    Guarantees, all enforced by the underlying Rust type:

    * **Redacted.** ``repr`` and ``str`` render
      ``ApiKey(sr25519, 0x…, <redacted>)``, so the key cannot reach a log line.
    * **Not picklable, not copyable.** ``__reduce__``, ``__copy__``, and
      ``__deepcopy__`` all raise, so a key cannot slip into a cache, a
      ``multiprocessing`` queue, or a task payload.
    * **No accessor for the secret.** The material stays in Rust memory; the only
      outputs are the public account id and signatures.

    Guardrails constrain accidents, not attackers — anything that can read the
    process can read the key. See ``docs/secure-signing.md`` for the trade against
    an HSM- or KMS-backed signer.

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
        """Adapt the key to the committee ``Signer`` protocol, so one key both
        submits extrinsics and authorizes ``/partial-decrypt`` requests."""
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

    Returns ``None`` when neither is set — a read-only client is a legitimate
    outcome, not an error, so the caller decides whether a key was required.
    ``getenv`` is injectable so tests need not mutate the process environment.
    """
    if getenv is None:
        import os

        getenv = os.environ.get

    for var in _ENV_VARS:
        value = getenv(var)
        if value and value.strip():
            return ApiKey(value)
    return None
