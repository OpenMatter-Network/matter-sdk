"""MatterVault Python SDK.

One cryptographic core (the compiled ``matter_vault._native`` extension, shared
byte-for-byte with the Rust and TypeScript SDKs) plus a pure-Python online layer:
a committee HTTP transport, the threshold-decrypt quorum loop, a bring-your-own
``Signer``, and on-chain call builders. The chain client (``ChainClient``) needs
``substrate-interface``; install it with ``pip install matter-vault[sdk]``.
"""

from ._native import (
    encrypt,
    lagrange_for,
    open_secret,
    signing_payload,
    verify_plaintext_proof,
)
from .aad import Aad, aad_bytes
from .calls import grant_access, rotate_secret, store_secret
from .committee import CommitteeNode, DecryptParams, decrypt
from .errors import DecryptError
from .hexutil import from_hex, secret_id_to_hex, to_hex
from .signer import Signer, substrate_signer
from .transport import Transport, UrllibTransport

try:  # The online chain client is optional (needs the [sdk] extra).
    from .chain import ChainClient
except ImportError:  # pragma: no cover
    ChainClient = None  # type: ignore[assignment]

__all__ = [
    # crypto core
    "encrypt",
    "signing_payload",
    "lagrange_for",
    "verify_plaintext_proof",
    "open_secret",
    # online layer
    "Aad",
    "aad_bytes",
    "store_secret",
    "rotate_secret",
    "grant_access",
    "decrypt",
    "CommitteeNode",
    "DecryptParams",
    "DecryptError",
    "Signer",
    "substrate_signer",
    "Transport",
    "UrllibTransport",
    "ChainClient",
    "to_hex",
    "from_hex",
    "secret_id_to_hex",
]
