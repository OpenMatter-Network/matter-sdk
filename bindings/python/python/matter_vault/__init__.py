"""OpenMatter Python SDK.

Two compiled Rust cores (in the ``matter_vault._native`` extension, shared
byte-for-byte with the Rust, TypeScript, and Go SDKs) — the cryptography and
API-key ingestion — plus a pure-Python online layer: a committee HTTP transport,
the threshold-decrypt quorum loop, the signer abstraction, on-chain call
builders, and a chain client that reaches every pallet the runtime exposes.

``ApiKey`` and the crypto functions work with no extra dependencies. The chain
client (``MatterClient``, ``ChainClient``) needs ``substrate-interface``::

    pip install matter-vault[sdk]
"""

from ._native import (
    encrypt,
    lagrange_for,
    open_secret,
    signing_payload,
    verify_plaintext_proof,
)
from .aad import Aad, aad_bytes
from .apikey import ApiKey, api_key_from_env
from .calls import (
    delete_secret,
    grant_access,
    grant_to_deployment,
    grant_to_user,
    revoke_access,
    rotate_secret,
    store_secret,
)
from .committee import CommitteeNode, DecryptParams, decrypt
from .errors import DecryptError
from .hexutil import from_hex, secret_id_to_hex, to_hex
from .signer import Signer, substrate_signer
from .transport import Transport, UrllibTransport

# The chain layer is optional (needs the [sdk] extra). Import failure is recorded
# rather than swallowed: a bare `None` turned "you didn't install the extra" into
# an AttributeError three frames away from the cause.
# Scopes are pure Python with no chain dependency, so they import either way —
# a caller can build and render a ScopeSet without installing the [sdk] extra.
from .scopes import Access, Scope, ScopeSet, required_scopes

_CHAIN_IMPORT_ERROR = None
try:
    from .chain import (
        ApiKeySigner,
        ChainClient,
        ChainError,
        DispatchError,
        OuterDispatchError,
        PoolRejectedError,
        TxReceipt,
        api_key_signer,
    )
    from .client import (
        ChainProperties,
        KeyRevokedError,
        MatterClient,
        NeverAdmittedError,
        Network,
        NotPermittedError,
        UnsponsoredError,
        format_amount,
        parse_amount,
    )
    from .facade import (
        DeploymentsFacade,
        KeysFacade,
        OrgsFacade,
        ResourcesFacade,
        SecretsFacade,
        StakingFacade,
    )
except ImportError as exc:  # pragma: no cover - depends on the install extra
    _CHAIN_IMPORT_ERROR = exc

    def _needs_sdk_extra(name):
        def _raise(*_args, **_kwargs):
            raise ImportError(
                f"{name} needs the chain dependencies: pip install matter-vault[sdk] "
                f"(original error: {_CHAIN_IMPORT_ERROR})"
            )

        return _raise

    ChainClient = _needs_sdk_extra("ChainClient")  # type: ignore[assignment]
    MatterClient = _needs_sdk_extra("MatterClient")  # type: ignore[assignment]
    ChainError = _needs_sdk_extra("ChainError")  # type: ignore[assignment]
    TxReceipt = _needs_sdk_extra("TxReceipt")  # type: ignore[assignment]
    ChainProperties = _needs_sdk_extra("ChainProperties")  # type: ignore[assignment]
    Network = _needs_sdk_extra("Network")  # type: ignore[assignment]
    ApiKeySigner = _needs_sdk_extra("ApiKeySigner")  # type: ignore[assignment]
    api_key_signer = _needs_sdk_extra("api_key_signer")  # type: ignore[assignment]
    parse_amount = _needs_sdk_extra("parse_amount")  # type: ignore[assignment]
    format_amount = _needs_sdk_extra("format_amount")  # type: ignore[assignment]
    SecretsFacade = _needs_sdk_extra("SecretsFacade")  # type: ignore[assignment]
    DeploymentsFacade = _needs_sdk_extra("DeploymentsFacade")  # type: ignore[assignment]
    ResourcesFacade = _needs_sdk_extra("ResourcesFacade")  # type: ignore[assignment]
    StakingFacade = _needs_sdk_extra("StakingFacade")  # type: ignore[assignment]
    OrgsFacade = _needs_sdk_extra("OrgsFacade")  # type: ignore[assignment]
    KeysFacade = _needs_sdk_extra("KeysFacade")  # type: ignore[assignment]
    NotPermittedError = _needs_sdk_extra("NotPermittedError")  # type: ignore[assignment]
    NeverAdmittedError = _needs_sdk_extra("NeverAdmittedError")  # type: ignore[assignment]
    KeyRevokedError = _needs_sdk_extra("KeyRevokedError")  # type: ignore[assignment]
    UnsponsoredError = _needs_sdk_extra("UnsponsoredError")  # type: ignore[assignment]
    DispatchError = _needs_sdk_extra("DispatchError")  # type: ignore[assignment]
    PoolRejectedError = _needs_sdk_extra("PoolRejectedError")  # type: ignore[assignment]
    OuterDispatchError = _needs_sdk_extra("OuterDispatchError")  # type: ignore[assignment]

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
    "revoke_access",
    "delete_secret",
    "grant_to_user",
    "grant_to_deployment",
    "decrypt",
    "CommitteeNode",
    "DecryptParams",
    "DecryptError",
    "Signer",
    "substrate_signer",
    "Transport",
    "UrllibTransport",
    # keys
    "ApiKey",
    "api_key_from_env",
    # chain
    "MatterClient",
    "ChainClient",
    "ChainProperties",
    "ChainError",
    "TxReceipt",
    "Network",
    "ApiKeySigner",
    "api_key_signer",
    "parse_amount",
    "format_amount",
    # façades
    "SecretsFacade",
    "DeploymentsFacade",
    "ResourcesFacade",
    "StakingFacade",
    "OrgsFacade",
    "KeysFacade",
    "NotPermittedError",
    "NeverAdmittedError",
    "KeyRevokedError",
    "UnsponsoredError",
    "DispatchError",
    "PoolRejectedError",
    "OuterDispatchError",
    "Access",
    "Scope",
    "ScopeSet",
    "required_scopes",
    "to_hex",
    "from_hex",
    "secret_id_to_hex",
]
