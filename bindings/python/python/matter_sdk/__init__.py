"""OpenMatter Python SDK.

The compiled ``_native`` extension holds the shared Rust crypto and API-key cores;
the committee transport, quorum decrypt, signers, call builders, and chain client
are pure Python.

``ApiKey`` and the crypto functions need no extra dependencies. The chain client
(``MatterClient``, ``ChainClient``) needs::

    pip install "matter-sdk[sdk]"
"""

from ._native import (
    CRYPTO_PROTOCOL_VERSION,
    MAX_COMMITTEE_RESPONSE_BYTES,
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
from .committee import CommitteeNode, DecryptParams, decrypt, wipe
from .errors import (
    ChainError,
    ConfigError,
    DecryptError,
    DispatchError,
    FaultStage,
    FinalityTimeoutError,
    KeyRevokedError,
    MainnetNotConfirmedError,
    NeverAdmittedError,
    NodeFault,
    NotPermittedError,
    OuterDispatchError,
    PoolRejectedError,
    ReadOnlyError,
    UnsponsoredError,
    WrongNetworkError,
)
from .hexutil import from_hex, secret_id_to_hex, to_hex
from .signer import Signer, substrate_signer
from .transport import Transport, UrllibTransport

# Pure Python: available without the [sdk] extra.
from .scopes import Access, Scope, ScopeSet, required_scopes

# The chain layer needs the [sdk] extra; without it, its names raise an ImportError
# that names the extra and the original error.
_CHAIN_IMPORT_ERROR = None
try:
    from .chain import (
        ApiKeySigner,
        ChainClient,
        CommitteeState,
        TxReceipt,
        api_key_signer,
    )
    from .client import (
        ChainProperties,
        MatterClient,
        Network,
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
                f'{name} needs the chain dependencies: pip install "matter-sdk[sdk]" '
                f"(original error: {_CHAIN_IMPORT_ERROR})"
            )

        return _raise

    ChainClient = _needs_sdk_extra("ChainClient")  # type: ignore[assignment,misc]
    CommitteeState = _needs_sdk_extra("CommitteeState")  # type: ignore[assignment,misc]
    MatterClient = _needs_sdk_extra("MatterClient")  # type: ignore[assignment,misc]
    TxReceipt = _needs_sdk_extra("TxReceipt")  # type: ignore[assignment,misc]
    ChainProperties = _needs_sdk_extra("ChainProperties")  # type: ignore[assignment,misc]
    Network = _needs_sdk_extra("Network")  # type: ignore[assignment,misc]
    ApiKeySigner = _needs_sdk_extra("ApiKeySigner")  # type: ignore[assignment,misc]
    api_key_signer = _needs_sdk_extra("api_key_signer")  # type: ignore[assignment,misc]
    parse_amount = _needs_sdk_extra("parse_amount")  # type: ignore[assignment,misc]
    format_amount = _needs_sdk_extra("format_amount")  # type: ignore[assignment,misc]
    SecretsFacade = _needs_sdk_extra("SecretsFacade")  # type: ignore[assignment,misc]
    DeploymentsFacade = _needs_sdk_extra("DeploymentsFacade")  # type: ignore[assignment,misc]
    ResourcesFacade = _needs_sdk_extra("ResourcesFacade")  # type: ignore[assignment,misc]
    StakingFacade = _needs_sdk_extra("StakingFacade")  # type: ignore[assignment,misc]
    OrgsFacade = _needs_sdk_extra("OrgsFacade")  # type: ignore[assignment,misc]
    KeysFacade = _needs_sdk_extra("KeysFacade")  # type: ignore[assignment,misc]

__all__ = [
    # crypto core
    "encrypt",
    "signing_payload",
    "lagrange_for",
    "verify_plaintext_proof",
    "open_secret",
    "CRYPTO_PROTOCOL_VERSION",
    "MAX_COMMITTEE_RESPONSE_BYTES",
    "wipe",
    "NodeFault",
    "FaultStage",
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
    "CommitteeState",
    "ChainProperties",
    "ChainError",
    "ReadOnlyError",
    "ConfigError",
    "WrongNetworkError",
    "MainnetNotConfirmedError",
    "FinalityTimeoutError",
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
