"""Associated-data registry — the versioned tags a secret is sealed under.

Use the enum, never a raw string, so a typo is an error rather than a silent
decrypt failure. Values are a wire contract shared with the provider; append-only.
"""

from enum import Enum
from typing import Union


class Aad(str, Enum):
    """Well-known AAD tags (same bytes as the Rust/TS ``Aad``)."""

    ENV_V1 = "matter-deployment/env/v1"
    TLS_V1 = "matter-deployment/tls/v1"
    STORAGE_CREDS_V1 = "matter-volume/storage-creds/v1"
    VOLUME_DEK_V1 = "matter-volume/dek/v1"
    DATASET_SOURCE_CREDS_V1 = "matter-dataset/source-creds/v1"


def aad_bytes(aad: Union[Aad, str, bytes]) -> bytes:
    """The canonical bytes for an AAD tag (or pass through raw bytes)."""
    if isinstance(aad, (bytes, bytearray)):
        return bytes(aad)
    if isinstance(aad, Aad):
        return aad.value.encode()
    if isinstance(aad, str):
        return aad.encode()
    raise TypeError(f"aad must be Aad | str | bytes, got {type(aad).__name__}")
