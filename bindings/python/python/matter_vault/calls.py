"""Ready-to-submit on-chain call arguments (substrate-interface ``call_params``).

The SDK never submits transactions or holds keys — you submit these with your own
Substrate client. The builders take an ``Aad`` tag so a secret can't be stored
under a different AAD than it was sealed with.
"""

from typing import Tuple, Union

from .aad import Aad, aad_bytes
from .hexutil import to_hex

# (binding_id, capsule, proof, ct) — exactly what ``encrypt`` returns.
EncryptedSecret = Tuple[bytes, bytes, bytes, bytes]


def _payload(env: EncryptedSecret) -> dict:
    binding_id, capsule, proof, ct = env
    return {
        "binding_id": to_hex(binding_id),
        "capsule": to_hex(capsule),
        "proof": to_hex(proof),
        "ct": to_hex(ct),
    }


def store_secret(
    payload: EncryptedSecret, epoch: int, label: Union[str, bytes], aad: Union[Aad, str, bytes]
) -> dict:
    """``call_params`` for ``secrets.store_secret(payload, epoch, label, aad)``."""
    return {
        "payload": _payload(payload),
        "epoch": int(epoch),
        "label": to_hex(label.encode() if isinstance(label, str) else bytes(label)),
        "aad": to_hex(aad_bytes(aad)),
    }


def rotate_secret(
    secret_id: int, payload: EncryptedSecret, epoch: int, aad: Union[Aad, str, bytes]
) -> dict:
    """``call_params`` for ``secrets.rotate_secret(secret_id, payload, epoch, aad)``."""
    return {
        "secret_id": int(secret_id),
        "payload": _payload(payload),
        "epoch": int(epoch),
        "aad": to_hex(aad_bytes(aad)),
    }


def grant_access(secret_id: int, grantee: bytes) -> dict:
    """``call_params`` for granting another account decryption access.

    ``grantee`` is the 32-byte account id; the chain wraps it in its grant-target
    enum on submission.
    """
    if len(grantee) != 32:
        raise ValueError("grantee must be a 32-byte account id")
    return {"secret_id": int(secret_id), "grantee": to_hex(grantee)}
