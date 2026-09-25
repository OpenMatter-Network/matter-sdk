"""substrate-interface ``call_params`` for callers who submit with their own client;
:class:`~matter_sdk.client.MatterClient` submits them for you.

Builders take an ``Aad`` tag so a secret cannot be stored under a different AAD
than it was sealed with.
"""

from typing import Tuple, Union

from .aad import Aad, aad_bytes
from .hexutil import to_hex

# (binding_id, capsule, proof, ct), as ``encrypt`` returns.
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


ACCOUNT_ID_BYTES = 32


def grant_to_user(account: bytes) -> dict:
    """A ``GrantTarget`` naming an account."""
    if len(account) != ACCOUNT_ID_BYTES:
        raise ValueError(f"account must be {ACCOUNT_ID_BYTES} bytes, got {len(account)}")
    return {"User": to_hex(account)}


def grant_to_deployment(deployment: int) -> dict:
    """A ``GrantTarget`` naming a deployment: authorizes whichever resource is
    currently assigned to it."""
    return {"Deployment": int(deployment)}


def grant_access(secret_id: int, target: dict) -> dict:
    """``call_params`` for ``secrets.grant_access(secret_id, target)``.

    ``target`` is a ``GrantTarget`` enum from :func:`grant_to_user` or
    :func:`grant_to_deployment`, not a bare account id.
    """
    return {"secret_id": int(secret_id), "target": target}


def revoke_access(secret_id: int, target: dict) -> dict:
    """``call_params`` for ``secrets.revoke_access(secret_id, target)``.

    The target must match the grant exactly, or this is a no-op on chain.
    """
    return {"secret_id": int(secret_id), "target": target}


def delete_secret(secret_id: int) -> dict:
    """``call_params`` for ``secrets.delete_secret(secret_id)``.

    Removes the secret and every grant on it. Owner only, and irreversible.
    """
    return {"secret_id": int(secret_id)}
