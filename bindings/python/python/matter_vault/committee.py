"""Threshold-decrypt orchestration: form a quorum, sign once, fan out, open.

The crypto stays in the compiled core; this is the networking + quorum shell, a
direct port of ``packages/typescript/src/committee.ts``.
"""

from dataclasses import dataclass
from typing import List, Union

from ._native import lagrange_for, open_secret
from .aad import Aad, aad_bytes
from .errors import DecryptError
from .hexutil import from_hex, secret_id_to_hex, to_hex
from .signer import Signer
from .transport import Transport


@dataclass
class CommitteeNode:
    """One committee node, with the chain-derived data a decryptor needs."""

    index: int
    endpoint: str
    share_commitment: bytes


@dataclass
class DecryptParams:
    """Everything needed to recover one secret (chain-derived fields supplied by you)."""

    secret_id: int
    epoch: int
    binding_id: bytes
    aad: Union[Aad, str, bytes]
    capsule: bytes
    ct: bytes
    shared_a: bytes
    block_hash: bytes
    threshold: int
    nodes: List[CommitteeNode]


def decrypt(transport: Transport, signer: Signer, params: DecryptParams) -> bytes:
    """Recover a secret by aggregating a threshold quorum of partial decryptions.

    health-probe -> pick ``threshold`` active nodes -> sign once -> query each ->
    verify + aggregate + AEAD-open. Returns the recovered plaintext (Python has no
    zeroizing buffer — keep it short-lived and never log it).
    """
    # 1. Health-probe; keep the active nodes.
    active: List[CommitteeNode] = []
    for node in params.nodes:
        try:
            health = transport.health(node.endpoint)
        except DecryptError:
            continue
        if health.get("status") == "active":
            active.append(node)

    if len(active) < params.threshold:
        raise DecryptError(
            "quorum",
            f"quorum unavailable: need {params.threshold} healthy nodes, found {len(active)}",
        )

    # 2. Lowest-indexed `threshold` nodes form the subset.
    active.sort(key=lambda n: n.index)
    chosen = active[: params.threshold]
    subset = [n.index for n in chosen]

    # 3. Query each chosen node, signing per node so the payload binds that
    #    node's index — a signature can't be replayed by it to a peer (MV-C1).
    partials = []
    for node in chosen:
        lam = lagrange_for(node.index, subset)
        auth = signer.authorize(params.secret_id, subset, node.index, params.block_hash)
        req = {
            "secret_id": secret_id_to_hex(params.secret_id),
            "subset": subset,
            "lagrange_coeff": to_hex(lam),
            "requester": auth["requester"],
            "block_hash": to_hex(params.block_hash),
            "signature": auth["signature"],
            "auth": auth["auth"],
        }
        resp = transport.partial_decrypt(node.endpoint, req)

        # A served_epoch that differs means a rotation: the supplied shared_a /
        # commitments are for the wrong key. Fail loudly. (0/None = current.)
        served = resp.get("served_epoch")
        if served and served != params.epoch:
            raise DecryptError(
                "epoch",
                f"secret served under epoch {served}, state supplied for {params.epoch}; "
                "refetch and retry",
            )
        partials.append(
            (from_hex(resp["partial"]), from_hex(resp["proof"]), bytes(node.share_commitment), lam)
        )

    # 5. Verify + aggregate + AEAD-open in the compiled core.
    try:
        return open_secret(
            params.shared_a,
            params.capsule,
            params.secret_id,
            params.epoch,
            params.binding_id,
            aad_bytes(params.aad),
            params.ct,
            partials,
        )
    except ValueError as e:
        raise DecryptError("crypto", str(e)) from e
