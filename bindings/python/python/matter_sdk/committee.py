"""Threshold-decrypt orchestration: form a quorum, sign per node, fan out, open.

Crypto runs in the compiled core. Port of ``packages/typescript-core/src/committee.ts``.
"""

import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Union

from ._native import CRYPTO_PROTOCOL_VERSION, lagrange_for, open_secret
from .aad import Aad, aad_bytes
from .errors import DecryptError, NodeFault
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


def wipe(buf: bytearray) -> None:
    """Zero ``buf`` in place.

    Call it on a recovered plaintext once you are done with it: the core wipes
    its own copy, and this clears the one Python holds.
    """
    buf[:] = bytes(len(buf))


def _speaks_our_protocol(reported: Optional[int]) -> bool:
    """Absent or ``0`` (a node predating the field) is accepted: the version tag on
    every proof still binds the transcript."""
    return not reported or reported == CRYPTO_PROTOCOL_VERSION


_SYSTEM_RANDOM = random.SystemRandom()

#: Auth fields an Ethereum (EIP-712) signer adds to a partial-decrypt request.
_ETHEREUM_AUTH_FIELDS = ("eth_address", "valid_until", "eth_signature")


def choose_quorum(
    available: Sequence[CommitteeNode], threshold: int, rng: random.Random = _SYSTEM_RANDOM
) -> List[CommitteeNode]:
    """Choose ``threshold`` of ``available`` uniformly at random, in index order.

    Random, so no fixed node sees (or can deny) every decrypt. ``rng`` is for
    tests only.
    """
    return sorted(rng.sample(list(available), threshold), key=lambda n: n.index)


def _summarize(faults: Sequence[NodeFault]) -> str:
    if not faults:
        return ""
    return " — " + "; ".join(f"node {f.index} ({f.endpoint}) {f.stage}: {f.detail}" for f in faults)


def _quorum_unavailable(needed: int, found: int, faults: Sequence[NodeFault]) -> DecryptError:
    return DecryptError(
        "quorum",
        f"quorum unavailable: need {needed} healthy nodes, found {found}{_summarize(faults)}",
        faults,
    )


def _rotated(served: int, provided: int) -> DecryptError:
    return DecryptError(
        "epoch", f"secret served under epoch {served}, state supplied for {provided}; refetch and retry"
    )


def decrypt(transport: Transport, signer: Signer, params: DecryptParams) -> bytearray:
    """Recover a secret by aggregating a threshold quorum of partial decryptions.

    A node that fails, or serves a different epoch than ``threshold`` of its
    peers, is dropped and named in :attr:`DecryptError.faults` rather than allowed
    to deny the decrypt. Raises :class:`DecryptError` (``quorum``, ``epoch``, or
    ``crypto``).

    Returns the plaintext as a ``bytearray``: never log it, and :func:`wipe` it
    when done.
    """
    # 1. Health-probe; keep active nodes and record why others dropped out.
    faults: List[NodeFault] = []
    active: List[CommitteeNode] = []
    for node in params.nodes:
        try:
            health = transport.health(node.endpoint)
        except DecryptError as e:
            faults.append(NodeFault(node.index, node.endpoint, "health", str(e)))
            continue
        version = health.get("crypto_protocol_version")
        if not _speaks_our_protocol(version):
            faults.append(
                NodeFault(
                    node.index,
                    node.endpoint,
                    "protocol-version",
                    f"speaks crypto protocol v{version}, this SDK speaks v{CRYPTO_PROTOCOL_VERSION}",
                )
            )
        elif health.get("status") != "active":
            faults.append(
                NodeFault(
                    node.index,
                    node.endpoint,
                    "inactive",
                    f"status {health.get('status')!r}, epoch {health.get('epoch', 0)}, "
                    f"crypto protocol v{version or 0}",
                )
            )
        else:
            active.append(node)

    if len(active) < params.threshold:
        raise _quorum_unavailable(params.threshold, len(active), faults)

    # 2. Assemble a quorum. A faulty node is dropped and the subset re-formed, so
    #    one node cannot deny the decrypt; a real rotation is `threshold` nodes
    #    agreeing on a new served_epoch. Each fault removes a node, so this ends.
    available = active
    rotated_votes: Dict[int, int] = {}

    while len(available) >= params.threshold:
        chosen = choose_quorum(available, params.threshold)
        subset = [n.index for n in chosen]
        partials = []
        faulty: Optional[int] = None

        # 3. Query each chosen node, signing per node so a signature cannot be
        #    replayed to a peer.
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
            # A custom Ethereum-auth signer supplies these; a substrate one omits them.
            for field in _ETHEREUM_AUTH_FIELDS:
                if auth.get(field) is not None:
                    req[field] = auth[field]
            try:
                resp = transport.partial_decrypt(node.endpoint, req)
            except DecryptError as e:
                faults.append(NodeFault(node.index, node.endpoint, "partial-decrypt", str(e)))
                faulty = node.index
                break

            # A different served_epoch: `threshold` agreeing is a real rotation
            # (the caller refetches); fewer is a misbehaving node, dropped.
            # 0/None is an older node serving the current epoch.
            served = resp.get("served_epoch")
            if served and served != params.epoch:
                rotated_votes[served] = rotated_votes.get(served, 0) + 1
                if rotated_votes[served] >= params.threshold:
                    raise _rotated(served, params.epoch)
                faults.append(
                    NodeFault(
                        node.index,
                        node.endpoint,
                        "epoch-mismatch",
                        f"served epoch {served}, state supplied for {params.epoch}",
                    )
                )
                faulty = node.index
                break

            partials.append(
                (node.index, from_hex(resp["partial"]), from_hex(resp["proof"]), bytes(node.share_commitment))
            )

        if faulty is not None:
            available = [n for n in available if n.index != faulty]
            continue

        # 4. Verify + aggregate + AEAD-open in the compiled core.
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

    # Out of good nodes: report the most common divergent epoch as a rotation, if any.
    if rotated_votes:
        served = max(rotated_votes, key=lambda epoch: (rotated_votes[epoch], -epoch))
        raise _rotated(served, params.epoch)
    raise _quorum_unavailable(params.threshold, len(available), faults)
