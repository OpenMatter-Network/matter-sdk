"""Typed errors for the online layer."""

from dataclasses import dataclass
from typing import Literal, Sequence

DecryptErrorKind = Literal["quorum", "epoch", "transport", "crypto"]

FaultStage = Literal["health", "inactive", "partial-decrypt", "epoch-mismatch", "protocol-version"]
"""Where in the decrypt round trip a node stopped being usable."""


@dataclass(frozen=True)
class NodeFault:
    """Why one committee node did not contribute to a quorum. Never carries
    request material."""

    index: int
    endpoint: str
    stage: FaultStage
    detail: str
    """The underlying reason, already rendered."""


class DecryptError(Exception):
    """A decrypt failure with a machine-branchable ``kind``.

    For ``kind == "quorum"``, ``faults`` says which nodes were dropped and why.
    Empty means no node failed: the caller supplied too few to begin with.
    """

    def __init__(self, kind: DecryptErrorKind, message: str, faults: Sequence[NodeFault] = ()) -> None:
        super().__init__(message)
        self.kind: DecryptErrorKind = kind
        self.faults: tuple = tuple(faults)


# Chain errors live here, free of optional dependencies, so they are catchable
# whether or not the ``[sdk]`` extra is installed.


class ChainError(RuntimeError):
    """A chain read or submission failed. Branch on ``pallet``/``call``, not on
    the message text."""

    def __init__(self, message: str, *, pallet: str = "", call: str = "") -> None:
        super().__init__(message)
        self.pallet = pallet
        self.call = call


class PoolRejectedError(ChainError):
    """The node refused the extrinsic at validation, before any block.

    For a delegated key this covers both a revoked key and an unpaid fee;
    ``MatterClient`` re-reads the grant to tell them apart.
    """


class OuterDispatchError(ChainError):
    """The ``proxy.proxy`` extrinsic itself failed, as opposed to the call it
    wrapped."""

    def __init__(
        self, message: str, *, pallet: str = "", call: str = "", module: str = "", name: str = ""
    ) -> None:
        super().__init__(message, pallet=pallet, call=call)
        self.module = module
        self.name = name


class DispatchError(ChainError):
    """A delegated call landed, but the call it wrapped was refused."""


class ReadOnlyError(ChainError):
    """The client holds no signer, so it cannot submit or authorize."""


class ConfigError(ChainError, ValueError):
    """The connection configuration is inconsistent or incomplete. Also a
    :class:`ValueError`."""


class WrongNetworkError(ChainError):
    """The endpoint serves a different network than the configuration selected."""


class MainnetNotConfirmedError(ChainError):
    """A signing client was pointed at mainnet without explicit confirmation."""


class KeyRevokedError(ChainError):
    """This key's proxy is gone, or now points at a different member.
    Confirmed against the chain, not inferred from a pool rejection."""


class UnsponsoredError(ChainError):
    """The call is within this key's scopes, but nobody would pay for it."""


class NotPermittedError(ChainError):
    """A member-tied API key was asked for a call its scopes do not cover.

    Raised before submission. The runtime would refuse it too, but with a fee
    error that names neither the call nor the missing scope.
    """


class NeverAdmittedError(NotPermittedError):
    """The call is admitted to no API key, whatever its scopes.

    Unlike the parent :class:`NotPermittedError`, widening the key cannot fix it.
    """
