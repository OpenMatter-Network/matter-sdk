"""Typed errors for the online layer."""

from typing import Literal

DecryptErrorKind = Literal["quorum", "epoch", "transport", "crypto"]


class DecryptError(Exception):
    """A decrypt failure with a machine-branchable ``kind`` (mirrors the TS SDK)."""

    def __init__(self, kind: DecryptErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind: DecryptErrorKind = kind
