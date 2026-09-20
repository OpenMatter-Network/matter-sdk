"""The committee HTTP transport.

``Transport`` is the seam between the quorum logic and the network, so the flow
can be tested against a fake committee. ``UrllibTransport`` is the stdlib-only
production implementation (no third-party dependency for the core online layer).
"""

import json
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable

from .errors import DecryptError


@runtime_checkable
class Transport(Protocol):
    """How the SDK reaches committee nodes. Swap in a fake for tests."""

    def health(self, endpoint: str) -> dict: ...

    def partial_decrypt(self, endpoint: str, req: dict) -> dict: ...


class UrllibTransport:
    """A ``urllib``-based transport. The caller may set a per-request timeout."""

    def __init__(self, timeout: float = 15.0) -> None:
        self._timeout = timeout

    def health(self, endpoint: str) -> dict:
        url = endpoint.rstrip("/") + "/health"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.URLError as e:
            raise DecryptError("transport", f"health from {endpoint}: {e}") from e

    def partial_decrypt(self, endpoint: str, req: dict) -> dict:
        url = endpoint.rstrip("/") + "/partial-decrypt"
        body = json.dumps(req).encode()
        request = urllib.request.Request(
            url, data=body, headers={"content-type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise DecryptError("transport", f"partial-decrypt {e.code} from {endpoint}") from e
        except urllib.error.URLError as e:
            raise DecryptError("transport", f"partial-decrypt from {endpoint}: {e}") from e
