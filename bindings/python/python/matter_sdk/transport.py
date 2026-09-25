"""Committee HTTP transport: the ``Transport`` protocol and the stdlib-only
``UrllibTransport``."""

import json
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable

from ._native import MAX_COMMITTEE_RESPONSE_BYTES
from .errors import DecryptError


@runtime_checkable
class Transport(Protocol):
    """How the SDK reaches committee nodes."""

    def health(self, endpoint: str) -> dict: ...

    def partial_decrypt(self, endpoint: str, req: dict) -> dict: ...


class UrllibTransport:
    """A ``urllib``-based transport.

    ``timeout`` (seconds) bounds each request, so a stalling node cannot hang the
    quorum; ``max_response_bytes`` bounds each body, so a hostile node cannot
    exhaust memory.
    """

    def __init__(self, timeout: float = 15.0, max_response_bytes: int = MAX_COMMITTEE_RESPONSE_BYTES) -> None:
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes

    def _read_json(self, resp, endpoint: str) -> dict:
        body = resp.read(self._max_response_bytes + 1)
        if len(body) > self._max_response_bytes:
            raise DecryptError(
                "transport", f"response from {endpoint} exceeded {self._max_response_bytes} bytes"
            )
        return json.loads(body.decode())

    def health(self, endpoint: str) -> dict:
        url = endpoint.rstrip("/") + "/health"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:
                return self._read_json(resp, endpoint)
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
                return self._read_json(resp, endpoint)
        except urllib.error.HTTPError as e:
            raise DecryptError("transport", f"partial-decrypt {e.code} from {endpoint}") from e
        except urllib.error.URLError as e:
            raise DecryptError("transport", f"partial-decrypt from {endpoint}: {e}") from e
