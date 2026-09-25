"""The quorum loop and transport, offline, against a fake committee serving the
conformance fixture."""

import json
import pathlib

import pytest

import random

from matter_sdk import (
    CRYPTO_PROTOCOL_VERSION,
    MAX_COMMITTEE_RESPONSE_BYTES,
    CommitteeNode,
    DecryptError,
    DecryptParams,
    UrllibTransport,
    decrypt,
    substrate_signer,
    wipe,
)
from matter_sdk.committee import choose_quorum

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "testvectors"


class _FakeTransport:
    def __init__(self, by_endpoint, active=True, unreachable=(), refuse=(), versions=None, served_epoch=0):
        self._by_endpoint = by_endpoint
        self._active = active
        self._unreachable = set(unreachable)
        self._refuse = set(refuse)
        self._versions = versions or {}
        self._served_epoch = served_epoch
        self.asked = []

    def health(self, endpoint):
        if endpoint in self._unreachable:
            raise DecryptError("transport", f"health from {endpoint}: connection refused")
        health = {"status": "active" if self._active else "joining", "epoch": 0}
        if endpoint in self._versions:
            health["crypto_protocol_version"] = self._versions[endpoint]
        return health

    def partial_decrypt(self, endpoint, req):
        self.asked.append(endpoint)
        if endpoint in self._refuse:
            raise DecryptError("transport", f"partial-decrypt 503 from {endpoint}")
        d = self._by_endpoint[endpoint]
        return {"node_index": 0, "partial": d["partial"], "proof": d["proof"], "served_epoch": self._served_epoch}


class _FakeSigner:
    def auth_scheme(self):
        return "substrate"

    def authorize(self, secret_id, subset, recipient_index, block_hash):
        return {"auth": "substrate", "requester": "0x" + "00" * 32, "signature": "0x01" + "00" * 64}


def _fixture_params():
    v = json.loads((VECTORS / "open_secret.json").read_text())
    by_endpoint, nodes = {}, []
    for idx, p in zip(v["subset"], v["partials"]):
        endpoint = f"http://fake-{idx}"
        by_endpoint[endpoint] = {"partial": p["partial_hex"], "proof": p["proof_hex"]}
        nodes.append(CommitteeNode(index=idx, endpoint=endpoint, share_commitment=bytes.fromhex(p["commitment_hex"])))
    params = DecryptParams(
        secret_id=int(v["secret_id"]),
        epoch=v["epoch"],
        binding_id=bytes.fromhex(v["binding_id_hex"]),
        aad=bytes.fromhex(v["aad_hex"]),
        capsule=bytes.fromhex(v["capsule_hex"]),
        ct=bytes.fromhex(v["ct_hex"]),
        shared_a=bytes.fromhex(v["shared_a_hex"]),
        block_hash=b"\x00" * 32,
        threshold=len(v["subset"]),
        nodes=nodes,
    )
    return by_endpoint, params, v["expected_plaintext_hex"]


def test_decrypt_recovers_the_secret_from_a_quorum():
    by_endpoint, params, expected = _fixture_params()
    out = decrypt(_FakeTransport(by_endpoint), _FakeSigner(), params)
    assert out.hex() == expected


def test_quorum_unavailable_when_no_node_is_active():
    by_endpoint, params, _ = _fixture_params()
    with pytest.raises(DecryptError) as exc:
        decrypt(_FakeTransport(by_endpoint, active=False), _FakeSigner(), params)
    assert exc.value.kind == "quorum"


def test_substrate_signer_frames_a_multisignature():
    account = bytes(range(32))
    auth = substrate_signer(account, lambda payload: b"\x07" * 64).authorize(42, [1, 2, 3], 2, b"\x11" * 32)
    assert auth["auth"] == "substrate"
    assert auth["requester"] == "0x" + account.hex()
    # 1-byte Sr25519 variant (0x01) + 64-byte signature.
    sig = bytes.fromhex(auth["signature"][2:])
    assert len(sig) == 65 and sig[0] == 0x01 and sig[1:] == b"\x07" * 64


def test_decrypt_returns_a_wipeable_buffer():
    by_endpoint, params, expected = _fixture_params()
    out = decrypt(_FakeTransport(by_endpoint), _FakeSigner(), params)
    assert isinstance(out, bytearray)
    assert out.hex() == expected
    wipe(out)
    assert not any(out)


def test_quorum_error_names_the_node_that_never_answered_health():
    by_endpoint, params, _ = _fixture_params()
    down = params.nodes[0].endpoint
    with pytest.raises(DecryptError) as exc:
        decrypt(_FakeTransport(by_endpoint, unreachable={down}), _FakeSigner(), params)
    assert exc.value.kind == "quorum"
    assert [(f.endpoint, f.stage) for f in exc.value.faults] == [(down, "health")]
    assert "connection refused" in exc.value.faults[0].detail


def test_a_node_refusing_the_real_request_is_dropped_and_named_not_raised():
    by_endpoint, params, _ = _fixture_params()
    bad = params.nodes[1].endpoint
    with pytest.raises(DecryptError) as exc:
        decrypt(_FakeTransport(by_endpoint, refuse={bad}), _FakeSigner(), params)
    assert exc.value.kind == "quorum"
    assert [(f.endpoint, f.stage) for f in exc.value.faults] == [(bad, "partial-decrypt")]


def test_a_threshold_agreeing_on_another_epoch_is_a_rotation():
    by_endpoint, params, _ = _fixture_params()
    with pytest.raises(DecryptError) as exc:
        decrypt(_FakeTransport(by_endpoint, served_epoch=params.epoch + 1), _FakeSigner(), params)
    assert exc.value.kind == "epoch"


def test_a_node_speaking_another_protocol_version_is_dropped_before_it_is_asked():
    by_endpoint, params, _ = _fixture_params()
    bad = params.nodes[0].endpoint
    transport = _FakeTransport(by_endpoint, versions={bad: CRYPTO_PROTOCOL_VERSION + 1})
    with pytest.raises(DecryptError) as exc:
        decrypt(transport, _FakeSigner(), params)
    assert [(f.endpoint, f.stage) for f in exc.value.faults] == [(bad, "protocol-version")]
    assert bad not in transport.asked


def test_a_node_that_does_not_report_a_version_is_accepted():
    by_endpoint, params, expected = _fixture_params()
    assert decrypt(_FakeTransport(by_endpoint), _FakeSigner(), params).hex() == expected


def _nodes(n):
    return [CommitteeNode(index=i, endpoint=f"http://node-{i}", share_commitment=b"") for i in range(1, n + 1)]


def test_a_quorum_is_t_distinct_available_nodes_in_index_order():
    rng = random.Random(7)
    for _ in range(100):
        indices = [n.index for n in choose_quorum(_nodes(7), 4, rng)]
        assert len(indices) == 4
        assert indices == sorted(set(indices))


def test_quorum_selection_is_not_the_fixed_lowest_indices():
    rng = random.Random(42)
    draws = [tuple(n.index for n in choose_quorum(_nodes(5), 3, rng)) for _ in range(200)]
    assert len(set(draws)) > 1
    for index in range(1, 6):
        # 3/5 of quorums on average; 60 of 200 is a loose floor.
        assert sum(index in d for d in draws) >= 60


class _BigBody:
    """A response whose body is larger than the transport allows."""

    def __init__(self, size):
        self._data = b"{" + b" " * size + b"}"

    def read(self, n=-1):
        return self._data if n < 0 else self._data[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_transport_refuses_a_body_over_the_cap(monkeypatch):
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _BigBody(64))
    with pytest.raises(DecryptError) as exc:
        UrllibTransport(max_response_bytes=32).health("http://node-1")
    assert exc.value.kind == "transport"
    assert "exceeded" in str(exc.value)


def test_transport_defaults_to_the_core_cap():
    assert UrllibTransport()._max_response_bytes == MAX_COMMITTEE_RESPONSE_BYTES
