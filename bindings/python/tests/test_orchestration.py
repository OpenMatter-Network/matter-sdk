"""Offline tests for the Python online layer (no network).

The quorum loop is replayed against a fake committee that serves the same
fixture the cross-language conformance vectors use, so the orchestration logic
(health filter, subset pick, request build, aggregate) is exercised end to end.
"""

import json
import pathlib

import pytest

from matter_vault import (
    CommitteeNode,
    DecryptError,
    DecryptParams,
    decrypt,
    substrate_signer,
)

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "testvectors"


class _FakeTransport:
    def __init__(self, by_endpoint, active=True):
        self._by_endpoint = by_endpoint
        self._active = active

    def health(self, endpoint):
        return {"status": "active" if self._active else "joining", "epoch": 0}

    def partial_decrypt(self, endpoint, req):
        d = self._by_endpoint[endpoint]
        return {"node_index": 0, "partial": d["partial"], "proof": d["proof"], "served_epoch": 0}


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
    # signature = 0x + 1-byte Sr25519 variant (0x01) + 64-byte sig.
    sig = bytes.fromhex(auth["signature"][2:])
    assert len(sig) == 65 and sig[0] == 0x01 and sig[1:] == b"\x07" * 64
