"""Cross-language conformance for the Python binding.

The deterministic outputs must match the fixtures the Rust core generated.
Build the extension first, then run:

    cd bindings/python && maturin develop && pytest
"""

import json
import pathlib

import matter_vault

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "testvectors"


def _load(name):
    return json.loads((VECTORS / name).read_text())


def test_signing_payload_conformance():
    for case in _load("signing_payload.json")["cases"]:
        got = matter_vault.signing_payload(
            int(case["secret_id"]),
            case["subset"],
            bytes.fromhex(case["block_hash_hex"]),
        )
        assert got.hex() == case["payload_hex"]


def test_lagrange_conformance():
    for case in _load("lagrange.json")["cases"]:
        got = matter_vault.lagrange_for(case["point"], case["subset"])
        assert got.hex() == case["lambda_hex"]


def test_open_secret_conformance():
    v = _load("open_secret.json")
    partials = [
        (
            bytes.fromhex(p["partial_hex"]),
            bytes.fromhex(p["proof_hex"]),
            bytes.fromhex(p["commitment_hex"]),
            bytes.fromhex(p["lambda_hex"]),
        )
        for p in v["partials"]
    ]
    plaintext = matter_vault.open_secret(
        bytes.fromhex(v["shared_a_hex"]),
        bytes.fromhex(v["capsule_hex"]),
        int(v["secret_id"]),
        v["epoch"],
        bytes.fromhex(v["binding_id_hex"]),
        bytes.fromhex(v["aad_hex"]),
        bytes.fromhex(v["ct_hex"]),
        partials,
    )
    assert plaintext.hex() == v["expected_plaintext_hex"]
