"""Seed-format conformance for the Python chain helper.

``keypair_from_seed`` must accept both encodings of the same secret — a ``0x``
hex mini-secret and its BIP39 mnemonic — and land on the account pinned by the
Rust-emitted fixture (testvectors/seed_formats.json). Public keys are compared
(not SS58) so the assertion is independent of the ss58_format in use. Chain
extras are optional, so skip when substrate-interface isn't installed.
"""

import json
import pathlib

import pytest

pytest.importorskip("substrateinterface")

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "testvectors"


def _cases():
    return json.loads((VECTORS / "seed_formats.json").read_text())["cases"]


def test_keypair_from_seed_accepts_both_encodings():
    from matter_vault.chain import ChainClient

    for case in _cases():
        from_hex = ChainClient.keypair_from_seed("0x" + case["mini_secret_hex"])
        from_mnemonic = ChainClient.keypair_from_seed(case["mnemonic"])
        assert from_hex.public_key.hex() == case["account_id_hex"]
        assert from_mnemonic.public_key.hex() == case["account_id_hex"]
        assert from_hex.ss58_address == from_mnemonic.ss58_address
