"""Extrinsic signing must use the same derivation the client reports.

This binding had two derivation paths — the shared Rust core and
``substrate-interface`` — and they disagreed: ``keypair_from_seed`` branched on the
``0x`` prefix, so ``0x…//hard`` went to ``create_from_seed``, which ignores
derivation junctions and returns the **root** account. The client would have
signed as a different account than it advertised.

The fix removes the second path. :class:`ApiKeySigner` is shaped like a
``substrate-interface`` keypair but delegates to the core, so there is one
derivation and nothing to diverge. These tests pin both that and the residual
limits of the raw ``keypair_from_seed`` helper.
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("substrateinterface")

from scalecodec.base import ScaleBytes  # noqa: E402

from matter_vault import ApiKey  # noqa: E402
from matter_vault.chain import ApiKeySigner, api_key_signer, ChainClient  # noqa: E402

VECTORS = Path(__file__).resolve().parents[3] / "testvectors" / "api_keys.json"

MNEMONIC = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
SEED_HEX = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"


def _valid_cases():
    return json.loads(VECTORS.read_text())["valid"]


@pytest.mark.parametrize("case", _valid_cases(), ids=[c["name"] for c in _valid_cases()])
def test_the_signing_adapter_matches_every_vector(case):
    # The signer's advertised account must equal the core's for every accepted
    # encoding — including the junctioned and scheme-prefixed ones that
    # substrate-interface cannot derive on its own.
    signer = api_key_signer(ApiKey(case["key"]))
    assert signer.public_key.hex() == case["account_id_hex"], case["name"]


def test_the_adapter_derives_junctions_substrate_interface_cannot():
    # substrate-interface's create_from_uri feeds the phrase to bip39, so a hex
    # phrase with junctions raises there. The adapter handles it because the core
    # does the derivation.
    root = api_key_signer(ApiKey(SEED_HEX))
    for path in ("//hard", "/soft", "//hard/soft", "//1"):
        derived = api_key_signer(ApiKey(SEED_HEX + path))
        assert derived.public_key != root.public_key, f"junction {path!r} was dropped"
        assert derived.public_key == ApiKey(SEED_HEX + path).account_id

    with pytest.raises(ValueError, match="cannot derive a hex phrase"):
        ChainClient.keypair_from_seed(SEED_HEX + "//hard")


def test_the_adapter_quacks_like_a_keypair():
    # These four members are all substrate-interface's create_signed_extrinsic
    # reads. If it starts reading more, this test is where that shows up.
    signer = api_key_signer(ApiKey(SEED_HEX))
    assert len(signer.public_key) == 32
    assert signer.ss58_address.startswith("5")
    assert signer.crypto_type == 1  # KeypairType.SR25519

    # sign() must accept every shape substrate-interface may pass.
    payload = b"\x01\x02\x03"
    for shape in (payload, ScaleBytes(payload), "0x010203", "plain text"):
        assert len(signer.sign(shape)) == 64


def test_the_adapter_never_exposes_the_key():
    signer = api_key_signer(ApiKey(SEED_HEX))
    rendered = repr(signer)
    assert SEED_HEX[2:] not in rendered.lower()
    assert not hasattr(signer, "private_key")
    # The ApiKey it holds is not reachable through a public attribute.
    assert "_key" in ApiKeySigner.__slots__


def test_raw_keypair_helper_still_agrees_where_it_is_usable():
    # Mnemonics (with or without junctions) and bare hex secrets are the cases
    # substrate-interface can handle; those must match the core exactly.
    for key in (
        MNEMONIC,
        SEED_HEX,
        "sr25519:" + SEED_HEX,
        MNEMONIC + "//hard",
        MNEMONIC + "/soft",
    ):
        pair = ChainClient.keypair_from_seed(key)
        assert bytes(pair.public_key) == ApiKey(key).account_id, key
