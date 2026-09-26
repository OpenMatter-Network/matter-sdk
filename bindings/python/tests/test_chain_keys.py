"""Extrinsic signing uses the core derivation the client reports, via
:class:`ApiKeySigner`; also pins the limits of ``keypair_from_seed``."""

import json
from pathlib import Path

import pytest

pytest.importorskip("substrateinterface")

from scalecodec.base import ScaleBytes  # noqa: E402

from matter_sdk import ApiKey  # noqa: E402
from matter_sdk.chain import ApiKeySigner, api_key_signer, ChainClient  # noqa: E402

VECTORS = Path(__file__).resolve().parents[3] / "testvectors" / "api_keys.json"

MNEMONIC = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
SEED_HEX = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"


def _valid_cases():
    return json.loads(VECTORS.read_text())["valid"]


@pytest.mark.parametrize("case", _valid_cases(), ids=[c["name"] for c in _valid_cases()])
def test_the_signing_adapter_matches_every_vector(case):
    signer = api_key_signer(ApiKey(case["key"]))
    assert signer.public_key.hex() == case["account_id_hex"], case["name"]


def test_the_adapter_derives_junctions_substrate_interface_cannot():
    root = api_key_signer(ApiKey(SEED_HEX))
    for path in ("//hard", "/soft", "//hard/soft", "//1"):
        derived = api_key_signer(ApiKey(SEED_HEX + path))
        assert derived.public_key != root.public_key, f"junction {path!r} was dropped"
        assert derived.public_key == ApiKey(SEED_HEX + path).account_id

    with pytest.raises(ValueError, match="cannot derive a hex phrase"):
        ChainClient.keypair_from_seed(SEED_HEX + "//hard")


def test_the_adapter_quacks_like_a_keypair():
    # The four members substrate-interface's create_signed_extrinsic reads.
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
    for key in (
        MNEMONIC,
        SEED_HEX,
        "sr25519:" + SEED_HEX,
        MNEMONIC + "//hard",
        MNEMONIC + "/soft",
    ):
        pair = ChainClient.keypair_from_seed(key)
        assert bytes(pair.public_key) == ApiKey(key).account_id, key


def test_the_adapter_renders_its_address_in_the_chains_format():
    from substrateinterface.utils.ss58 import ss58_encode

    key = ApiKey(SEED_HEX)
    assert api_key_signer(key).ss58_address == ss58_encode(key.account_id, 42)
    assert api_key_signer(key, ss58_format=0).ss58_address == ss58_encode(key.account_id, 0)
