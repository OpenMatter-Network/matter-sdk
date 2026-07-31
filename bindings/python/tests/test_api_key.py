"""API-key ingestion conformance.

Replays testvectors/api_keys.json so this binding agrees with Rust, TypeScript,
and Go on what parses, what is rejected, and which account each key derives.
Derivation happens in the shared Rust core, so a divergence here means the core
changed — not that Python drifted.

The redaction cases are Python-specific: repr, pickle, and copy are how a
credential escapes in this runtime.
"""

import copy
import json
import pickle
from pathlib import Path

import pytest

from matter_vault import ApiKey, api_key_from_env

VECTORS = Path(__file__).resolve().parents[3] / "testvectors" / "api_keys.json"

MNEMONIC = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
SEED_HEX = "0xfac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"
SEED_BODY = SEED_HEX[2:]


def _vectors():
    return json.loads(VECTORS.read_text())


def _ids(cases):
    return [c["name"] for c in cases]


@pytest.mark.parametrize("case", _vectors()["valid"], ids=_ids(_vectors()["valid"]))
def test_valid_keys_derive_the_expected_account(case):
    key = ApiKey(case["key"])
    assert key.account_id_hex == "0x" + case["account_id_hex"]
    assert key.account_id.hex() == case["account_id_hex"]
    assert len(key.account_id) == 32
    assert key.scheme == "sr25519"


@pytest.mark.parametrize("case", _vectors()["invalid"], ids=_ids(_vectors()["invalid"]))
def test_invalid_keys_are_rejected(case):
    with pytest.raises(ValueError):
        ApiKey(case["key"])


def test_junctions_are_applied_not_dropped():
    # The live defect this replaces: branching on the `0x` prefix routed hex SURIs
    # to create_from_seed, which ignores junctions and derives the ROOT account.
    root = ApiKey(SEED_HEX)
    hard = ApiKey(SEED_HEX + "//hard")
    soft = ApiKey(SEED_HEX + "/soft")

    assert hard.account_id != root.account_id, "//hard silently derived the root account"
    assert soft.account_id != root.account_id
    assert hard.account_id != soft.account_id

    # The mnemonic form of the same secret must land on the same account.
    assert ApiKey(MNEMONIC + "//hard").account_id == hard.account_id


def test_phraseless_suri_is_rejected():
    # Most SURI parsers substitute the public well-known development phrase, so an
    # unset environment variable would otherwise mint a working, globally
    # controlled signer.
    for bad in ("//Alice", "/soft", "//Alice//stash"):
        with pytest.raises(ValueError):
            ApiKey(bad)


def test_reserved_scheme_reports_as_unsupported():
    # An Ethereum secp256k1 key is also 32 bytes of hex, so only the explicit
    # prefix distinguishes it. The message must say "unsupported", not "malformed".
    with pytest.raises(ValueError, match="unsupported"):
        ApiKey("secp256k1:" + SEED_HEX)


def test_repr_and_str_are_redacted():
    key = ApiKey(SEED_HEX)
    for rendered in (repr(key), str(key), f"{key}", f"{key!r}", f"{[key]}", f"{ {'k': key} }"):
        lowered = rendered.lower()
        assert SEED_BODY not in lowered, rendered
        assert "bottom drive" not in lowered, rendered
        assert "<redacted>" in rendered, rendered


def test_cannot_be_pickled_or_copied():
    # __reduce__ is how a credential reaches a cache, a multiprocessing queue, or
    # a task payload without anyone writing serialization code.
    key = ApiKey(MNEMONIC)
    with pytest.raises(TypeError):
        pickle.dumps(key)
    with pytest.raises(TypeError):
        copy.copy(key)
    with pytest.raises(TypeError):
        copy.deepcopy(key)


def test_errors_never_echo_the_key():
    # A raised message is the most likely thing to be logged verbatim.
    for bad in (SEED_HEX + "00", "secp256k1:" + SEED_HEX, MNEMONIC + " zoo"):
        with pytest.raises(ValueError) as excinfo:
            ApiKey(bad)
        message = str(excinfo.value).lower()
        assert SEED_BODY not in message
        assert "bottom drive" not in message


def test_signs_a_64_byte_signature_and_frames_it():
    key = ApiKey(SEED_HEX)
    signature = key.sign(b"canonical payload bytes")
    assert len(signature) == 64

    # The committee adapter must frame it and advertise the same account, so one
    # key serves both the chain and the committee.
    auth = key.signer().authorize(42, [1, 2, 3], 2, b"\x11" * 32)
    assert auth["requester"] == key.account_id_hex
    framed = bytes.fromhex(auth["signature"][2:])
    assert len(framed) == 65 and framed[0] == 0x01


def test_signs_a_distinct_payload_per_recipient():
    # MV-C1: the same request addressed to two nodes must not be interchangeable.
    # sr25519 is non-deterministic, so assert on the bytes handed to the key rather
    # than on the signatures.
    from matter_vault import substrate_signer

    seen = []

    def record(payload: bytes) -> bytes:
        seen.append(payload)
        return b"\x00" * 64

    signer = substrate_signer(ApiKey(SEED_HEX).account_id, record)
    signer.authorize(9, [2, 4, 6], 2, b"\xab" * 32)
    signer.authorize(9, [2, 4, 6], 4, b"\xab" * 32)

    assert seen[0] != seen[1], "the same payload was signed for two different nodes"


def test_api_key_from_env_reads_both_variables():
    assert api_key_from_env(getenv={}.get) is None

    primary = api_key_from_env(getenv={"MATTER_API_KEY": SEED_HEX}.get)
    assert primary is not None and primary.account_id_hex.startswith("0x46ebddef")

    # MATTER_SIGNER_SEED is the fallback, for parity with the e2e harnesses.
    fallback = api_key_from_env(getenv={"MATTER_SIGNER_SEED": MNEMONIC}.get)
    assert fallback is not None and fallback.account_id == primary.account_id

    # Whitespace-only is treated as unset, not as a malformed key.
    assert api_key_from_env(getenv={"MATTER_API_KEY": "   "}.get) is None
