"""Consumer smoke test for the installed matter-sdk wheel (scripts/smoke-python-wheel.sh).

Golden-vector recovery, a seal (core RNG), and an sr25519 signature (key core).

    usage: python python-consumer.py <path/to/testvectors/open_secret.json>
"""

import json
import pathlib
import sys

import matter_sdk

SR25519_ACCOUNT_ID_LEN = 32
SR25519_SIGNATURE_LEN = 64
SMOKE_KEY = "0x" + "11" * 32  # fixed, non-secret seed


def fail(message: str) -> None:
    sys.exit(f"python smoke: {message}")


# Must test the installed wheel, not symlinked sources.
location = pathlib.Path(matter_sdk.__file__).resolve()
if "site-packages" not in location.parts:
    fail(f"matter_sdk resolved outside site-packages: {location}")

v = json.loads(pathlib.Path(sys.argv[1]).read_text())

plaintext = matter_sdk.open_secret(
    bytes.fromhex(v["shared_a_hex"]),
    bytes.fromhex(v["capsule_hex"]),
    int(v["secret_id"]),
    v["epoch"],
    bytes.fromhex(v["binding_id_hex"]),
    bytes.fromhex(v["aad_hex"]),
    bytes.fromhex(v["ct_hex"]),
    [
        (p["point"], *(bytes.fromhex(p[field]) for field in ("partial_hex", "proof_hex", "commitment_hex")))
        for p in v["partials"]
    ],
)
if plaintext.hex() != v["expected_plaintext_hex"]:
    fail("open_secret did not recover the golden plaintext")

_binding_id, capsule, _proof, _ct = matter_sdk.encrypt(
    bytes.fromhex(v["joint_pk_hex"]), v["epoch"], b"smoke", bytes.fromhex(v["aad_hex"])
)
if len(capsule) != len(v["capsule_hex"]) // 2:
    fail("encrypt produced a capsule of the wrong size")

key = matter_sdk.ApiKey(SMOKE_KEY)
if len(key.account_id) != SR25519_ACCOUNT_ID_LEN:
    fail("ApiKey did not derive a 32-byte account id")
if len(key.sign(b"\x01")) != SR25519_SIGNATURE_LEN:
    fail("ApiKey did not produce a 64-byte signature")
