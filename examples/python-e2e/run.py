#!/usr/bin/env python3
"""Live Secrets round trip against a chain + committee.

seal -> secrets.storeSecret (pays a fee) -> read back -> threshold-decrypt -> verify.
Needs a FUNDED account; the key stays in this process and the SDK only gets a sign
callback. Environment variables: examples/README.md.

Run:  ./bindings/python/.venv/bin/python examples/python-e2e/run.py
"""

import os
import sys

from matter_sdk import (
    Aad,
    ChainClient,
    DecryptParams,
    Network,
    UrllibTransport,
    aad_bytes,
    decrypt,
    encrypt,
    store_secret,
    substrate_signer,
    wipe,
)

DEFAULT_SECRET = "API_KEY=swordfish\nDATABASE_URL=postgres://prod"

#: The on-chain label of a secret this harness stores; the other harnesses use the same.
LABEL = "matter-sdk e2e"


def guard_mainnet(rpc_url: str) -> None:
    """Refuse mainnet without ``MATTER_CONFIRM=yes``.

    Checks the URL as well as ``MATTER_NETWORK``: a mistyped ``MATTER_RPC_URL`` is
    the likelier mistake.
    """
    network = os.environ.get("MATTER_NETWORK", "testnet")
    if network != "mainnet" and "mainnet" not in rpc_url:
        return
    if os.environ.get("MATTER_CONFIRM") == "yes":
        print("WARNING: running against MAINNET with real funds (MATTER_CONFIRM=yes).", file=sys.stderr)
        return
    raise SystemExit(
        f"refusing to run a gas-paying harness against mainnet ({rpc_url}) without "
        "explicit confirmation: set MATTER_CONFIRM=yes. This spends real funds."
    )


def main() -> int:
    # Without the [sdk] extra the chain names are stubs that raise on use, not None.
    if not isinstance(ChainClient, type):
        print('install the chain client: pip install "matter-sdk[sdk]"', file=sys.stderr)
        return 2
    # Default endpoint per network: testvectors/networks.json.
    network = os.environ.get("MATTER_NETWORK", Network.TESTNET)
    if network not in (Network.TESTNET, Network.MAINNET):
        raise SystemExit(f"MATTER_NETWORK must be testnet or mainnet, got {network!r}")
    rpc_url = os.environ.get("MATTER_RPC_URL") or Network.default_rpc_url(network)
    guard_mainnet(rpc_url)
    seed = os.environ.get("MATTER_SIGNER_SEED") or os.environ.get("TEST_KEY")
    if not seed:
        print("set MATTER_SIGNER_SEED or TEST_KEY (sr25519 SURI / 0x-seed)", file=sys.stderr)
        return 2
    secret_text = os.environ.get("MATTER_SECRET", DEFAULT_SECRET)
    existing = os.environ.get("MATTER_SECRET_ID")
    aad = Aad.ENV_V1

    keypair = ChainClient.keypair_from_seed(seed)
    print(f"Account: {keypair.ss58_address}")

    def sign(payload: bytes) -> bytes:
        sig = keypair.sign(payload)
        if isinstance(sig, str):
            sig = bytes.fromhex(sig[2:] if sig.startswith("0x") else sig)
        return bytes(sig)

    with ChainClient(rpc_url) as chain:
        balance = chain.free_balance(keypair.ss58_address)
        print(f"Balance: {balance} planck (~{balance / 10**12} MTR)")
        if balance == 0:
            print(f"FAIL: account {keypair.ss58_address} has zero balance — fund it first.", file=sys.stderr)
            return 1

        joint_pk = chain.joint_pk()
        epoch = chain.dkg_epoch()
        print(f"Connected. Committee epoch={epoch}, joint_pk={len(joint_pk)}B")

        if existing:
            secret_id = int(existing)
            print(f"Using existing secret {secret_id}.")
        else:
            env = encrypt(joint_pk, epoch, secret_text.encode(), aad_bytes(aad))
            print(f"Sealed {len(secret_text.encode())}B -> capsule {len(env[1])}B, proof {len(env[2])}B, ct {len(env[3])}B")
            print("Submitting secrets.storeSecret ...")
            secret_id = chain.store_secret(keypair, store_secret(env, epoch, LABEL, aad))
            print(f"Stored on chain: secret_id={secret_id}.")

        secret_epoch = chain.secret_epoch(secret_id)
        wire = chain.secret_payload(secret_id)
        # The committee as it stood at the secret's epoch, which survives rotations.
        committee = chain.committee_at(secret_epoch)
        print(f"Committee: {len(committee.nodes)} reachable nodes, threshold t={committee.threshold}.")
        signer = substrate_signer(bytes(keypair.public_key), sign)

        print("Collecting partial decryptions ...")
        recovered = decrypt(
            UrllibTransport(),
            signer,
            DecryptParams(
                secret_id=secret_id,
                epoch=secret_epoch,
                binding_id=wire["binding_id"],
                aad=aad,
                capsule=wire["capsule"],
                ct=wire["ct"],
                shared_a=committee.shared_a,
                block_hash=committee.block_hash,
                threshold=committee.threshold,
                nodes=committee.nodes,
            ),
        )

        # Recovered plaintext is compared in process, never printed.
        print(f"\nRecovered {len(recovered)} bytes")
        matches = recovered == secret_text.encode()
        wipe(recovered)
        if not existing:
            if not matches:
                print("MISMATCH: recovered plaintext != original", file=sys.stderr)
                return 1
            print("Round trip verified ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
