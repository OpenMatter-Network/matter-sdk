#!/usr/bin/env python3
"""MatterVault end-to-end test against a LIVE chain + committee (Python).

The Python analogue of examples/e2e/run.ts and examples/rust-e2e: connect -> fetch
committee context -> encrypt -> secrets.storeSecret (pays a fee) -> read back ->
threshold-decrypt -> assert the round trip. The key stays in this process (a
substrate-interface keyring pair); the SDK only gets a sign callback.

Env:
  MATTER_RPC_URL      ws(s) endpoint            (default: testnet)
  MATTER_SIGNER_SEED  sr25519 SURI / 0x-seed    (falls back to TEST_KEY)
  MATTER_SECRET       plaintext to seal         (default: a sample env line)
  MATTER_SECRET_ID    decrypt an existing secret instead of storing a new one

Run:  ./bindings/python/.venv/bin/python examples/python-e2e/run.py
"""

import os
import sys

from matter_vault import (
    Aad,
    ChainClient,
    CommitteeNode,
    DecryptParams,
    UrllibTransport,
    aad_bytes,
    decrypt,
    encrypt,
    store_secret,
    substrate_signer,
)

DEFAULT_RPC = "wss://node2.testnet.openmatter.network"
DEFAULT_SECRET = "API_KEY=swordfish\nDATABASE_URL=postgres://prod"


def main() -> int:
    rpc_url = os.environ.get("MATTER_RPC_URL", DEFAULT_RPC)
    seed = os.environ.get("MATTER_SIGNER_SEED") or os.environ.get("TEST_KEY")
    if not seed:
        print("set MATTER_SIGNER_SEED or TEST_KEY (sr25519 SURI / 0x-seed)", file=sys.stderr)
        return 2
    if ChainClient is None:
        print("install the chain client: pip install matter-vault[sdk]", file=sys.stderr)
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
            secret_id = chain.store_secret(keypair, store_secret(env, epoch, b"", aad))
            print(f"Stored on chain: secret_id={secret_id}.")

        secret_epoch = chain.secret_epoch(secret_id)
        wire = chain.secret_payload(secret_id)
        threshold = chain.threshold_at_epoch(secret_epoch)
        shared_a = chain.shared_a()
        nodes = chain.nodes()
        print(f"Committee: {len(nodes)} nodes, threshold t={threshold}.")

        committee_nodes = [
            CommitteeNode(index=index, endpoint=endpoint, share_commitment=chain.share_commitment(secret_epoch, account))
            for (account, index, endpoint) in nodes
        ]
        block_hash = chain.finalized_head()
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
                shared_a=shared_a,
                block_hash=block_hash,
                threshold=threshold,
                nodes=committee_nodes,
            ),
        )

        text = recovered.decode("utf-8", "replace")
        print(f"\nRecovered: {text}")
        if not existing:
            if text != secret_text:
                print("MISMATCH: recovered plaintext != original", file=sys.stderr)
                return 1
            print("Round trip verified ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
