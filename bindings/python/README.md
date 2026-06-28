# matter-vault (Python)

**Status: crypto surface working & conformance-verified; orchestration pending.**
See [`docs/parity.md`](../../docs/parity.md).

PyO3 binding over the one shared MatterVault cryptographic core
(`crates/matter-vault-core`). The exposed functions (`encrypt`, `signing_payload`,
`lagrange_for`, `verify_plaintext_proof`, `open_secret`) call real core crypto and
pass the same cross-language fixtures as the Rust and TS bindings — including a full
`open_secret` round trip that recovers the exact plaintext the Rust core sealed. The
committee client, quorum orchestration, and `Signer` abstraction are not yet
implemented (they involve no new cryptography — see the parity doc).

## Build & test

```bash
pip install maturin            # or: uv tool install maturin
cd bindings/python
maturin develop                # builds + installs the extension into the venv
pytest                         # runs the conformance tests
```

## Usage (current surface)

```python
import matter_vault

binding_id, capsule, proof, ct = matter_vault.encrypt(
    joint_pk, epoch, b"API_KEY=swordfish", b"matter-deployment/env/v1"
)
payload = matter_vault.signing_payload(secret_id, [1, 3, 5], block_hash)  # sign this
```

## Why a Rust core via PyO3

The RLWE/BGV threshold cryptography is novel and must exist in exactly one audited
implementation. PyO3 lets Python call that core directly rather than re-implementing
lattice crypto — see the repo README's architecture section.
