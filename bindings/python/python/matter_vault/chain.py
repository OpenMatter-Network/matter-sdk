"""Substrate chain client for the matter-kgc chain (optional ``[sdk]`` extra).

Reads the committee context the SDK needs (joint_pk, nodes, commitments, ...) via
runtime-API ``state_call``s and submits the gas-paying ``secrets.store_secret``
extrinsic — the analogue of @polkadot/api in the TypeScript example. The SDK
proper never holds keys or submits; this is the "your own Substrate client" half.

Requires ``substrate-interface`` (``pip install matter-vault[sdk]``).
"""

from typing import Dict, List, Tuple

from scalecodec.base import ScaleBytes
from substrateinterface import Keypair, KeypairType, SubstrateInterface
from substrateinterface.utils.ss58 import ss58_decode

# Custom return types the runtime APIs use (scalecodec needs them registered).
_CUSTOM_TYPES = {
    "KgcNodeInfo": {"type": "struct", "type_mapping": [["endpoint", "Bytes"], ["dkg_index", "u64"]]},
    "EncSecretWire": {
        "type": "struct",
        "type_mapping": [
            ["binding_id", "Bytes"],
            ["capsule", "Bytes"],
            ["proof", "Bytes"],
            ["ct", "Bytes"],
        ],
    },
}
_SS58_FORMAT = 42


def _bytes_field(v) -> bytes:
    """A scalecodec ``Bytes`` value -> raw bytes (it renders binary as ``0x``-hex,
    valid UTF-8 as a plain string)."""
    if isinstance(v, str):
        return bytes.fromhex(v[2:]) if v.startswith("0x") else v.encode()
    return bytes(v)


def _account_bytes(acct) -> bytes:
    if isinstance(acct, str):
        return bytes.fromhex(acct[2:]) if acct.startswith("0x") else bytes.fromhex(ss58_decode(acct))
    return bytes(acct)


def _normalize_endpoint(raw: str) -> str:
    s = raw.strip()
    if "://" not in s:
        s = "https://" + s
    return s.rstrip("/")


def _secret_id_from_attributes(attrs) -> int:
    """Field 0 of Secrets.SecretStored is the chain-assigned secret_id (u128)."""
    if isinstance(attrs, dict):
        if "secret_id" in attrs:
            return int(attrs["secret_id"])
        values = list(attrs.values())
    elif isinstance(attrs, (list, tuple)):
        values = list(attrs)
    else:
        values = [attrs]
    head = values[0]
    if isinstance(head, dict) and "value" in head:
        head = head["value"]
    return int(head)


class ChainClient:
    """A thin wrapper over ``substrate-interface`` for the matter-kgc chain."""

    def __init__(self, url: str) -> None:
        self.substrate = SubstrateInterface(url=url)
        self.substrate.runtime_config.update_type_registry_types(_CUSTOM_TYPES)

    def close(self) -> None:
        self.substrate.close()

    def __enter__(self) -> "ChainClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @staticmethod
    def keypair_from_seed(seed: str) -> Keypair:
        """An sr25519 keypair from a ``0x`` hex seed or a BIP39 mnemonic / SURI
        (the funded signer). No ``///password`` support for sr25519."""
        # substrate-interface's create_from_uri feeds the phrase to
        # create_from_mnemonic, so hex seeds must branch to create_from_seed.
        factory = Keypair.create_from_seed if seed.startswith("0x") else Keypair.create_from_uri
        return factory(seed, ss58_format=_SS58_FORMAT, crypto_type=KeypairType.SR25519)

    # --- runtime-API reads -------------------------------------------------

    def _call(self, method: str, args: bytes = b"") -> bytes:
        res = self.substrate.rpc_request("state_call", [method, "0x" + bytes(args).hex()])
        return bytes.fromhex(res["result"][2:])

    def _decode(self, type_str: str, raw: bytes):
        return self.substrate.runtime_config.create_scale_object(type_str, ScaleBytes(raw)).decode()

    def joint_pk(self) -> bytes:
        v = self._decode("Option<Bytes>", self._call("KgcApi_joint_pk"))
        if not v:
            raise RuntimeError("KGC DKG not finalised on chain (joint_pk is None)")
        return _bytes_field(v)

    def dkg_epoch(self) -> int:
        return int(self._decode("u32", self._call("KgcApi_dkg_epoch")))

    def shared_a(self) -> bytes:
        v = self._decode("Option<Bytes>", self._call("KgcApi_shared_a"))
        if not v:
            raise RuntimeError("KGC shared_a unavailable (DKG not finalised)")
        return _bytes_field(v)

    def threshold_at_epoch(self, epoch: int) -> int:
        t = self._decode("(u64, u64)", self._call("KgcApi_threshold_params_at_epoch", epoch.to_bytes(4, "little")))
        return int(t[1])

    def nodes(self) -> List[Tuple[bytes, int, str]]:
        """``(account_bytes, dkg_index, endpoint)`` for each committee node."""
        # Decode the account as an explicit [u8; 32]: scalecodec's `AccountId`
        # resolution is metadata-state-dependent and can misread the raw bytes as
        # an enum once full metadata is loaded; the fixed array is unambiguous.
        vec = self._decode("Vec<([u8; 32], KgcNodeInfo)>", self._call("KgcApi_kgc_nodes"))
        return [
            (_account_bytes(acct), int(info["dkg_index"]), _normalize_endpoint(info["endpoint"]))
            for acct, info in vec
        ]

    def share_commitment(self, epoch: int, account_bytes: bytes) -> bytes:
        arg = epoch.to_bytes(4, "little") + bytes(account_bytes)
        v = self._decode("Option<Bytes>", self._call("KgcApi_share_commitment", arg))
        if not v:
            raise RuntimeError("missing share commitment for a node")
        return _bytes_field(v)

    def secret_payload(self, secret_id: int) -> Dict[str, bytes]:
        v = self._decode("Option<EncSecretWire>", self._call("SecretsApi_secret_payload", secret_id.to_bytes(16, "little")))
        if v is None:
            raise RuntimeError(f"secret {secret_id} not found on chain")
        return {k: _bytes_field(val) for k, val in v.items()}

    def secret_epoch(self, secret_id: int) -> int:
        v = self._decode("Option<u32>", self._call("SecretsApi_secret_epoch", secret_id.to_bytes(16, "little")))
        if v is None:
            raise RuntimeError(f"secret {secret_id} has no epoch")
        return int(v)

    def finalized_head(self) -> bytes:
        return bytes.fromhex(self.substrate.get_chain_finalised_head()[2:])

    def free_balance(self, address: str) -> int:
        return int(self.substrate.query("System", "Account", [address]).value["data"]["free"])

    # --- extrinsic ---------------------------------------------------------

    def store_secret(self, keypair: Keypair, call_params: dict) -> int:
        """Submit ``secrets.store_secret`` and return the chain-assigned secret_id.

        Waits for FINALIZATION: the committee authorizes a partial-decrypt against
        a finalized block, so decrypting before the storing block is finalized
        gets a 403. (The same race the TypeScript example had to fix.)
        """
        call = self.substrate.compose_call("Secrets", "store_secret", call_params)
        # Take the nonce from System.Account directly: get_account_nonce() can
        # report 0 on this runtime, which signs a stale tx ("outdated", 1010).
        nonce = int(self.substrate.query("System", "Account", [keypair.ss58_address]).value["nonce"])
        extrinsic = self.substrate.create_signed_extrinsic(call=call, keypair=keypair, nonce=nonce)
        receipt = self.substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True, wait_for_finalization=True)
        if not receipt.is_success:
            raise RuntimeError(f"storeSecret failed: {receipt.error_message}")
        for event in receipt.triggered_events:
            e = event.value["event"]
            if e.get("module_id") == "Secrets" and e.get("event_id") == "SecretStored":
                return _secret_id_from_attributes(e["attributes"])
        raise RuntimeError("storeSecret landed but emitted no Secrets.SecretStored event")
