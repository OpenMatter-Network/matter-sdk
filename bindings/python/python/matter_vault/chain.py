"""Substrate chain client for MatterChain (optional ``[sdk]`` extra).

Reads the committee context the SDK needs (joint_pk, nodes, commitments, ...) via
runtime-API ``state_call``s, and signs and submits extrinsics — any pallet the
runtime exposes, resolved by name from live metadata.

Most callers want :class:`~matter_vault.client.MatterClient`, which wraps this with
the network guards, amount helpers, and identity handling. This module is the layer
underneath, and stays usable directly for anything the client does not cover.

Requires ``substrate-interface`` (``pip install matter-vault[sdk]``).
"""

import re
from typing import Dict, List, Optional, Tuple

from scalecodec.base import ScaleBytes
from substrateinterface import Keypair, KeypairType, SubstrateInterface
from substrateinterface.utils.ss58 import ss58_decode, ss58_encode

# A bare 32-byte hex mini-secret: no derivation junctions, no ``///password``.
# Anything else — including ``0x…//hard`` — must not go to ``create_from_seed``, or
# the junctions are silently dropped.
_BARE_MINI_SECRET = re.compile(r"0x[0-9a-fA-F]{64}")

#: Scheme tokens ``ApiKey`` accepts as a prefix, stripped before derivation.
_SCHEME_PREFIX = "sr25519:"


def _strip_scheme(text: str) -> str:
    """Remove an optional ``sr25519:`` prefix, case-insensitively."""
    return text[len(_SCHEME_PREFIX) :] if text[: len(_SCHEME_PREFIX)].lower() == _SCHEME_PREFIX else text


class ApiKeySigner:
    """An :class:`~matter_vault.apikey.ApiKey` shaped like a ``substrate-interface``
    ``Keypair``, so it can sign extrinsics.

    ``create_signed_extrinsic`` only reads ``crypto_type``, ``public_key``,
    ``ss58_address``, and ``sign`` — so this adapter is enough, and it means the
    binding has exactly **one** derivation path (the shared Rust core) instead of
    two that can disagree. It also lifts substrate-interface's limitation that a
    hex phrase cannot carry derivation junctions.

    The key material stays in Rust: this holds an ``ApiKey``, which has no
    accessor for its secret.
    """

    __slots__ = ("_key", "public_key", "ss58_address", "crypto_type")

    def __init__(self, key) -> None:
        self._key = key
        self.public_key = key.account_id
        self.ss58_address = ss58_encode(key.account_id, _SS58_FORMAT)
        self.crypto_type = KeypairType.SR25519

    def sign(self, data) -> bytes:
        """Sign ``data``, accepting the same shapes ``Keypair.sign`` does."""
        return self._key.sign(_as_bytes_to_sign(data))

    def __repr__(self) -> str:
        return f"ApiKeySigner({self.ss58_address})"


def _as_bytes_to_sign(data) -> bytes:
    """Normalize what substrate-interface passes to ``keypair.sign``.

    It may hand over a ``ScaleBytes``, a ``0x`` hex string, or plain text; the
    real ``Keypair.sign`` accepts all three, so the adapter must too.
    """
    if isinstance(data, ScaleBytes):
        return bytes(data.data)
    if isinstance(data, str):
        return bytes.fromhex(data[2:]) if data.startswith("0x") else data.encode()
    return bytes(data)


def api_key_signer(key) -> ApiKeySigner:
    """Adapt an :class:`~matter_vault.apikey.ApiKey` for extrinsic signing.

    The recommended way to submit: one derivation, full SURI support, and the key
    never leaves the Rust core.
    """
    return ApiKeySigner(key)

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
        """An sr25519 ``substrate-interface`` keypair from a ``0x`` hex mini-secret
        or a BIP39 mnemonic / SURI.

        **Prefer** :func:`api_key_signer`, which derives in the shared Rust core and
        therefore cannot drift. This helper exists for callers that need a real
        ``substrate-interface`` ``Keypair``, and it inherits that library's limits:

        * ``create_from_uri`` feeds the phrase to bip39, so it cannot derive a
          **hex** phrase with junctions (``0x…//hard`` raises). Use
          :func:`api_key_signer` for those.
        * ``create_from_seed`` ignores junctions entirely, so it is only used for a
          bare 32-byte secret — routing every ``0x``-prefixed string to it is what
          made ``0x…//hard`` silently derive the **root** account.

        A ``sr25519:`` scheme prefix is accepted and stripped, matching
        :class:`~matter_vault.apikey.ApiKey`.
        """
        text = _strip_scheme(seed.strip())
        if _BARE_MINI_SECRET.fullmatch(text):
            # A bare 32-byte hex secret: no junctions, no password.
            return Keypair.create_from_seed(
                text, ss58_format=_SS58_FORMAT, crypto_type=KeypairType.SR25519
            )
        if text.startswith("0x"):
            raise ValueError(
                "substrate-interface cannot derive a hex phrase with derivation "
                "junctions or a password; use matter_vault.api_key_signer(), which "
                "derives in the shared core"
            )
        return Keypair.create_from_uri(
            text, ss58_format=_SS58_FORMAT, crypto_type=KeypairType.SR25519
        )

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

    # --- the generic surface -----------------------------------------------

    def query(self, pallet: str, entry: str, keys: Optional[List] = None):
        """Read any storage entry. ``None`` means the entry is absent, which is
        normal control flow — an unfunded account has no ``System.Account`` row."""
        result = self.substrate.query(pallet, entry, keys or [])
        return None if result is None else result.value

    def runtime_api(self, method: str, args: bytes = b"", return_type: str = "Bytes"):
        """Call any runtime API by its ``state_call`` name, e.g.
        ``runtime_api("KgcApi_dkg_epoch", return_type="Option<u32>")``."""
        return self._decode(return_type, self._call(method, args))

    def constant(self, pallet: str, name: str):
        """Read any pallet constant from the live metadata."""
        return self.substrate.get_constant(pallet, name).value

    def submit(self, keypair: Keypair, pallet: str, call: str, params: dict) -> "TxReceipt":
        """Sign and submit any call, waiting for FINALIZATION.

        Resolution is by name against the live metadata, so this reaches every
        pallet the runtime exposes — including ones added by a forkless upgrade.

        Finalization, not inclusion: the committee authorizes a partial-decrypt
        against a finalized block, so resolving earlier gets an HTTP 403. That was
        a real bug in the TypeScript harness before it was fixed.
        """
        composed = self.substrate.compose_call(pallet, call, params)
        # Read the nonce from System.Account directly: get_account_nonce() can
        # report 0 on this runtime, which signs a stale tx ("outdated", 1010).
        nonce = int(
            self.substrate.query("System", "Account", [keypair.ss58_address]).value["nonce"]
        )
        extrinsic = self.substrate.create_signed_extrinsic(
            call=composed, keypair=keypair, nonce=nonce
        )
        receipt = self.substrate.submit_extrinsic(
            extrinsic, wait_for_inclusion=True, wait_for_finalization=True
        )
        if not receipt.is_success:
            raise ChainError(
                f"{pallet}.{call} failed on chain: {receipt.error_message}",
                pallet=pallet,
                call=call,
            )

        events = []
        for event in receipt.triggered_events:
            e = event.value["event"]
            events.append((e.get("module_id"), e.get("event_id"), e.get("attributes")))
        return TxReceipt(
            tx_hash=receipt.extrinsic_hash,
            block_hash=receipt.block_hash,
            events=events,
        )

    # --- extrinsic ---------------------------------------------------------

    def store_secret(self, keypair: Keypair, call_params: dict) -> int:
        """Submit ``secrets.store_secret`` and return the chain-assigned secret_id.

        A thin wrapper over :meth:`submit` that pulls the id out of the
        ``Secrets.SecretStored`` event, so the id is read from the chain's own
        output rather than predicted from a counter.
        """
        receipt = self.submit(keypair, "Secrets", "store_secret", call_params)
        attributes = receipt.require_event("Secrets", "SecretStored")
        return _secret_id_from_attributes(attributes)


class TxReceipt:
    """The outcome of a submitted extrinsic, after finalization."""

    __slots__ = ("tx_hash", "block_hash", "events")

    def __init__(self, tx_hash: str, block_hash: str, events: List[Tuple]) -> None:
        self.tx_hash = tx_hash
        self.block_hash = block_hash
        #: ``(pallet, event, attributes)`` for each event this extrinsic emitted.
        self.events = events

    def emitted(self, pallet: str, event: str) -> bool:
        """Whether ``pallet.event`` fired."""
        return any(p == pallet and e == event for p, e, _ in self.events)

    def require_event(self, pallet: str, event: str):
        """The attributes of ``pallet.event``, or raise.

        A call that landed without the event it is defined to emit means the
        runtime changed under us; returning ``None`` would push a confusing
        failure downstream.
        """
        for p, e, attributes in self.events:
            if p == pallet and e == event:
                return attributes
        emitted = ", ".join(f"{p}.{e}" for p, e, _ in self.events) or "none"
        raise ChainError(
            f"extrinsic finalized but emitted no {pallet}.{event} (saw: {emitted})",
            pallet=pallet,
            call=event,
        )

    def __repr__(self) -> str:
        return f"TxReceipt(block={self.block_hash}, events={len(self.events)})"


class ChainError(RuntimeError):
    """A chain read or submission failed. Branch on ``pallet``/``call``, not on
    the message text."""

    def __init__(self, message: str, *, pallet: str = "", call: str = "") -> None:
        super().__init__(message)
        self.pallet = pallet
        self.call = call
