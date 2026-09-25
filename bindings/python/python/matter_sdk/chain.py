"""Substrate chain client for MatterChain (needs the ``[sdk]`` extra).

Reads committee context via runtime-API ``state_call``s and submits extrinsics to
any pallet, resolved by name from live metadata. Most callers want
:class:`~matter_sdk.client.MatterClient`, which wraps this.
"""

import re
from typing import Dict, List, Optional, Tuple

from scalecodec.base import ScaleBytes
from substrateinterface import Keypair, KeypairType, SubstrateInterface
from substrateinterface.exceptions import SubstrateRequestException
from substrateinterface.utils.ss58 import ss58_decode, ss58_encode

from .errors import ChainError, DispatchError, OuterDispatchError, PoolRejectedError

# A bare 32-byte hex mini-secret. Anything else (e.g. ``0x…//hard``) must not reach
# ``create_from_seed``, which silently drops junctions.
_BARE_MINI_SECRET = re.compile(r"0x[0-9a-fA-F]{64}")

#: Scheme prefix ``ApiKey`` accepts, stripped before derivation.
_SCHEME_PREFIX = "sr25519:"

#: Scoped API keys need runtime spec >= 322. V14 metadata lists calls but not
#: runtime APIs, so the call's presence tells a pre-322 chain from one that failed
#: to answer.
_AGENT_KEY_PALLET = "Budgets"
_AGENT_KEY_CALL = "authorize_agent_key"
_AGENT_KEY_API = "BudgetsApi_agent_key"


def _strip_scheme(text: str) -> str:
    """Remove an optional ``sr25519:`` prefix, case-insensitively."""
    return text[len(_SCHEME_PREFIX) :] if text[: len(_SCHEME_PREFIX)].lower() == _SCHEME_PREFIX else text


class ApiKeySigner:
    """An :class:`~matter_sdk.apikey.ApiKey` shaped like a ``substrate-interface``
    ``Keypair``, so it can sign extrinsics.

    ``create_signed_extrinsic`` reads only ``crypto_type``, ``public_key``,
    ``ss58_address``, and ``sign``. Derivation stays in the shared Rust core
    (junctions on hex phrases included), and the secret never leaves it.
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
    """Normalize a ``ScaleBytes``, ``0x`` hex string, or plain text, as
    ``Keypair.sign`` accepts."""
    if isinstance(data, ScaleBytes):
        return bytes(data.data)
    if isinstance(data, str):
        return bytes.fromhex(data[2:]) if data.startswith("0x") else data.encode()
    return bytes(data)


def api_key_signer(key) -> ApiKeySigner:
    """Adapt an :class:`~matter_sdk.apikey.ApiKey` for extrinsic signing; the
    recommended signer."""
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


def _proxy_result(attributes):
    """The ``Err`` payload of a ``Proxy.ProxyExecuted`` event, or ``None`` if the
    wrapped call succeeded.

    Depending on loaded metadata, scalecodec renders the ``DispatchResult`` as
    ``{"Err"|"Ok": …}``, ``{"result": …}``, or a one-element sequence; all are read.
    """
    if isinstance(attributes, (list, tuple)):
        attributes = attributes[0] if attributes else None
    if isinstance(attributes, dict) and "result" in attributes:
        attributes = attributes["result"]
    if not isinstance(attributes, dict):
        return None
    if "Err" in attributes:
        return attributes["Err"]
    # An explicit Ok, or a shape with neither arm, is not a failure.
    return None


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
        """An sr25519 ``substrate-interface`` keypair from a bare ``0x`` hex
        mini-secret or a BIP39 mnemonic / SURI; an ``sr25519:`` prefix is stripped.

        Prefer :func:`api_key_signer`, which derives in the shared core. A hex
        phrase with junctions or a password (``0x…//hard``) raises ``ValueError``:
        substrate-interface cannot derive it.
        """
        text = _strip_scheme(seed.strip())
        if _BARE_MINI_SECRET.fullmatch(text):
            return Keypair.create_from_seed(
                text, ss58_format=_SS58_FORMAT, crypto_type=KeypairType.SR25519
            )
        if text.startswith("0x"):
            raise ValueError(
                "substrate-interface cannot derive a hex phrase with derivation "
                "junctions or a password; use matter_sdk.api_key_signer(), which "
                "derives in the shared core"
            )
        return Keypair.create_from_uri(
            text, ss58_format=_SS58_FORMAT, crypto_type=KeypairType.SR25519
        )

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
        # [u8; 32], not AccountId: scalecodec can misread AccountId as an enum once
        # full metadata is loaded.
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

    def query(self, pallet: str, entry: str, keys: Optional[List] = None):
        """Read any storage entry. ``None`` means the entry is absent (not an error)."""
        result = self.substrate.query(pallet, entry, keys or [])
        return None if result is None else result.value

    def runtime_api(self, method: str, args: bytes = b"", return_type: str = "Bytes"):
        """Call any runtime API by its ``state_call`` name, e.g.
        ``runtime_api("KgcApi_dkg_epoch", return_type="Option<u32>")``."""
        return self._decode(return_type, self._call(method, args))

    def constant(self, pallet: str, name: str):
        """Read any pallet constant from the live metadata."""
        return self.substrate.get_constant(pallet, name).value

    def supports_agent_keys(self) -> bool:
        """Whether this runtime has scoped API keys (spec >= 322), read from the
        metadata already held rather than probed."""
        return (
            self.substrate.get_metadata_call_function(_AGENT_KEY_PALLET, _AGENT_KEY_CALL)
            is not None
        )

    def agent_key(self, key: bytes):
        """``BudgetsApi_agent_key(key)``: who ``key`` acts for, and what it may do.

        Returns ``(principal_bytes, scope_bits)``, or ``None`` when the chain has
        no scoped keys or ``key`` is not registered. A failed lookup raises
        :class:`ChainError` instead: resolving it as "no delegation" would sign
        later writes as the key's own balance-less account.
        """
        if not self.supports_agent_keys():
            return None
        try:
            raw = self._call(_AGENT_KEY_API, bytes(key))
        except SubstrateRequestException as exc:
            raise ChainError(
                f"{_AGENT_KEY_API} failed: {exc}",
                pallet=_AGENT_KEY_PALLET,
                call="agent_key",
            ) from exc
        # A decode failure here is a shape bug, not an absent grant: let it out.
        v = self._decode("Option<([u8; 32], u32)>", raw)
        if v is None:
            return None
        principal, bits = v
        return (_account_bytes(principal), int(bits))

    def submit(
        self,
        keypair: Keypair,
        pallet: str,
        call: str,
        params: dict,
        principal: Optional[bytes] = None,
    ) -> "TxReceipt":
        """Sign and submit any call, resolved by name from live metadata, and wait
        for finalization.

        Finalization, not inclusion: the committee authorizes a partial-decrypt
        against a finalized block, so returning earlier gets an HTTP 403.

        With ``principal`` set the call is wrapped in ``proxy.proxy`` and runs as
        that member, which is how a member-tied API key acts.

        Raises :class:`PoolRejectedError` if the node refuses it at validation,
        :class:`OuterDispatchError` if the extrinsic fails, :class:`DispatchError` if
        the proxied call fails, and :class:`ChainError` if it cannot be submitted.
        """
        composed = self.substrate.compose_call(pallet, call, params)
        if principal is not None:
            composed = self.substrate.compose_call(
                "Proxy",
                "proxy",
                {
                    "real": {"Id": principal},
                    "force_proxy_type": None,
                    "call": composed,
                },
            )
        # get_account_nonce() can report 0 on this runtime, signing a stale tx (1010).
        nonce = int(
            self.substrate.query("System", "Account", [keypair.ss58_address]).value["nonce"]
        )
        extrinsic = self.substrate.create_signed_extrinsic(
            call=composed, keypair=keypair, nonce=nonce
        )
        try:
            receipt = self.substrate.submit_extrinsic(
                extrinsic, wait_for_inclusion=True, wait_for_finalization=True
            )
        except SubstrateRequestException as exc:
            if _is_pool_rejection(exc):
                raise PoolRejectedError(
                    f"{pallet}.{call} was refused by the node at validation: {exc}",
                    pallet=pallet,
                    call=call,
                ) from exc
            raise ChainError(
                f"{pallet}.{call} could not be submitted: {exc}", pallet=pallet, call=call
            ) from exc

        if not receipt.is_success:
            detail = receipt.error_message
            module, name = "", ""
            if isinstance(detail, dict):
                module = str(detail.get("type", ""))
                name = str(detail.get("name", ""))
            raise OuterDispatchError(
                f"{pallet}.{call} failed on chain: {detail}",
                pallet=pallet,
                call=call,
                module=module,
                name=name,
            )

        # `proxy.proxy` succeeds even when the wrapped call fails, which
        # `receipt.is_success` cannot see.
        if principal is not None:
            failure = self._wrapped_failure(receipt)
            if failure is not None:
                raise DispatchError(
                    f"{pallet}.{call} failed under delegation: {failure}",
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

    def _wrapped_failure(self, receipt) -> Optional[str]:
        """The wrapped call's own error from ``Proxy.ProxyExecuted``, or ``None``,
        rendered like a direct ``ExtrinsicFailed``."""
        for event in receipt.triggered_events:
            e = event.value["event"]
            if e.get("module_id") != "Proxy" or e.get("event_id") != "ProxyExecuted":
                continue
            result = _proxy_result(e.get("attributes"))
            if result is None:
                return None
            module = result.get("Module") if isinstance(result, dict) else None
            if isinstance(module, dict):
                try:
                    meta = self.substrate.metadata.get_module_error(
                        module_index=module["index"], error_index=module["error"][0]
                    )
                    return f"{meta.name}: {' '.join(meta.docs).strip()}"
                except Exception:
                    pass
            return str(result)
        return None

    def store_secret(self, keypair: Keypair, call_params: dict) -> int:
        """Submit ``secrets.store_secret`` and return the chain-assigned secret_id,
        read from the ``Secrets.SecretStored`` event."""
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
        """The attributes of ``pallet.event``; raises :class:`ChainError` if it
        did not fire."""
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


#: Substrate's "Invalid Transaction" JSON-RPC error code.
_POOL_REJECTION_CODE = 1010

#: Pool-rejection markers for when the JSON-RPC code is unavailable (same as Rust).
_POOL_REJECTION_MARKERS = ("1010", "Inability to pay", "InvalidTransaction")


def _is_pool_rejection(exc: BaseException) -> bool:
    """Whether ``exc`` is the node refusing a transaction at validation.

    substrate-interface raises the whole JSON-RPC error dict from
    ``submit_extrinsic`` and a bare string elsewhere, so both are read.
    """
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], dict) and args[0].get("code") == _POOL_REJECTION_CODE:
        return True
    text = str(exc)
    return any(marker in text for marker in _POOL_REJECTION_MARKERS)
