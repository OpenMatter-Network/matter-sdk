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
from substrateinterface.exceptions import SubstrateRequestException
from substrateinterface.utils.ss58 import ss58_decode, ss58_encode

# A bare 32-byte hex mini-secret: no derivation junctions, no ``///password``.
# Anything else — including ``0x…//hard`` — must not go to ``create_from_seed``, or
# the junctions are silently dropped.
_BARE_MINI_SECRET = re.compile(r"0x[0-9a-fA-F]{64}")

#: Scheme tokens ``ApiKey`` accepts as a prefix, stripped before derivation.
_SCHEME_PREFIX = "sr25519:"

#: Scoped API keys arrived in runtime spec 322, which added both the
#: ``Budgets.authorize_agent_key`` call and the ``BudgetsApi_agent_key`` runtime
#: API. V14 metadata carries calls but not runtime-API declarations, so the call
#: is what a substrate-interface client can see locally — and seeing it is how
#: this binding tells a pre-322 chain from a chain that failed to answer. The
#: dashboard gates on the same call for the same reason.
_AGENT_KEY_PALLET = "Budgets"
_AGENT_KEY_CALL = "authorize_agent_key"
_AGENT_KEY_API = "BudgetsApi_agent_key"


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


def _proxy_result(attributes):
    """The ``Err`` payload of a ``Proxy.ProxyExecuted`` event, or ``None`` if the
    wrapped call succeeded.

    The event carries one ``DispatchResult`` field, but scalecodec renders it
    differently depending on the metadata it loaded: as ``{"Err": …}`` /
    ``{"Ok": …}``, as a bare ``{"result": {...}}`` mapping, or as a single-element
    sequence. Reading all three shapes is cheaper than pinning one and finding out
    in production which one this node emits.
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

    def supports_agent_keys(self) -> bool:
        """Whether this runtime has scoped API keys (spec 322 or later).

        Read from the live metadata the client already holds, not from a probe:
        ``get_metadata_call_function`` answers ``None`` for a call the runtime
        does not define.
        """
        return (
            self.substrate.get_metadata_call_function(_AGENT_KEY_PALLET, _AGENT_KEY_CALL)
            is not None
        )

    def agent_key(self, key: bytes):
        """``BudgetsApi_agent_key(key)`` — who ``key`` acts for, and what it may do.

        Returns ``(principal_bytes, scope_bits)``, or ``None`` when this chain
        has no scoped keys at all or has them and says this key is not
        registered. Both of those are answers; a lookup that *failed* is not,
        and raises :class:`ChainError` rather than being reported as "no
        delegation" — a client that resolved Direct because a socket blinked
        would sign every later write as its own balance-less account and fail
        with a fee error that names nothing.

        The account decodes as an explicit ``[u8; 32]`` for the same reason
        :meth:`nodes` does — scalecodec misreads ``AccountId`` as an enum once
        full metadata is loaded.
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
        """Sign and submit any call, waiting for FINALIZATION.

        Resolution is by name against the live metadata, so this reaches every
        pallet the runtime exposes — including ones added by a forkless upgrade.

        Finalization, not inclusion: the committee authorizes a partial-decrypt
        against a finalized block, so resolving earlier gets an HTTP 403. That was
        a real bug in the TypeScript harness before it was fixed.

        With ``principal`` set the call is wrapped in ``proxy.proxy`` and runs as
        that member — the only way a member-tied API key can act, since its own
        account has neither authority nor a balance.
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
        # Read the nonce from System.Account directly: get_account_nonce() can
        # report 0 on this runtime, which signs a stale tx ("outdated", 1010).
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

        # `proxy.proxy` succeeds as an extrinsic even when the call it wrapped
        # failed, and `receipt.is_success` above cannot see that: substrate-
        # interface only special-cases System.ExtrinsicSuccess/ExtrinsicFailed.
        # Without this every delegated failure would read as a win.
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
        """The wrapped call's own error from ``Proxy.ProxyExecuted``, or ``None``.

        Resolved through the same ``get_module_error`` substrate-interface uses
        for ``ExtrinsicFailed``, so a delegated failure reads like a direct one.
        """
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


class PoolRejectedError(ChainError):
    """The node refused the extrinsic at validation, before any block.

    A balance-less key whose call the runtime will not admit is not sponsored at
    fee time, so it is refused here — which is why a revoked key reports
    "cannot pay fees" and never ``Proxy.NotProxy``. The two causes are
    indistinguishable from the message, so the client re-reads the grant rather
    than guessing.
    """


class OuterDispatchError(ChainError):
    """The ``proxy.proxy`` extrinsic itself failed, as opposed to the call it
    wrapped."""

    def __init__(
        self, message: str, *, pallet: str = "", call: str = "", module: str = "", name: str = ""
    ) -> None:
        super().__init__(message, pallet=pallet, call=call)
        self.module = module
        self.name = name


class DispatchError(ChainError):
    """A delegated call landed, but the call it wrapped was refused."""


#: Substrate's "Invalid Transaction" JSON-RPC error code.
_POOL_REJECTION_CODE = 1010

#: Markers for a pool rejection when the JSON-RPC code is unavailable. The same
#: list the Rust client uses, so the bindings agree on what one looks like.
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
