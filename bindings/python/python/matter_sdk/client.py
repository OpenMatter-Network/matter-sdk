"""The OpenMatter client: one key, every pallet (needs the ``[sdk]`` extra).

Mirrors the Rust ``MatterClient``: four named constructors, a metadata-driven
generic surface, plancks-only amounts, and a mainnet guard on what the endpoint
serves rather than what was configured.
"""

import logging
import os
from typing import List, Optional

from substrateinterface.utils.ss58 import ss58_decode, ss58_encode

from .apikey import ApiKey
from .errors import (
    ChainError,
    ConfigError,
    OuterDispatchError,
    PoolRejectedError,
    KeyRevokedError,
    MainnetNotConfirmedError,
    NeverAdmittedError,
    NotPermittedError,
    ReadOnlyError,
    UnsponsoredError,
    WrongNetworkError,
)
from .chain import (
    ChainClient,
    TxReceipt,
    api_key_signer,
)
from .facade import (
    DeploymentsFacade,
    KeysFacade,
    OrgsFacade,
    ResourcesFacade,
    SecretsFacade,
    StakingFacade,
)
from .scopes import ScopeSet, required_scopes

__all__ = [
    "MatterClient",
    "ChainProperties",
    "Network",
    "KeyRevokedError",
    "NeverAdmittedError",
    "NotPermittedError",
    "UnsponsoredError",
    "TESTNET_RPC",
    "MAINNET_RPC",
]


#: Diagnostics; silent unless the application configures logging.
_log = logging.getLogger("matter_sdk.client")

#: Outcomes of re-reading the chain's grant.
_REFRESH_UNCHANGED = "unchanged"
_REFRESH_RESCOPED = "rescoped"
_REFRESH_GONE = "gone"
#: The lookup itself failed, so nothing new is known.
_REFRESH_UNKNOWN = "unknown"

#: pallet-proxy's complaint that no definition matches this (key, member) pair.
_NOT_PROXY_ERROR = "NotProxy"


def _after_refresh(previous, fresh) -> str:
    """Classify a fresh grant against the held one as unchanged, rescoped, or gone."""
    if previous is None:
        return _REFRESH_UNCHANGED
    principal, scopes = previous
    if fresh is None or fresh[0] != principal:
        return _REFRESH_GONE
    if fresh[1] != scopes.bits:
        return _REFRESH_RESCOPED
    return _REFRESH_UNCHANGED


def _decode_account(text: str) -> bytes:
    """``MATTER_PRINCIPAL`` as raw account bytes: ``0x``-hex or SS58."""
    text = text.strip()
    try:
        if text.startswith("0x"):
            raw = bytes.fromhex(text[2:])
            if len(raw) != 32:
                raise ValueError("expected 32 bytes")
            return raw
        return bytes.fromhex(ss58_decode(text))
    except Exception as exc:
        raise ValueError(
            "MATTER_PRINCIPAL is neither 0x-prefixed hex nor a valid SS58 address"
        ) from exc

#: Default RPC endpoint per network. Pinned for every binding by ``testvectors/networks.json``.
TESTNET_RPC = "wss://node2.testnet.openmatter.network"
MAINNET_RPC = "wss://node2.mainnet.openmatter.network"

#: Genesis hash of the public testnet (``chain_getBlockHash(0)``): the only
#: spoof-resistant network signal pinned.
TESTNET_GENESIS = "0xd87ca10ad40194ff37525c0b5fc5997d94010107a399d03bf5672c0a7b30f058"

#: Fallback network signal while the mainnet genesis hash is unpinned: mainnet
#: mints ``MTR``, testnet ``MTR-Test``.
MAINNET_TOKEN_SYMBOL = "MTR"

_CONFIRM_ENV = "MATTER_CONFIRM"
_CONFIRM_VALUE = "yes"

#: ``Balances.ExistentialDeposit`` is ``UNIT / 1000``, i.e. ``10 ** (decimals - 3)``.
_ED_DECIMAL_OFFSET = 3


class Network:
    """Network names. A plain namespace rather than an ``Enum`` so the values are
    the same strings ``MATTER_NETWORK`` takes."""

    TESTNET = "testnet"
    MAINNET = "mainnet"
    CUSTOM = "custom"

    @staticmethod
    def default_rpc_url(network: str) -> Optional[str]:
        return {Network.TESTNET: TESTNET_RPC, Network.MAINNET: MAINNET_RPC}.get(network)


class ChainProperties:
    """Chain identity and unit metadata, read once at connect.

    ``token_decimals_declared`` comes from the node's chain-spec file and is
    presentational; ``token_decimals_effective`` is derived from the runtime's
    ``Balances.ExistentialDeposit`` and is what all arithmetic uses. They disagree
    when a node serves a stale chain spec.
    """

    __slots__ = (
        "genesis_hash",
        "chain_name",
        "spec_version",
        "token_symbol",
        "ss58_prefix",
        "token_decimals_declared",
        "token_decimals_effective",
        "existential_deposit",
    )
    genesis_hash: str
    chain_name: str
    spec_version: int
    token_symbol: str
    ss58_prefix: int
    token_decimals_declared: int
    token_decimals_effective: int
    existential_deposit: int

    def __init__(self, **kwargs) -> None:
        for name in self.__slots__:
            setattr(self, name, kwargs[name])

    @property
    def decimals_disagree(self) -> bool:
        """Whether the node's chain spec disagrees with the runtime it executes."""
        return self.token_decimals_declared != self.token_decimals_effective

    def is_mainnet(self):
        """``(is_mainnet, detected_via)``. Genesis hash wins where it is pinned."""
        if self.genesis_hash == TESTNET_GENESIS:
            return False, "genesis-hash"
        return self.token_symbol == MAINNET_TOKEN_SYMBOL, "token-symbol"

    def __repr__(self) -> str:
        return (
            f"ChainProperties({self.chain_name!r}, spec={self.spec_version}, "
            f"token={self.token_symbol!r}, decimals={self.token_decimals_effective})"
        )


def _decimals_from_existential_deposit(ed: int) -> Optional[int]:
    """Recover the decimal count from ``ED == 10 ** (d - 3)``.

    ``None`` when ED is not a clean power of ten, rather than guess.
    """
    if ed <= 0:
        return None
    value, exponent = ed, 0
    while value > 1 and value % 10 == 0:
        value //= 10
        exponent += 1
    return exponent + _ED_DECIMAL_OFFSET if value == 1 else None


def parse_amount(text: str, decimals: int) -> int:
    """Parse a decimal token amount into plancks, without floats.

    Raises ``ValueError`` on more fractional digits than ``decimals`` rather than
    truncating.

    >>> parse_amount("1.5", 12)
    1500000000000
    >>> parse_amount("0.0001", 3)
    Traceback (most recent call last):
    ValueError: amount has more fractional digits than this chain's decimals
    """
    body = text.strip()
    if body.startswith("+"):
        body = body[1:]
    if not body:
        raise ValueError("amount is empty")
    if body.startswith("-"):
        raise ValueError("amount must not be negative")

    whole, _, fraction = body.partition(".")
    if not whole.isdigit() or ("." in body and not fraction.isdigit()):
        raise ValueError("amount must be decimal digits with at most one point")
    if len(fraction) > decimals:
        raise ValueError("amount has more fractional digits than this chain's decimals")
    return int(whole + fraction.ljust(decimals, "0") or "0")


def format_amount(plancks: int, decimals: int) -> str:
    """Render plancks as a decimal string with no trailing zeros. Lossless.

    >>> format_amount(1500000000000, 12)
    '1.5'
    >>> format_amount(1, 12)
    '0.000000000001'
    """
    if decimals == 0:
        return str(plancks)
    digits = str(plancks).rjust(decimals + 1, "0")
    whole, fraction = digits[:-decimals], digits[-decimals:]
    fraction = fraction.rstrip("0")
    return f"{whole}.{fraction}" if fraction else whole


class MatterClient:
    """A client for the OpenMatter chain and the matter-kgc committee.

    Four named constructors, one per intent. No builder, so there is never a
    question of which credential wins.

    >>> client = MatterClient.from_env()                      # doctest: +SKIP
    >>> client.query("System", "Account", [client.address])   # doctest: +SKIP
    """

    def __init__(
        self,
        chain: ChainClient,
        properties: ChainProperties,
        *,
        api_key: Optional[ApiKey] = None,
        keypair=None,
        confirm_mainnet: bool = False,
        network: str = Network.TESTNET,
    ) -> None:
        # Private: use the connect_* constructors, which enforce the guards.
        self._chain = chain
        self._properties = properties
        self._api_key = api_key
        self._keypair = keypair
        self._confirm_mainnet = confirm_mainnet
        self._network = network
        self._enforce_network_guards()
        # Guards first, so a refused client costs no round trip.
        self._mode = self._resolve_mode()

    @classmethod
    def connect(
        cls,
        *,
        network: str = Network.TESTNET,
        rpc_url: Optional[str] = None,
    ) -> "MatterClient":
        """Connect read-only. Queries work; submitting raises."""
        chain = ChainClient(cls._resolve_url(network, rpc_url))
        return cls(chain, cls._read_properties(chain), network=network)

    @classmethod
    def connect_with_api_key(
        cls,
        key,
        *,
        network: str = Network.TESTNET,
        rpc_url: Optional[str] = None,
        confirm_mainnet: bool = False,
    ) -> "MatterClient":
        """Connect with an API key string or :class:`ApiKey`.

        Signing goes through :class:`~matter_sdk.chain.ApiKeySigner`, so the
        reported and signing accounts come from one derivation.
        """
        api_key = key if isinstance(key, ApiKey) else ApiKey(key)
        chain = ChainClient(cls._resolve_url(network, rpc_url))
        return cls(
            chain,
            cls._read_properties(chain),
            api_key=api_key,
            keypair=api_key_signer(api_key),
            confirm_mainnet=confirm_mainnet,
            network=network,
        )

    @classmethod
    def connect_with_keypair(
        cls,
        keypair,
        *,
        network: str = Network.TESTNET,
        rpc_url: Optional[str] = None,
        confirm_mainnet: bool = False,
    ) -> "MatterClient":
        """Connect with a ``substrate-interface`` keypair you built yourself — from
        a keystore, an unwrapped KMS blob, or your own derivation."""
        chain = ChainClient(cls._resolve_url(network, rpc_url))
        return cls(
            chain,
            cls._read_properties(chain),
            keypair=keypair,
            confirm_mainnet=confirm_mainnet,
            network=network,
        )

    @classmethod
    def from_env(cls) -> "MatterClient":
        """Connect from ``MATTER_API_KEY`` (falling back to ``MATTER_SIGNER_SEED``),
        ``MATTER_RPC_URL``, ``MATTER_NETWORK``, and ``MATTER_CONFIRM``.

        With no key set this connects read-only rather than failing.
        """
        network = os.environ.get("MATTER_NETWORK", Network.TESTNET)
        if network not in (Network.TESTNET, Network.MAINNET):
            raise ConfigError(
                f"MATTER_NETWORK must be 'testnet' or 'mainnet', got {network!r}"
            )
        rpc_url = os.environ.get("MATTER_RPC_URL")

        for var in ("MATTER_API_KEY", "MATTER_SIGNER_SEED"):
            value = os.environ.get(var)
            if value and value.strip():
                return cls.connect_with_api_key(value, network=network, rpc_url=rpc_url)
        return cls.connect(network=network, rpc_url=rpc_url)

    @property
    def properties(self) -> ChainProperties:
        return self._properties

    @property
    def chain(self) -> ChainClient:
        """The underlying chain client, for anything this surface does not cover."""
        return self._chain

    @property
    def account_id(self) -> Optional[bytes]:
        """The signing identity's 32-byte account id, or ``None`` if read-only."""
        if self._api_key is not None:
            return self._api_key.account_id
        if self._keypair is not None:
            return bytes(self._keypair.public_key)
        return None

    @property
    def address(self) -> Optional[str]:
        """The signing identity's SS58 address, or ``None`` if read-only."""
        return None if self._keypair is None else self._keypair.ss58_address

    @property
    def principal_address(self) -> Optional[str]:
        """The member this client acts for, as SS58; ``None`` when it acts as itself."""
        principal = self.principal
        if principal is None:
            return None
        return ss58_encode(principal, self._properties.ss58_prefix)

    def signer(self):
        """This identity as a committee ``Signer``; raises :class:`ReadOnlyError`
        without one."""
        if self._api_key is not None:
            return self._api_key.signer()
        if self._keypair is not None:
            from .signer import substrate_signer

            def sign(payload: bytes) -> bytes:
                signature = self._keypair.sign(payload)
                return bytes.fromhex(signature[2:]) if isinstance(signature, str) else signature

            return substrate_signer(bytes(self._keypair.public_key), sign)
        raise ReadOnlyError("this client is read-only: connect with an api key or a keypair")

    def parse_amount(self, text: str) -> int:
        """Parse a decimal token amount into plancks, at this chain's effective
        decimals."""
        return parse_amount(text, self._properties.token_decimals_effective)

    def format_amount(self, plancks: int) -> str:
        """Render plancks as a decimal string, at this chain's effective decimals."""
        return format_amount(plancks, self._properties.token_decimals_effective)

    def one_token(self) -> int:
        """One whole token in plancks, on this chain."""
        return 10 ** self._properties.token_decimals_effective

    def tx(self, pallet: str, call: str, params: dict) -> TxReceipt:
        """Sign and submit any call, waiting for finalization.

        Under a member-tied API key the call is wrapped in ``proxy.proxy`` and
        runs as the key's principal; otherwise it is submitted directly.
        """
        self._refuse_if_out_of_scope(pallet, call, params)
        try:
            return self._chain.submit(
                self._require_keypair(), pallet, call, params, principal=self.principal
            )
        except PoolRejectedError as exc:
            raise self._explain_pool_rejection(pallet, call, params, exc) from exc
        except OuterDispatchError as exc:
            raise self._explain_outer_dispatch(pallet, call, exc) from exc

    def _explain_pool_rejection(self, pallet, call, params, exc):
        """Explain a delegated pool rejection (revoked, re-scoped, or unsponsored)
        by re-reading the grant rather than guessing from the message."""
        if not self.is_delegated:
            return exc
        outcome = self._refresh_delegation()
        if outcome == _REFRESH_GONE:
            return KeyRevokedError(
                f"this key's proxy is gone or now points at a different member, so "
                f"{pallet}.{call} was refused; mint a new key or have the member "
                f"re-authorize this one",
                pallet=pallet,
                call=call,
            )
        if outcome == _REFRESH_RESCOPED:
            # Name the missing scope if the call is now out of scope.
            try:
                self._refuse_if_out_of_scope(pallet, call, params)
            except NotPermittedError as rescoped:
                return rescoped
        if outcome == _REFRESH_UNKNOWN:
            return exc
        return UnsponsoredError(
            f"{pallet}.{call} is within this key's scopes, but nobody would pay for it: "
            f"{self.principal_address} and their billing org must cover the fee",
            pallet=pallet,
            call=call,
        )

    def _explain_outer_dispatch(self, pallet, call, exc):
        """Report ``Proxy.NotProxy`` as a revoked key once the chain confirms it."""
        if not self.is_delegated or exc.name != _NOT_PROXY_ERROR:
            return exc
        if self._refresh_delegation() == _REFRESH_GONE:
            return KeyRevokedError(
                f"this key's proxy is gone or now points at a different member, so "
                f"{pallet}.{call} was refused; mint a new key or have the member "
                f"re-authorize this one",
                pallet=pallet,
                call=call,
            )
        return exc

    def _refresh_delegation(self) -> str:
        """Re-read the chain's grant, updating the cached scopes if they moved.

        A gone grant leaves this client delegated, so a revoked key keeps
        reporting as revoked rather than failing on fees as a direct signer.
        """
        account = self.account_id
        if self._mode is None or account is None:
            return _REFRESH_UNCHANGED
        try:
            fresh = self._chain.agent_key(account)
        except ChainError:
            return _REFRESH_UNKNOWN
        outcome = _after_refresh(self._mode, fresh)
        if outcome == _REFRESH_RESCOPED:
            self._mode = (self._mode[0], ScopeSet.from_bits(fresh[1]))
        return outcome

    def _resolve_mode(self):
        """Ask the chain who this client's key acts for.

        ``MATTER_PRINCIPAL`` overrides the lookup, for a key whose pointer is stale
        while its proxy stands. Scopes are then unknown, so the full set is assumed:
        local checking is off and the runtime alone enforces (logged as a warning).
        """
        account = self.account_id
        if account is None:
            return None

        override = os.environ.get("MATTER_PRINCIPAL", "").strip()
        if override:
            _log.warning(
                "MATTER_PRINCIPAL is set, so this client acts for %s "
                "without asking the chain. Local scope checking is disabled; the "
                "runtime still enforces.",
                override,
            )
            return (_decode_account(override), ScopeSet.all())

        resolved = self._chain.agent_key(account)
        if resolved is None:
            return None
        principal, bits = resolved
        scopes = ScopeSet.from_bits(bits)
        _log.info(
            "acting for %s with scopes %s",
            ss58_encode(principal, self._properties.ss58_prefix),
            scopes,
        )
        return (principal, scopes)

    @property
    def is_delegated(self) -> bool:
        """Whether this client's key acts for a member rather than for itself."""
        return self._mode is not None

    @property
    def principal(self) -> Optional[bytes]:
        """The member this client acts for, or ``None`` when it acts as itself."""
        return None if self._mode is None else self._mode[0]

    @property
    def scopes(self):
        """What this client's key may do, or ``None`` when the chain grants it no
        scoped proxy."""
        return None if self._mode is None else self._mode[1]

    def _refuse_if_out_of_scope(self, pallet: str, call: str, params: dict) -> None:
        """Refuse, before submitting, a call this client's key cannot make.

        A courtesy, not a boundary: the runtime enforces, but its refusal of a
        balance-less delegated key is a fee error naming neither call nor scope.
        """
        if self._mode is None:
            return
        target = f"{pallet}.{call}"

        # Never admitted inside a proxy: nesting would let a key launder authority.
        if pallet in ("Proxy", "Utility", "EthSigning"):
            raise NeverAdmittedError(
                f"{target} is never admitted to an api key; sign it with the "
                "member's own key",
                pallet=pallet,
                call=call,
            )

        required = required_scopes(pallet, call, params)
        if required is None:
            raise NeverAdmittedError(
                f"{target} is never admitted to an api key; sign it with the "
                "member's own key",
                pallet=pallet,
                call=call,
            )
        held = self._mode[1]
        if not held.is_superset(required):
            raise NotPermittedError(
                f"key lacks {required} for {target}; it holds {held}",
                pallet=pallet,
                call=call,
            )

    def query(self, pallet: str, entry: str, keys: Optional[List] = None):
        """Read any storage entry. ``None`` means absent."""
        return self._chain.query(pallet, entry, keys)

    def runtime_api(self, method: str, args: bytes = b"", return_type: str = "Bytes"):
        """Call any runtime API by its ``state_call`` name."""
        return self._chain.runtime_api(method, args, return_type)

    def constant(self, pallet: str, name: str):
        """Read any pallet constant."""
        return self._chain.constant(pallet, name)

    # Façades are properties so adding a call touches only facade.py.

    @property
    def secrets(self) -> SecretsFacade:
        """Secrets: store, rotate, share, and delete secrets."""
        return SecretsFacade(self)

    @property
    def deployments(self) -> DeploymentsFacade:
        """Deployments (``pallet-jobs``): request compute, wire networking, bind secrets."""
        return DeploymentsFacade(self)

    @property
    def resources(self) -> ResourcesFacade:
        """Resources: register capacity, price it, control who may use it."""
        return ResourcesFacade(self)

    @property
    def staking(self) -> StakingFacade:
        """Staking on MatterChain, including nomination pools."""
        return StakingFacade(self)

    @property
    def keys(self) -> KeysFacade:
        """Minting and revoking member-tied API keys. Member-signed: the runtime
        never admits these to a key, so a key cannot widen its own authority."""
        return KeysFacade(self)

    @property
    def orgs(self) -> OrgsFacade:
        """Organizations and budgets."""
        return OrgsFacade(self)

    def close(self) -> None:
        self._chain.close()

    def __enter__(self) -> "MatterClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        who = self.address or "read-only"
        return f"MatterClient({self._properties.chain_name!r}, {who})"

    def _require_keypair(self):
        if self._keypair is None:
            raise ReadOnlyError(
                "this client is read-only: connect with an api key or a keypair to submit"
            )
        return self._keypair

    @staticmethod
    def _resolve_url(network: str, rpc_url: Optional[str]) -> str:
        if rpc_url:
            return rpc_url
        default = Network.default_rpc_url(network)
        if default is None:
            raise ConfigError(f"network {network!r} requires an explicit rpc_url")
        return default

    @staticmethod
    def _read_properties(chain: ChainClient) -> ChainProperties:
        substrate = chain.substrate
        props = substrate.rpc_request("system_properties", [])["result"]
        chain_name = substrate.rpc_request("system_chain", [])["result"]
        genesis = substrate.get_block_hash(0)

        existential_deposit = int(chain.constant("Balances", "ExistentialDeposit"))
        declared = int(props.get("tokenDecimals", 0) or 0)
        effective = _decimals_from_existential_deposit(existential_deposit) or declared

        properties = ChainProperties(
            genesis_hash=genesis,
            chain_name=chain_name,
            spec_version=int(substrate.runtime_version),
            token_symbol=props.get("tokenSymbol", "") or "",
            ss58_prefix=int(props.get("ss58Format", 42) or 42),
            token_decimals_declared=declared,
            token_decimals_effective=effective,
            existential_deposit=existential_deposit,
        )

        if properties.decimals_disagree:
            _log.warning(
                "%s reports tokenDecimals=%d in its chain spec but is executing a "
                "runtime whose ExistentialDeposit implies %d. Using %d for all "
                "arithmetic.",
                properties.chain_name,
                declared,
                effective,
                effective,
            )
        return properties

    def _enforce_network_guards(self) -> None:
        """Refuse a testnet config on a mainnet endpoint, and a signing client on
        mainnet without confirmation.

        Checks what the endpoint serves, not the configured network, so a testnet
        config pointed at a mainnet URL still trips.
        """
        is_mainnet, detected_via = self._properties.is_mainnet()

        if self._network == Network.TESTNET and is_mainnet:
            raise WrongNetworkError(
                f"expected the testnet network but the endpoint serves "
                f"{self._properties.chain_name!r}"
            )

        # Read-only mainnet access needs no confirmation.
        if not is_mainnet or self._keypair is None:
            return

        confirmed = self._confirm_mainnet or os.environ.get(_CONFIRM_ENV) == _CONFIRM_VALUE
        if not confirmed:
            raise MainnetNotConfirmedError(
                f"refusing to build a signing client against mainnet "
                f"{self._properties.chain_name!r} (detected via {detected_via}) "
                f"without explicit confirmation: set {_CONFIRM_ENV}={_CONFIRM_VALUE} "
                "or pass confirm_mainnet=True. This client can spend real funds"
            )
