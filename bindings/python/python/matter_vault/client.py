"""The OpenMatter client: one key, every pallet.

Mirrors the Rust ``MatterClient`` — four named constructors, a generic
metadata-driven surface, plancks-only amounts, and a mainnet guard that checks
what the *endpoint* serves rather than what the caller configured.

Needs ``substrate-interface``: ``pip install matter-vault[sdk]``.
"""

import os
from typing import List, Optional

from .apikey import ApiKey
from .chain import ChainClient, ChainError, TxReceipt, api_key_signer
from .facade import (
    DeploymentsFacade,
    OrgsFacade,
    ResourcesFacade,
    SecretsFacade,
    StakingFacade,
)

__all__ = ["MatterClient", "ChainProperties", "Network", "TESTNET_RPC", "MAINNET_RPC"]

TESTNET_RPC = "wss://node2.testnet.openmatter.network"
MAINNET_RPC = "wss://node1.mainnet.openmatter.network"

#: Genesis hash of the public testnet, read with ``chain_getBlockHash(0)`` on
#: 2026-07-29. The only spoof-resistant network signal we have pinned.
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

    Both decimal counts are exposed on purpose, because they can disagree:
    ``token_decimals_declared`` comes from the node's chain-spec *file* and is
    presentational, while ``token_decimals_effective`` is derived from the live
    runtime's own ``Balances.ExistentialDeposit`` and is consensus-backed.
    matter-node changed ``UNIT`` from ``10**12`` to ``10**18`` with no storage
    migration, so a node serving a stale spec reports 18 while executing a
    12-decimal runtime.
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

    ``None`` when the constant is not a clean power of ten, meaning the runtime
    changed its ED policy — better to fall back than to report a confidently
    wrong exponent.
    """
    if ed <= 0:
        return None
    value, exponent = ed, 0
    while value > 1 and value % 10 == 0:
        value //= 10
        exponent += 1
    return exponent + _ED_DECIMAL_OFFSET if value == 1 else None


def parse_amount(text: str, decimals: int) -> int:
    """Parse a decimal token amount into plancks.

    Rejects more fractional digits than the chain supports rather than
    truncating — silent truncation is how people lose money. No floats at any
    step; a float cannot represent 18 decimal places.

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
    """A client for the OpenMatter chain and the MatterVault committee.

    Four named constructors, four distinct intents. There is deliberately no
    builder: a builder would let you set both an API key and a signer and defer
    "which wins?" to run time.

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

    # --- constructors -------------------------------------------------------

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
        """Connect with an OpenMatter API key — a key string or an :class:`ApiKey`.

        Extrinsics are signed through :class:`~matter_vault.chain.ApiKeySigner`, an
        adapter that is shaped like a ``substrate-interface`` keypair but delegates
        to the shared Rust core. That leaves exactly one derivation path, so the
        account this client reports and the account it signs as cannot diverge.
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

        With no key set this connects read-only rather than failing, so the same
        code path serves read-only tooling.
        """
        network = os.environ.get("MATTER_NETWORK", Network.TESTNET)
        if network not in (Network.TESTNET, Network.MAINNET):
            raise ValueError(
                f"MATTER_NETWORK must be 'testnet' or 'mainnet', got {network!r}"
            )
        rpc_url = os.environ.get("MATTER_RPC_URL")

        for var in ("MATTER_API_KEY", "MATTER_SIGNER_SEED"):
            value = os.environ.get(var)
            if value and value.strip():
                return cls.connect_with_api_key(value, network=network, rpc_url=rpc_url)
        return cls.connect(network=network, rpc_url=rpc_url)

    # --- identity and properties -------------------------------------------

    @property
    def properties(self) -> ChainProperties:
        return self._properties

    @property
    def chain(self) -> ChainClient:
        """The underlying chain client, for anything this surface does not cover.

        Exposed deliberately: a client that cannot be escaped from is a client
        that blocks work.
        """
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

    def signer(self):
        """A committee ``Signer`` for this identity, so one key both submits
        extrinsics and authorizes ``/partial-decrypt`` requests."""
        if self._api_key is not None:
            return self._api_key.signer()
        if self._keypair is not None:
            from .signer import substrate_signer

            def sign(payload: bytes) -> bytes:
                signature = self._keypair.sign(payload)
                return bytes.fromhex(signature[2:]) if isinstance(signature, str) else signature

            return substrate_signer(bytes(self._keypair.public_key), sign)
        raise ChainError("this client is read-only: connect with an api key or a keypair")

    # --- amounts ------------------------------------------------------------

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

    # --- the generic surface ------------------------------------------------

    def tx(self, pallet: str, call: str, params: dict) -> TxReceipt:
        """Sign and submit ``pallet.call(params)``, waiting for finalization."""
        return self._chain.submit(self._require_keypair(), pallet, call, params)

    def query(self, pallet: str, entry: str, keys: Optional[List] = None):
        """Read any storage entry. ``None`` means absent."""
        return self._chain.query(pallet, entry, keys)

    def runtime_api(self, method: str, args: bytes = b"", return_type: str = "Bytes"):
        """Call any runtime API by its ``state_call`` name."""
        return self._chain.runtime_api(method, args, return_type)

    def constant(self, pallet: str, name: str):
        """Read any pallet constant."""
        return self._chain.constant(pallet, name)

    # --- curated façades ----------------------------------------------------
    #
    # Properties rather than attributes, so adding a call touches only facade.py.
    # If a new façade call ever forces a change to ChainError or to this class,
    # the seam has leaked — treat that as a design bug, not a routine edit.

    @property
    def secrets(self) -> SecretsFacade:
        """Secrets: store, rotate, share, and delete MatterVault secrets."""
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

    # --- internals ----------------------------------------------------------

    def _require_keypair(self):
        if self._keypair is None:
            raise ChainError(
                "this client is read-only: connect with an api key or a keypair to submit"
            )
        return self._keypair

    @staticmethod
    def _resolve_url(network: str, rpc_url: Optional[str]) -> str:
        if rpc_url:
            return rpc_url
        default = Network.default_rpc_url(network)
        if default is None:
            raise ValueError(f"network {network!r} requires an explicit rpc_url")
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
            # Loud once, then trust the runtime. Quiet success, loud surprise.
            import sys

            print(
                f"WARNING: {properties.chain_name} reports tokenDecimals="
                f"{declared} in its chain spec but is executing a runtime whose "
                f"ExistentialDeposit implies {effective}. Using {effective} for "
                "all arithmetic.",
                file=sys.stderr,
            )
        return properties

    def _enforce_network_guards(self) -> None:
        """Two guards, both about not spending real money by accident.

        The checks are on what the *endpoint* actually serves, not on the
        configured network — pointing a testnet config at a mainnet URL must still
        trip, which is exactly the hole a config-flag check would leave open.
        """
        is_mainnet, detected_via = self._properties.is_mainnet()

        if self._network == Network.TESTNET and is_mainnet:
            raise ChainError(
                f"expected the testnet network but the endpoint serves "
                f"{self._properties.chain_name!r}"
            )

        # Read-only mainnet access needs no confirmation.
        if not is_mainnet or self._keypair is None:
            return

        confirmed = self._confirm_mainnet or os.environ.get(_CONFIRM_ENV) == _CONFIRM_VALUE
        if not confirmed:
            raise ChainError(
                f"refusing to build a signing client against mainnet "
                f"{self._properties.chain_name!r} (detected via {detected_via}) "
                f"without explicit confirmation: set {_CONFIRM_ENV}={_CONFIRM_VALUE} "
                "or pass confirm_mainnet=True. This client can spend real funds"
            )
