"""Per-interaction-group Read/Write permissions for member-tied API keys.

A member-tied API key is a delegate holding a ``ProxyType::Scoped(ScopeSet)``
proxy on the account of the member who minted it, and everything it does it does
as that member. The runtime maps every tenant-facing call to the set it requires
and admits the call iff the key's set covers it.

This is a wire contract, mirrored from matter-node's ``common/src/scopes.rs`` and
pinned across languages by ``testvectors/scope_bits.json`` and
``testvectors/required_scopes.json``. A ``ScopeSet`` is a bare ``u32`` whose bit
for ``(scope, access)`` is ``scope * 2 + access``. Both vocabularies are
append-only: a new group takes the next index and the next two bits, and nothing
already assigned ever moves.

Ported rather than reached through the FFI on purpose. A scope set is not
cryptography, so it does not belong behind ``matter-vault-ffi``; and the two
argument-sensitive rows below must read call arguments as Python values, before
anything is SCALE-encoded, which could not cross that boundary without shipping
the whole argument tree with them.
"""

from enum import IntEnum
from typing import Any, Mapping, Optional, Sequence

__all__ = ["Access", "Scope", "ScopeSet", "required_scopes"]


class Scope(IntEnum):
    """An interaction group a key may be permissioned for. Value = bit-pair index."""

    DEPLOYMENTS = 0
    COLLABORATIONS = 1
    SECRETS = 2
    VOLUMES = 3
    DATASETS = 4
    NETWORKING = 5
    RESOURCES = 6
    ORGANIZATION = 7
    BILLING = 8
    COMMUNITIES = 9


class Access(IntEnum):
    """The half of a scope a key is granted. Neither implies the other."""

    READ = 0
    WRITE = 1


#: Scope names, indexed by value. One table, so rendering and parsing cannot
#: disagree about a spelling.
_NAMES = (
    "deployments",
    "collaborations",
    "secrets",
    "volumes",
    "datasets",
    "networking",
    "resources",
    "organization",
    "billing",
    "communities",
)

#: How an empty set renders, and one of the two spellings that parse back to it.
_EMPTY_TEXT = "(none)"


def _bit(scope: Scope, access: Access) -> int:
    return 1 << (int(scope) * 2 + int(access))


class ScopeSet:
    """A set of ``(scope, access)`` grants, as a bare ``u32`` bitmask.

    Immutable and hashable: every combinator returns a new set, so a set handed
    to a client cannot be widened behind its back.
    """

    __slots__ = ("bits",)

    def __init__(self, bits: int = 0) -> None:
        if not 0 <= bits <= 0xFFFFFFFF:
            raise ValueError(f"a ScopeSet is a u32; got {bits}")
        object.__setattr__(self, "bits", bits)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ScopeSet is immutable")

    # --- constructors ------------------------------------------------------

    @classmethod
    def empty(cls) -> "ScopeSet":
        """No grants."""
        return cls(0)

    @classmethod
    def all(cls) -> "ScopeSet":
        """Every defined ``(scope, access)`` bit."""
        return cls((1 << (len(_NAMES) * 2)) - 1)

    @classmethod
    def from_bits(cls, bits: int) -> "ScopeSet":
        """A set from raw bits — the wire form. Validate with :meth:`is_valid`."""
        return cls(bits)

    @classmethod
    def single(cls, scope: Scope, access: Access) -> "ScopeSet":
        """The set holding exactly ``(scope, access)``."""
        return cls(_bit(scope, access))

    @classmethod
    def covering(cls, scopes: Sequence[Scope]) -> "ScopeSet":
        """Both halves of every listed scope."""
        bits = 0
        for scope in scopes:
            bits |= _bit(scope, Access.READ) | _bit(scope, Access.WRITE)
        return cls(bits)

    # --- combinators -------------------------------------------------------

    def with_(self, scope: Scope, access: Access) -> "ScopeSet":
        """``self`` plus ``(scope, access)``."""
        return ScopeSet(self.bits | _bit(scope, access))

    def union(self, other: "ScopeSet") -> "ScopeSet":
        """``self ∪ other``."""
        return ScopeSet(self.bits | other.bits)

    def contains(self, scope: Scope, access: Access) -> bool:
        """Whether ``(scope, access)`` is granted."""
        return self.bits & _bit(scope, access) != 0

    def is_superset(self, other: "ScopeSet") -> bool:
        """Whether every grant in ``other`` is also here (``self ⊇ other``)."""
        return self.bits & other.bits == other.bits

    def is_subset(self, other: "ScopeSet") -> bool:
        """Whether every grant here is also in ``other`` (``self ⊆ other``)."""
        return other.is_superset(self)

    def is_empty(self) -> bool:
        """Whether the set grants nothing."""
        return self.bits == 0

    def is_valid(self) -> bool:
        """Whether every set bit names a defined ``(scope, access)``."""
        return self.bits & ~ScopeSet.all().bits == 0

    # --- text --------------------------------------------------------------

    def __str__(self) -> str:
        """``deployments:rw, secrets:r``, in index order; ``(none)`` when empty."""
        if self.is_empty():
            return _EMPTY_TEXT
        parts = []
        for index, name in enumerate(_NAMES):
            scope = Scope(index)
            r = self.contains(scope, Access.READ)
            w = self.contains(scope, Access.WRITE)
            if not r and not w:
                continue
            parts.append(f"{name}:{'r' if r else ''}{'w' if w else ''}")
        return ", ".join(parts)

    def __repr__(self) -> str:
        return f"ScopeSet({self})"

    @classmethod
    def parse(cls, text: str) -> "ScopeSet":
        """Parse ``deployments:rw, secrets:r``.

        Case-insensitive; entries may be separated by commas, whitespace, or
        both. An empty string and ``(none)`` both yield an empty set, so
        ``str()`` round-trips.
        """
        trimmed = text.strip()
        if trimmed == "" or trimmed.lower() == _EMPTY_TEXT:
            return cls.empty()

        result = cls.empty()
        for entry in trimmed.replace(",", " ").split():
            name, sep, access = entry.partition(":")
            if not sep:
                raise ValueError(f"scope entry {entry!r} is missing its :r, :w or :rw suffix")
            name = name.lower()
            if name not in _NAMES:
                raise ValueError(f"unknown scope {name!r}")

            read = write = False
            for char in access.lower():
                # A repeated letter means the caller's generator is confused;
                # folding it silently would hide that.
                if char == "r" and not read:
                    read = True
                elif char == "w" and not write:
                    write = True
                else:
                    raise ValueError(
                        f"scope {name!r} has invalid access {access!r}: expected r, w, or rw"
                    )
            if not read and not write:
                raise ValueError(
                    f"scope {name!r} has invalid access {access!r}: expected r, w, or rw"
                )

            scope = Scope(_NAMES.index(name))
            if read:
                result = result.with_(scope, Access.READ)
            if write:
                result = result.with_(scope, Access.WRITE)
        return result

    # --- value semantics ---------------------------------------------------

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, ScopeSet) and other.bits == self.bits

    def __hash__(self) -> int:
        return hash(self.bits)


def _write(scope: Scope) -> ScopeSet:
    return ScopeSet.single(scope, Access.WRITE)


#: Shipping a secret into a container the key controls is a read of it.
_DEPLOY_WITH_SECRET = _write(Scope.DEPLOYMENTS).with_(Scope.SECRETS, Access.READ)

# `report_consumption`, `report_capacity`, `request_consumption_report` are
# provider-signed; the SKU and stake setters are root.
_RESOURCES_WRITE = frozenset(
    {
        "register_resource",
        "register_private_resource",
        "register_org_resource",
        "reactivate_resource",
        "set_resource_privacy",
        "add_to_whitelist",
        "remove_from_whitelist",
        "update_resource_name",
        "remove_resource",
    }
)

# `create_org` / `delete_org` stay human-signed.
_ORGANIZATION_WRITE = frozenset(
    {
        "add_member",
        "set_member_role",
        "remove_member",
        "create_project",
        "assign_to_project",
        "unassign_from_project",
        "delete_project",
        "add_project_deployment_peer",
    }
)

# Everything else in budgets — the roster calls, so a key never mints authority,
# and the treasury value movers.
_BILLING_WRITE = frozenset(
    {
        "allot",
        "defund_project",
        "set_plan_allotment",
        "add_purchased_allotment",
        "set_purchased_allotment",
        "set_member_billing",
        "clear_member_billing",
        "set_member_gas_limit",
    }
)

_DEPLOYMENTS_WRITE = frozenset(
    {
        "cancel_deployment",
        "set_deployment_env",
        "set_deployment_image",
        "set_deployment_launch",
        "set_deployment_policy_root",
    }
)


def required_scopes(
    pallet: str, call: str, params: Optional[Mapping[str, Any]] = None
) -> Optional[ScopeSet]:
    """What ``pallet.call(params)`` requires of a delegated key.

    ``None`` means no set admits it at all — provider-signed, root-only, org
    lifecycle, the roster calls, and every treasury value mover.

    **This check is a courtesy, not a boundary.** The runtime's own filter is the
    only real enforcer. It exists so a caller reads "your key lacks volumes:w"
    instead of the pool rejection a balance-less delegated key actually gets,
    which complains about fees and names neither the call nor the scope. It
    follows that being wrong in the *safe* direction — demanding more than the
    chain would — costs a caller a local rejection they can work around, while
    the opposite would let through a call the chain then refuses. So where an
    argument cannot be read, the wider set is required.
    """
    params = params or {}

    if pallet == "Jobs":
        if call == "request_deployment":
            return (
                _DEPLOY_WITH_SECRET
                if _request_references_secret(params.get("request"), "request" in params)
                else _write(Scope.DEPLOYMENTS)
            )
        if call == "set_deployment_secret_ref":
            # Presence before value: an argument that is absent is one this
            # client cannot read, which takes the wider set, while one passed
            # explicitly as ``None`` is a real ``Option::None`` and takes the
            # narrow one. Conflating the two breaks the fail-safe direction.
            if "secret_ref" in params and _is_none(params["secret_ref"]):
                return _write(Scope.DEPLOYMENTS)
            return _DEPLOY_WITH_SECRET
        if call in _DEPLOYMENTS_WRITE:
            return _write(Scope.DEPLOYMENTS)
        if call in ("register_wg_peer", "remove_wg_peer"):
            return _write(Scope.NETWORKING)
        # update_deployment_status, set_deployment_network, report_tls_status:
        # provider-signed.
        return None

    if pallet == "Collaborations":
        # Every call but the two root-only setters, cranks included.
        if call in ("set_compute_node_image", "set_compute_node_sku_id"):
            return None
        return _write(Scope.COLLABORATIONS)

    if pallet == "Secrets":
        return _write(Scope.SECRETS)
    if pallet == "Volumes":
        return _write(Scope.VOLUMES)
    if pallet == "OverlayNetworks":
        return _write(Scope.NETWORKING)
    if pallet == "Datasets":
        return None if call.startswith("force_") else _write(Scope.DATASETS)
    if pallet == "Communities":
        return None if call.startswith("force_") else _write(Scope.COMMUNITIES)
    if pallet == "Resources":
        return _write(Scope.RESOURCES) if call in _RESOURCES_WRITE else None
    if pallet == "Organizations":
        return _write(Scope.ORGANIZATION) if call in _ORGANIZATION_WRITE else None
    if pallet == "Budgets":
        return _write(Scope.BILLING) if call in _BILLING_WRITE else None
    return None


def _is_none(value: Any) -> bool:
    """Whether ``value`` is definitely an absent ``Option``.

    ``substrate-interface`` accepts both ``None`` and ``{"None": None}`` for one.
    Anything else — including a value this cannot read — counts as present, which
    is the wider requirement.
    """
    if value is None:
        return True
    return isinstance(value, Mapping) and set(value) == {"None"}


def _request_references_secret(request: Any, present: bool) -> bool:
    """Whether a ``ResourceRequest`` sets either secret reference.

    The request is whatever the caller passed — the deployments façade
    deliberately does not mirror its shape — so this reads the fields by name and
    gives up safely. Anything unreadable, the argument being absent included, is
    treated as referencing a secret.
    """
    if not present or not isinstance(request, Mapping):
        return True
    for name in ("secret_ref", "tls_secret_ref"):
        # A request without the field is one this client cannot reason about.
        if name not in request:
            return True
        if not _is_none(request[name]):
            return True
    return False
