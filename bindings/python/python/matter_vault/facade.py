"""Curated typed façades over the generic surface.

Every method here is a thin, named wrapper around :meth:`MatterClient.tx` — it
shapes typed arguments into ``call_params`` and delegates. No encoding, no error
handling, no chain access of its own. That is deliberate: composing the extrinsic
lives in exactly one place, so a façade can be wrong about a *name* but never
about the wire format.

The generic surface already reaches every pallet, including ones added by a
future forkless upgrade. These exist for the domains callers reach for daily.
Anything not here is one ``client.tx(...)`` away — a façade is a convenience, not
a gate.

Names resolve at call time from live metadata, so a rename in an upgrade surfaces
as a :class:`~matter_vault.chain.ChainError` at the call rather than silently. The
surface itself is pinned by ``testvectors/facade_calls.json`` and replayed by
``tests/test_facade.py``, checked both ways: a fixture row without a method fails,
and a method without a row fails.

``substrate-interface`` takes call arguments as a dict keyed by the runtime's own
argument names, so the ``call_params`` below use those names verbatim — they are
the same names the fixture pins.
"""

from typing import Any, Dict, List, Optional

__all__ = [
    "SecretsFacade",
    "DeploymentsFacade",
    "ResourcesFacade",
    "StakingFacade",
    "OrgsFacade",
]


class _Facade:
    """Common base: holds the client and forwards a named call."""

    __slots__ = ("_client",)

    def __init__(self, client) -> None:
        self._client = client

    def _tx(self, pallet: str, call: str, params: Dict[str, Any]):
        return self._client.tx(pallet, call, params)


class SecretsFacade(_Facade):
    """Secrets: store, rotate, share, and delete MatterVault secrets."""

    def store(self, payload, epoch: int, label, aad):
        """Publish a sealed envelope.

        ``payload`` is the ``(binding_id, capsule, proof, ct)`` tuple ``encrypt``
        returns. The chain-assigned id is in the ``Secrets.SecretStored`` event on
        the returned receipt.
        """
        from .calls import store_secret

        return self._tx("Secrets", "store_secret", store_secret(payload, epoch, label, aad))

    def rotate(self, secret_id: int, payload, epoch: int, aad):
        """Re-seal an existing secret in place under the current epoch."""
        from .calls import rotate_secret

        return self._tx(
            "Secrets", "rotate_secret", rotate_secret(secret_id, payload, epoch, aad)
        )

    def grant(self, secret_id: int, target: dict):
        """Authorize a principal to request decryption.

        ``target`` comes from :func:`~matter_vault.calls.grant_to_user` or
        :func:`~matter_vault.calls.grant_to_deployment` — the chain's
        ``GrantTarget`` is an enum, not a bare account id.
        """
        from .calls import grant_access

        return self._tx("Secrets", "grant_access", grant_access(secret_id, target))

    def revoke(self, secret_id: int, target: dict):
        """Withdraw a grant.

        The target must match the grant exactly, or this is a no-op on chain.
        """
        from .calls import revoke_access

        return self._tx("Secrets", "revoke_access", revoke_access(secret_id, target))

    def delete(self, secret_id: int):
        """Delete a secret and every grant on it. Owner only, and irreversible."""
        from .calls import delete_secret

        return self._tx("Secrets", "delete_secret", delete_secret(secret_id))


class DeploymentsFacade(_Facade):
    """Deployments (``pallet-jobs``): request compute, wire networking, bind secrets."""

    def request(self, request: Any):
        """Request a deployment.

        ``request`` is the runtime's ``ResourceRequest``, which is large and
        evolving, so it is passed through rather than mirrored here — mirroring it
        would be a second source of truth that rots.
        """
        return self._tx("Jobs", "request_deployment", {"request": request})

    def cancel(self, deployment: int):
        """Cancel a deployment."""
        return self._tx("Jobs", "cancel_deployment", {"deployment": int(deployment)})

    def set_secret_ref(self, deployment: int, secret_ref: Optional[int]):
        """Point a deployment at a MatterVault secret, or clear it with ``None``.

        The bridge between a deployment and a sealed secret: the assigned resource
        is authorized to decrypt whatever ``secret_ref`` names.
        """
        return self._tx(
            "Jobs",
            "set_deployment_secret_ref",
            {
                "deployment": int(deployment),
                "secret_ref": None if secret_ref is None else int(secret_ref),
            },
        )

    def set_env(self, deployment: int, env_vars: Optional[Any]):
        """Set or clear a deployment's **plaintext** environment variables.

        Anything sensitive belongs in a sealed secret referenced by
        :meth:`set_secret_ref`, not here.
        """
        return self._tx(
            "Jobs",
            "set_deployment_env",
            {"deployment": int(deployment), "env_vars": env_vars},
        )

    def register_wg_peer(self, deployment: int, user_wg_pubkey: bytes):
        """Register a WireGuard peer public key against a deployment."""
        from .hexutil import to_hex

        return self._tx(
            "Jobs",
            "register_wg_peer",
            {"deployment": int(deployment), "user_wg_pubkey": to_hex(user_wg_pubkey)},
        )


class ResourcesFacade(_Facade):
    """Resources: register capacity, price it, control who may use it."""

    def register(self, resource_id: str, ownership_proof: Any, name: str):
        """Register a resource you operate."""
        return self._tx(
            "Resources",
            "register_resource",
            {"resource_id": resource_id, "ownership_proof": ownership_proof, "name": name},
        )

    def update_sku(self, uuid: int, sku: Any):
        """Publish or update a SKU's pricing."""
        return self._tx("Resources", "update_sku", {"uuid": int(uuid), "sku": sku})

    def report_capacity(self, capacity: Any):
        """Report current capacity."""
        return self._tx("Resources", "report_capacity", {"capacity": capacity})

    def set_privacy(self, resource_id: str, is_private: bool):
        """Make a resource private (whitelist-only) or public."""
        return self._tx(
            "Resources",
            "set_resource_privacy",
            {"resource_id": resource_id, "is_private": bool(is_private)},
        )

    def allow(self, resource_id: str, user: str):
        """Allow an account to use a private resource."""
        return self._tx(
            "Resources", "add_to_whitelist", {"resource_id": resource_id, "user": user}
        )

    def disallow(self, resource_id: str, user: str):
        """Withdraw a private resource's whitelist entry."""
        return self._tx(
            "Resources", "remove_from_whitelist", {"resource_id": resource_id, "user": user}
        )


class StakingFacade(_Facade):
    """Staking on MatterChain: the standard FRAME staking surface.

    Amounts are **plancks**. Use :meth:`MatterClient.parse_amount` rather than
    writing an exponent by hand — this chain's decimal count changed once already,
    without a storage migration.

    ``pallet-staking-gateway`` is deliberately absent: it is the Ethereum
    meta-transaction path, and belongs with the reserved secp256k1 scheme.
    """

    def bond(self, value: int, payee: Any):
        """Bond funds and set a reward destination, e.g. ``{"Staked": None}``."""
        return self._tx("Staking", "bond", {"value": int(value), "payee": payee})

    def bond_extra(self, additional: int):
        """Add to an existing bond."""
        return self._tx("Staking", "bond_extra", {"additional": int(additional)})

    def unbond(self, value: int):
        """Schedule an unbond.

        Funds stay locked until the unbonding period elapses and
        :meth:`withdraw_unbonded` is called.
        """
        return self._tx("Staking", "unbond", {"value": int(value)})

    def withdraw_unbonded(self, num_slashing_spans: int):
        """Move unlocked funds back to free balance."""
        return self._tx(
            "Staking", "withdraw_unbonded", {"num_slashing_spans": int(num_slashing_spans)}
        )

    def nominate(self, targets: List[str]):
        """Nominate validators, by SS58 address."""
        return self._tx("Staking", "nominate", {"targets": list(targets)})

    def chill(self):
        """Stop nominating or validating."""
        return self._tx("Staking", "chill", {})

    def join_pool(self, amount: int, pool_id: int):
        """Join a nomination pool with ``amount`` plancks."""
        return self._tx(
            "NominationPools", "join", {"amount": int(amount), "pool_id": int(pool_id)}
        )

    def claim_pool_payout(self):
        """Claim accrued nomination-pool rewards."""
        return self._tx("NominationPools", "claim_payout", {})


class OrgsFacade(_Facade):
    """Organizations and budgets: membership, projects, and who may spend or decrypt."""

    def create(self, metadata: Any):
        """Create an organization."""
        return self._tx("Organizations", "create_org", {"metadata": metadata})

    def add_member(self, org: Any, who: str, role: Any):
        """Add a member with a role."""
        return self._tx(
            "Organizations", "add_member", {"org": org, "who": who, "role": role}
        )

    def remove_member(self, org: Any, who: str):
        """Remove a member."""
        return self._tx("Organizations", "remove_member", {"org": org, "who": who})

    def allot(self, org: Any, project: Any, amount: int):
        """Allot budget from an org treasury to a project, in plancks."""
        return self._tx(
            "Budgets", "allot", {"org": org, "project": project, "amount": int(amount)}
        )

    def authorize_secrets_agent(self, org: Any, project: Any, who: str):
        """Authorize an account to decrypt a project's secrets.

        The org-scoped analogue of ``secrets.grant_access``.
        """
        return self._tx(
            "Budgets",
            "authorize_project_secrets_agent",
            {"org": org, "project": project, "who": who},
        )

    def revoke_secrets_agent(self, org: Any, project: Any, who: str):
        """Withdraw a project secrets-agent authorization."""
        return self._tx(
            "Budgets",
            "revoke_project_secrets_agent",
            {"org": org, "project": project, "who": who},
        )
