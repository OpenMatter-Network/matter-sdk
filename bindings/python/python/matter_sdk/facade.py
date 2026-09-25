"""Curated typed façades over :meth:`MatterClient.tx`.

Each method only shapes typed arguments into ``call_params``, keyed by the
runtime's own argument names, and delegates: no encoding or chain access of its
own. Anything not here is one ``client.tx(...)`` away.

Names resolve at call time from live metadata, so a runtime rename fails at the call.

The surface is pinned by ``testvectors/facade_calls.json``; ``tests/test_facade.py``
checks it both ways.
"""

from typing import Any, Dict, List, Optional


def _account_arg(account: Any) -> Any:
    """Render raw account bytes (as ``lookup`` returns) as the ``0x`` hex
    scalecodec accepts; pass anything else through."""
    if isinstance(account, (bytes, bytearray)):
        return "0x" + bytes(account).hex()
    return account

__all__ = [
    "SecretsFacade",
    "DeploymentsFacade",
    "ResourcesFacade",
    "StakingFacade",
    "OrgsFacade",
    "KeysFacade",
]


class _Facade:
    """Common base: holds the client and forwards a named call."""

    __slots__ = ("_client",)

    def __init__(self, client) -> None:
        self._client = client

    def _tx(self, pallet: str, call: str, params: Dict[str, Any]):
        return self._client.tx(pallet, call, params)


class SecretsFacade(_Facade):
    """Secrets: store, rotate, share, and delete secrets."""

    def store(self, payload, epoch: int, label, aad):
        """Publish a sealed envelope.

        ``payload`` is the tuple ``encrypt`` returns. The chain-assigned id is in
        the receipt's ``Secrets.SecretStored`` event.
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

        ``target`` comes from :func:`~matter_sdk.calls.grant_to_user` or
        :func:`~matter_sdk.calls.grant_to_deployment`.
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

        ``request`` is the runtime's ``ResourceRequest``, passed through as-is.
        """
        return self._tx("Jobs", "request_deployment", {"request": request})

    def cancel(self, deployment: int):
        """Cancel a deployment."""
        return self._tx("Jobs", "cancel_deployment", {"deployment": int(deployment)})

    def set_secret_ref(self, deployment: int, secret_ref: Optional[int]):
        """Point a deployment at a secret, or clear it with ``None``.

        The assigned resource is authorized to decrypt whatever ``secret_ref`` names.
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

    def register_wg_peer(self, deployment: int, user_wg_pubkey: bytes, pq_ciphertext: bytes):
        """Register a WireGuard peer public key against a deployment.

        ``pq_ciphertext`` is the ML-KEM-768 ciphertext (1088 bytes) the peer
        encapsulated to the provider's on-chain ML-KEM key
        (``OverlayNetworks.PqKemPubkeys``); the provider decapsulates it to
        derive the tunnel's post-quantum preshared key. Requires runtime spec >= 330.
        """
        from .hexutil import to_hex

        return self._tx(
            "Jobs",
            "register_wg_peer",
            {
                "deployment": int(deployment),
                "user_wg_pubkey": to_hex(user_wg_pubkey),
                "pq_ciphertext": to_hex(pq_ciphertext),
            },
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

    Amounts are **plancks**; use :meth:`MatterClient.parse_amount` rather than a
    hand-written exponent. ``pallet-staking-gateway`` (Ethereum meta-transactions)
    is intentionally absent.
    """

    def bond(self, value: int, payee: Any):
        """Bond funds and set a reward destination, e.g. ``{"Staked": None}``."""
        return self._tx("Staking", "bond", {"value": int(value), "payee": payee})

    def bond_extra(self, max_additional: int):
        """Add to an existing bond."""
        return self._tx(
            "Staking", "bond_extra", {"max_additional": int(max_additional)}
        )

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

    def create(self):
        """Create an organization.

        The runtime derives the org id from the signer and a sequence number.
        """
        return self._tx("Organizations", "create_org", {})

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


class KeysFacade(_Facade):
    """Minting and revoking member-tied API keys (``pallet-budgets``' roster calls).

    **Member-signed.** The runtime never admits these to a key, so a key cannot
    widen its own authority; use a client built on a seed or keypair. ``authorize``
    from a delegated client raises before submitting.
    """

    def authorize(self, key: Any, scopes: Any):
        """Register ``key`` as an API key acting for the signer, with ``scopes``.

        An upsert, so re-scoping a live key is this same call. ``scopes`` is a
        :class:`~matter_sdk.scopes.ScopeSet` or its raw ``u32`` bits.
        """
        bits = scopes.bits if hasattr(scopes, "bits") else int(scopes)
        return self._tx(
            "Budgets", "authorize_agent_key", {"key": _account_arg(key), "scopes": bits}
        )

    def revoke(self, key: Any):
        """Revoke ``key``, cutting off its authority and committee decrypt rights
        from the next request onward."""
        return self._tx("Budgets", "revoke_agent_key", {"key": _account_arg(key)})

    def lookup(self, key: bytes):
        """Who ``key`` acts for and what it may do, or ``None`` if unregistered.

        A read, so it needs no signer and works on a read-only client.
        """
        from .scopes import ScopeSet

        resolved = self._client.chain.agent_key(key)
        if resolved is None:
            return None
        principal, bits = resolved
        return (principal, ScopeSet.from_bits(bits))
