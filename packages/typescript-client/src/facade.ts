// Curated typed façades over the generic surface.
//
// Every method is a thin, named wrapper around MatterClient.tx — it shapes typed
// arguments and delegates. No encoding, no error handling, no chain access of its
// own, so a façade can be wrong about a *name* but never about the wire format.
//
// The generic surface already reaches every pallet, including ones added by a
// future forkless upgrade. These exist for the domains callers reach for daily.
// Anything not here is one `client.tx(...)` away — a façade is a convenience, not
// a gate.
//
// Names resolve at call time from live metadata, so a rename in an upgrade
// surfaces as a ClientError at the call rather than silently. The Rust
// `the_curated_pallets_all_exist_in_live_metadata` test is the shared tripwire.

import type { Aad, EncryptedSecret, GrantTarget, StoreSecret } from "@openmatter-network/matter-vault";
import { aadBytes } from "@openmatter-network/matter-vault";

import type { TxReceipt } from "./backend.js";

/** What a façade needs from the client: the ability to submit a named call. */
export interface FacadeHost {
  tx(pallet: string, call: string, args: unknown[]): Promise<TxReceipt>;
}

/** The four-blob sealed envelope as the runtime's `EncryptedSecret` composite. */
function envelope(payload: EncryptedSecret): unknown {
  return {
    binding_id: payload.bindingId,
    capsule: payload.capsule,
    proof: payload.proof,
    ct: payload.ct,
  };
}

/** Secrets: store, rotate, share, and delete MatterVault secrets. */
export class SecretsFacade {
  constructor(private readonly host: FacadeHost) {}

  /**
   * Publish a sealed envelope. The chain-assigned id is in the
   * `Secrets.SecretStored` event on the returned receipt.
   */
  async store(args: StoreSecret): Promise<TxReceipt> {
    return this.host.tx("Secrets", "store_secret", [
      envelope(args.payload),
      args.epoch,
      args.label,
      args.aad,
    ]);
  }

  /** Re-seal an existing secret in place under the current epoch. */
  async rotate(
    secretId: bigint,
    payload: EncryptedSecret,
    epoch: number,
    aad: Aad,
  ): Promise<TxReceipt> {
    return this.host.tx("Secrets", "rotate_secret", [
      secretId,
      envelope(payload),
      epoch,
      aadBytes(aad),
    ]);
  }

  /** Authorize a principal to request decryption. */
  async grant(secretId: bigint, target: GrantTarget): Promise<TxReceipt> {
    return this.host.tx("Secrets", "grant_access", [secretId, target]);
  }

  /**
   * Withdraw a grant. The target must match the grant exactly, or this is a
   * no-op on chain.
   */
  async revoke(secretId: bigint, target: GrantTarget): Promise<TxReceipt> {
    return this.host.tx("Secrets", "revoke_access", [secretId, target]);
  }

  /** Delete a secret and every grant on it. Owner only, and irreversible. */
  async delete(secretId: bigint): Promise<TxReceipt> {
    return this.host.tx("Secrets", "delete_secret", [secretId]);
  }
}

/** Deployments (`pallet-jobs`): request compute, wire networking, bind secrets. */
export class DeploymentsFacade {
  constructor(private readonly host: FacadeHost) {}

  /**
   * Request a deployment. `request` is the runtime's `ResourceRequest`, which is
   * large and evolving, so it is passed through rather than mirrored here —
   * mirroring it would be a second source of truth that rots.
   */
  async request(request: unknown): Promise<TxReceipt> {
    return this.host.tx("Jobs", "request_deployment", [request]);
  }

  /** Cancel a deployment. */
  async cancel(deployment: bigint): Promise<TxReceipt> {
    return this.host.tx("Jobs", "cancel_deployment", [deployment]);
  }

  /**
   * Point a deployment at a MatterVault secret, or clear it with `null`.
   *
   * The bridge between a deployment and a sealed secret: the assigned resource is
   * authorized to decrypt whatever `secretRef` names.
   */
  async setSecretRef(deployment: bigint, secretRef: bigint | null): Promise<TxReceipt> {
    return this.host.tx("Jobs", "set_deployment_secret_ref", [deployment, secretRef]);
  }

  /**
   * Set or clear a deployment's **plaintext** environment variables. Anything
   * sensitive belongs in a sealed secret referenced by {@link setSecretRef}.
   */
  async setEnv(deployment: bigint, env: unknown | null): Promise<TxReceipt> {
    return this.host.tx("Jobs", "set_deployment_env", [deployment, env]);
  }

  /** Register a WireGuard peer public key against a deployment. */
  async registerWgPeer(deployment: bigint, pubkey: Uint8Array): Promise<TxReceipt> {
    return this.host.tx("Jobs", "register_wg_peer", [deployment, pubkey]);
  }
}

/** Resources: register capacity, price it, control who may use it. */
export class ResourcesFacade {
  constructor(private readonly host: FacadeHost) {}

  /** Register a resource you operate. */
  async register(resource: Uint8Array, ownershipProof: unknown, name: string): Promise<TxReceipt> {
    return this.host.tx("Resources", "register_resource", [resource, ownershipProof, name]);
  }

  /** Publish or update a SKU's pricing. */
  async updateSku(uuid: bigint, sku: unknown): Promise<TxReceipt> {
    return this.host.tx("Resources", "update_sku", [uuid, sku]);
  }

  /** Report current capacity. */
  async reportCapacity(capacity: unknown): Promise<TxReceipt> {
    return this.host.tx("Resources", "report_capacity", [capacity]);
  }

  /** Make a resource private (whitelist-only) or public. */
  async setPrivacy(resource: Uint8Array, isPrivate: boolean): Promise<TxReceipt> {
    return this.host.tx("Resources", "set_resource_privacy", [resource, isPrivate]);
  }

  /** Allow an account to use a private resource. */
  async allow(resource: Uint8Array, user: Uint8Array): Promise<TxReceipt> {
    return this.host.tx("Resources", "add_to_whitelist", [resource, user]);
  }

  /** Withdraw a private resource's whitelist entry. */
  async disallow(resource: Uint8Array, user: Uint8Array): Promise<TxReceipt> {
    return this.host.tx("Resources", "remove_from_whitelist", [resource, user]);
  }
}

/**
 * Staking on MatterChain: the standard FRAME staking surface.
 *
 * Amounts are **plancks** (`bigint`). Use `client.parseAmount()` rather than
 * writing an exponent by hand — this chain's decimal count changed once already,
 * without a storage migration.
 *
 * `pallet-staking-gateway` is deliberately absent: it is the Ethereum
 * meta-transaction path, and belongs with the reserved secp256k1 scheme.
 */
export class StakingFacade {
  constructor(private readonly host: FacadeHost) {}

  /** Bond funds and set a reward destination, e.g. `{ Staked: null }`. */
  async bond(value: bigint, payee: unknown): Promise<TxReceipt> {
    return this.host.tx("Staking", "bond", [value, payee]);
  }

  /** Add to an existing bond. */
  async bondExtra(additional: bigint): Promise<TxReceipt> {
    return this.host.tx("Staking", "bond_extra", [additional]);
  }

  /**
   * Schedule an unbond. Funds stay locked until the unbonding period elapses and
   * {@link withdrawUnbonded} is called.
   */
  async unbond(value: bigint): Promise<TxReceipt> {
    return this.host.tx("Staking", "unbond", [value]);
  }

  /** Move unlocked funds back to free balance. */
  async withdrawUnbonded(numSlashingSpans: number): Promise<TxReceipt> {
    return this.host.tx("Staking", "withdraw_unbonded", [numSlashingSpans]);
  }

  /** Nominate validators, by 32-byte account id. */
  async nominate(targets: Uint8Array[]): Promise<TxReceipt> {
    return this.host.tx("Staking", "nominate", [targets.map((id) => ({ Id: id }))]);
  }

  /** Stop nominating or validating. */
  async chill(): Promise<TxReceipt> {
    return this.host.tx("Staking", "chill", []);
  }

  /** Join a nomination pool with `amount` plancks. */
  async joinPool(amount: bigint, poolId: number): Promise<TxReceipt> {
    return this.host.tx("NominationPools", "join", [amount, poolId]);
  }

  /** Claim accrued nomination-pool rewards. */
  async claimPoolPayout(): Promise<TxReceipt> {
    return this.host.tx("NominationPools", "claim_payout", []);
  }
}

/** Organizations and budgets: membership, projects, and who may spend or decrypt. */
export class OrgsFacade {
  constructor(private readonly host: FacadeHost) {}

  /** Create an organization. */
  async create(metadata: unknown): Promise<TxReceipt> {
    return this.host.tx("Organizations", "create_org", [metadata]);
  }

  /** Add a member with a role. */
  async addMember(org: Uint8Array, who: Uint8Array, role: unknown): Promise<TxReceipt> {
    return this.host.tx("Organizations", "add_member", [org, who, role]);
  }

  /** Remove a member. */
  async removeMember(org: Uint8Array, who: Uint8Array): Promise<TxReceipt> {
    return this.host.tx("Organizations", "remove_member", [org, who]);
  }

  /** Allot budget from an org treasury to a project, in plancks. */
  async allot(org: Uint8Array, project: Uint8Array, amount: bigint): Promise<TxReceipt> {
    return this.host.tx("Budgets", "allot", [org, project, amount]);
  }

  /**
   * Authorize an account to decrypt a project's secrets — the org-scoped
   * analogue of `secrets.grantAccess`.
   */
  async authorizeSecretsAgent(
    org: Uint8Array,
    project: Uint8Array,
    who: Uint8Array,
  ): Promise<TxReceipt> {
    return this.host.tx("Budgets", "authorize_project_secrets_agent", [org, project, who]);
  }

  /** Withdraw a project secrets-agent authorization. */
  async revokeSecretsAgent(
    org: Uint8Array,
    project: Uint8Array,
    who: Uint8Array,
  ): Promise<TxReceipt> {
    return this.host.tx("Budgets", "revoke_project_secrets_agent", [org, project, who]);
  }
}
