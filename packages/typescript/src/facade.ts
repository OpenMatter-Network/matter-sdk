// Typed convenience wrappers over MatterClient.tx: they shape arguments and
// delegate, with no encoding or chain access of their own. Anything not here is
// one `client.tx(...)` away.

import type { Aad, EncryptedSecret, GrantTarget, StoreSecret } from "@openmatter-network/matter-sdk-core";
import { aadBytes } from "@openmatter-network/matter-sdk-core";

import type { TxReceipt } from "./backend.js";
import type { ScopeSet } from "./scopes.js";

/** What a façade needs from the client. */
export interface FacadeHost {
  tx(pallet: string, call: string, args: unknown[]): Promise<TxReceipt>;
  agentKey?(key: Uint8Array): Promise<readonly [Uint8Array, ScopeSet] | undefined>;
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

/** Secrets: store, rotate, share, and delete secrets. */
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

  /** Withdraw a grant. `target` must match the grant exactly, else a no-op on chain. */
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

  /** Request a deployment. `request` is the runtime's `ResourceRequest`, passed through. */
  async request(request: unknown): Promise<TxReceipt> {
    return this.host.tx("Jobs", "request_deployment", [request]);
  }

  async cancel(deployment: bigint): Promise<TxReceipt> {
    return this.host.tx("Jobs", "cancel_deployment", [deployment]);
  }

  /**
   * Point a deployment at a secret, or clear it with `null`. The assigned
   * resource may then decrypt whatever `secretRef` names.
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

  /**
   * Register a WireGuard peer public key against a deployment. Requires runtime
   * spec >= 330.
   *
   * `pqCiphertext`: the 1088-byte ML-KEM-768 ciphertext encapsulated to the
   * provider's `OverlayNetworks.PqKemPubkeys` key; it derives the tunnel's PSK.
   */
  async registerWgPeer(
    deployment: bigint,
    pubkey: Uint8Array,
    pqCiphertext: Uint8Array,
  ): Promise<TxReceipt> {
    return this.host.tx("Jobs", "register_wg_peer", [deployment, pubkey, pqCiphertext]);
  }
}

/** Resources: register capacity, price it, control who may use it. */
export class ResourcesFacade {
  constructor(private readonly host: FacadeHost) {}

  async register(resource: Uint8Array, ownershipProof: unknown, name: string): Promise<TxReceipt> {
    return this.host.tx("Resources", "register_resource", [resource, ownershipProof, name]);
  }

  /** Publish or update a SKU's pricing. */
  async updateSku(uuid: bigint, sku: unknown): Promise<TxReceipt> {
    return this.host.tx("Resources", "update_sku", [uuid, sku]);
  }

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
 * Staking on MatterChain, including nomination pools. Amounts are **plancks**;
 * use `client.parseAmount()` rather than a hand-written exponent.
 */
export class StakingFacade {
  constructor(private readonly host: FacadeHost) {}

  /** Bond funds and set a reward destination, e.g. `{ Staked: null }`. */
  async bond(value: bigint, payee: unknown): Promise<TxReceipt> {
    return this.host.tx("Staking", "bond", [value, payee]);
  }

  async bondExtra(maxAdditional: bigint): Promise<TxReceipt> {
    return this.host.tx("Staking", "bond_extra", [maxAdditional]);
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

  async chill(): Promise<TxReceipt> {
    return this.host.tx("Staking", "chill", []);
  }

  /** Join a nomination pool with `amount` plancks. */
  async joinPool(amount: bigint, poolId: number): Promise<TxReceipt> {
    return this.host.tx("NominationPools", "join", [amount, poolId]);
  }

  async claimPoolPayout(): Promise<TxReceipt> {
    return this.host.tx("NominationPools", "claim_payout", []);
  }
}

/** Organizations and budgets: membership, projects, and who may spend or decrypt. */
export class OrgsFacade {
  constructor(private readonly host: FacadeHost) {}

  /** Create an organization; the runtime derives its id from the signer. */
  async create(): Promise<TxReceipt> {
    return this.host.tx("Organizations", "create_org", []);
  }

  async addMember(org: Uint8Array, who: Uint8Array, role: unknown): Promise<TxReceipt> {
    return this.host.tx("Organizations", "add_member", [org, who, role]);
  }

  async removeMember(org: Uint8Array, who: Uint8Array): Promise<TxReceipt> {
    return this.host.tx("Organizations", "remove_member", [org, who]);
  }

  /** Allot budget from an org treasury to a project, in plancks. */
  async allot(org: Uint8Array, project: Uint8Array, amount: bigint): Promise<TxReceipt> {
    return this.host.tx("Budgets", "allot", [org, project, amount]);
  }

  /** Authorize an account to decrypt a project's secrets. */
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

/**
 * Minting and revoking member-tied API keys.
 *
 * **Member-signed only.** From a delegated client, `authorize` and `revoke`
 * throw `ClientError` `never-admitted` before submitting, so a key cannot widen
 * its own authority.
 */
export class KeysFacade {
  constructor(private readonly host: FacadeHost) {}

  /**
   * Register `key` as an API key acting for the signer, with `scopes`. Upsert:
   * re-scoping a live key is this same call.
   */
  async authorize(key: Uint8Array, scopes: ScopeSet): Promise<TxReceipt> {
    return this.host.tx("Budgets", "authorize_agent_key", [key, scopes.bits]);
  }

  /** Revoke `key`'s authority and committee decrypt rights from the next request on. */
  async revoke(key: Uint8Array): Promise<TxReceipt> {
    return this.host.tx("Budgets", "revoke_agent_key", [key]);
  }

  /**
   * Who `key` acts for and what it may do, or `undefined` if unregistered. Works
   * on a read-only client.
   */
  async lookup(key: Uint8Array): Promise<readonly [Uint8Array, ScopeSet] | undefined> {
    if (this.host.agentKey === undefined) {
      throw new Error("this backend cannot resolve an api key's grant");
    }
    return this.host.agentKey(key);
  }
}
