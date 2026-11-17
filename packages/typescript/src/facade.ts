// Typed façades for common domains. A write shapes its arguments and delegates
// to MatterClient.tx, which owns all encoding. A read takes one block's state,
// fetches its sources there, and hands the raw bytes to a pure decoder in
// ./reads. Anything not here is one `client.tx(...)` or `client.query(...)` away.

import type { Aad, EncryptedSecret, GrantTarget, StoreSecret } from "@openmatter-network/matter-sdk-core";
import { aadBytes } from "@openmatter-network/matter-sdk-core";

import { requireEvent, type ChainBackend, type Mode, type TxReceipt } from "./backend.js";
import { ClientError } from "./errors.js";
import type { ChainProperties } from "./network.js";
import { balanceRequests, decodeBalance, type AccountBalance } from "./reads/accounts.js";
import {
  FEE_PAYER,
  QUERY_CALL_INFO,
  callInfoArgs,
  decodeDispatchInfo,
  decodeEstimate,
  feePayerArgs,
  type FeeEstimate,
} from "./reads/fees.js";
import {
  GET_BLOCK_HASH,
  GET_HEADER,
  GET_RUNTIME_VERSION,
  SYSTEM_HEALTH,
  SYSTEM_NAME,
  SYSTEM_VERSION,
  TIMING_CONSTANTS,
  blockNumberParam,
  decodeBlock,
  decodeHeader,
  decodeTiming,
  hashFromHex,
  networkInfo,
  nodeStatus,
  nowRequest,
  type Block,
  type BlockHeader,
  type NetworkInfo,
  type NetworkTiming,
  type NodeStatus,
} from "./reads/network.js";
import {
  accountIdOf,
  blockHash,
  request,
  snapshot,
  type RawReads,
  type Snapshot,
} from "./reads/source.js";
import type { ScopeSet } from "./scopes.js";

/** What a façade needs from the client. Writes need `tx`; reads need the rest. */
export interface FacadeHost {
  tx(pallet: string, call: string, args: unknown[]): Promise<TxReceipt>;
  agentKey?(key: Uint8Array): Promise<readonly [Uint8Array, ScopeSet] | undefined>;
  /** The backend, for its block-pinned raw reads and the chain's address form. */
  readonly backend?: Pick<ChainBackend, "reads" | "encodeAddress">;
  /** Chain facts read once at connect, which some decoders need. */
  readonly properties?: ChainProperties;
  /** The signing identity's account id; absent for a read-only client. */
  readonly accountId?: Uint8Array;
  /** Who the client's signature speaks for; absent means itself. */
  readonly mode?: Mode;
}

/** What a read needs from its host, or a `config` error naming what is missing. */
function readHost(host: FacadeHost): {
  reads: RawReads;
  properties: ChainProperties;
  address: (accountId: Uint8Array) => string;
} {
  const { backend, properties } = host;
  const reads = backend?.reads;
  if (backend === undefined || reads === undefined || properties === undefined) {
    throw ClientError.config("this backend cannot serve block-pinned reads");
  }
  return { reads, properties, address: (accountId) => backend.encodeAddress(accountId) };
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

/** Field of `Secrets.SecretStored` that carries the chain-assigned id. */
const SECRET_ID_FIELD = "secret_id";

/**
 * The id the chain assigned in a `secrets.store` receipt, from its
 * `Secrets.SecretStored` event. Never predict it from a counter: two concurrent
 * stores would each read the other's id.
 */
export function secretIdFromReceipt(receipt: TxReceipt): bigint {
  const fields = requireEvent(receipt, "Secrets", "SecretStored");
  const raw = fields[SECRET_ID_FIELD];
  if (typeof raw !== "number" && typeof raw !== "string") {
    throw ClientError.chain(
      "Secrets.SecretStored",
      `event carries no ${SECRET_ID_FIELD} (fields: ${Object.keys(fields).join(", ") || "none"})`,
    );
  }
  return BigInt(raw);
}

/**
 * Accounts: what an account holds and how much of it can move.
 *
 * Reads only, at the latest finalized block unless pinned with `at`. Works on a
 * read-only client.
 */
export class AccountsFacade {
  constructor(
    private readonly host: FacadeHost,
    private readonly pin?: Uint8Array,
  ) {}

  /**
   * Read at `block` (a block hash, as bytes or hex) instead of the latest
   * finalized block, so several reads share one view of the chain.
   */
  at(block: Uint8Array | string): AccountsFacade {
    return new AccountsFacade(this.host, blockHash(block));
  }

  /**
   * What `who` holds: free, on hold and frozen amounts, what a transfer may
   * move, and the reasons behind each hold and freeze. `who` is an account id,
   * or hex or SS58 text. An account the chain does not store reads as zeros
   * with `exists === false`.
   */
  async balance(who: Uint8Array | string): Promise<AccountBalance> {
    const { reads, properties, address } = readHost(this.host);
    const account = accountIdOf(reads, who);
    const view = await snapshot(reads, this.pin);
    const values = await view.storage(balanceRequests(account));
    return decodeBalance(address(account), properties.existentialDeposit, values);
  }
}

/**
 * Fees: what a call would cost, and who would be charged for it.
 *
 * Reads only, at the latest finalized block unless pinned with `at`.
 */
export class FeesFacade {
  constructor(
    private readonly host: FacadeHost,
    private readonly pin?: Uint8Array,
  ) {}

  /**
   * Read at `block` (a block hash, as bytes or hex) instead of the latest
   * finalized block, so several reads share one view of the chain.
   */
  at(block: Uint8Array | string): FeesFacade {
    return new FeesFacade(this.host, blockHash(block));
  }

  /**
   * What `pallet.call(args)` would cost this client, and who would be charged.
   * Takes exactly what `tx` takes, and prices the call as it would be
   * submitted: wrapped in `Proxy.proxy` when the client acts for a member.
   * Nothing is signed or submitted.
   *
   * An estimate, not a quote: the fee is computed for an upper bound on the
   * signed length, with no tip. It is also not a permission check; a call a
   * scoped key may not make is still priced. Works on a read-only client, which
   * learns the fee but not the payer.
   */
  async estimate(pallet: string, call: string, args: unknown[]): Promise<FeeEstimate> {
    const { reads, address } = readHost(this.host);
    const { accountId: signer, mode } = this.host;
    const principal = mode?.kind === "delegated" ? mode.principal : undefined;
    const bytes = reads.callData(pallet, call, args, principal);
    const { encodedLen, args: infoArgs } = callInfoArgs(bytes);

    const view = await snapshot(reads, this.pin);
    const info = decodeDispatchInfo(await view.call(QUERY_CALL_INFO, infoArgs));
    // The payer depends on the fee, so this is asked second.
    const payer =
      signer === undefined
        ? undefined
        : await view.call(FEE_PAYER, feePayerArgs(signer, bytes, info.partialFee));
    const priced = {
      pallet,
      call,
      encodedLen,
      wrappedInProxy: principal !== undefined,
      signer: signer === undefined ? undefined : address(signer),
    };
    return decodeEstimate(priced, info, payer, address);
  }
}

/** The header of the block `view` reads at. */
async function headerAt(view: Snapshot): Promise<BlockHeader> {
  return decodeHeader(view.at, await view.requestHere(GET_HEADER));
}

/**
 * The network: which chain this is, its blocks, its timing, and the health of
 * the node answering.
 *
 * Reads only. `head` reads at the latest finalized block unless pinned with
 * `at`; the other reads are not about one block.
 */
export class NetworkFacade {
  constructor(
    private readonly host: FacadeHost,
    private readonly pin?: Uint8Array,
  ) {}

  /**
   * Make `head` describe `block` (a block hash, as bytes or hex) instead of the
   * latest finalized block.
   */
  at(block: Uint8Array | string): NetworkFacade {
    return new NetworkFacade(this.host, blockHash(block));
  }

  /**
   * Which chain this is: its name, genesis hash, token and address format, as
   * read once at connect. No request is made.
   */
  info(): NetworkInfo {
    return networkInfo(readHost(this.host).properties);
  }

  /**
   * The latest finalized block, or the pinned one: its height, hash, time and
   * runtime version. Its `hash` is what a façade's `at` takes, to make several
   * reads share this block.
   */
  async head(): Promise<Block> {
    const view = await snapshot(readHost(this.host).reads, this.pin);
    const header = await headerAt(view);
    const [now] = await view.storage(nowRequest());
    const version = await view.requestHere(GET_RUNTIME_VERSION);
    return decodeBlock(header, now, version);
  }

  /**
   * The block at height `number`, or `undefined` if the chain has not reached
   * it. Read from headers alone, so it works for blocks whose state the node
   * has pruned; `at(hash).head()` adds the time and runtime version where it
   * has not.
   */
  async block(number: bigint | number): Promise<BlockHeader | undefined> {
    const { reads } = readHost(this.host);
    const hash = await request(reads, GET_BLOCK_HASH, [blockNumberParam(BigInt(number))]);
    if (hash === null || hash === undefined) return undefined;
    return headerAt(await snapshot(reads, blockHash(hashFromHex(GET_BLOCK_HASH, hash))));
  }

  /**
   * The node answering this client: its software, peers, whether it is still
   * syncing, and its best and finalized blocks. About the node, not a block, so
   * a pin does not apply.
   */
  async node(): Promise<NodeStatus> {
    const { reads } = readHost(this.host);
    const name = await request(reads, SYSTEM_NAME, []);
    const version = await request(reads, SYSTEM_VERSION, []);
    const health = await request(reads, SYSTEM_HEALTH, []);
    const bestHash = hashFromHex(GET_BLOCK_HASH, await request(reads, GET_BLOCK_HASH, []));
    const best = await headerAt(await snapshot(reads, blockHash(bestHash)));
    const finalized = await headerAt(await snapshot(reads, undefined));
    return nodeStatus(name, version, health, best, finalized);
  }

  /**
   * How the chain measures time: its block time, and the length of a session,
   * an era and the unbonding period. Constants of the connected runtime; no
   * request is made.
   */
  timing(): NetworkTiming {
    const { reads } = readHost(this.host);
    return decodeTiming(TIMING_CONSTANTS.map(({ pallet, name }) => reads.constant(pallet, name)));
  }
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
