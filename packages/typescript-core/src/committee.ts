// Threshold-decrypt orchestration: form a quorum, sign once, fan out, open.
// The crypto stays in the wasm core; this is the networking + quorum shell,
// ported from the dashboard's hand-rolled glue into a reusable, typed module.

import { Aad, aadBytes } from "./aad.js";
import { lagrangeFor, openSecret } from "./crypto.js";
import type { Signer } from "./signer.js";
import type { PartialInput } from "./types.js";
import { fromHex, secretIdToHex, toHex } from "./util.js";

/** A committee node's `/health` response. */
export interface Health {
  status: string;
  epoch?: number;
  crypto_protocol_version?: number;
}

/** `/partial-decrypt` request body (matches the on-chain wire type). */
export interface PartialDecryptRequest {
  secret_id: string;
  subset: number[];
  lagrange_coeff: string;
  requester: string;
  block_hash: string;
  signature: string;
  auth: "substrate" | "ethereum";
  eth_address?: string;
  valid_until?: number;
  eth_signature?: string;
}

/** `/partial-decrypt` response body. */
export interface PartialDecryptResponse {
  node_index: number;
  partial: string;
  proof: string;
  crypto_protocol_version?: number;
  served_epoch?: number;
  shared_a?: string | null;
  joint_pk?: string | null;
  served_threshold?: number;
}

/** How the SDK reaches committee nodes. Swap in a fake for tests. */
export interface Transport {
  health(endpoint: string): Promise<Health>;
  partialDecrypt(endpoint: string, req: PartialDecryptRequest): Promise<PartialDecryptResponse>;
}

/** A `fetch`-based transport for browsers and Node 18+. */
export class FetchTransport implements Transport {
  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  async health(endpoint: string): Promise<Health> {
    const res = await this.fetchImpl(`${trimEnd(endpoint)}/health`);
    if (!res.ok) throw new DecryptError("transport", `health ${res.status} from ${endpoint}`);
    return (await res.json()) as Health;
  }

  async partialDecrypt(endpoint: string, req: PartialDecryptRequest): Promise<PartialDecryptResponse> {
    const res = await this.fetchImpl(`${trimEnd(endpoint)}/partial-decrypt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new DecryptError("transport", `partial-decrypt ${res.status} from ${endpoint}`);
    return (await res.json()) as PartialDecryptResponse;
  }
}

/** One committee node, with the chain-derived data a decryptor needs. */
export interface CommitteeNode {
  /** 1-based DKG evaluation point. */
  index: number;
  /** Base URL, no trailing `/partial-decrypt`. */
  endpoint: string;
  /** Bincode `FeldmanCommitment` for the secret's epoch, read from chain. */
  shareCommitment: Uint8Array;
}

/** Everything needed to recover one secret (chain-derived fields supplied by you). */
export interface DecryptParams {
  secretId: bigint;
  epoch: number;
  bindingId: Uint8Array;
  aad: Aad | Uint8Array;
  capsule: Uint8Array;
  ct: Uint8Array;
  sharedA: Uint8Array;
  blockHash: Uint8Array;
  threshold: number;
  nodes: CommitteeNode[];
}

/** Distinct failure causes, so callers branch on `.kind` instead of message text. */
export type DecryptErrorKind = "quorum" | "epoch" | "transport" | "crypto";

/** Where in the decrypt round trip a node stopped being usable. */
export type FaultStage = "health" | "inactive" | "partial-decrypt" | "epoch-mismatch";

/**
 * Why one committee node did not contribute to a quorum.
 *
 * Carries the endpoint because "which nodes could this caller not reach" is the
 * first question asked, and an index does not answer it when the caller and the
 * operator are looking at different machines. Never carries request material.
 */
export interface NodeFault {
  index: number;
  endpoint: string;
  stage: FaultStage;
  /** The underlying reason, already rendered. */
  detail: string;
}

/** Render faults so a caller that only logs `err.message` still gets them. */
function summarizeFaults(faults: readonly NodeFault[]): string {
  if (faults.length === 0) return "";
  return (
    " — " +
    faults.map((f) => `node ${f.index} (${f.endpoint}) ${f.stage}: ${f.detail}`).join("; ")
  );
}

/** The reason an unknown throw carries, without assuming it is an Error. */
function reasonOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** A typed decrypt failure. */
export class DecryptError extends Error {
  constructor(
    readonly kind: DecryptErrorKind,
    message: string,
    /**
     * For `kind === "quorum"`, one entry per node that was dropped. Without it
     * the error reports only a count, and a count cannot distinguish "the
     * committee is down" from "this caller cannot reach two of them" from "the
     * partials do not verify" — three problems with three different fixes.
     */
    readonly faults: readonly NodeFault[] = [],
  ) {
    super(message);
    this.name = "DecryptError";
  }
}

/**
 * Recover a secret by collecting and aggregating a threshold quorum of partial
 * decryptions: health-probe → pick `threshold` active nodes → sign once → query
 * each → verify + aggregate + AEAD-open.
 *
 * Returns the recovered plaintext. JS has no zeroizing buffer — keep it
 * short-lived and never log it.
 */
export async function decrypt(
  transport: Transport,
  signer: Signer,
  params: DecryptParams,
): Promise<Uint8Array> {
  // 1. Health-probe concurrently; keep the active nodes.
  //
  //    Every node that drops out records why. This used to filter `allSettled`
  //    results, discarding both the rejection reason and the not-active case and
  //    leaving only a count — which cannot tell an operator whether the
  //    committee is down or this caller simply cannot reach part of it.
  const faults: NodeFault[] = [];
  const probes = await Promise.allSettled(
    params.nodes.map(async (node) => ({ node, health: await transport.health(node.endpoint) })),
  );
  const active: CommitteeNode[] = [];
  probes.forEach((probe, i) => {
    const node = params.nodes[i]!;
    if (probe.status === "rejected") {
      faults.push({
        index: node.index,
        endpoint: node.endpoint,
        stage: "health",
        detail: reasonOf(probe.reason),
      });
    } else if (probe.value.health.status !== "active") {
      const h = probe.value.health;
      faults.push({
        index: node.index,
        endpoint: node.endpoint,
        stage: "inactive",
        detail: `status ${JSON.stringify(h.status)}, epoch ${h.epoch ?? 0}, crypto protocol v${h.crypto_protocol_version ?? 0}`,
      });
    } else {
      active.push(node);
    }
  });

  if (active.length < params.threshold) {
    throw new DecryptError(
      "quorum",
      `quorum unavailable: need ${params.threshold} healthy nodes, found ${active.length}${summarizeFaults(faults)}`,
      faults,
    );
  }

  // 2. Assemble a quorum. A node that fails or serves a *different* epoch is a
  //    per-node fault: drop it and re-form the subset from the remaining nodes,
  //    rather than letting one node deny the whole decrypt (audit MV-H2). A
  //    *genuine* rotation still surfaces as `threshold` nodes agreeing on the
  //    same new served_epoch. Each fault removes a node, so the loop terminates.
  active.sort((a, b) => a.index - b.index);
  let available = active;
  const rotatedVotes = new Map<number, number>();

  while (available.length >= params.threshold) {
    const chosen = available.slice(0, params.threshold);
    const subset = chosen.map((n) => n.index);

    // 3. Query each chosen node, signing per node so the payload binds that
    //    node's index — a signature can't be replayed by it to a peer (MV-C1).
    const partials: PartialInput[] = [];
    let faulty: number | null = null;

    for (const node of chosen) {
      const lambda = lagrangeFor(node.index, subset);
      const auth = await signer.authorize({
        secretId: params.secretId,
        subset,
        recipientIndex: node.index,
        blockHash: params.blockHash,
      });
      const req: PartialDecryptRequest = {
        secret_id: secretIdToHex(params.secretId),
        subset,
        lagrange_coeff: toHex(lambda),
        requester: auth.requester,
        block_hash: toHex(params.blockHash),
        signature: auth.signature,
        auth: auth.auth,
        eth_address: auth.eth_address,
        valid_until: auth.valid_until,
        eth_signature: auth.eth_signature,
      };

      let resp: PartialDecryptResponse;
      try {
        resp = await transport.partialDecrypt(node.endpoint, req);
      } catch (e) {
        // Treat an unreachable/erroring node as a per-node fault — but keep the
        // reason: a node that passed `/health` and then refused the real request
        // is a different problem from one that was never reachable.
        faults.push({
          index: node.index,
          endpoint: node.endpoint,
          stage: "partial-decrypt",
          detail: reasonOf(e),
        });
        faulty = node.index;
        break;
      }

      // A served_epoch that differs means this node is serving a different key
      // than the caller's state is for. If a `threshold` of nodes agree on the
      // same new epoch it's a real rotation (fail loudly so the caller
      // refetches); otherwise it's one misbehaving node — drop it.
      // (0/undefined = older node serving current.)
      if (resp.served_epoch && resp.served_epoch !== params.epoch) {
        const votes = (rotatedVotes.get(resp.served_epoch) ?? 0) + 1;
        rotatedVotes.set(resp.served_epoch, votes);
        if (votes >= params.threshold) {
          throw new DecryptError(
            "epoch",
            `secret served under epoch ${resp.served_epoch}, state supplied for ${params.epoch}; refetch and retry`,
          );
        }
        faults.push({
          index: node.index,
          endpoint: node.endpoint,
          stage: "epoch-mismatch",
          detail: `served epoch ${resp.served_epoch}, state supplied for ${params.epoch}`,
        });
        faulty = node.index;
        break;
      }

      partials.push({
        partial: fromHex(resp.partial),
        proof: fromHex(resp.proof),
        commitment: node.shareCommitment,
        lambda,
      });
    }

    if (faulty !== null) {
      available = available.filter((n) => n.index !== faulty);
      continue;
    }
    return openOrThrow(params, partials);
  }

  // Ran out of good nodes. If divergent served_epochs dominated, surface the most
  // common one as a rotation (refetch + retry); otherwise no quorum could form.
  let dominant: { epoch: number; votes: number } | null = null;
  for (const [epoch, votes] of rotatedVotes) {
    if (!dominant || votes > dominant.votes) dominant = { epoch, votes };
  }
  if (dominant) {
    throw new DecryptError(
      "epoch",
      `secret served under epoch ${dominant.epoch}, state supplied for ${params.epoch}; refetch and retry`,
    );
  }
  throw new DecryptError(
    "quorum",
    `quorum unavailable: need ${params.threshold} healthy nodes, found ${available.length}${summarizeFaults(faults)}`,
    faults,
  );
}

/** Step 5: verify + aggregate + AEAD-open in the wasm core. */
function openOrThrow(params: DecryptParams, partials: PartialInput[]): Uint8Array {
  try {
    return openSecret({
      sharedA: params.sharedA,
      capsule: params.capsule,
      secretId: params.secretId,
      epoch: params.epoch,
      bindingId: params.bindingId,
      aad: aadBytes(params.aad),
      ct: params.ct,
      partials,
    });
  } catch (e) {
    throw new DecryptError("crypto", e instanceof Error ? e.message : String(e));
  }
}
function trimEnd(url: string): string {
  return url.replace(/\/+$/, "");
}
