// Threshold-decrypt orchestration: networking and quorum only; crypto is in the wasm core.

import { Aad, aadBytes } from "./aad.js";
import { cryptoProtocolVersion, lagrangeFor, maxCommitteeResponseBytes, openSecret } from "./crypto.js";
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

/** Bounds on each committee request, so one node can neither stall nor flood a decrypt. */
export interface FetchTransportOptions {
  /** Whole-request deadline in milliseconds. Default 30 000. */
  timeoutMs?: number;
  /** Cap on a response body in bytes. Default: the core's shared cap. */
  maxResponseBytes?: number;
}

/** A `fetch`-based transport for browsers and Node 22+. */
export class FetchTransport implements Transport {
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    options: FetchTransportOptions = {},
  ) {
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxResponseBytes = options.maxResponseBytes ?? maxCommitteeResponseBytes();
  }

  async health(endpoint: string): Promise<Health> {
    const res = await this.fetchImpl(`${trimEnd(endpoint)}/health`, {
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new DecryptError("transport", `health ${res.status} from ${endpoint}`);
    return this.readJson<Health>(res, endpoint);
  }

  async partialDecrypt(endpoint: string, req: PartialDecryptRequest): Promise<PartialDecryptResponse> {
    const res = await this.fetchImpl(`${trimEnd(endpoint)}/partial-decrypt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!res.ok) throw new DecryptError("transport", `partial-decrypt ${res.status} from ${endpoint}`);
    return this.readJson<PartialDecryptResponse>(res, endpoint);
  }

  /** JSON-decode a body, refusing one over the cap instead of buffering it. */
  private async readJson<T>(res: Response, endpoint: string): Promise<T> {
    const tooLarge = () =>
      new DecryptError("transport", `response from ${endpoint} exceeded ${this.maxResponseBytes} bytes`);
    const declared = Number(res.headers.get("content-length"));
    if (declared > this.maxResponseBytes) throw tooLarge();
    const chunks: Uint8Array[] = [];
    let total = 0;
    const reader = res.body?.getReader();
    for (;;) {
      const next = reader ? await reader.read() : { done: true as const, value: undefined };
      if (next.done) break;
      total += next.value.length;
      if (total > this.maxResponseBytes) {
        await reader!.cancel();
        throw tooLarge();
      }
      chunks.push(next.value);
    }
    const body = new Uint8Array(total);
    chunks.reduce((offset, chunk) => (body.set(chunk, offset), offset + chunk.length), 0);
    return JSON.parse(new TextDecoder().decode(body)) as T;
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
export type FaultStage =
  | "health"
  | "inactive"
  | "partial-decrypt"
  | "epoch-mismatch"
  | "protocol-version";

/**
 * Absent or `0` (node predates the field) is accepted: the version tag on every
 * proof still binds the transcript.
 */
function speaksOurProtocol(reported: number | undefined): boolean {
  return !reported || reported === cryptoProtocolVersion();
}

/** A uniform random integer in `[0, bound)` from the platform CSPRNG. */
function randomBelow(bound: number): number {
  // Rejection sampling avoids modulo bias.
  const limit = Math.floor(0x1_0000_0000 / bound) * bound;
  const word = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(word);
    if (word[0]! < limit) return word[0]! % bound;
  }
}

/**
 * Choose `threshold` of `available` uniformly at random, returned in index order
 * (the signed subset's order).
 *
 * Random so no single node sees, or can deny, every decrypt. `random` is
 * injectable for tests only.
 */
export function chooseQuorum(
  available: readonly CommitteeNode[],
  threshold: number,
  random: (bound: number) => number = randomBelow,
): CommitteeNode[] {
  const pool = [...available];
  // Partial Fisher–Yates: the first `threshold` slots end up a uniform sample.
  for (let i = 0; i < threshold; i++) {
    const j = i + random(pool.length - i);
    [pool[i], pool[j]] = [pool[j]!, pool[i]!];
  }
  return pool.slice(0, threshold).sort((a, b) => a.index - b.index);
}

/** Why one committee node did not contribute to a quorum. Never carries request material. */
export interface NodeFault {
  index: number;
  endpoint: string;
  stage: FaultStage;
  /** The underlying reason, already rendered. */
  detail: string;
}

/** Appended to the message so a caller that only logs `err.message` still sees faults. */
function summarizeFaults(faults: readonly NodeFault[]): string {
  if (faults.length === 0) return "";
  return (
    " — " +
    faults.map((f) => `node ${f.index} (${f.endpoint}) ${f.stage}: ${f.detail}`).join("; ")
  );
}

function reasonOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** A typed decrypt failure. */
export class DecryptError extends Error {
  constructor(
    readonly kind: DecryptErrorKind,
    message: string,
    /** For `kind === "quorum"`, one entry per dropped node. */
    readonly faults: readonly NodeFault[] = [],
  ) {
    super(message);
    this.name = "DecryptError";
  }
}

/**
 * Recover a secret from a threshold quorum: health-probe, pick `threshold` active
 * nodes at random, sign per node, query each, then verify + aggregate + AEAD-open.
 *
 * A failing node is dropped and the quorum re-formed; `threshold` nodes agreeing
 * on another served epoch throws `kind: "epoch"` (refetch and retry).
 *
 * Returns the recovered plaintext: never log it, and {@link wipe} it when done.
 */
export async function decrypt(
  transport: Transport,
  signer: Signer,
  params: DecryptParams,
): Promise<Uint8Array> {
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
    } else if (!speaksOurProtocol(probe.value.health.crypto_protocol_version)) {
      faults.push({
        index: node.index,
        endpoint: node.endpoint,
        stage: "protocol-version",
        detail: `speaks crypto protocol v${probe.value.health.crypto_protocol_version}, this SDK speaks v${cryptoProtocolVersion()}`,
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

  // Each fault removes a node, so the loop terminates.
  let available = active;
  const rotatedVotes = new Map<number, number>();

  while (available.length >= params.threshold) {
    const chosen = chooseQuorum(available, params.threshold);
    const subset = chosen.map((n) => n.index);

    // Sign per node: the payload binds the recipient, so it can't replay to a peer.
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
        faults.push({
          index: node.index,
          endpoint: node.endpoint,
          stage: "partial-decrypt",
          detail: reasonOf(e),
        });
        faulty = node.index;
        break;
      }

      // `threshold` votes for the same new epoch is a real rotation; fewer is one
      // misbehaving node. 0/undefined means an older node serving the current epoch.
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
        point: node.index,
        partial: fromHex(resp.partial),
        proof: fromHex(resp.proof),
        commitment: node.shareCommitment,
      });
    }

    if (faulty !== null) {
      available = available.filter((n) => n.index !== faulty);
      continue;
    }
    return openOrThrow(params, partials);
  }

  // Out of nodes: report the most-voted divergent epoch as a rotation, if any.
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
