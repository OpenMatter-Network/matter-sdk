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

/** A typed decrypt failure. */
export class DecryptError extends Error {
  constructor(
    readonly kind: DecryptErrorKind,
    message: string,
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
  const probes = await Promise.allSettled(
    params.nodes.map(async (node) => ({ node, health: await transport.health(node.endpoint) })),
  );
  const active = probes
    .filter((p): p is PromiseFulfilledResult<{ node: CommitteeNode; health: Health }> =>
      p.status === "fulfilled" && p.value.health.status === "active",
    )
    .map((p) => p.value.node);

  if (active.length < params.threshold) {
    throw new DecryptError(
      "quorum",
      `quorum unavailable: need ${params.threshold} healthy nodes, found ${active.length}`,
    );
  }

  // 2. Lowest-indexed `threshold` nodes form the subset.
  active.sort((a, b) => a.index - b.index);
  const chosen = active.slice(0, params.threshold);
  const subset = chosen.map((n) => n.index);

  // 3. Query each chosen node, signing per node so the payload binds that node's
  //    index — a signature can't be replayed by it to a peer (MV-C1).
  const partials: PartialInput[] = [];
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
    const resp = await transport.partialDecrypt(node.endpoint, req);

    // A served_epoch that differs means a rotation: the supplied shared_a /
    // commitments are for the wrong key. Fail loudly. (0/undefined = current.)
    if (resp.served_epoch && resp.served_epoch !== params.epoch) {
      throw new DecryptError(
        "epoch",
        `secret served under epoch ${resp.served_epoch}, state supplied for ${params.epoch}; refetch and retry`,
      );
    }

    partials.push({
      partial: fromHex(resp.partial),
      proof: fromHex(resp.proof),
      commitment: node.shareCommitment,
      lambda,
    });
  }

  // 5. Verify + aggregate + AEAD-open in the wasm core.
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
