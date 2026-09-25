import { describe, expect, it } from "vitest";

import { DecryptError, FetchTransport, maxCommitteeResponseBytes } from "../src/index.js";

function fakeFetch(body: string, seen: RequestInit[] = []): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    seen.push(init ?? {});
    return new Response(body, { status: 200 });
  }) as typeof fetch;
}

describe("FetchTransport", () => {
  it("refuses a body over the cap", async () => {
    const big = JSON.stringify({ status: "active", padding: "x".repeat(64) });
    const transport = new FetchTransport(fakeFetch(big), { maxResponseBytes: 32 });
    const err = await transport.health("http://node-1").catch((e) => e);
    expect(err).toBeInstanceOf(DecryptError);
    expect(err.kind).toBe("transport");
    expect(err.message).toMatch(/exceeded/);
  });

  it("reads a body within the cap", async () => {
    const transport = new FetchTransport(fakeFetch('{"status":"active","epoch":3}'));
    expect(await transport.health("http://node-1")).toEqual({ status: "active", epoch: 3 });
  });

  it("puts a deadline on every request", async () => {
    const seen: RequestInit[] = [];
    await new FetchTransport(fakeFetch('{"status":"active"}', seen)).health("http://node-1");
    expect(seen[0]!.signal).toBeInstanceOf(AbortSignal);
  });

  it("defaults to the core's shared cap", () => {
    expect(maxCommitteeResponseBytes()).toBeGreaterThan(1_180_574);
  });
});
