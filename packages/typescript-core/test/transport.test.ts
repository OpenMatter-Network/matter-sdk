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

// A browser's `fetch` accepts only an undefined receiver or the window:
// called as a method of anything else it throws ("Illegal invocation";
// Firefox: "'fetch' called on an object that does not implement interface
// Window"). Node's does not, and every test above passes its own function —
// so a transport that kept `fetch` as a field and called `this.fetchImpl(...)`
// passed here and failed every request in every browser (found 2026-11-12:
// a first sign-in read as "0 of N nodes answered"). `strictFetch` gives the
// tests the browser's rule.
describe("FetchTransport under a browser's receiver rule", () => {
  const strictFetch = (seen: string[]): typeof fetch =>
    function strict(this: unknown, input: string | URL | Request) {
      if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
      seen.push(String(input));
      return Promise.resolve(new Response('{"status":"active","attestation":"0x00"}', { status: 200 }));
    } as typeof fetch;

  const withGlobalFetch = async <T>(replacement: typeof fetch, body: () => Promise<T>): Promise<T> => {
    const original = globalThis.fetch;
    globalThis.fetch = replacement;
    try {
      return await body();
    } finally {
      globalThis.fetch = original;
    }
  };

  it("the default transport sends every kind of request", async () => {
    const seen: string[] = [];
    await withGlobalFetch(strictFetch(seen), async () => {
      const transport = new FetchTransport();
      await transport.health("http://node-1");
      await transport.partialDecrypt("http://node-1", {} as never);
      await transport.attestLogin("http://node-1", { id_token: "a.b.c" } as never);
    });
    expect(seen).toEqual(["http://node-1/health", "http://node-1/partial-decrypt", "http://node-1/attest-login"]);
  });

  it("a caller who passes the global `fetch` itself is served too", async () => {
    const seen: string[] = [];
    await withGlobalFetch(strictFetch(seen), async () => {
      await new FetchTransport(globalThis.fetch).health("http://node-1");
    });
    expect(seen).toEqual(["http://node-1/health"]);
  });
});

describe("the request deadline", () => {
  it("still exists where `AbortSignal.timeout` does not (Safari before 16)", async () => {
    const original = AbortSignal.timeout;
    (AbortSignal as { timeout?: unknown }).timeout = undefined;
    try {
      const seen: RequestInit[] = [];
      await new FetchTransport(fakeFetch('{"status":"active"}', seen), { timeoutMs: 5 }).health("http://node-1");
      const signal = seen[0]!.signal as AbortSignal;
      expect(signal).toBeInstanceOf(AbortSignal);
      expect(signal.aborted).toBe(false);
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(signal.aborted).toBe(true);
    } finally {
      AbortSignal.timeout = original;
    }
  });
});
