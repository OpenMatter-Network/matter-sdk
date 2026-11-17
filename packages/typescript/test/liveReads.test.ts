// Every catalogue read against a live chain, read-only: no key, no submission.
// Strict decoders fail when a forkless upgrade changes a layout, and this is
// where that shows first. Needs the network:
//
//   MATTER_LIVE=yes npx vitest run test/liveReads.test.ts
//
// MATTER_AT_BLOCK pins the block; MATTER_LIVE_READS_OUT writes the results, for
// scripts/compare-live-reads.sh to hold the four bindings to the same bytes.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { toHex } from "@openmatter-network/matter-sdk-core";
import { describe, expect, it } from "vitest";

import { MatterClient, canonicalJson } from "../src/index.js";
import { argsOf, readFixture, toCamel } from "./readFixture.js";

const live = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../testvectors/live_reads.json"), "utf8"),
) as { reads: Array<{ facade: string; method: string; args: Record<string, unknown> }> };

const env = process.env;
const LIVE_TIMEOUT_MS = 60_000;

describe.skipIf(env["MATTER_LIVE"] !== "yes")("live reads", () => {
  it("the live arguments exercise exactly the reads the catalogue pins", () => {
    const name = (row: { facade: string; method: string }) => `${row.facade}.${row.method}`;
    expect(new Set(live.reads.map(name))).toEqual(new Set(readFixture.reads.map(name)));
  });

  it(
    "every catalogue read decodes against the live runtime",
    async () => {
      const client = await MatterClient.connect({ rpcUrl: env["MATTER_RPC_URL"] });
      try {
        const at = env["MATTER_AT_BLOCK"] ?? toHex(await client.finalizedHead());
        const reads = [];
        for (const row of live.reads) {
          const pinned = readFixture.reads.find(
            (candidate) => candidate.facade === row.facade && candidate.method === row.method,
          )!;
          const facade = (client as unknown as Record<string, Record<string, unknown>>)[row.facade]!;
          const view = pinned.pinnable
            ? (facade[readFixture.pin_method] as (block: string) => Record<string, unknown>).call(facade, at)
            : facade;
          const method = view[toCamel(row.method)] as (...args: unknown[]) => unknown;
          const result = await method.apply(view, argsOf(pinned, row.args));
          // The canonical text itself: the comparison is of bytes, not parsed values.
          reads.push({
            facade: row.facade,
            method: row.method,
            args: row.args,
            result_json: canonicalJson(result),
          });
        }
        const out = env["MATTER_LIVE_READS_OUT"];
        if (out !== undefined) writeFileSync(out, JSON.stringify({ at, reads }, null, 2));
        expect(reads).toHaveLength(live.reads.length);
      } finally {
        await client.disconnect();
      }
    },
    LIVE_TIMEOUT_MS,
  );
});
