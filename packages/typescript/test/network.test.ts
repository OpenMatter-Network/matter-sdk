// The default endpoints, replayed from testvectors/networks.json — the one home for
// where each network is. A drifted default dialed a mainnet host with no public RPC on
// 2026-09-16, and every QuantumGuard boot there died connecting to it.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { defaultRpcUrl, type Network } from "../src/network.js";

const vectorsDir = resolve(import.meta.dirname, "../../../testvectors");

const fixture = JSON.parse(readFileSync(resolve(vectorsDir, "networks.json"), "utf8")) as {
  default_rpc: { network: Network; url: string | null }[];
};

describe("default endpoints", () => {
  it("has rows to replay", () => {
    expect(fixture.default_rpc.length).toBeGreaterThan(0);
  });

  it.each(fixture.default_rpc)("$network resolves to the fixture's endpoint", ({ network, url }) => {
    expect(defaultRpcUrl(network) ?? null).toBe(url);
  });
});
