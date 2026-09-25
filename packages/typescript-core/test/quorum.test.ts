import { describe, expect, it } from "vitest";

import { chooseQuorum, type CommitteeNode } from "../src/committee.js";
import { wipe } from "../src/index.js";

function nodes(n: number): CommitteeNode[] {
  return Array.from({ length: n }, (_, i) => ({
    index: i + 1,
    endpoint: `http://node-${i + 1}`,
    shareCommitment: new Uint8Array(),
  }));
}

/** A small deterministic generator (mulberry32), so these tests never flake. */
function seeded(seed: number): (bound: number) => number {
  let a = seed >>> 0;
  return (bound) => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (((t ^ (t >>> 14)) >>> 0) / 2 ** 32) * bound | 0;
  };
}

describe("chooseQuorum", () => {
  it("picks t distinct available nodes in index order", () => {
    const random = seeded(7);
    for (let i = 0; i < 100; i++) {
      const chosen = chooseQuorum(nodes(7), 4, random).map((n) => n.index);
      expect(chosen).toHaveLength(4);
      chosen.slice(1).forEach((index, j) => expect(index).toBeGreaterThan(chosen[j]!));
    }
  });

  it("is not the fixed lowest indices", () => {
    const random = seeded(42);
    const draws = Array.from({ length: 200 }, () =>
      chooseQuorum(nodes(5), 3, random).map((n) => n.index),
    );
    expect(new Set(draws.map(String)).size).toBeGreaterThan(1);
    for (let index = 1; index <= 5; index++) {
      // 3/5 of quorums on average; 60 of 200 is a loose floor.
      expect(draws.filter((d) => d.includes(index)).length).toBeGreaterThanOrEqual(60);
    }
  });
});

describe("wipe", () => {
  it("zeroes a recovered plaintext in place", () => {
    const secret = new TextEncoder().encode("top secret");
    wipe(secret);
    expect(secret.every((b) => b === 0)).toBe(true);
  });
});
