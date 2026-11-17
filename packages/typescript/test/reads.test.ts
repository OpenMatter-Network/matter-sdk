// Façade reads against testvectors/facade_reads.json (emitted from Rust): every
// case replayed through the real façade, plus the primitives the decoders stand
// on. A binding that disagrees with a vector has a bug.

import { toHex } from "@openmatter-network/matter-sdk-core";
import { describe, expect, it } from "vitest";

import { AccountsFacade, ClientError, canonicalJson, toJson, type FacadeHost } from "../src/index.js";
import { ss58Decode, ss58Encode } from "../src/polkadot.js";
import {
  FREEZE_REASONS,
  HOLD_REASONS,
  LOCK_REASONS,
  type ReasonGroup,
} from "../src/reads/accounts.js";
import { DISPATCH_CLASSES } from "../src/reads/fees.js";
import { bytesFromHex, textFromBytes, trimPadding } from "../src/reads/leaf.js";
import { ScaleReader, decodeStrict } from "../src/reads/scale.js";
import { accountIdOf, blockHash } from "../src/reads/source.js";
import {
  FIXTURE_HEAD,
  FixtureChain,
  argsOf,
  readFacadeFor,
  readFixture,
  readingHost,
  toCamel,
  type ReadCase,
  type ReadRow,
  type ReasonTable,
} from "./readFixture.js";

const ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

function bytes(hex: string): Uint8Array {
  const decoded = bytesFromHex(hex);
  if (decoded === undefined) throw new Error(`the fixture holds bad hex: ${hex}`);
  return decoded;
}

/** Read one primitive the way a decoder would, as the fixture's decimal string. */
function readPrimitive(kind: string, reader: ScaleReader): string {
  switch (kind) {
    case "u8":
      return String(reader.u8());
    case "u16":
      return String(reader.u16());
    case "u32":
      return String(reader.u32());
    case "u64":
      return String(reader.u64());
    case "u128":
      return String(reader.u128());
    case "bool":
      return String(reader.bool());
    case "compact_u32":
      return String(reader.compactU32());
    case "compact_u64":
      return String(reader.compactU64());
    case "compact_u128":
      return String(reader.compactU128());
    case "bytes":
      return toHex(reader.bytes());
    default:
      throw new Error(`the fixture names an unknown primitive: ${kind}`);
  }
}

describe("the SCALE reader", () => {
  it.each(readFixture.scale.valid)("reads $type $hex as $value", ({ type, hex, value }) => {
    expect(decodeStrict("test", bytes(hex), (reader) => readPrimitive(type, reader))).toBe(value);
  });

  it.each(readFixture.scale.invalid)("refuses $type $hex: $why", ({ type, hex }) => {
    const attempt = () => decodeStrict("Some.Source", bytes(hex), (reader) => readPrimitive(type, reader));
    expect(attempt).toThrow(ClientError);
    expect(attempt).toThrow(/Some\.Source/);
  });

  it("a 32-bit compact is a number, like every integer up to 32 bits", () => {
    expect(decodeStrict("test", bytes("feffffff"), (reader) => reader.compactU32())).toBe(2 ** 30 - 1);
  });

  it("reads options and sequences in wire order", () => {
    const raw = Uint8Array.from([0x00, 0x01, 0x07, 0x08, 0x01, 0x02]);
    const value = decodeStrict("test", raw, (reader) => ({
      none: reader.option((r) => r.u8()),
      some: reader.option((r) => r.u8()),
      items: reader.vec((r) => r.u8()),
    }));
    expect(value).toEqual({ none: undefined, some: 7, items: [1, 2] });
  });

  it("refuses an option tag that is neither none nor some", () => {
    expect(() => decodeStrict("test", Uint8Array.from([2]), (r) => r.option((i) => i.u8()))).toThrow(
      ClientError,
    );
  });
});

describe("accounts in and out", () => {
  const chain = new FixtureChain();

  it.each(readFixture.accounts.accepted)("accepts $text", ({ text, account_hex }) => {
    expect(toHex(accountIdOf(chain, text))).toBe(`0x${account_hex}`);
  });

  it.each(readFixture.accounts.refused.map((text) => ({ text })))("refuses $text", ({ text }) => {
    expect(() => accountIdOf(chain, text)).toThrow(TypeError);
  });

  it("accepts 32 bytes, as a copy, and refuses any other length or type", () => {
    const account = bytes(readFixture.accounts.accepted[0]!.account_hex);
    const parsed = accountIdOf(chain, account);
    expect(parsed).toEqual(account);
    // The caller may reuse its buffer: the read keeps its own.
    expect(parsed).not.toBe(account);
    expect(() => accountIdOf(chain, account.slice(1))).toThrow(TypeError);
    expect(() => accountIdOf(chain, 32 as unknown as string)).toThrow(TypeError);
  });

  it.each(readFixture.accounts.addresses)(
    "an address is SS58 under prefix $prefix, and parses back",
    ({ account_hex, prefix, address }) => {
      expect(ss58Encode(bytes(account_hex), prefix)).toBe(address);
      expect(toHex(ss58Decode(address)!)).toBe(`0x${account_hex}`);
    },
  );

  it("a block hash is 32 bytes, as bytes or hex, and is copied", () => {
    expect(toHex(blockHash(FIXTURE_HEAD))).toBe(FIXTURE_HEAD);
    expect(toHex(blockHash(` ${FIXTURE_HEAD.slice(2)}\n`))).toBe(FIXTURE_HEAD);
    expect(() => blockHash("0x1234")).toThrow(TypeError);
    expect(() => blockHash(new Uint8Array(31))).toThrow(TypeError);

    const mine = bytes(FIXTURE_HEAD);
    const pinned = blockHash(mine);
    mine.fill(0);
    expect(toHex(pinned)).toBe(FIXTURE_HEAD);
  });

  it("only spaces, tabs and line breaks are padding", () => {
    expect(trimPadding(" \t\r\nx\n ")).toBe("x");
    // `String.prototype.trim` would strip both of these.
    expect(trimPadding("\ufeffx\u00a0")).toBe("\ufeffx\u00a0");
  });
});

/** A decoder's reason table in the fixture's form. */
function asFixtureTable(source: string, groups: readonly ReasonGroup[]): ReasonTable {
  return {
    source,
    groups: groups.map((group) => ({
      index: group.index,
      pallet: group.pallet,
      reasons: [...group.reasons].map(([index, name]) => ({ index, name })),
    })),
  };
}

describe("the enum tables decoders carry", () => {
  it("are the ones Rust checked against the runtime metadata", () => {
    const { tables } = readFixture;
    expect(asFixtureTable(tables.hold_reasons.source, HOLD_REASONS)).toEqual(tables.hold_reasons);
    expect(asFixtureTable(tables.freeze_reasons.source, FREEZE_REASONS)).toEqual(tables.freeze_reasons);
    expect(LOCK_REASONS).toEqual(tables.lock_reasons);
    expect(DISPATCH_CLASSES).toEqual(tables.dispatch_classes);
  });
});

describe("canonical JSON", () => {
  it("carries wide integers as strings, bytes as hex, absence as null, keys in snake_case", () => {
    const value = {
      blockNumber: 2n ** 64n - 1n,
      specVersion: 330,
      ownerId: Uint8Array.from([0xab, 0xcd]),
      missing: undefined,
      nested: [{ transferableKeepAlive: 1n }],
    };
    expect(toJson(value)).toEqual({
      block_number: "18446744073709551615",
      spec_version: 330,
      owner_id: "0xabcd",
      missing: null,
      nested: [{ transferable_keep_alive: "1" }],
    });
    expect(canonicalJson(value)).toBe(
      '{"block_number":"18446744073709551615","spec_version":330,"owner_id":"0xabcd",' +
        '"missing":null,"nested":[{"transferable_keep_alive":"1"}]}',
    );
  });

  it("text is a string when UTF-8 and hex when not", () => {
    expect(textFromBytes(new TextEncoder().encode("prod-db"))).toBe("prod-db");
    expect(textFromBytes(Uint8Array.from([0xff, 0x00, 0xfe]))).toEqual({ hex: "0xff00fe" });
  });
});

const cases = readFixture.reads.flatMap((row) =>
  row.cases.map((testCase) => ({
    label: `${row.facade}.${row.method}: ${testCase.name}`,
    row,
    testCase,
  })),
);

async function replay(
  row: ReadRow,
  testCase: ReadCase,
  chain: FixtureChain,
  pinned: boolean,
): Promise<unknown> {
  const facade = readFacadeFor(row.facade, readingHost(chain, testCase.client)) as Record<string, unknown>;
  const view = pinned
    ? ((facade[readFixture.pin_method] as (block: string) => Record<string, unknown>).call(
        facade,
        testCase.at,
      ) as Record<string, unknown>)
    : facade;
  const method = view[toCamel(row.method)];
  expect(typeof method, `${row.facade}.${row.method} is missing`).toBe("function");
  // `await` on purpose: a read answered from facts in hand returns at once.
  return (method as (...args: unknown[]) => unknown).apply(view, argsOf(row, testCase.args));
}

/** Assert the read ended as the transcript says: these bytes, or this error. */
async function expectOutcome(testCase: ReadCase, run: Promise<unknown>): Promise<void> {
  if (testCase.error !== undefined) {
    await expect(run).rejects.toMatchObject({ kind: "chain", target: testCase.error.target });
    return;
  }
  const result = await run;
  expect(toJson(result)).toEqual(testCase.expected);
  expect(canonicalJson(result)).toBe(testCase.expected_json);
}

/** Whether the unpinned read resolves the finalized head before its recorded requests. */
function asksForTheHead(row: ReadRow, testCase: ReadCase): boolean {
  const refusedBeforeAsking = testCase.error !== undefined && testCase.exchanges.length === 0;
  return row.pinnable && !refusedBeforeAsking;
}

function requestsOf(testCase: ReadCase): Array<{ method: string; params: unknown[] }> {
  return testCase.exchanges.map(({ method, params }) => ({ method, params }));
}

describe("façade reads replay the shared vectors", () => {
  it("a read that asks the chain has a second returning case and a failing one", () => {
    expect(readFixture.reads.length).toBeGreaterThan(0);
    for (const row of readFixture.reads) {
      const name = `${row.facade}.${row.method}`;
      const failing = row.cases.filter((testCase) => testCase.error !== undefined);
      const returning = row.cases.length - failing.length;
      expect(returning, name).toBeGreaterThanOrEqual(1);
      if (row.cases.some((testCase) => testCase.exchanges.length > 0)) {
        expect(returning, name).toBeGreaterThanOrEqual(2);
        expect(failing.length, name).toBeGreaterThan(0);
      }
    }
  });

  it.each(cases.filter(({ row }) => row.pinnable))("pinned, $label", async ({ row, testCase }) => {
    const chain = new FixtureChain(testCase);

    await expectOutcome(testCase, replay(row, testCase, chain, true));

    // Exactly the recorded requests, in order: nothing more to resolve a head.
    expect(chain.requests).toEqual(requestsOf(testCase));
  });

  it.each(cases)("unpinned, $label", async ({ row, testCase }) => {
    const chain = new FixtureChain(testCase);

    await expectOutcome(testCase, replay(row, testCase, chain, false));

    // A read about one block asks for the finalized head once, then makes the
    // same requests at it; any other read asks exactly what was recorded. So
    // does a read refused before it asks anything: it never needs a block.
    const head = asksForTheHead(row, testCase) ? [{ method: "chain_getFinalizedHead", params: [] }] : [];
    expect(chain.requests).toEqual([...head, ...requestsOf(testCase)]);
  });
});

describe("reads fail loudly", () => {
  it("a backend without raw reads is a config error, not a crash", async () => {
    const host: FacadeHost = {
      async tx() {
        throw new Error("a read must not submit an extrinsic");
      },
    };
    await expect(new AccountsFacade(host).balance(ALICE)).rejects.toMatchObject({ kind: "config" });
  });

  it("a node that leaves a key out of its answer is an error", async () => {
    const silent = new (class extends FixtureChain {
      override async rpc(method: string, params: readonly unknown[]): Promise<unknown> {
        return method === "state_queryStorageAt" ? [{ block: params[1], changes: [] }] : FIXTURE_HEAD;
      }
    })();
    await expect(new AccountsFacade(readingHost(silent)).balance(ALICE)).rejects.toMatchObject({
      kind: "chain",
      target: "System.Account",
    });
  });

  it("a node that answers with something that is not hex is an error", async () => {
    const garbled = new (class extends FixtureChain {
      override async rpc(method: string, params: readonly unknown[]): Promise<unknown> {
        if (method !== "state_queryStorageAt") return FIXTURE_HEAD;
        const [keys, at] = params as [string[], string];
        return [{ block: at, changes: keys.map((key) => [key, "not hex"]) }];
      }
    })();
    await expect(new AccountsFacade(readingHost(garbled)).balance(ALICE)).rejects.toMatchObject({
      kind: "chain",
      target: "System.Account",
    });
  });

  it("a refused request names the method that failed", async () => {
    const down = new (class extends FixtureChain {
      override async rpc(): Promise<unknown> {
        throw new Error("socket closed");
      }
    })();
    const accounts = new AccountsFacade(readingHost(down));
    await expect(accounts.balance(ALICE)).rejects.toMatchObject({
      kind: "chain",
      target: "chain_getFinalizedHead",
    });
    await expect(accounts.at(FIXTURE_HEAD).balance(ALICE)).rejects.toMatchObject({
      kind: "chain",
      target: "state_queryStorageAt",
    });
  });
});
