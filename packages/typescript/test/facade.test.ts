// Façade parity with testvectors/facade_calls.json (emitted from Rust), checked
// both ways: every row has a method routing to its (pallet, call), and every
// method has a row.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  DeploymentsFacade,
  KeysFacade,
  OrgsFacade,
  ResourcesFacade,
  SecretsFacade,
  StakingFacade,
  type FacadeHost,
  type TxReceipt,
} from "../src/index.js";

const vectorsDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../../testvectors");
const fixture = JSON.parse(readFileSync(resolve(vectorsDir, "facade_calls.json"), "utf8")) as {
  runtimeApiCalls?: never;
  runtime_api_calls: Array<{
    facade: string;
    method: string;
    state_call: string;
    args: string[];
  }>;
  calls: Array<{
    facade: string;
    method: string;
    pallet: string;
    call: string;
    args: string[];
  }>;
};

class RecordingHost implements FacadeHost {
  calls: Array<[string, string, unknown[]]> = [];
  async tx(pallet: string, call: string, args: unknown[]): Promise<TxReceipt> {
    this.calls.push([pallet, call, args]);
    return { txHash: "0x", blockHash: "0x", events: [] };
  }
}

function toCamel(text: string): string {
  return text.replace(/_([a-z0-9])/g, (_all, ch: string) => ch.toUpperCase());
}

function facadeFor(name: string, host: FacadeHost): object {
  switch (name) {
    case "secrets":
      return new SecretsFacade(host);
    case "deployments":
      return new DeploymentsFacade(host);
    case "resources":
      return new ResourcesFacade(host);
    case "staking":
      return new StakingFacade(host);
    case "orgs":
      return new OrgsFacade(host);
    case "keys":
      return new KeysFacade(host);
    default:
      throw new Error(`the fixture names an unknown façade: ${name}`);
  }
}

const ENVELOPE = {
  bindingId: new Uint8Array([1]),
  capsule: new Uint8Array([2]),
  proof: new Uint8Array([3]),
  ct: new Uint8Array([4]),
};

/** Façade methods whose arguments differ from the runtime call's (the fixture pins the latter). */
const METHOD_ARGS: Record<string, unknown[]> = {
  "secrets.store": [
    { payload: ENVELOPE, epoch: 1, label: new Uint8Array([0]), aad: new Uint8Array([1]) },
  ],
};

/** Placeholder arguments shaped by the fixture's arg names; only routing is under test. */
function placeholders(argNames: string[]): unknown[] {
  return argNames.map((name) => {
    switch (name) {
      case "payload":
        return ENVELOPE;
      case "targets":
        return [new Uint8Array(32)];
      case "target":
        return { User: new Uint8Array(32) };
      case "aad":
        return "matter-deployment/env/v1";
      case "label":
        return new Uint8Array([0]);
      default:
        return 1n;
    }
  });
}

function argsFor(facade: string, method: string, argNames: string[]): unknown[] {
  return METHOD_ARGS[`${facade}.${method}`] ?? placeholders(argNames);
}

describe("façade parity", () => {
  it("the fixture is non-empty", () => {
    expect(fixture.calls.length).toBeGreaterThan(20);
  });

  it.each(fixture.calls)("$facade.$method routes to $pallet.$call", async (row) => {
    const host = new RecordingHost();
    const facade = facadeFor(row.facade, host) as Record<string, unknown>;
    const methodName = toCamel(row.method);

    const method = facade[methodName];
    expect(typeof method, `${row.facade}.${methodName} is missing`).toBe("function");

    await (method as (...args: unknown[]) => Promise<TxReceipt>).apply(
      facade,
      argsFor(row.facade, row.method, row.args),
    );

    expect(host.calls).toHaveLength(1);
    const [pallet, call] = host.calls[0]!;
    expect([pallet, call]).toEqual([row.pallet, row.call]);
  });

  it("routes every pinned read through the named state_call", async () => {
    for (const row of fixture.runtime_api_calls) {
      const seen: Uint8Array[] = [];
      const host: FacadeHost = {
        async tx() {
          throw new Error("a read must not submit an extrinsic");
        },
        async agentKey(key: Uint8Array) {
          seen.push(key);
          return undefined;
        },
      };
      const facade = facadeFor(row.facade, host) as Record<string, unknown>;
      const method = facade[toCamel(row.method)];
      expect(typeof method, `${row.facade}.${row.method} is missing`).toBe("function");
      await (method as (...args: unknown[]) => Promise<unknown>).apply(facade, [
        new Uint8Array(32),
      ]);
      expect(seen).toHaveLength(1);
    }
  });

  it("exposes no façade method the fixture does not pin", () => {
    // A façade's surface is the union of both tables.
    const expected = new Map<string, Set<string>>();
    for (const row of [...fixture.calls, ...fixture.runtime_api_calls]) {
      const methods = expected.get(row.facade) ?? new Set<string>();
      methods.add(toCamel(row.method));
      expected.set(row.facade, methods);
    }

    const host = new RecordingHost();
    for (const [name, pinned] of expected) {
      const facade = facadeFor(name, host);
      const actual = Object.getOwnPropertyNames(Object.getPrototypeOf(facade)).filter(
        (member) => member !== "constructor",
      );
      expect(new Set(actual), `${name} façade`).toEqual(pinned);
    }
  });

  it("covers every pallet-secrets call, including revoke", async () => {
    const host = new RecordingHost();
    const secrets = new SecretsFacade(host);
    await secrets.grant(1n, { User: new Uint8Array(32) });
    await secrets.revoke(1n, { User: new Uint8Array(32) });
    await secrets.delete(1n);

    expect(host.calls.map(([, call]) => call)).toEqual([
      "grant_access",
      "revoke_access",
      "delete_secret",
    ]);
  });

  it("passes a grant target as a named variant, not a bare account", async () => {
    // A raw 32-byte grantee does not decode as GrantTarget<AccountId>.
    const host = new RecordingHost();
    const account = new Uint8Array(32).fill(7);
    await new SecretsFacade(host).grant(1n, { User: account });

    const [, , args] = host.calls[0]!;
    expect(args[1]).toEqual({ User: account });
    expect(args[1]).not.toBeInstanceOf(Uint8Array);
  });
});
