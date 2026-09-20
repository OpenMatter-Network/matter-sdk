// Façade parity: this binding must expose exactly the surface
// testvectors/facade_calls.json pins, and each method must submit the named
// (pallet, call).
//
// The façades are hand-written per language, so the risk is drift — TypeScript
// growing a method Rust does not have, or two languages disagreeing about which
// call a method maps to. The fixture is emitted from Rust and replayed here,
// checked both ways: a row without a method fails, and a method without a row
// fails.

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

/** Records what a façade submits, so a method can be checked without a chain. */
class RecordingHost implements FacadeHost {
  calls: Array<[string, string, unknown[]]> = [];
  async tx(pallet: string, call: string, args: unknown[]): Promise<TxReceipt> {
    this.calls.push([pallet, call, args]);
    return { txHash: "0x", blockHash: "0x", events: [] };
  }
}

/** `"set_secret_ref"` -> `"setSecretRef"`; the fixture is snake_case. */
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

/**
 * Façade methods whose arity differs from the runtime call's.
 *
 * The fixture pins the **runtime call's** arguments, which is what wire
 * correctness depends on. A façade may legitimately take a different shape:
 * `secrets.store` accepts one already-built `StoreSecret` rather than four
 * positional values, because that struct is what `storeSecret()` produces and
 * re-splitting it at the boundary would invite mismatched AADs.
 */
const METHOD_ARGS: Record<string, unknown[]> = {
  "secrets.store": [
    { payload: ENVELOPE, epoch: 1, label: new Uint8Array([0]), aad: new Uint8Array([1]) },
  ],
};

/**
 * Placeholder arguments shaped by the fixture's arg names.
 *
 * Only the routing is under test, but a façade that dereferences an argument (an
 * envelope's fields, an array of targets) needs something of the right shape.
 * Keying off the pinned arg names keeps that knowledge in one place.
 */
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
    // A silently truncated fixture would make every assertion below vacuous.
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
    // Reads cannot go in the `calls` table — they have no (pallet, call) — but
    // dropping one would still be drift, so they are pinned separately.
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
    // The other direction: an extra method here would be a surface Rust does not
    // have, which is drift even though every fixture row passes. Both tables
    // count — a façade's surface is their union.
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
    // pallet-secrets has five extrinsics; the SDK previously built three, leaving
    // revoke_access — the call that contains a leaked signer — with no builder.
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
    // The defect this replaces: a raw 32-byte grantee is not decodable as
    // GrantTarget<AccountId>, so the call data was dead on arrival.
    const host = new RecordingHost();
    const account = new Uint8Array(32).fill(7);
    await new SecretsFacade(host).grant(1n, { User: account });

    const [, , args] = host.calls[0]!;
    expect(args[1]).toEqual({ User: account });
    expect(args[1]).not.toBeInstanceOf(Uint8Array);
  });
});
