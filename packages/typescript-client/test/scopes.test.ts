// The scope contract, replayed from the fixtures Rust emits.
//
// Both ways, like facade.test.ts: a fixture row this client cannot classify is
// drift, and so is a classification the fixture does not know about.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { Access, Scope, ScopeSet, requiredScopes } from "../src/scopes.js";

const vectorsDir = resolve(import.meta.dirname, "../../../testvectors");

const bits = JSON.parse(readFileSync(resolve(vectorsDir, "scope_bits.json"), "utf8")) as {
  scopes: { scope: string; index: number; read_bit: number; write_bit: number }[];
  all_bits: number;
  algebra: { held: number; required: number; held_text: string; is_superset: boolean }[];
};

const table = JSON.parse(readFileSync(resolve(vectorsDir, "required_scopes.json"), "utf8")) as {
  calls: {
    pallet: string;
    call: string;
    required: number | null;
    required_text: string | null;
    arg_sensitive: boolean;
  }[];
};

describe("ScopeSet bit layout", () => {
  it("places every scope where the fixture says", () => {
    for (const row of bits.scopes) {
      const scope = row.index as Scope;
      expect(ScopeSet.single(scope, Access.Read).bits).toBe(row.read_bit);
      expect(ScopeSet.single(scope, Access.Write).bits).toBe(row.write_bit);
      // The name is what `toString` must emit for that scope alone.
      expect(ScopeSet.single(scope, Access.Read).toString()).toBe(`${row.scope}:r`);
    }
    expect(ScopeSet.ALL.bits).toBe(bits.all_bits);
  });

  it("knows exactly the scopes the fixture knows", () => {
    expect(bits.scopes.map((s) => s.index)).toEqual(bits.scopes.map((_, i) => i));
    // A scope added on either side without the other fails here.
    expect(ScopeSet.ALL.toString().split(", ").length).toBe(bits.scopes.length);
  });

  it("agrees with the fixture's superset truth table", () => {
    for (const row of bits.algebra) {
      const held = ScopeSet.fromBits(row.held);
      const required = ScopeSet.fromBits(row.required);
      expect(held.isSuperset(required)).toBe(row.is_superset);
      expect(held.toString()).toBe(row.held_text);
    }
  });

  it("keeps read and write independent", () => {
    const readOnly = ScopeSet.single(Scope.Secrets, Access.Read);
    expect(readOnly.contains(Scope.Secrets, Access.Write)).toBe(false);
    const writeOnly = ScopeSet.single(Scope.Secrets, Access.Write);
    expect(writeOnly.contains(Scope.Secrets, Access.Read)).toBe(false);
  });

  it("stays unsigned across the whole range", () => {
    // JS bitwise operators are signed int32, so the top bits are where a naive
    // port goes negative. The set only reaches bit 19 today, but ALL must stay
    // positive as the vocabulary grows.
    expect(ScopeSet.ALL.bits).toBeGreaterThan(0);
    expect(ScopeSet.fromBits(0xffffffff).bits).toBeGreaterThan(0);
    expect(ScopeSet.fromBits(0xffffffff).isValid()).toBe(false);
  });

  it("round-trips through toString and parse", () => {
    for (const set of [
      ScopeSet.EMPTY,
      ScopeSet.ALL,
      ScopeSet.single(Scope.Communities, Access.Write),
      ScopeSet.covering([Scope.Deployments, Scope.Billing]),
    ]) {
      expect(ScopeSet.parse(set.toString()).bits).toBe(set.bits);
    }
    expect(ScopeSet.parse("").bits).toBe(0);
    expect(ScopeSet.parse("Deployments:W  Secrets:R").toString()).toBe(
      "deployments:w, secrets:r",
    );
    expect(() => ScopeSet.parse("deployments")).toThrow(/suffix/);
    expect(() => ScopeSet.parse("deploy:r")).toThrow(/unknown scope/);
    expect(() => ScopeSet.parse("secrets:x")).toThrow(/invalid access/);
    expect(() => ScopeSet.parse("secrets:rr")).toThrow(/invalid access/);
  });
});

describe("requiredScopes", () => {
  it("classifies every call the fixture pins, identically", () => {
    for (const row of table.calls) {
      const got = requiredScopes(row.pallet, row.call, []);
      const target = `${row.pallet}.${row.call}`;
      if (row.required === null) {
        expect(got, `${target} must be admitted by no set`).toBeNull();
      } else {
        expect(got?.bits, `${target} requires ${row.required_text}`).toBe(row.required);
      }
    }
  });

  it("scopes no pallet the fixture does not list", () => {
    // The other direction. A pallet the fixture never mentions must admit
    // nothing, whatever the call — this is where token movement, staking,
    // governance and sudo live, and admitting any of them would be the one
    // mistake in this table that actually matters.
    const scoped = new Set(table.calls.map((row) => row.pallet));
    for (const pallet of ["Balances", "Staking", "Sudo", "Proxy", "Utility", "EthSigning"]) {
      expect(scoped.has(pallet), `${pallet} is not a scoped pallet`).toBe(false);
      for (const call of ["transfer_all", "bond", "sudo", "proxy", "batch_all", "anything"]) {
        expect(requiredScopes(pallet, call, []), `${pallet}.${call}`).toBeNull();
      }
    }
  });

  it("reads the two argument-sensitive rows from their arguments", () => {
    const sensitive = table.calls.filter((row) => row.arg_sensitive);
    expect(sensitive.map((row) => `${row.pallet}.${row.call}`)).toEqual([
      "Jobs.request_deployment",
      "Jobs.set_deployment_secret_ref",
    ]);

    const deployOnly = ScopeSet.single(Scope.Deployments, Access.Write);
    const withSecret = deployOnly.with(Scope.Secrets, Access.Read);

    // Clearing a reference needs no read; setting one does.
    expect(requiredScopes("Jobs", "set_deployment_secret_ref", [1, null])?.bits).toBe(
      deployOnly.bits,
    );
    expect(requiredScopes("Jobs", "set_deployment_secret_ref", [1, { None: null }])?.bits).toBe(
      deployOnly.bits,
    );
    expect(requiredScopes("Jobs", "set_deployment_secret_ref", [1, 9])?.bits).toBe(
      withSecret.bits,
    );

    // A readable request with both references cleared is the narrow case.
    expect(
      requiredScopes("Jobs", "request_deployment", [
        { secret_ref: null, tls_secret_ref: null },
      ])?.bits,
    ).toBe(deployOnly.bits);
    expect(
      requiredScopes("Jobs", "request_deployment", [
        { secret_ref: 7, tls_secret_ref: null },
      ])?.bits,
    ).toBe(withSecret.bits);
  });

  it("demands the wider set when the request cannot be read", () => {
    // The fail-safe direction, and the fixture's value for these rows.
    const withSecret = ScopeSet.single(Scope.Deployments, Access.Write).with(
      Scope.Secrets,
      Access.Read,
    );
    for (const args of [[], [undefined], [42], [{ secret_ref: null }], [["positional"]]]) {
      expect(
        requiredScopes("Jobs", "request_deployment", args)?.bits,
        `unreadable request ${JSON.stringify(args)} must take the wider set`,
      ).toBe(withSecret.bits);
    }
  });
});
