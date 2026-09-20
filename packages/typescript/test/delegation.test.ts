import { describe, expect, it } from "vitest";

import { afterRefresh, isPoolRejection } from "../src/delegation.js";
import { Access, Scope, ScopeSet } from "../src/scopes.js";

const account = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

describe("afterRefresh", () => {
  const narrow = ScopeSet.single(Scope.Deployments, Access.Write);
  const wider = narrow.with(Scope.Secrets, Access.Read);
  const held = { principal: account(1), scopes: narrow };

  it("reports a revoked grant as gone", () => {
    expect(afterRefresh(held, undefined)).toEqual({ outcome: "gone" });
  });

  it("reports a key rebound to another member as gone", () => {
    expect(afterRefresh(held, [account(2), narrow])).toEqual({ outcome: "gone" });
  });

  it("reports the fresh set when the scopes moved", () => {
    expect(afterRefresh(held, [account(1), wider])).toEqual({
      outcome: "rescoped",
      scopes: wider,
    });
  });

  it("says nothing changed when nothing did", () => {
    expect(afterRefresh(held, [account(1), narrow])).toEqual({ outcome: "unchanged" });
  });
});

describe("isPoolRejection", () => {
  it("recognises the JSON-RPC code", () => {
    expect(isPoolRejection({ code: 1010, message: "Invalid Transaction" })).toBe(true);
  });

  it("falls back to the message when the code is lost", () => {
    expect(isPoolRejection(new Error("Invalid Transaction: Inability to pay some fees"))).toBe(
      true,
    );
  });

  it("does not claim unrelated failures", () => {
    expect(isPoolRejection(new Error("connection reset"))).toBe(false);
    expect(isPoolRejection({ code: 1002, message: "Verification Error" })).toBe(false);
    expect(isPoolRejection(undefined)).toBe(false);
  });
});
