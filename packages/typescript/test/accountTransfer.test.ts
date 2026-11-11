// The operator account transfer, replayed from the hand-maintained fixture.
// Expectations come from the fixture and from literals here, never from the planner.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  AgentKeyKind,
  KeyPrincipal,
  MIN_TRANSFER_SPEC_VERSION,
  OrgRole,
  TransferActor,
  TransferRefusal,
  oldAccountHoldsNothing,
  planAccountTransfer,
  planSecretCleanup,
  toSudoBatch,
} from "../src/admin/accountTransfer.js";
import type { CallTree, OldSecretFacts, TransferFacts, TransferStep } from "../src/admin/accountTransfer.js";

type StepRow = [as: string, actor: string, call: string, args: unknown[]];
type Allowance = { plan: string; purchased: string };
type RawFacts = Omit<TransferFacts, "orgs" | "oldTransferable"> & {
  oldTransferable: string;
  orgs: (Omit<TransferFacts["orgs"][number], "oldAllowance" | "newAllowance"> & {
    oldAllowance: { before: Allowance; now: Allowance };
    newAllowance: Allowance;
  })[];
};

const fixture = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../testvectors/account_transfer.json"), "utf8"),
) as {
  min_spec_version: number;
  cases: { name: string; facts: RawFacts; refusals: string[]; unmovable: [string, number][]; steps: StepRow[] }[];
  cleanup: { old: string; oldSecrets: OldSecretFacts[]; steps: StepRow[] };
  sudo_batch: { steps: StepRow[]; tree: CallTree };
};

const amounts = (a: Allowance) => ({ plan: BigInt(a.plan), purchased: BigInt(a.purchased) });

/** The fixture spells amounts as decimal strings; the planner takes bigints. */
const toFacts = (raw: RawFacts): TransferFacts => ({
  ...raw,
  oldTransferable: BigInt(raw.oldTransferable),
  orgs: raw.orgs.map((o) => ({
    ...o,
    oldAllowance: { before: amounts(o.oldAllowance.before), now: amounts(o.oldAllowance.now) },
    newAllowance: amounts(o.newAllowance),
  })),
});

const toRow = (s: TransferStep): StepRow => [s.as, s.actor, `${s.pallet}.${s.call}`, [...s.args]];
const toStep = ([as, actor, call, args]: StepRow): TransferStep => {
  const [pallet, name] = call.split(".");
  return { as: as as TransferActor, actor, pallet, call: name, args };
};

const caseNamed = (fragment: string) => {
  const found = fixture.cases.find((c) => c.name.includes(fragment));
  if (!found) throw new Error(`no fixture case named like "${fragment}"`);
  return found;
};

describe("planAccountTransfer", () => {
  it("pins the first runtime that can hand an organization over", () => {
    expect(MIN_TRANSFER_SPEC_VERSION).toBe(333);
    expect(fixture.min_spec_version).toBe(333);
  });

  it.each(fixture.cases)("$name", (c) => {
    const plan = planAccountTransfer(toFacts(c.facts));
    expect(plan.refusals).toEqual(c.refusals);
    expect(plan.unmovable.map((u) => [u.kind, u.count])).toEqual(c.unmovable);
    expect(plan.steps.map(toRow)).toEqual(c.steps);
  });

  it("uses the enums' wire spellings the fixture is written in", () => {
    expect([TransferActor.Old, TransferActor.New, TransferActor.OrgOwner, TransferActor.Sponsor]).toEqual([
      "old",
      "new",
      "org_owner",
      "sponsor",
    ]);
    expect([OrgRole.Owner, OrgRole.Admin, OrgRole.Member, OrgRole.Viewer]).toEqual(["Owner", "Admin", "Member", "Viewer"]);
    expect([KeyPrincipal.Old, KeyPrincipal.New, KeyPrincipal.None]).toEqual(["old", "new", "none"]);
    expect([AgentKeyKind.ApiKey, AgentKeyKind.SessionKey]).toEqual(["api_key", "session_key"]);
    expect(TransferRefusal.SameAccount).toBe("same_account");
  });

  it("refuses to move an account onto itself", () => {
    const facts = toFacts(caseNamed("owner of an org").facts);
    const plan = planAccountTransfer({ ...facts, new: facts.old });
    expect(plan.refusals).toEqual(["same_account"]);
    expect(plan.steps).toEqual([]);
  });

  it("moves the balance only once what cannot move has been acknowledged", () => {
    const facts = toFacts(caseNamed("member of an org").facts);
    const withWorkload = { ...facts, oldTransferable: 9n, personal: { ...facts.personal, deployments: 1 } };
    expect(planAccountTransfer(withWorkload).refusals).toEqual(["unmovable_not_acknowledged"]);
    const acknowledged = planAccountTransfer({ ...withWorkload, acknowledgedUnmovable: true });
    expect(acknowledged.refusals).toEqual([]);
    expect(toRow(acknowledged.steps.at(-1)!)).toEqual(["old", "5Old", "Balances.transfer_all", ["5New", false]]);
    expect(acknowledged.unmovable.map((u) => [u.kind, u.count])).toEqual([["deployments", 1]]);
  });

  it("has a third-party sponsor move the allowance, not the org's owner", () => {
    const base = toFacts(caseNamed("member of an org").facts);
    const facts: TransferFacts = {
      ...base,
      orgs: base.orgs.map((o) => ({
        ...o,
        sponsor: "5Carol",
        oldAllowance: { before: { plan: 40n, purchased: 0n }, now: { plan: 40n, purchased: 0n } },
      })),
    };
    const rows = planAccountTransfer(facts).steps.map(toRow);
    expect(rows).toContainEqual(["sponsor", "5Carol", "Budgets.set_plan_allotment", ["0xa2", "5New", "40"]]);
    expect(rows).toContainEqual(["sponsor", "5Carol", "Budgets.set_plan_allotment", ["0xa2", "5Old", "0"]]);
    expect(rows.filter(([, , call]) => call === "Budgets.set_purchased_allotment")).toEqual([]);
  });

  it("never lowers an allowance the new account already holds", () => {
    const base = toFacts(caseNamed("owner of an org").facts);
    const facts: TransferFacts = {
      ...base,
      orgs: base.orgs.map((o) => ({ ...o, newAllowance: { plan: 9000n, purchased: 200n } })),
    };
    const rows = planAccountTransfer(facts).steps.map(toRow);
    expect(rows.filter(([, , call, args]) => call.endsWith("_allotment") && args[1] === "5New")).toEqual([]);
    expect(rows).toContainEqual(["new", "5New", "Budgets.set_plan_allotment", ["0xa1", "5Old", "0"]]);
  });

  it("grants from the snapshot and takes away from the live state, independently", () => {
    const base = toFacts(caseNamed("member of an org").facts);
    // The old account's deploy permission is already gone; the new one never got it.
    const lost: TransferFacts = {
      ...base,
      orgs: base.orgs.map((o) => ({
        ...o,
        projects: o.projects.map((p) => ({ ...p, oldDeployer: { before: true, now: false } })),
      })),
    };
    const calls = planAccountTransfer(lost).steps.map((s) => s.call);
    expect(calls).toContain("authorize_project_deployer");
    expect(calls).not.toContain("revoke_project_deployer");
  });

  it("is a fixed point: planning the finished state plans nothing", () => {
    const done = planAccountTransfer(toFacts(caseNamed("nothing left").facts));
    expect(done).toEqual({ steps: [], refusals: [], unmovable: [] });
  });
});

describe("oldAccountHoldsNothing", () => {
  it("is true only for the finished state", () => {
    expect(oldAccountHoldsNothing(toFacts(caseNamed("nothing left").facts))).toBe(true);
    expect(oldAccountHoldsNothing(toFacts(caseNamed("interrupted").facts))).toBe(false);
    expect(oldAccountHoldsNothing(toFacts(caseNamed("owner of an org").facts))).toBe(false);
  });

  it("does not count a secret the new account has not replaced yet as nothing", () => {
    const finished = toFacts(caseNamed("nothing left").facts);
    const pending = { ...finished, oldSecrets: [{ id: "7", grantedToNew: true, replaced: false }] };
    expect(oldAccountHoldsNothing(pending)).toBe(false);
  });
});

describe("planSecretCleanup", () => {
  it("deletes only the secrets the new account has replaced", () => {
    const steps = planSecretCleanup(fixture.cleanup.old, fixture.cleanup.oldSecrets);
    expect(steps.map(toRow)).toEqual(fixture.cleanup.steps);
  });
});

describe("toSudoBatch", () => {
  it("wraps each step in sudo_as inside one batch_all, in order", () => {
    expect(toSudoBatch(fixture.sudo_batch.steps.map(toStep))).toEqual(fixture.sudo_batch.tree);
  });

  it("refuses an empty plan rather than build an empty batch", () => {
    expect(() => toSudoBatch([])).toThrow(/no steps/);
  });
});
