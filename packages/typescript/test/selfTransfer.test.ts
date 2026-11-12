// The self-serve account move, replayed from the hand-maintained fixture.
// Expectations come from the fixture and from literals here, never from the planner.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  SelfTransferPhase,
  SelfTransferRefusal,
  TransferActor,
  planSelfTransfer,
  selfTransferIsComplete,
} from "../src/admin/accountTransfer.js";
import type { TransferFacts, TransferStep } from "../src/admin/accountTransfer.js";

type StepRow = [as: string, actor: string, call: string, args: unknown[]];
type PhaseRow = [phase: string, signer: string, steps: StepRow[]];
type Allowance = { plan: string; purchased: string };
type RawOrg = Omit<TransferFacts["orgs"][number], "oldAllowance" | "newAllowance"> & {
  oldAllowance: { before: Allowance; now: Allowance };
  newAllowance: Allowance;
};
type RawFacts = Omit<TransferFacts, "orgs" | "oldTransferable"> & { oldTransferable: string; orgs: RawOrg[] };

const vector = <T>(name: string): T =>
  JSON.parse(readFileSync(resolve(import.meta.dirname, "../../../testvectors", name), "utf8")) as T;

const operator = vector<{ cases: { name: string; facts: RawFacts }[] }>("account_transfer.json");
const fixture = vector<{
  phase_order: string[];
  cases: {
    name: string;
    facts_from: string;
    orgs_from?: string;
    with?: Partial<RawFacts>;
    kept?: string[];
    refusals: string[];
    phases: PhaseRow[];
    needs_others: StepRow[];
    complete: boolean;
  }[];
}>("self_transfer.json");

const factsNamed = (fragment: string): RawFacts => {
  const found = operator.cases.find((c) => c.name.includes(fragment));
  if (!found) throw new Error(`no account_transfer.json case named like "${fragment}"`);
  return found.facts;
};

const amounts = (a: Allowance) => ({ plan: BigInt(a.plan), purchased: BigInt(a.purchased) });

const factsOf = (c: (typeof fixture.cases)[number]): TransferFacts => {
  const base = factsNamed(c.facts_from);
  const raw: RawFacts = {
    ...base,
    orgs: [...base.orgs, ...(c.orgs_from ? factsNamed(c.orgs_from).orgs : [])],
    ...c.with,
  };
  return {
    ...raw,
    oldTransferable: BigInt(raw.oldTransferable),
    orgs: raw.orgs.map((o) => ({
      ...o,
      oldAllowance: { before: amounts(o.oldAllowance.before), now: amounts(o.oldAllowance.now) },
      newAllowance: amounts(o.newAllowance),
    })),
  };
};

const toRow = (s: TransferStep): StepRow => [s.as, s.actor, `${s.pallet}.${s.call}`, [...s.args]];

describe("planSelfTransfer", () => {
  it("uses the wire spellings the fixture is written in", () => {
    expect(Object.values(SelfTransferPhase)).toEqual(fixture.phase_order);
    expect(Object.values(SelfTransferPhase)).toEqual(["share", "take", "leave", "settle", "close"]);
    expect(Object.values(SelfTransferRefusal)).toEqual([
      "same_account",
      "spec_too_old",
      "new_account_is_agent_key",
      "new_account_has_workspace",
      "old_owns_no_organization",
      "unmovable_not_acknowledged",
    ]);
  });

  it.each(fixture.cases)("$name", (c) => {
    const facts = factsOf(c);
    const plan = planSelfTransfer(facts);
    expect(plan.refusals).toEqual(c.refusals);
    expect(plan.phases.map((p) => [p.phase, p.signer, p.steps.map(toRow)])).toEqual(c.phases);
    expect(plan.needsOthers.map(toRow)).toEqual(c.needs_others);
    expect(selfTransferIsComplete(facts, c.kept ?? [])).toBe(c.complete);
  });

  it("every step of a phase is signed by that phase's one account, and the phases come in the fixed order", () => {
    for (const c of fixture.cases) {
      const plan = planSelfTransfer(factsOf(c));
      const order = plan.phases.map((p) => fixture.phase_order.indexOf(p.phase));
      expect(order).toEqual([...order].sort((a, b) => a - b));
      for (const phase of plan.phases) {
        expect(phase.steps.length).toBeGreaterThan(0);
        expect(new Set(phase.steps.map((s) => s.as))).toEqual(new Set([phase.signer]));
        expect([TransferActor.Old, TransferActor.New]).toContain(phase.signer);
      }
    }
  });

  it("the old account's balance is the last thing it sends", () => {
    const leaving = fixture.cases.flatMap((c) => planSelfTransfer(factsOf(c)).phases).filter((p) => p.signer === "old");
    const withBalance = leaving.filter((p) => p.steps.some((s) => s.call === "transfer_all"));
    expect(withBalance.length).toBeGreaterThan(0);
    for (const phase of withBalance) {
      expect(phase.phase).toBe("leave");
      expect(phase.steps.at(-1)?.call).toBe("transfer_all");
    }
  });
});
