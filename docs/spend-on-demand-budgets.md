# Spend-on-demand budgets (matter-node spec 323) — SDK work

Status: `[ ]` todo · `[~]` in progress · `[x]` done. Written 2026-09-07 from
the matter-node `budget-refactor` branch (built + tested, not yet enacted).

## Contract change

matter-node spec 323 / `transaction_version` 10 retires the budget
pre-funding calls: `Budgets.allot` (call 1), `set_plan_allotment` (11),
`add_purchased_allotment` (12), `set_purchased_allotment` (13) no longer
exist. A project budget account is now a zero-balance billing identity; its
org treasury pays gas and hosting fees on the fly, bounded by an optional
per-project cap set with the new `Budgets.set_project_spend_cap(org: [u8;32],
project: [u8;32], cap: Option<u128>)` (call 23, org Owner/Admin). The new
`BudgetsApi_project_spend(project) -> (spent: u128, cap: Option<u128>)`
(API v3) exposes usage against the cap. Events `Allotted` /
`PlanAllotmentSet` / `PurchasedAllotmentSet` are replaced by
`ProjectCharged { org, project, payer, amount, kind: Gas | Hosting }` and
`ProjectSpendCapSet { org, project, cap }`.

Proxied dispatch (`proxy.proxy(real = budget, inner)`) is unchanged, so
`authorize_secrets_agent` / `revoke_secrets_agent` and every vault call keep
working. A proxied call whose project credit cannot cover the fee is now
rejected with `InvalidTransaction::Payment` at submission (no signer
fallback).

## Work items

- [ ] `crates/matter-vault/src/chain/facade.rs:410-420`: remove `allot`; add
      `set_project_spend_cap` and a `project_spend` read (runtime API).
- [ ] Mirror in every binding: `bindings/python/python/matter_vault/facade.py`,
      `packages/typescript-client/src/facade.ts`,
      `packages/go/mattervault/facade.go`.
- [ ] `testvectors/facade_calls.json`, `crates/matter-vault/tests/facade_calls.rs`,
      `crates/matter-vault/tests/live_chain.rs`: drop the `allot` vectors, add
      the cap call; keep `docs/parity.md` in step.
- [ ] Regenerate the vault's subxt metadata from a spec-323 node
      (`transaction_version` 10: stale metadata is rejected at submission).
- [ ] `docs/client-guide.md`: replace any "fund the project budget" step with
      "fund the org treasury; optionally set a project cap".
