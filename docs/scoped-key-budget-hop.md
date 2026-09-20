# Scoped keys: the budget hop (matter-node spec 325) — SDK work

Status: `[ ]` todo · `[~]` in progress · `[x]` done. Written 2026-09-11 from
matter-node `main` (runtime built and unit-tested, not yet enacted on any
network). Source of truth for the wire contract: `matter-node/docs/api-keys.md`,
section "Deploying into a project (the budget hop)". Companion to
[`scoped-api-keys.md`](scoped-api-keys.md), which this extends.

## Contract change

Until spec 325 a member-tied key could act only *as its member*. A deployment
it requested was owned by the member and billed to the member, and did not
belong to any project. A human member deploys into a project differently:
through the `Deploy` proxy an Owner/Admin registered for them on the
**project budget account** (`Budgets.authorize_project_deployer`, call 4). The
deployment is then owned and billed by the budget, because `pallet-jobs`
records the *signer* as owner. `ResourceRequest.treasury` is only echoed back.

From spec 325 a key follows its member there with exactly one extra hop:

```
Proxy.proxy(real = principal, force_proxy_type = None,
  call = Proxy.proxy(real = budget, force_proxy_type = Some(Deploy), call))
```

- `budget` is `BudgetsApi_project_budget_account(project)`. It is a pure
  derivation, so cache it for the life of the client. It must be a
  *registered* budget, one that has had a deployer authorized.
- `force_proxy_type` must be **exactly** `Some(Deploy)`. `None` or any other
  type is refused.
- The key needs `required_scopes(call) ∪ deployments:w`.
- `call` must also be a call the `Deploy` proxy admits: `Jobs`, `Volumes`,
  `Secrets`, `OverlayNetworks`, `Collaborations` or `Datasets`, intersected
  with the table (so `EthSigning` and `IpLookup` stay out). The key's filter
  checks this up front, so a hop around, say, `Organizations.add_member` is
  refused before it can be billed.
- A second hop inside the hop is refused, and so is a batch inside it. A
  **top-level** `Utility.batch_all` of hops into one budget is sponsored as
  one uniform batch.
- `call` runs **as the budget**. Gas and hosting are the project's: its org
  treasury pays on demand, bounded by the project spend cap
  (`BudgetsApi_project_spend`, `BudgetsApi_project_credit`). Neither the
  member nor the key is charged.
- The member's `Deploy` delegation is checked live. The key loses the hop
  the moment the member stops being a deployer on that project.
- Nothing clients encode changes: no call index, type or storage change, and
  `transaction_version` stays 9.

### Outcomes, as seen in the key's extrinsic

Pinned by the runtime test
`agent_key_budget_hop_deploys_into_the_project_as_the_budget`.

| Situation | Extrinsic | `Proxy.ProxyExecuted` events, in order | SDK error |
|---|---|---|---|
| success | `Ok` | `Ok` (the budget ran `call`), then `Ok` | — |
| `call` itself fails | `Ok` | `Err(<call's error>)`, then `Ok`. **The outer event does not carry the failure** | `Dispatch` |
| the member is no longer a deployer on the project | `Ok` | one: `Err(Proxy.NotProxy)` | new `NotProjectDeployer { project }` |
| the key lacks the scopes, or `call` is not deployable | `Ok` (if a funded payer existed), else pool `Payment` | one: `Err(System.CallFiltered)` | `NotPermitted` (normally caught locally) |
| the key was revoked | fails `Proxy.NotProxy` | none | `KeyRevoked` (existing path) |

In every row the **first** `ProxyExecuted` decides the outcome. `NotProxy`
*inside* the event means the member lost the project; `NotProxy` as the
extrinsic's *own* error means the key was revoked.

## Detection

The hop changes no metadata, so the rule in `scoped-api-keys.md` ("nothing
here is gated on a version number") cannot hold for it. There is no metadata
fact to read. Gate on `runtimeVersion.specVersion >= 325`
(`state_getRuntimeVersion`), and below that refuse a project-targeted call
locally with a typed `Unsupported { feature: "budget hop", min_spec_version: 325 }`.
Record this in "Deviations" as deliberate.

The fact-based alternative is to probe `PaymasterApi_fee_payer(key, hop)`,
which names the budget from spec 325 and the key before it. It costs a round
trip and needs a real budget, so keep it as a diagnostic, not the gate.

## Work items

- [ ] **`Deployments` façade** (`crates/matter-sdk/src/chain/facade.rs:175-190`).
  Add a project target to `request`, `cancel` and the `set_*` calls
  (`Deployments::in_project(project)` or a `project: Option<ProjectId>`
  argument; follow whichever idiom the façade already uses):
  - resolve `budget` via `BudgetsApi_project_budget_account`
  - in `Delegated` mode, wrap as the hop
  - in `Direct` mode (a human seed that is a project deployer), wrap as
    `Proxy.proxy(budget, Some(Deploy), call)`, the dashboard's own shape
  - without a project, behaviour is unchanged (the deployment is the
    principal's)
- [ ] **Wrapping** in `MatterClient::tx` (`crates/matter-sdk/src/chain/mod.rs:508`).
  Make the wrap target explicit (`Principal` | `Budget { budget }`) instead
  of the fixed principal wrap. The hop's inner call as a dynamic `Value`:

  ```
  Value::unnamed_variant("Proxy", [Value::named_variant("proxy", [
      ("real",             Value::unnamed_variant("Id", [Value::from_bytes(budget)])),
      ("force_proxy_type", Value::unnamed_variant("Some", [Value::unnamed_variant("Deploy", [])])),
      ("call",             inner_call_value),
  ])])
  ```

  The outer call stays `Proxy.proxy(Id(principal), None, <that>)`, signed by
  the key.
- [ ] **Local scope mirror**:
  - Files: `crates/matter-sdk/src/chain/scopes_table.rs`, the TS
    (`packages/typescript/src/scopes.ts`), Python
    (`bindings/python/python/matter_sdk/scopes.py`) and Go
    (`packages/go/mattersdk/scopes.go`) ports, and
    `testvectors/required_scopes.json`.
  - Add `hop_requirement(pallet, call, args) = required_scopes(..) ∪ deployments:w`,
    returning `None` for a pallet outside the `Deploy` list above.
  - A raw `("Proxy", "proxy")` stays `None`, as
    `unscoped_pallets_are_never_admitted` pins; the hop is a separate entry
    point, not a table row.
  - New vectors:
    - hop + `request_deployment` → `2` (`deployments:w`)
    - hop + secret-bearing `request_deployment` → `18`
    - hop + `Volumes.delete_volume` → `130`
    - hop + `Organizations.add_member` → `null`
- [ ] **Receipts.** The first `ProxyExecuted` decides the outcome (see the
  table).
  - Rust `inner_dispatch_error` (`mod.rs:749`, `.find`), TS `wrappedFailure`
    (`packages/typescript/src/polkadot.ts:434`, returns on the first)
    and Python (`bindings/python/python/matter_sdk/chain.py:447-452`,
    returns on the first) are all correct today, but only because of
    emission order.
  - Go `parseOutcome` (`packages/go/mattersdk/receipt.go:171-179`) keeps
    any `Err`, which is also correct.
  - Pin it in each binding with a two-event fixture,
    `[Err(Jobs.InvalidSkuRequested), Ok]`, which must surface as a dispatch
    error. A refactor to "last event wins" would then fail a test instead of
    reporting success for a failed deploy.
  - `TxReceipt.events` should include the inner events.
- [ ] **Error mapping** (the SDK error column above):
  - `NotProxy` **inside** `ProxyExecuted` under a hop maps to the new
    `NotProjectDeployer { project }`. It must **not** go through
    `refresh_delegation` / `KeyRevoked`: the key is fine, the member lost
    the project.
  - `NotProxy` as the extrinsic's error keeps today's `outer_dispatch_error`
    path (`mod.rs:728`).
  - A pool `Payment` rejection for a hop means the project's credit or cap
    is spent. Report `ProjectUnfunded { project }` with
    `BudgetsApi_project_credit`, not `Unsponsored { principal }`.
- [ ] **Docs.**
  - `docs/client-guide.md`, "Keys and scopes": add "Deploying into a
    project".
  - `docs/parity.md`: new rows for the project target, hop wrapping,
    `hop_requirement`, `NotProjectDeployer` and the version gate, across
    Rust, TS, Python and Go. wasm is n/a.
  - `docs/agent-credential-delivery.md`: a key that deploys needs its
    member to be a deployer on the project; the dashboard should say so at
    mint.
- [ ] **Tests.**
  - Unit: the exact hop encoding; the version gate below 325; the new
    vectors in every binding.
  - Dev node (`crates/matter-sdk/tests/scoped_keys_dev.rs`, matter-node
    at spec ≥ 325), mirroring the runtime smoke test:
    1. Alice creates an org and a project.
    2. Bob is added as a `Member`, assigned to the project, and authorized
       with `authorize_project_deployer`.
    3. Bob mints Ferdie with `deployments:w`.
    4. Ferdie, unfunded, deploys into the project. The deployment's
       `DeploymentQueued.requester` is the budget and the project pays.
    5. Revoke Bob's deployer and expect `NotProjectDeployer`.
    6. Revoke the key and expect `KeyRevoked`.

## Sequencing

1. matter-node spec 325 enacted on testnet, then mainnet. The metadata is
   re-exported for the spec bump; no types change.
2. SDK release carrying the project target, gated on spec ≥ 325. It is safe
   against older networks, which refuse locally with `Unsupported`.
3. datavizor copy: `Deployments` now covers every project the member can
   deploy to.

## Open questions

- Should the façade default to a project when the member deploys to exactly
  one? Recommendation: no. An implicit billing target is the surprising
  kind of default; make the project explicit.
