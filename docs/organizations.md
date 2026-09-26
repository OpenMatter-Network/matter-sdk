# Organizations and budgets

The `orgs` façade covers `Organizations` and `Budgets`: create an organization, manage
its members, fund projects from the org treasury, and choose who may decrypt a
project's secrets. Each method signs, waits for finalization, and returns a
[receipt](chain-surface.md#receipts-and-events).

## Methods

| Method | Pallet call | Notes |
|---|---|---|
| `create` | `Organizations.create_org` | The runtime derives the org id from the signer. Human-signed only; returns `NeverAdmitted` from a scoped key |
| `add_member` | `Organizations.add_member` | Takes an org id, an account, and the runtime's `Role` value. Scoped key: `organization:w` |
| `remove_member` | `Organizations.remove_member` | Scoped key: `organization:w` |
| `allot` | `Budgets.allot` | Moves `amount` plancks from the org treasury to a project. Scoped key: `billing:w` |
| `authorize_secrets_agent` | `Budgets.authorize_project_secrets_agent` | Lets an account decrypt the project's secrets. Member-signed only; returns `NeverAdmitted` from a scoped key |
| `revoke_secrets_agent` | `Budgets.revoke_project_secrets_agent` | Withdraws that authorization. Member-signed only; returns `NeverAdmitted` from a scoped key |

TypeScript camelCases these names (`addMember`) and Go PascalCases them (`AddMember`).
Org and project ids are 32 bytes in every language.

```rust
use matter_sdk::chain::Value;

let orgs = client.orgs();
orgs.add_member(org, member, Value::unnamed_variant("Member", [])).await?;
orgs.allot(org, project, client.parse_amount("100")?).await?;
orgs.authorize_secrets_agent(org, project, agent).await?;
```

```ts
await client.orgs.addMember(org, member, { Member: null });
await client.orgs.allot(org, project, client.parseAmount("100"));
await client.orgs.authorizeSecretsAgent(org, project, agent);
```

```python
client.orgs.add_member(org, member, {"Member": None})
client.orgs.allot(org, project, client.parse_amount("100"))
client.orgs.authorize_secrets_agent(org, project, agent)
```

```go
hundred, err := client.ParseAmount("100")
if err != nil {
	return err
}
if _, err := client.Orgs().Allot(org, project, hundred); err != nil {
	return err
}
_, err = client.Orgs().AuthorizeSecretsAgent(org, project, agent)
```

`Role` is `Owner`, `Admin`, `Member` or `Viewer`. `Owner` is never assigned through
`add_member`. Owners and Admins can add Members and Viewers, and only an Owner can add or
promote an Admin.

## What keys may do here

A [scoped key](keys-and-scopes.md#scoped-keys) can run an organization day to day. It
cannot create authority:

- **Admitted with `organization:w`:** membership, roles and projects: `add_member`,
  `set_member_role`, `remove_member`, `create_project`, `assign_to_project`,
  `unassign_from_project`, `delete_project` and `add_project_deployment_peer`.
- **Admitted with `billing:w`:** budget allotment and limits: `allot`, `defund_project`,
  plan and purchased allotments, member billing and gas limits, and
  `set_project_spend_cap`.
- **Never admitted:** org lifecycle (`create_org`, `delete_org`), roster calls
  (project deployers, secrets agents, resource operators, agent keys), and treasury
  value movers (funding, withdrawal, org stake, sponsorship). A scoped key gets
  `NeverAdmitted` for these, so a key can never mint another key or widen its own
  reach.

Minting and revoking API keys is also a `Budgets` call. It has its own façade,
[`keys`](keys-and-scopes.md#minting-keys).

Reach any `Organizations` or `Budgets` call not covered here by name through
[`tx`](chain-surface.md).
