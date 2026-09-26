# Resources

The `resources` façade is the provider side of the network. Use it to register machines
you operate, publish capacity and pricing, and control who may deploy onto a private
resource. Each method signs, waits for finalization, and returns a
[receipt](chain-surface.md#receipts-and-events).

## Methods

| Method | Pallet call | Notes |
|---|---|---|
| `register` | `Resources.register_resource` | Takes the resource's account id, an ownership proof (the runtime's type, passed as a value), and a display name. Scoped key: `resources:w` |
| `update_sku` | `Resources.update_sku` | Publishes or updates a SKU's pricing. Root-signed; returns `NeverAdmitted` from a scoped key |
| `report_capacity` | `Resources.report_capacity` | Reports current capacity. Provider-signed; returns `NeverAdmitted` from a scoped key |
| `set_privacy` | `Resources.set_resource_privacy` | `true` restricts deployment to whitelisted accounts. Scoped key: `resources:w` |
| `allow` | `Resources.add_to_whitelist` | Lets an account use a private resource. Scoped key: `resources:w` |
| `disallow` | `Resources.remove_from_whitelist` | Removes an account's whitelist entry. Scoped key: `resources:w` |

TypeScript camelCases these names (`setPrivacy`) and Go PascalCases them (`SetPrivacy`).
Rust takes account ids as `AccountId`, TypeScript as 32-byte `Uint8Array`, Python as an
address string, and Go as `[]byte`. Sign `update_sku` and `report_capacity` with the
provider's or root account directly, never through a
[scoped key](keys-and-scopes.md#scoped-keys).

```rust
let resources = client.resources();
resources.register(resource, ownership_proof, "gpu-rack-7").await?;
resources.set_privacy(resource, true).await?;
resources.allow(resource, customer).await?;
```

```ts
await client.resources.register(resource, ownershipProof, "gpu-rack-7");
await client.resources.setPrivacy(resource, true);
await client.resources.allow(resource, customer);
```

```python
client.resources.register(resource, ownership_proof, "gpu-rack-7")
client.resources.set_privacy(resource, True)
client.resources.allow(resource, customer)
```

```go
if _, err := client.Resources().Register(resource, ownershipProof, "gpu-rack-7"); err != nil {
	return err
}
if _, err := client.Resources().SetPrivacy(resource, true); err != nil {
	return err
}
_, err := client.Resources().Allow(resource, customer)
```

## Private resources

A private resource accepts only deployments from accounts on its whitelist. A deployment
request can also restrict itself with the `private_resources_only` and
`allowed_resources` fields of its `ResourceRequest`; see
[Deployments](deployments.md#requesting-a-deployment).

## Other `Resources` calls

Every other `Resources` extrinsic is reachable by name through
[`tx`](chain-surface.md): `register_private_resource`, `register_org_resource`,
`suspend_resource`, `reactivate_resource`, `update_resource_name` and
`remove_resource` (all `resources:w` for a scoped key). Consumption reporting, SKU
removal and provider minimum stake are provider- or root-signed and return
`NeverAdmitted` from a scoped key. See [Errors](errors.md).
