# matter-node: `jobs.set_deployment_volumes` (spec 326)

Handoff from `matter-node` (2026-09-11). Nothing here is urgent: the call is
additive and the SDK passes `ResourceRequest` through as a dynamic value, so
only the **scopes tables** need a line.

## What landed on chain

`jobs.set_deployment_volumes(deployment, volumes: Option<Vec<VolumeRequest>>)`
— call index **19**, `spec_version` 326, `transaction_version` unchanged (9),
no storage migration.

Owner-only, `ContainerRequest` deployments only. It replaces the deployment's
**whole volume list** in place: attach, detach, re-point (a new image digest, a
different volume at the same target) and reconfigure (`read_only`, `target`)
are all expressed as the new list, and `None` detaches everything. The
deployment id, image, env, secrets, overlay address, WireGuard peers, TLS route
and billing are preserved.

Emits `DeploymentVolumesUpdated { deployment }`; the assigned provider recreates
the pod once.

## What to change here

Add `set_deployment_volumes` beside `set_deployment_launch` /
`set_deployment_policy_root` in all three scopes tables — it needs
`Deployments:Write`, the same as the other `set_deployment_*` calls:

- `packages/typescript-client/src/scopes.ts`
- `crates/matter-vault/src/chain/scopes_table.rs`
- `bindings/python/python/matter_vault/scopes.py`

The runtime's own table (`runtime/src/configs/budgets.rs::required_scopes`) is
already updated, and a runtime test pins the admitted set, so a drift here is
a client-side rejection only.

## The one behavioural rule worth surfacing to callers

Volume-side changes do **not** reach a running deployment on their own.
`update_volume`, `restore_backup` and a swapped `storage_secret` change the
manifest, but the deployment keeps its current mount and its assign-time secret
grants until its owner re-applies the list.

**Re-sending the current list is the refresh that applies them.** It re-derives
the volume-secret grants from current volume state and makes the provider
resolve every volume again. This matters most for a rotated `storage_secret`:
without the refresh the new secret is never granted to the deployment and its
next restart fails to recover the backend credentials.

Recommended sequencing for a content update:

```
utility.batch_all([
  volumes.update_volume(...),   // resets the volume to Preparing
  volumes.confirm_ready(id),
])
jobs.set_deployment_volumes(deployment, <same list>)   // per deployment
```

Batching keeps the window where a finalized block shows the new `content_root`
unconfirmed at zero — a deployment restarting in that window would try to
attach content that is not confirmed yet.

Full contract: `docs/persistent-volumes.md` §9 in matter-node.

## Validation the call applies (all pre-existing rules, now also on updates)

| Rule | Error |
|---|---|
| targets non-empty and unique | `EmptyVolumeTarget`, `DuplicateVolumeTarget` |
| Docker-safe `name` on volumes that become Docker named volumes (`[A-Za-z0-9][A-Za-z0-9_.-]*`) | `InvalidVolumeName` |
| image volumes pinned by manifest digest | `InvalidImageVolumeReference` |
| every `Persistent` volume exists, owned by caller, `Ready` | `VolumeNotFound`, `VolumeOwnerMismatch`, `VolumeNotReady` |
| no pre-`StorageVersion(1)` config-bound secret on the deployment | `LegacySealedSecretBoundToConfig` |

`InvalidVolumeName` is **new** and also applies to `request_deployment`: an
empty or non-Docker-safe volume name is now refused at request time rather than
failing later as an opaque container-create error on the provider.
