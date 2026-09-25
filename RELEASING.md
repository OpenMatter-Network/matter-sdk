# Releasing MatterSDK

One tag releases every binding at one version: both npm packages, the PyPI wheels, the Go
module, and the C-ABI archives on the GitHub Release. Rust consumers depend on the tag
itself ([why](README.md#install)). The workflow is
[`.github/workflows/release.yml`](.github/workflows/release.yml):

```
gate -> ci -> build -> verify -> [approval] -> publish -> github-release -> postflight
```

**Public registries never let a version be replaced.** Everything before the approval can
be re-run freely. Publishing is last, uploads the exact bytes that were verified (no
rebuild), and needs a person's approval.

## Cutting a release

1. **Describe it.** In [`CHANGELOG.md`](CHANGELOG.md), rename `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD`; the gate refuses a version with no section. A release
   candidate uses its final version's section; there is no `[X.Y.Z-rc.1]` heading.
2. **Set the version** (the only supported way to change it):
   ```bash
   scripts/set-version.sh X.Y.Z        # or X.Y.Z-rc.N — no other shape is accepted
   ```
   It writes every manifest, the five lockfiles, the Go examples and the README, then
   runs `scripts/check-versions.sh`. Commit and merge to `main`.
3. **Dry-run it.** Actions → Release → *Run workflow* on `main` runs gate, build and
   verify on all six platforms and publishes nothing. Do not tag until it is green.
4. **Tag the merged commit and push the tag:**
   ```bash
   git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
   ```
   If the tag and the manifests disagree, the gate fails. Fix it with a **new** version:
   a pushed tag is never moved or deleted (the Go proxy caches it forever, and a ruleset
   forbids it).
5. **Approve.** When verify is green, the three publish jobs wait on the `release`
   environment; one approval releases all three. First check that every verify job passed
   and the job summary's tarball checksums are what you expect.
6. **Done means postflight is green**: the same consumer tests, run against the real
   registries on every platform.

Release candidates (`vX.Y.Z-rc.N`) use the identical pipeline. npm publishes them under
the `next` dist-tag; PyPI and Go treat them as pre-releases, which `pip` and `go get`
skip unless asked.

## When something fails

**Before the approval:** fix it and re-run, or cut a new tag. Nothing has been published.

**During publishing:** use *Re-run failed jobs*. Each publisher classifies what its
registry already holds ([`scripts/lib-registry-state.sh`](scripts/lib-registry-state.sh)):
`ABSENT` → publish, `SAME` (byte-identical) → skip, `DIFFERENT` → stop. Artifacts
persist across re-runs, so the retry ships the same verified bytes. If the npm core
published and the client did not, leave the core; the re-run publishes only the client.

**A bad version is already public.** Release a fixed version, then mark the bad one:

| Registry | Command | Effect |
|---|---|---|
| npm | `npm deprecate @openmatter-network/<pkg>@X.Y.Z "<reason>"` | Warns on install. (Unpublish is possible for 72 h, but the version number stays burned.) |
| PyPI | *Yank* the release in the project's web UI | `pip` skips it unless pinned exactly. |
| Go | Add `retract vX.Y.Z // <reason>` to `go.mod` and release | `go get` skips it; the proxy still serves it to existing users. |
| GitHub | Edit the Release | Notes and assets are editable. |

## One-time setup

These live outside the repository and must exist before the first tag.

**npm**: the organisation `openmatter-network` owns the `@openmatter-network` scope.
After the first publish (below), on **each** package: Settings → Trusted publisher →
GitHub Actions, with organisation `OpenMatter-Network`, repository `matter-sdk`, workflow
`release.yml`, environment `release`. The organisation name is case-sensitive, for npm's
provenance check and for `scripts/check-npm-tarball.sh`'s `repository.url` check.

**PyPI**: a *pending* trusted publisher (Account → Publishing): project `matter-sdk`,
owner `OpenMatter-Network`, repository `matter-sdk`, workflow `release.yml`, environment
`release`. A pending publisher does **not** reserve the name, so create it shortly before
the first release candidate.

**GitHub, this repository**
- Environment `release`: required reviewers; deployment branches and tags restricted to
  `v*`; secret `GO_REPO_DEPLOY_KEY`.
- A tag ruleset on `v*` that blocks updates and deletions.
- Secret `DEPS_PAT`: a fine-grained token, resource owner `OpenMatter-Network`,
  repositories `matter-crypto` and `matter-kgc` only, permission *Contents: read-only*.
  npm and PyPI use OIDC and store no token. Record the token's expiry and rotate it
  before then; an expired token fails every workflow at `fetch-core-crates`, naming the
  repository it cannot read.

**GitHub, `OpenMatter-Network/matter-sdk-go`**: public, with an initial commit on `main`
(a proxy lookup of an empty repository fails and the failure is cached), a deploy key
**with write access** whose private half is `GO_REPO_DEPLOY_KEY`, and the same `v*` tag
ruleset. Never commit there by hand: the release workflow replaces the whole tree from
[`scripts/assemble-go-module.sh`](scripts/assemble-go-module.sh).

## Release gates

The first public release and its announcement wait on all of these; the workflow checks
none of them.

- **An external audit** of the cryptographic core and committee (`matter-crypto`,
  `matter-kgc`, `matter-node`) and of this SDK, with the report published and linked from
  the README and [`SECURITY.md`](SECURITY.md).
- **Every known finding resolved** in its owning repository and deployed to the network
  the announcement points at. Findings owned outside this repository, including erasure
  of superseded key shares after a rotation, are tracked in `matter-kgc`'s remediation
  log.
- **Licensing confirmed:** the licence of the private `matter-crypto` and `matter-kgc`
  crates permits distributing their compiled form inside Apache-2.0 packages, and the
  strings visible in the archives are acceptable:
  `strings libmatter_sdk_ffi_*.a | grep -i matter-crypto`.
- **`OpenMatter-Network/matter-sdk-go` is public**; until it is, `go get` fails.

## The first release (bootstrap)

npm configures a trusted publisher only on an existing package, so the first npm publish
is manual, using the tarballs CI built and verified. Both npm packages exist since
`2.1.2-rc.1`; if their trusted publishers are configured, start at step 5.

1. Push `vX.Y.Z-rc.1`. The run stops at the approval.
2. Download the `npm-tarballs` artifact; check its sha256 against the job summary.
3. Publish the core, then the client, with your own 2FA-protected login:
   ```bash
   npm publish openmatter-network-matter-sdk-core-X.Y.Z-rc.1.tgz --tag next
   npm publish openmatter-network-matter-sdk-X.Y.Z-rc.1.tgz --tag next
   ```
4. Configure the trusted publisher on both packages (above), then approve the run.
   `publish-npm` finds both packages `SAME`; PyPI converts its pending publisher; the Go
   module gets its first tag.
5. Push `vX.Y.Z-rc.2` to prove the token-less path end to end. If it fails, nothing is
   published.
6. Release `vX.Y.Z`. Then set both npm packages to *require two-factor authentication
   and disallow tokens*.

Keep rc.1 → final short: until a final release exists, `pip` and `go get` fall back to the
newest pre-release.

**Never publish from a package directory.** `prepublishOnly` refuses: only the CI-built
tarball has been checked and smoke-tested.

## Adding a platform

Add a row to [`scripts/native-targets.json`](scripts/native-targets.json). The build and
smoke matrices, the Go module's generated `link.go`, the expected wheel set and the
README table derive from it. Run `scripts/platform-table.sh` to refresh the README
block, then dry-run the release. `scripts/build-ffi-staticlib.sh` fails if the row's
`ldflags` omit a library the archive needs.
