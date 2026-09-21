# Releasing MatterSDK

One tag releases every binding at one version: both npm packages, the PyPI wheels, the Go
module, and the C-ABI archives on the GitHub Release. Rust consumers depend on the tag
itself ([why](README.md#install)). The workflow is
[`.github/workflows/release.yml`](.github/workflows/release.yml):

```
gate -> ci -> build -> verify -> [approval] -> publish -> github-release -> postflight
```

**Public registries never let a version be replaced.** Everything before the approval can
be re-run freely; publishing is the one irreversible step, which is why it is last, why
it uploads the exact bytes that were verified rather than rebuilding, and why a person
approves it.

## Cutting a release

1. **Describe it.** Add a `## [X.Y.Z]` section to [`CHANGELOG.md`](CHANGELOG.md). A
   release candidate is described by its final version's section — there is no
   `[X.Y.Z-rc.1]` heading.
2. **Set the version** — the only way it is ever changed:
   ```bash
   scripts/set-version.sh X.Y.Z        # or X.Y.Z-rc.N — no other shape is accepted
   ```
   It writes every manifest, the five lockfiles, the Go examples and the README, then
   runs `scripts/check-versions.sh`. Commit the result and merge it to `main`.
3. **Dry-run it.** Actions → Release → *Run workflow* on `main`. This runs gate, build and
   verify exactly as a release does, on all six platforms, and publishes nothing. Do not
   tag until it is green.
4. **Tag the merged commit and push the tag:**
   ```bash
   git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
   ```
   If the tag and the manifests disagree, the gate fails in seconds. Fix it with a **new**
   version — a pushed tag is never moved or deleted (the Go proxy caches it forever, and a
   ruleset forbids it).
5. **Approve.** When verify is green the three publish jobs wait on the `release`
   environment; one approval releases all three. Before approving, check that every
   verify job passed and that the job summary's tarball checksums are what you expect.
6. **Done means postflight is green**: the same consumer tests, run against the real
   registries on every platform. Until then the release is not finished.

Release candidates (`vX.Y.Z-rc.N`) go through the identical pipeline. npm publishes them
under the `next` dist-tag so `latest` does not move; PyPI and Go treat them as
pre-releases, which `pip` and `go get` skip unless asked.

## When something fails

**Before the approval:** fix it and re-run, or cut a new tag. Nothing has been published.

**During publishing:** use *Re-run failed jobs*. Each publisher first classifies what its
registry already holds ([`scripts/lib-registry-state.sh`](scripts/lib-registry-state.sh)):
`ABSENT` → publish, `SAME` (byte-identical) → nothing to do, `DIFFERENT` → stop. Workflow
artifacts persist across re-runs, so the retry ships the same verified bytes. If the npm
core published and the client did not, leave the core: it is a complete, verified
package, and the re-run publishes only the client.

**A bad version is already public.** It cannot be replaced; release a fixed version, then
mark the bad one:

| Registry | Command | Effect |
|---|---|---|
| npm | `npm deprecate @openmatter-network/<pkg>@X.Y.Z "<reason>"` | Warns on install. (Unpublish is possible for 72 h, but the version number stays burned.) |
| PyPI | *Yank* the release in the project's web UI | `pip` skips it unless pinned exactly. |
| Go | Add `retract vX.Y.Z // <reason>` to `go.mod` and release | `go get` skips it; the proxy still serves it to existing users. |
| GitHub | Edit the Release | Notes and assets are editable. |

## One-time setup

These live outside the repository and must exist before the first tag.

**npm** — the organisation `openmatter-network` must exist and own the
`@openmatter-network` scope. After the first publish (below), on **each** of the two
packages: Settings → Trusted publisher → GitHub Actions, with organisation
`OpenMatter-Network`, repository `matter-sdk`, workflow `release.yml`, environment
`release`. Spell the organisation exactly: npm's provenance check is case-sensitive, and
so is `scripts/check-npm-tarball.sh` about `repository.url`.

**PyPI** — a *pending* trusted publisher (Account → Publishing): project `matter-sdk`,
owner `OpenMatter-Network`, repository `matter-sdk`, workflow `release.yml`, environment
`release`. A pending publisher does **not** reserve the name, so create it shortly before
the first release candidate.

**GitHub, this repository**
- Environment `release`: required reviewers; deployment branches and tags restricted to
  `v*`; secret `GO_REPO_DEPLOY_KEY`.
- A tag ruleset on `v*` that blocks updates and deletions.
- Secret `DEPS_PAT`: a fine-grained token, resource owner `OpenMatter-Network`,
  repositories `matter-crypto` and `matter-kgc` only, permission *Contents: read-only*.
  It does nothing else — npm and PyPI publishing use OIDC and store no token anywhere.
  **Expiry: record the date here when it is minted: `____-__-__`.** An expired token is
  what turned every workflow red from 2026-09-08; `fetch-core-crates` now fails at once,
  naming the repository it cannot read.

**GitHub, `OpenMatter-Network/matter-sdk-go`** — public, with an initial commit on `main`
(the first proxy lookup of an empty repository fails, and the failure is cached), a
deploy key **with write access** whose private half is `GO_REPO_DEPLOY_KEY`, and the same
`v*` tag ruleset. Nothing is ever committed there by hand: the release workflow replaces
the whole tree from [`scripts/assemble-go-module.sh`](scripts/assemble-go-module.sh).

**Before the first public release, confirm** that the licence of the private
`matter-crypto` and `matter-kgc` crates permits distributing their compiled form inside
Apache-2.0 packages, and that the strings visible in the archives are acceptable:
`strings libmatter_sdk_ffi_*.a | grep -i matter-crypto`.

## The first release (bootstrap)

npm can only configure a trusted publisher on a package that already exists, so the very
first npm publish is done by a person — with the tarballs CI built and verified, not a
local build:

1. Push `vX.Y.Z-rc.1`. The run stops at the approval.
2. Download the `npm-tarballs` artifact; check its sha256 against the job summary.
3. Publish the core, then the client, with your own 2FA-protected login:
   ```bash
   npm publish openmatter-network-matter-sdk-core-X.Y.Z-rc.1.tgz --tag next
   npm publish openmatter-network-matter-sdk-X.Y.Z-rc.1.tgz --tag next
   ```
4. Configure the trusted publisher on both packages (above), then approve the run.
   `publish-npm` finds both packages `SAME` and moves on; PyPI converts its pending
   publisher; the Go module gets its first tag.
5. Push `vX.Y.Z-rc.2`. This one proves the token-less path end to end, with nobody
   involved. If it fails, nothing is published.
6. Release `vX.Y.Z`. Then set both npm packages to *require two-factor authentication
   and disallow tokens*.

Keep rc.1 → final short: until a final release exists, `pip` and `go get` fall back to the
newest pre-release.

**Never publish from a package directory.** `prepublishOnly` refuses, deliberately: only
the CI-built tarball has been checked and smoke-tested.

## Adding a platform

Add a row to [`scripts/native-targets.json`](scripts/native-targets.json). The build and
smoke matrices, the Go module's generated `link.go`, the expected wheel set and the
README table all derive from it; run `scripts/platform-table.sh` to refresh the README
block, and dry-run the release. `scripts/build-ffi-staticlib.sh` fails if the row's
`ldflags` omit a library rustc says the archive needs.
