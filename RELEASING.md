# Releasing MatterSDK

One tag releases every binding at one version: both npm packages, the PyPI wheels, the Go
module and the C-ABI archives attached to the GitHub Release. Rust consumers depend on the
tag itself, because the crates depend on the private core and cannot go to crates.io. The
workflow is [`.github/workflows/release.yml`](.github/workflows/release.yml):

```
gate -> build -> verify ---+
gate -> ci ----------------+-> [approval] -> publish -> github-release -> postflight
```

**Public registries never let a version be replaced.** Everything before the approval can
be re-run freely. Publishing comes last, uploads the exact bytes that were verified
without rebuilding them, and needs a person's approval.

| Stage | Jobs | Does |
|---|---|---|
| gate | `gate` | Works out the version (`scripts/release-plan.sh`). Refuses the run unless the manifests match it (`check-versions.sh --expect`), `CHANGELOG.md` has a non-empty section for it (`changelog-section.sh`), and the licence copies agree. |
| ci | `ci` | The full CI suite, because a tag can point at a commit CI never saw. Runs alongside the builds; publishing waits for it. |
| build | `build-npm`, `build-wheels`, `build-ffi`, `assemble-go` | Builds every artifact exactly once. These jobs have no publish rights. |
| verify | `verify-npm`, `check-wheels`, `verify-wheels`, `verify-go` | Installs each artifact from outside the repository on every platform it claims to support. |
| publish | `publish-npm`, `publish-pypi`, `publish-go` | Waits on the `release` environment's approval, then uploads the verified bytes. |
| github-release | `github-release` | Creates the Release, with the changelog section as its notes and the C-ABI archives attached. |
| postflight | `postflight-npm`, `postflight-native` | Runs the verify tests again against the real registries. |

## Cutting a release

1. **Describe it.** In [`CHANGELOG.md`](CHANGELOG.md), rename `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD`, then start a new empty `## [Unreleased]` above it.
   - The gate refuses a version whose section is missing or empty.
   - A release candidate uses its final version's section: `2.4.0-rc.1` reads `[2.4.0]`,
     and there is no `-rc` heading.
2. **Set the version.** This is the only supported way to change it:
   ```bash
   scripts/set-version.sh X.Y.Z        # or X.Y.Z-rc.N; no other shape is accepted
   ```
   The script writes every manifest, the five lockfiles, the Go examples and the README's
   Rust install line, then runs `scripts/check-versions.sh`. Commit and merge to `main`.
3. **Dry-run it.** In GitHub, go to Actions → Release → *Run workflow* on `main`. This
   runs gate, build and verify on every platform and publishes nothing. Do not tag until
   it is green.
4. **Tag the merged commit and push the tag.**
   ```bash
   git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
   ```
   If the tag and the manifests disagree, the gate fails. Fix it with a **new** version.
   A pushed tag is never moved or deleted: the Go proxy caches it forever, and a ruleset
   forbids it.
5. **Approve.** When verify is green, the three publish jobs wait on the `release`
   environment, and one approval releases all three. First check that every verify job
   passed and that the tarball checksums in the job summary are the ones you expect.
6. **Wait for postflight.** The release is done only when postflight is green.

Release candidates (`vX.Y.Z-rc.N`) go through the same pipeline. npm publishes them under
the `next` dist-tag. PyPI and Go treat them as pre-releases, which `pip` and `go get` skip
unless asked for.

## When something fails

**Before the approval:** fix it and re-run, or cut a new tag. Nothing has been published.

**During publishing:** use *Re-run failed jobs*. Artifacts persist across re-runs, so the
retry ships the same verified bytes. Each publisher first classifies what its registry
already holds ([`scripts/lib-registry-state.sh`](scripts/lib-registry-state.sh)):

| State | Publisher |
|---|---|
| `ABSENT` | publishes |
| `SAME` (byte-identical) | skips |
| `PARTIAL` (PyPI only: some wheels uploaded, all byte-identical) | uploads the rest |
| `DIFFERENT` | stops |

If the npm core published and the client did not, leave the core alone. The re-run
publishes only the client.

**A bad version is already public.** Release a fixed version first, then mark the bad one:

| Registry | Action | Effect |
|---|---|---|
| npm | `npm deprecate @openmatter-network/<pkg>@X.Y.Z "<reason>"` | Warns on install. Unpublishing is possible for 72 h, but the version number stays burned. |
| PyPI | *Yank* the release in the project's web UI | `pip` skips it unless pinned exactly. |
| Go | Add `retract vX.Y.Z // <reason>` to `packages/go/mattersdk/go.mod` and release | `go get` skips it. The proxy still serves it to existing users. |
| GitHub | Edit the Release | Notes and assets are editable. |

## One-time setup

These live outside the repository and must exist before the first tag.

**npm**
- The organisation `openmatter-network` owns the `@openmatter-network` scope.
- After the first publish ([bootstrap](#the-first-release-bootstrap)), configure a trusted
  publisher on **each** package under Settings → Trusted publisher → GitHub Actions:

  | Field | Value |
  |---|---|
  | Organisation | `OpenMatter-Network` |
  | Repository | `matter-sdk` |
  | Workflow | `release.yml` |
  | Environment | `release` |

- The organisation name is case-sensitive. npm's provenance check and
  `scripts/check-npm-tarball.sh`'s `repository.url` check both compare it exactly.

**PyPI**
- Create a *pending* trusted publisher under Account → Publishing: project `matter-sdk`,
  owner `OpenMatter-Network`, repository `matter-sdk`, workflow `release.yml`,
  environment `release`.
- A pending publisher does **not** reserve the name, so create it shortly before the
  first release candidate.

**GitHub, this repository**
- Environment `release`, with:
  - required reviewers
  - deployment branches and tags restricted to `v*`
  - the secret `GO_REPO_DEPLOY_KEY`
- A tag ruleset on `v*` that blocks updates and deletions.
- The secret `DEPS_PAT`: a fine-grained token with resource owner `OpenMatter-Network`,
  access to the private core repositories only, and *Contents: read-only* permission.
  - npm and PyPI use OIDC and store no token.
  - Record the token's expiry and rotate it before then. An expired token fails every
    workflow at `fetch-core-crates`, and the error names the repository it cannot read.

**GitHub, `OpenMatter-Network/matter-sdk-go`**
- It must be public.
- It needs an initial commit on `main`. A proxy lookup of an empty repository fails, and
  the failure is cached.
- It needs a deploy key **with write access**, whose private half is
  `GO_REPO_DEPLOY_KEY`, and the same `v*` tag ruleset.
- Never commit there by hand. Each release replaces the whole tree with the output of
  [`scripts/assemble-go-module.sh`](scripts/assemble-go-module.sh).

## Release gates

The first public release and its announcement wait on all of these. The workflow checks
none of them, so the person approving the release checks them.

- **An external audit** of the cryptographic core, the committee and this SDK. The report
  must be published and linked from the README and [`SECURITY.md`](SECURITY.md).
- **Every known finding resolved** in the repository that owns it, and deployed to the
  network the announcement points at.
- **Licensing confirmed.** The licence of the private core crates must permit
  distributing their compiled form inside Apache-2.0 packages, and the strings visible in
  the archives must be acceptable:
  `strings libmatter_sdk_ffi_*.a | grep -i matter-crypto`.
- **`OpenMatter-Network/matter-sdk-go` is public.** Until it is, `go get` fails.

## The first release (bootstrap)

npm can only configure a trusted publisher on a package that already exists, so the first
npm publish is manual and uses the tarballs CI built and verified. Both npm packages
already exist at `2.1.2-rc.1`, so once their trusted publishers are configured, start at
step 5.

1. Push `vX.Y.Z-rc.1`. The run stops at the approval.
2. Download the `npm-tarballs` artifact and check its sha256 against the job summary.
3. Publish the core, then the client, logged in with your own 2FA-protected account:
   ```bash
   npm publish openmatter-network-matter-sdk-core-X.Y.Z-rc.1.tgz --tag next
   npm publish openmatter-network-matter-sdk-X.Y.Z-rc.1.tgz --tag next
   ```
4. Configure the trusted publisher on both packages ([one-time setup](#one-time-setup)),
   then approve the run. Three things happen:
   - `publish-npm` finds both packages `SAME` and skips them.
   - PyPI converts its pending publisher.
   - The Go module gets its first tag.
5. Push `vX.Y.Z-rc.2` to prove the token-less path end to end. If it fails, nothing is
   published.
6. Release `vX.Y.Z`. Then set both npm packages to *require two-factor authentication and
   disallow tokens*.

Keep the gap between rc.1 and the final release short. Until a final release exists,
`pip` and `go get` fall back to the newest pre-release.

**Never publish from a package directory.** `prepublishOnly` refuses, because only the
CI-built tarball has been checked and smoke-tested.

## Adding a platform

1. Add a row to [`scripts/native-targets.json`](scripts/native-targets.json). Everything
   else derives from it: the build and smoke matrices, the Go module's generated
   `link.go`, the expected wheel set and the README's platform table.
2. Run `scripts/platform-table.sh` and paste its output between the README's
   `platforms` markers.
3. Dry-run the release.

`scripts/build-ffi-staticlib.sh` fails if the row's `ldflags` leave out a library the
archive needs. On darwin, that includes `-liconv`.
