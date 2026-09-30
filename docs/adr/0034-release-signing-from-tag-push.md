# ADR-0034: Release artifacts are signed only in the tag-push run of publish.yml

- **Status**: Proposed
- **Date**: 2026-09-30

## Context
Releases publish the console and agent images to GHCR and, from phase 7, the agent `.deb` files, the
deployment bundle (`deploy/` at the tag), `image-digests.txt` and a `SHA256SUMS` list. Everything is
signed with cosign in keyless mode: the Fulcio certificate names the GitHub workflow that ran, as
`https://github.com/<owner>/<repo>/<workflow path>@<ref>` (for a reusable workflow, the called
workflow's path with the caller's ref), and users check that identity with `cosign verify`
([RELEASE.md](../../RELEASE.md), [deploy/README.md](../../deploy/README.md)). No ADR covers the
release process so far: it is described in RELEASE.md only.

Until now `release.yml`, triggered by `pull_request: closed` on `main`, called `publish.yml` as a
reusable workflow, and a pre-release tag push also triggered `publish.yml`. Regular releases were
therefore signed as `publish.yml@refs/pull/<N>/merge`, which is not predictable before the release.
The documented check was a pattern (`…/publish.yml@refs/`) that accepts **any ref**. Anyone who can
run `publish.yml` from a ref of their choice gets `id-token: write`, `packages: write` and
`contents: write`, and produces signatures that pattern accepts. That covers a contributor with
write access or a leaked token pushing a branch with a modified `publish.yml`, a same-repository
pull request to `main` whose `release.yml` drops the `merged` guard, then gets closed, and a
compromised action in either workflow (PR #86 security review, H1).

## Decision
1. **One signing context.** `publish.yml` runs only on the push of a release tag (`X.Y.Z` or
   `X.Y.Z-…`), and checks that it was started that way. It is no longer a reusable workflow, and
   nothing calls it. `release.yml` keeps computing the version, the changelog, the release commit
   and the draft release; release-it pushes the `X.Y.Z` tag with `RELEASE_TOKEN` (a personal token,
   so the push triggers workflows), and that push starts `publish.yml`. Pre-release tags keep being
   pushed by a maintainer.
2. **Exact identity.** Every signature of a release carries
   `https://github.com/Yil00/databastion/.github/workflows/publish.yml@refs/tags/<version>`, with the
   GitHub issuer and the workflow trigger `push`. Users verify with `--certificate-identity` (exact
   string, not a pattern), `--certificate-oidc-issuer https://token.actions.githubusercontent.com` and
   `--certificate-github-workflow-trigger push`, for images and for `SHA256SUMS`.
   `publish.yml` runs the same checks on what it has just signed, plus the workflow commit.
3. **Who can start a signing run.** A tag ruleset restricts the creation, update and deletion of
   `*.*.*` tags to repository admins (the maintainers; release-it's push through the owner's token
   bypasses as admin). The jobs of `publish.yml` that push images or sign (`build`, `manifest`,
   `release-assets`) run in the GitHub Environment `release`, whose deployment rule only admits
   version tags and whose required reviewers approve each release. These are repository settings,
   made by the maintainer; RELEASE.md lists them as release prerequisites.
4. **No shared state in release builds.** Release image builds use no build cache (`no-cache`,
   fresh base image pulls), so nothing another workflow wrote into the GitHub Actions cache can end
   up in a release. CI keeps its caches under scopes the release never reads. A pull-request job
   (`packaging.yml`, `publish-dry-run`) runs the release build configuration without a push.
5. **Assets are attached to drafts only.** `publish.yml` refuses to change the assets of a published
   release, and moves the `next` / `X.Y` / `latest` tags only after the signature and the SBOM /
   provenance attestations of the new index are verified.

## Consequences
- The identity users check is fully determined by the version they install. A signature made from a
  branch, a pull request ref or a manually dispatched run no longer verifies.
- The security of the chain now rests on the tag ruleset, the `release` environment and the
  protection of `RELEASE_TOKEN`. Until the maintainer has configured the ruleset and the
  environment, anyone with write access can still push a tag and start a signing run: RELEASE.md
  makes their configuration a release prerequisite and a pre-release checklist item.
- A regular release now needs an approval of the `release` environment jobs, in up to three waves
  (image builds, signature, release assets).
- Release builds take longer without a cache (the Rust and Next.js builds run in full).
- If release-it's tag push does not trigger workflows (for example if `RELEASE_TOKEN` is replaced by
  the default `GITHUB_TOKEN`), nothing is published. The failure is visible (no publish run, draft
  without assets), and pushing the tag again as a maintainer is not possible because tags are never
  moved: re-run release-it or publish a new patch version.
- `workflow_dispatch` re-runs of a failed release are not possible. A failed publish run is re-run
  from its own page (same tag, same identity).

## Rejected alternatives
- **Keep the reusable call and verify with a pattern restricted to `refs/pull/[0-9]+/merge` and
  `refs/tags/`**: any pull request ref would still match, and a closed pull request can reach a
  modified `release.yml`.
- **Sign in `release.yml` itself**: its trigger is `pull_request`, whose ref is the pull request's
  merge ref: the same unpredictable identity.
- **Long-lived signing keys** (cosign key pair in a secret): a key to protect, rotate and revoke,
  and a leaked key signs anything, anywhere. Keyless signing with an exact workflow identity and
  Rekor transparency avoids both.
- **GitHub artifact attestations only** (`actions/attest-build-provenance`): useful, but they rely on
  the same workflow identity. They could be added later, next to cosign, with the same exact-ref
  check.
