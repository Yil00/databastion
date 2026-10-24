# ADR-0058: Release automation with one human approval

- **Status**: Proposed
- **Date**: 2026-10-24

## Context
A regular release ([RELEASE.md § 5](../../RELEASE.md#5-release-walkthrough)) needs these manual steps
today:
- one approval of the `release-it` environment, which holds `RELEASE_TOKEN`
  ([release.yml](../../.github/workflows/release.yml));
- three approvals of the `release` environment: the jobs `build`, `manifest` and `release-assets` of
  [publish.yml](../../.github/workflows/publish.yml) each declare `environment: release`, and each
  prompts when it starts;
- the maintainer publishing the draft release by hand, after checking the assets.

The criteria of the [pre-release checklist](../../RELEASE.md#7-pre-release-checklist) are checked by
hand, and the long runs (nightly fuzz, load, engine matrix) were release gates the maintainer read
off run pages (0.8.0: G1, G2, G6; 0.9.0: G-a to G-d).

Pull requests are merged by AI agents under the maintainer's mandate. On 2026-10-24 the maintainer
chose to keep **one** human approval, the `release-it` one, and to replace the others with checks
the workflows run (option A). Zero human approval (option B) was rejected: without a human pause, an
agent or a compromised token could produce a signed release end to end.

Facts this decision relies on, checked on 2026-10-24:
- The releases 0.8.0, 0.8.1, 0.8.2 and 0.9.0 were each a merge commit `M` on `main` whose first
  parent is an ancestor of its second parent, so that the tree of `M` equals the tree of `M^2`; each
  tag is annotated and points to a commit `chore(release): X.Y.Z` with `M` as its only parent, which
  changes only `CHANGELOG.md` and the files of `scripts/bump-version.mjs` (`package.json`,
  `package-lock.json`, `console/package.json`, `agent/Cargo.toml`, `agent/Cargo.lock`,
  `agent/fuzz/Cargo.lock`).
- Scheduled workflows run on the default branch (`main`): the nightly fuzz, weekly load and weekly
  engine matrix runs test `main`, not the next release. The release runs are `workflow_dispatch`
  runs on `dev`. For 0.9.0, the fuzz run (40013969966) and a load run (40023333007) were on `dev`
  commits that later SQL Server connector changes followed; the engine matrix run (40028400957) was
  on the release head.
- An environment approval is enforced only on jobs that declare the environment. Whoever can choose
  the `publish.yml` that a tag runs (an administrator, or the holder of `RELEASE_TOKEN`) can drop the
  `environment:` lines; `id-token: write` and `packages: write` are job permissions, not environment
  ones. The `release` approval therefore never protected against that actor (the
  [§ 6 residual risk](../../RELEASE.md#repository-configuration-one-time) says so for pre-release
  tags); it was a pause on the honest path.
- `RELEASE_TOKEN` is an environment secret of `release-it`, whose deployment rule admits `main` only:
  a job reads it only after the approval, whatever the workflow file says.
- No workflow of the repository listens to `release` events.

## Decision

### 1. The single human approval
1. The `release-it` environment keeps its required reviewers and its `main`-only deployment rule,
   unchanged. Its approval is the only human step of a final release (`X.Y.Z`), regular or hotfix.
2. The approver approves only after reading the `release-criteria` summary (decision 2.6) and
   checking the § 7 items that stay human (decision 2.8). From then on, nothing waits for a human:
   the tag, the signed artifacts and the published release follow.

### 2. Release criteria in `release.yml`
1. A new job `release-criteria` runs before the `release-it` job, which `needs` it. It declares no
   environment and no secret; permissions `contents: read`, `actions: read`, `checks: read`,
   `pull-requests: read`. If a criterion is not met, it prints one `::error::` per failed criterion
   (all criteria are evaluated, naming what is missing and how to fix it) and fails: the
   `release-it` job is skipped, so no approval is requested, no commit is made and no tag is created.
   Once the missing runs exist, *Re-run failed jobs* on the same run evaluates them again (the
   "main has not moved" check of `release-it` still applies).
2. **Identification**, from the pushed commit `M` (`GITHUB_SHA`), every item a criterion:
   - `M` has exactly two parents. `M^1` is the previous `main`, `D = M^2` is the **release head**.
   - The pull request is the one GitHub returns for `M` (`GET /commits/{M}/pulls`) with `merged_at`
     set, `base.ref == main`, `merge_commit_sha == M`, `head.sha == D` and a head repository equal to
     this repository. Exactly one must match.
   - Kind: `head.ref == dev` is a **regular** release; `head.ref` matching `hotfix/*` is a **hotfix**;
     any other head branch fails.
   - The title matches `^release: ([0-9]+\.[0-9]+\.[0-9]+)( \[skip-holdout\])?$`. Its version `V` is
     the job output; a pre-release version is refused (pre-releases are tagged by hand, decision 3.4).
     The `release-it` job fails before any commit when the version release-it computes differs from
     `V`.
   - `M^1` is an ancestor of `D`, and the tree of `M` equals the tree of `D`. A regular release
     therefore needs the previous release and its hotfixes back-merged into `dev`; a hotfix branch
     must contain the tip of `main`. This makes every run on `D` (and the pull request's CI, whose
     merge ref then has the tree of `D`) a run of exactly what is released.
3. **Criteria for every final release** (regular and hotfix):
   - **CI**: the latest `ci.yml` run of event `pull_request` for that pull request at head `D`
     succeeded, and in it the jobs `CI result`, `E2E (enrollment, Discovery, Audit, invariant I2)`,
     `E2E OIDC login (Keycloak)`, `E2E CAS target`, `E2E SQL Server target`,
     `E2E Valkey and Redis targets` and the job of the called `e2e-compat.yml`
     (`… / E2E compatibility (console N, agent N-1)`) concluded `success`, not `skipped`. The
     implementation makes `detect` in `ci.yml` run every end-to-end job on pull requests into `main`,
     as it already does for `packaging`.
   - **PR checks**: the latest `pr-checks.yml` run for that pull request at head `D`, whose
     `display_title` equals the current title, has the jobs `Release version`,
     `Conventional Commits title` and `DCO (Signed-off-by)` at `success`.
   - **Holdout seed**: the seed rule of [RELEASE.md § 8](../../RELEASE.md#8-holdout-seed-rotation)
     is evaluated again in the criteria job, on `M` with base `M^1` and the pull request title. Its
     logic moves from `pr-checks.yml` to `.github/scripts/check-holdout-seed.sh`, which both
     workflows call. The `Release version` result is not the only evidence: it ran the pull
     request's code ([pr-checks.yml](../../.github/workflows/pr-checks.yml) says never to feed it to
     a privileged workflow).
   - **Open release gates**: in `RELEASE.md` at `M`, the first non-empty line after the line
     starting with `Gates that hold back` under `### Open release gates` is exactly
     `None at the moment.`
   - **Curated notes**: already enforced (release-it fails before any commit when "Unreleased" is
     empty); not repeated.
4. **Criteria for regular releases only.** A run *qualifies* when its commit `C` has the tree of `D`,
   or `C` is an ancestor of `D` and `git diff --name-only C D` lists only paths under `docs/`, root
   `*.md` files or `dev/holdout/`; its event is `workflow_dispatch` or `schedule`; it started at most
   7 days before the criteria job.
   - **Fuzz**: a qualifying `fuzz-nightly.yml` run concluded `success` (every target).
   - **Load**: the jobs `Load / database impact`, `Load / CAS target`, `Load / SQL Server target`,
     `Load / Valkey target` and `Load / Redis target` each concluded `success` in a qualifying
     `load.yml` run (they may come from different runs, `only` selecting one job). A
     `workflow_dispatch` run counts only with the default inputs apart from `only`; the
     implementation adds a `run-name` to `load.yml` that carries every input, which the criteria job
     reads from `display_title`.
   - **Engine matrix**: a qualifying `engine-matrix.yml` run concluded `success`, with the `engine`
     and `e2e-sqlserver` jobs run.
   - **Advisories**: an `advisories.yml` run of any event but `pull_request` concluded `success`,
     started at most 72 hours before, on a commit whose `agent/Cargo.lock`, `agent/fuzz/Cargo.lock`,
     `console/pnpm-lock.yaml`, `package-lock.json`, `shared/protocol/package-lock.json` and
     `agent/deny.toml` equal those of `D`.
5. **Hotfixes** need decisions 2.2 and 2.3 only, with no fuzz, load, engine matrix or advisories
   requirement, and in addition:
   - `V` is the patch successor `X.Y.(Z+1)` of the latest final tag reachable from `M^1` (a
     `feat` commit, hence a minor version, is refused);
   - no commit of `M^1..D` is reachable from `origin/dev`, so that the hotfix path cannot release
     `dev`'s unreleased work without the long runs.
   There is no override label: a label is set by whoever can merge, the actor this decision does not
   trust. A release that cannot meet a criterion is either fixed (dispatch the runs, rotate the
   seed, close the gate) or the criterion is changed by a pull request, reviewed at the next
   approval.
6. **Summary for the approver.** The criteria job writes a job summary: `V`, the kind, the pull
   request, `D`, one row per criterion with its result and the URL of the run it used, and the
   `git diff --stat` since the previous final tag of `.github/`, `scripts/`, `.release-it.json` and
   `Makefile` with a `::warning::` when it is not empty: release tooling changes are what the
   criteria cannot judge, because whoever changes them changes the criteria.
7. The criteria are assistance, not a control. A pull request merged into `dev` and then `main`
   can change `release.yml`, `ci.yml` or the workflows of the long runs; such a change is in the
   released tree and in the summary of decision 2.6. The control is the approval.
8. **§ 7 items that stay human**, covered by the one approval:
   - Security reviews: every pull request of the release that touches `shared/protocol/`, the
     uplink, masking or authentication was merged with an approved `security-reviewer` review; no
     open **Gate** item in the ROADMAP (in tables, not machine-readable).
   - The CHANGELOG "Unreleased" notes: accurate, breaking changes first, upgrade steps. They become
     the published release notes with no later review, so upgrade notes must be in them before the
     release pull request is merged.
   - Documentation up to date (docs/08, the user guide, SECURITY.md supported versions, ROADMAP,
     CONTEXT.md).
   - The GitHub settings the guard cannot read: `RELEASE_TOKEN` not expired and absent at
     repository level, merge methods, the `main` and `dev` rulesets with Code Owners, private
     vulnerability reporting.
   - The release tooling changes listed by decision 2.6, and, for a hotfix, that the hotfix path
     is warranted.

   The other § 7 items become automated: CI and the end-to-end and I2 tests (2.3), the holdout seed
   (2.3), compatibility (2.3), advisories (2.4), and the "after publishing" checks (decision 4).

### 3. `publish.yml`
1. The `release` environment loses its required reviewers and keeps its deployment rule (tags
   `[0-9]*.[0-9]*.[0-9]*` only). The jobs `build`, `manifest`, `release-assets` and the new
   `publish-release` keep `environment: release`. One gate job for everything was rejected: the
   deployment rule applies only to jobs that declare the environment, and it would leave the
   signing jobs outside it.
2. **Final versions.** The `prepare` job (its checkout with `fetch-depth: 0`; permissions
   `contents: read`, `actions: read`, `pull-requests: read`) checks, before any build:
   - the tag ref `refs/tags/V` is an annotated tag object (as release-it makes it,
     `tagAnnotation`) whose message is `DataBastion V` and whose target is `GITHUB_SHA` (`T`);
   - `T` is an ancestor of `origin/main`;
   - `T` has one parent `P`, its subject is exactly `chore(release): V`, its author and committer
     e-mail are the release identity (`vars.RELEASE_GIT_EMAIL`, or the owner's noreply address as
     in `release.yml`), and it carries a `Signed-off-by` trailer;
   - `git diff --name-only P T` lists only `CHANGELOG.md` and the files of
     `scripts/bump-version.mjs`, and `CHANGELOG.md` at `T` has a `## [V]` section;
   - `P` has two parents and is the `merge_commit_sha` of a merged pull request into `main`;
   - the `release.yml` run of event `push` at head `P` completed with `success` (`prepare` waits
     for it, polling every 20 s for up to 15 minutes, since release-it pushes the tag before it
     creates the draft), its jobs `release-criteria` and `release-it` concluded `success`, and its
     approvals (`GET /actions/runs/{id}/approvals`) include one `approved` for `release-it`.

   A final-version tag pushed by hand, by an administrator, is therefore refused by the reviewed
   `publish.yml`. For final versions, `release-assets` requires the draft created by release-it
   and no longer creates one.
3. **Pre-release tags** (`X.Y.Z-…`, pushed by a maintainer) keep a human approval through a new job
   `prerelease-approval` (`if: needs.prepare.outputs.prerelease == 'true'`, `permissions: {}`, one
   step), in a new environment `release-prerelease`: required reviewers, deployment rule tags
   `[0-9]*.[0-9]*.[0-9]*-*` only. `build` needs it and runs when it succeeded, or when it was
   skipped for a final version. `prepare` also checks, for pre-releases: an annotated tag that
   GitHub reports as verified (`git tag -s`, RELEASE.md § 3), a commit that is an ancestor of
   `origin/dev` or `origin/main`, and `X.Y.Z` greater than the latest final tag.
   GitHub accepts an expression in `jobs.<id>.environment` (contexts `github`, `needs`, `strategy`,
   `matrix`, `vars`, `inputs`), so the three jobs could pick `release-prerelease` by expression. Not
   chosen: a pre-release would prompt three times again, and a mistyped or unevaluated name makes
   GitHub create an environment with no protection on first use. A static name read by the
   settings guard avoids both.
4. **Residual risk of ADR-0034 (self-approval of a pre-release tag on any commit): unchanged.** An
   administrator can still push a pre-release tag on a commit whose `publish.yml` they edited, with
   no gate job and no checks, and get artifacts signed with the exact identity; this was true of
   the `release` approval too. The checks of decision 3.3 catch mistakes on the honest path only.
   For final-version tags pushed by hand, the honest path improves (decision 3.2 refuses them
   instead of a self-approval signing them); with an edited `publish.yml` they stay possible, as
   before.

### 4. Automatic publication of final releases
1. A new job `publish-release` (`needs: [prepare, manifest, deb, release-assets, install-test]`,
   runs only when they all succeeded and `prerelease == 'false'`; `environment: release`;
   `permissions: contents: write`; `timeout-minutes: 10`) publishes the draft, after these checks:
   - the release `V` exists, is a draft, is not a pre-release, and its tag resolves to
     `GITHUB_SHA`;
   - its assets are exactly six, each `uploaded` and non-empty: `SHA256SUMS`,
     `SHA256SUMS.cosign.bundle`, `image-digests.txt`, `databastion-deploy-V.tar.gz`,
     `databastion-agent_V_amd64.deb`, `databastion-agent_V_arm64.deb` (the files `release-assets`
     writes when both images are built; a release missing an image is not published automatically);
   - `SHA256SUMS`, downloaded, lists exactly the four other files and `sha256sum -c` passes on the
     downloaded assets; `cosign verify-blob` of `SHA256SUMS` with its bundle passes with the exact
     identity `…/publish.yml@refs/tags/V`, the GitHub issuer, trigger `push`, the repository and
     `--certificate-github-workflow-sha` set to `GITHUB_SHA`;
   - `image-digests.txt` holds exactly two lines `ghcr.io/<owner>/databastion-{console,agent}:V@sha256:<64 hex>`,
     each digest passes `cosign verify` with the same options, and each resolves without registry
     credentials (the GHCR packages are public);
   - the release notes are not empty.
2. It then runs `gh release edit V --draft=false`, with `--latest` when `V` is the highest final
   tag, `--latest=false` otherwise, using `GITHUB_TOKEN`. That token can publish a release with
   `contents: write`; the tag exists already, so no tag is created; and no workflow needs to run on
   publication (none listens to `release` events, and events caused by `GITHUB_TOKEN` start no
   workflow anyway). No other token is added to `publish.yml`.
3. Assets are still only ever attached to a draft (ADR-0034 decision 7): `release-assets` keeps
   refusing a published release, and `publish-release` uploads nothing.
4. Pre-releases stay drafts, published by a maintainer after review (RELEASE.md § 5).
5. If `publish-release` fails, the draft stays a draft. The maintainer re-runs the job, or checks the
   items of decision 4.1 by hand (RELEASE.md lists them) and publishes it.

### 5. Settings guard
`check-release-settings.sh` gains a fourth argument for environments, `reviewers` (the default) or
`no-reviewers`:
- `release.yml`: `environment release-it branch main` (unchanged) and `tag-ruleset` (unchanged).
- `publish.yml` `prepare`, at every run, final or pre-release: `environment release tag no-reviewers`,
  `environment release-prerelease tag` and `tag-ruleset`. `release-prerelease` is checked on final
  runs too, so that a missing one is found before an urgent pre-release (a job naming a missing
  environment would create it unprotected).
- `no-reviewers` accepts an environment with required reviewers with a `::warning::` (transition,
  decision 7), and still requires tag-only deployment rules and no administrator bypass (or
  `RELEASE_ALLOW_ADMIN_BYPASS`), since the bypass may also cover deployment rules.

This amends ADR-0034 **decision 3** (the `release` environment no longer has required reviewers that
approve each release; final releases are approved once, at `release-it`, and pre-releases at
`release-prerelease`) and **decision 5** (the expectations of the settings check). It extends
**decision 7** (publication of final releases is automatic, after decision 4's checks) and replaces
the consequence "up to three waves" of approvals. Decisions 1, 2, 4 and 6 are unchanged.

### 6. Security analysis
| Actor | Before | After |
|-------|--------|-------|
| Can merge into `dev` (an agent's token, CI green, no required review) | Code on `dev`; no release | Same. It can also dispatch the long runs and, by merging workflow edits, make them pass trivially: visible in the released tree and in the summary of decision 2.6 |
| Can merge into `main` | `release.yml` waits for the `release-it` approval; then three `release` approvals and a manual publication, all by the same human | `release.yml` evaluates the criteria, then waits for the one approval; after it, signed and published with no other pause. Edits of `release.yml` or `publish.yml` merged into `main` cannot reach `RELEASE_TOKEN` without the approval |
| Holds `RELEASE_TOKEN` (or a compromised step of the `release-it` job reads it) | Pushes to `main` and tags any commit with a `publish.yml` of its choice (without environments): signed artifacts | Same. With the reviewed `publish.yml`, a final tag it creates is refused unless an approved `release.yml` run exists for its parent (decision 3.2) |
| Administrator (the maintainer's account, or a token of it) | Self-approves every environment; can push any tag | Same. With `RELEASE_ALLOW_ADMIN_BYPASS` true, can also bypass the one approval |

- **What the approval still protects.** `RELEASE_TOKEN` is readable only by a job in `release-it`,
  on `main`, after the approval, so the release commit and the tag of the release path need a
  human. It does not protect against an administrator or the token holder pushing a tag directly
  (only the tag ruleset limits that, ADR-0034 decision 3).
- **Precondition of option A.** The approval is a human pause only if no agent can give it. The
  credentials agents use must not be able to review the pending deployments of `release-it`: not a
  token of a required reviewer or of an administrator, or one without the permission GitHub
  requires to review deployments. If agents act with such a token, option A is option B. Nothing
  in the repository can check this; the maintainer confirms it in the rollout (decision 7).
- **`RELEASE_ALLOW_ADMIN_BYPASS`.** With one approval left, an administrator bypass removes the last
  forced pause. The single maintainer approves as a required reviewer (*Prevent self-review* off)
  and does not need the bypass: the variable is removed and *Allow administrators to bypass* is
  unchecked on `release-it`, `release` and `release-prerelease` as part of the rollout.
- **Recommended future work: a GitHub App instead of `RELEASE_TOKEN`** (ADR-0034 decision 4, its own
  ADR). Its token is minted in the job, limited to this repository and revoked when the job ends,
  so a dependency of release-it that reads it gets a token valid for minutes instead of the
  owner's long-lived administrator token; the app, not *Repository admin*, sits in the bypass lists
  of `main` and of the tag ruleset. The private key stays an environment secret of `release-it`,
  seen only by the minting step.

### 7. Rollout
Settings changes and merges happen in this order, so that every release in between works with the
workflows it runs (the old `publish.yml` refuses a `release` environment without reviewers):
1. The maintainer creates the `release-prerelease` environment (required reviewers, administrator
   bypass unchecked, deployment rule *Tag* `[0-9]*.[0-9]*.[0-9]*-*`). Unused until step 2.
2. The implementation is merged into `dev` (`release.yml`, `publish.yml`, `ci.yml` `detect`,
   `load.yml` `run-name`, `check-holdout-seed.sh`, `check-release-settings.sh` and its tests, a
   read-only `.github/scripts/release-criteria.sh` callable outside Actions, RELEASE.md), with a
   `security-reviewer` review. The `release` environment keeps its reviewers: the guard warns.
3. Dry run: `release-criteria.sh` against the 0.9.0 merge commit `6b26b05`, read-only. Expected: the
   fuzz and load criteria fail (their runs were on earlier commits, Context) and the others pass.
4. A pre-release tag on `dev` (`X.Y.Z-rc.N` of the next version): `prepare` passes its checks, the
   `prerelease-approval` gate prompts (and still the three `release` jobs), the draft stays a draft,
   `cosign verify` with the exact identity passes. Published or not by hand, as today.
5. The next regular release runs the new workflows from `main`: criteria, one `release-it` approval,
   the three `release` prompts still, then the automatic publication.
6. After that release is published (every later tag, hotfixes included, runs the new
   `publish.yml`), the maintainer removes the required reviewers of `release`, removes
   `RELEASE_ALLOW_ADMIN_BYPASS` and unchecks the administrator bypass on the three environments, and
   confirms the precondition of decision 6 for the agents' credentials.
7. RELEASE.md: § 5 (regular release steps 4 to 6, pre-release, hotfix criteria; the paragraph on a
   pre-release computed by release-it removed, such a title is refused), § 6 (the
   `release-prerelease` environment, the `release` environment without reviewers, the residual
   risks with decision 6), § 7 (the automated items marked as checked by `release-criteria` or
   `publish-release`, the human items of decision 2.8), and a transition note removed after step 6.

## Consequences
- A final release needs one human action, the `release-it` approval; then about an hour unattended.
  The maintainer no longer reviews the draft: the release notes are final when the release pull
  request is merged.
- A regular release needs the fuzz, load, engine matrix and advisories runs on the release head or
  on a commit that differs from it only in documentation: after the last code merge, they are
  dispatched again (0.9.0 would have needed new fuzz and load runs). The 0.8.0 and 0.9.0 practice of
  gates read off earlier heads ends.
- `dev` must contain the previous release and its hotfixes before a release pull request; a hotfix
  branch must be up to date with `main`.
- Hotfixes are faster (no long runs) and limited to patch versions of commits not on `dev`.
- A final-version tag pushed by hand is refused by `publish.yml`; a release whose `publish-release`
  checks fail stays a draft.
- The criteria and the publication checks read the GitHub API with `GITHUB_TOKEN`; an API outage
  fails the release, which is re-run.
- Every end-to-end job runs on pull requests into `main`, which lengthens their CI.

## Rejected alternatives
- **Option B, no human approval**: an agent merging into `main`, or a stolen token, would produce a
  signed and published release with no pause (maintainer decision of 2026-10-24).
- **Status quo** (four approvals and a manual publication): the same human approves each time, so
  the later prompts add little control (Context) and are approved without being read.
- **Keep the `release` reviewers, automate only the publication**: two human steps for no control
  an edited `publish.yml` could not drop.
- **Environment chosen by expression on the three jobs**: decision 3.3.
- **One gate job for every version, signing jobs without environment**: decision 3.1.
- **Trust the `Release version` result for the holdout seed**: it runs the pull request's code
  (decision 2.3).
- **A labeled override for missing criteria**: decision 2.5.
- **A custom deployment protection rule** (a GitHub App answering for `release` from outside the
  repository): it would hold even against an edited `publish.yml`, but it is a service to host and
  secure; to reconsider with the GitHub App of decision 6.

## Open questions
Each with a proposed answer, for the maintainer.
1. **Which differences keep a long run valid?** Proposed: `docs/`, root `*.md` and `dev/holdout/`
   only (decision 2.4); not tests or any path under `agent/` or `console/` (0.8.0's test-only fix
   #270 would have needed new runs: accepted).
2. **Age bounds.** Proposed: 7 days for fuzz, load and engine matrix; 72 hours for advisories, whose
   result depends on the date.
3. **Required load legs.** Proposed: the five of decision 2.4 with default parameters; the SQL
   Server 2019 / 2025 and Extended Events load runs stay measurements, not criteria.
4. **Hotfix criteria.** Proposed: decisions 2.3 and 2.5 only, patch versions only, no override
   label; the next regular release runs the long runs on code that includes the hotfix.
5. **Agents' credentials.** Proposed: before step 6 of the rollout, the maintainer confirms that the
   credentials agents use cannot review deployments (a separate account or app that is neither a
   required reviewer nor an administrator, or a fine-grained token without the deployment review
   permission); until then, the `release` reviewers stay.
6. **`RELEASE_ALLOW_ADMIN_BYPASS`.** Proposed: removed in step 6, on the three environments; it is
   not needed by a single maintainer who is a required reviewer.
7. **GitHub App for `RELEASE_TOKEN`.** Proposed: its own ADR, after this rollout, before a second
   maintainer or any widening of agent permissions.
8. **GitHub immutable releases.** Proposed: enable after the first automatic publication: every asset
   is attached before publication, so GitHub then enforces ADR-0034 decision 7 for assets and tags.
