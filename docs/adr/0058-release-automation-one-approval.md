# ADR-0058: Release automation with one human approval

- **Status**: Accepted by the maintainer on 2026-10-24 with the proposed answer to every open question, revised after its [security review of 2026-10-24](#security-review-of-2026-10-24); hard gate of decision 6.1 not met: the maintainer keeps the current agent identity (decision of 2026-10-24), so rollout step 6 is not done and the `release` reviewers and the hand publication stay
  (sound after changes)
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
  `environment:` lines; `id-token: write` and `packages: write` are job permissions, and the OIDC
  token used for keyless signing is not tied to an environment (confirmed by the security review,
  N1). The `release` approval therefore never protected against that actor (the
  [§ 6 residual risk](../../RELEASE.md#repository-configuration-one-time) says so for pre-release
  tags); it was a pause on the honest path.
- `RELEASE_TOKEN` is an environment secret of `release-it`, whose deployment rule admits `main` only:
  a job reads it only after the approval, whatever the workflow file says.
- No workflow of the repository listens to `release` events.
- **The GitHub credential that agent sessions use today acts as the maintainer's account** (`Yil00`,
  repository `admin: true`), with `current_user_can_bypass: "always"` on the tag ruleset
  `protect-release-tags` (24118675) and on `protect-main` (24118671). With it, an agent can push a
  final or pre-release tag on any commit (with a `publish.yml` stripped of every check) and get
  artifacts signed with the documented identity, push to `main` directly, approve `release-it`
  deployments and edit the environments. This is possible today, before this ADR.
- The `main` ruleset requires the check `CI result` with no source pinned, and
  `require_code_owner_review` is `false` on `main` and `dev`, while RELEASE.md § 7 expects
  "Require review from Code Owners".

## Decision

### 1. The single human approval
1. The `release-it` environment keeps its required reviewers and its `main`-only deployment rule,
   unchanged. Its approval is the only human step of a final release (`X.Y.Z`), regular or hotfix.
2. The approver approves only after reading the `release-criteria` summary (decision 2.6) and
   checking the § 7 items that stay human (decision 2.9). From then on, nothing waits for a human:
   the tag, the signed artifacts and, once decision 6.1 holds, the published release follow.
3. **This approval protects only against actors who cannot give it.** While agents hold an
   administrator credential (Context), option A gives no protection against them; decision 6.1 is
   therefore a hard gate of the rollout.

### 2. Release criteria in `release.yml`
1. A new job `release-criteria` runs before the `release-it` job, which `needs` it. It declares no
   environment and no secret; permissions `contents: read`, `actions: read`, `checks: read`,
   `pull-requests: read`; `timeout-minutes: 150`. Its logic is a read-only script,
   `.github/scripts/release-criteria.sh`, also callable outside Actions. If a criterion is not
   met, it prints one `::error::` per failed criterion (all criteria are evaluated, naming what is
   missing and how to fix it) and fails: the `release-it` job is skipped, so no approval is
   requested, no commit is made and no tag is created. Once the missing runs exist, *Re-run failed
   jobs* on the same run evaluates them again (the "main has not moved" check of `release-it`
   still applies).
2. **Identification**, from the pushed commit `M` (`GITHUB_SHA`), every item a criterion:
   - `M` has exactly two parents. `M^1` is the previous `main`, `D = M^2` is the **release head**.
   - The pull request is the one GitHub returns for `M` (`GET /commits/{M}/pulls`) with `merged_at`
     set, `base.ref == main`, `merge_commit_sha == M`, `head.sha == D` and a head repository equal to
     this repository. Exactly one must match.
   - Kind: `head.ref == dev` is a **regular** release; `head.ref` matching `hotfix/*` is a **hotfix**;
     any other head branch fails.
   - The title matches `^release: ([0-9]+\.[0-9]+\.[0-9]+)( \[skip-holdout\])?$`. Its version `V` is
     the job output; a pre-release version is refused (pre-releases are tagged by hand, decision 3.3).
   - `M^1` is an ancestor of `D`, and the tree of `M` equals the tree of `D`. A regular release
     therefore needs the previous release and its hotfixes back-merged into `dev`; a hotfix branch
     must contain the tip of `main`. Every run on a commit with the tree of `D` is then a run of
     exactly what is released.
3. **Criteria for every final release** (regular and hotfix):
   - **CI**: the `ci.yml` run with `path == .github/workflows/ci.yml`, `event == push`,
     `head_branch == main` and `head_sha == M` (it runs `M`'s own, merged `ci.yml`) concluded
     `success`, and in it the jobs `CI result`, `E2E (enrollment, Discovery, Audit, invariant I2)`,
     `E2E OIDC login (Keycloak)`, `E2E CAS target`, `E2E SQL Server target`,
     `E2E Valkey and Redis targets` and the job of the called `e2e-compat.yml`
     (`… / E2E compatibility (console N, agent N-1)`) concluded `success`, not `skipped`. The
     implementation makes `detect` in `ci.yml` run every end-to-end job, and `e2e-compat` with `M^1`
     as its base, on pushes to `main`. The criteria job polls for that run every 60 s for up to 140
     minutes. A `workflow_dispatch` run of `ci.yml` on a commit with the tree of `D`, with the same
     path and job checks, is accepted instead. A pull request run is never accepted: a pull request
     with head `dev` into a branch carrying a fake `ci.yml` gives a green run with head `D` and the
     right job names (review M1).
   - **PR checks, from the merged code**: the criteria job evaluates them itself, not from their
     `pr-checks.yml` results, which a pull request into another base fakes the same way: the title
     rule above; `npx release-it --ci --release-version` at `M` (no token, no GitHub release, as in
     `pr-checks.yml`) prints exactly `V`; every commit of `M^1..D` carries a `Signed-off-by`
     trailer. The `release-it` job still fails before any commit when the version it computes
     differs from `V`.
   - **Holdout seed**: the seed rule of [RELEASE.md § 8](../../RELEASE.md#8-holdout-seed-rotation)
     is evaluated on `M` with base `M^1` and the pull request title; its logic moves from
     `pr-checks.yml` to `.github/scripts/check-holdout-seed.sh`, which both workflows call.
   - **Open release gates**: in `RELEASE.md` at `M`, the first non-empty line after the line
     starting with `Gates that hold back` under `### Open release gates` is exactly
     `None at the moment.`
   - **Curated notes**: already enforced (release-it fails before any commit when "Unreleased" is
     empty); not repeated.
4. **Criteria for regular releases only.** A commit `C` *qualifies* when it has the tree of `D`, or
   `C` is an ancestor of `D` and `git diff --no-renames --name-status C D` lists only paths under
   `docs/`, root `*.md` files or `dev/holdout/` (with `--no-renames`, a code file moved into `docs/`
   shows as a deletion outside it). `dev/holdout/` holds an executable `generate.py`, but no long
   run uses it: it feeds only the holdout gate of `ci.yml`, which runs on `M` (decision 2.3). A run
   qualifies when its commit qualifies, its event is `workflow_dispatch` or `schedule`, and every
   job it is used for started at most 7 days before the criteria job (each job's `started_at`: a
   *Re-run failed jobs* refreshes the run's `run_started_at` only).
   - **Fuzz**: a qualifying `fuzz-nightly.yml` run concluded `success` (every target).
   - **Load**: the jobs `Load / database impact`, `Load / CAS target`, `Load / SQL Server target`,
     `Load / Valkey target` and `Load / Redis target` each concluded `success` in a qualifying
     `load.yml` run (they may come from different runs, `only` selecting one job). A
     `workflow_dispatch` run counts only with the default inputs apart from `only`. The
     implementation makes `load.yml` refuse non-numeric values for its numeric inputs, and gives
     it a `run-name` that carries `toJSON(inputs)`; the criteria job compares that JSON exactly
     with the defaults (`only` excepted), from `display_title`.
   - **Engine matrix**: a qualifying `engine-matrix.yml` run concluded `success`, with the `engine`
     and `e2e-sqlserver` jobs run.
   - **Advisories**: an `advisories.yml` run of event `workflow_dispatch`, `schedule` or `push`, on a
     qualifying commit, concluded `success`, with each job started at most 72 hours before.
5. **Hotfixes** need decisions 2.2 and 2.3 only, with no fuzz, load, engine matrix or advisories
   requirement, and in addition:
   - `V` is the patch successor `X.Y.(Z+1)` of the latest final tag reachable from `M^1` (a
     `feat` commit, hence a minor version, is refused);
   - no commit of `M^1..D` is reachable from `origin/dev`.

   These two checks catch honest mistakes only: a cherry-pick of `dev` commits gives new SHAs, and a
   `feat` header can be reworded as `fix`. What keeps the hotfix path from releasing `dev`'s work
   without the long runs is the approver reading the whole hotfix diff (decisions 2.6 and 2.9).
   There is no override label: a label is set by whoever can merge, the actor this decision does
   not trust. A release that cannot meet a criterion is either fixed (dispatch the runs, rotate the
   seed, close the gate) or the criterion is changed by a pull request, reviewed at the next
   approval.
6. **Summary for the approver.** The criteria job writes a job summary: `V`, the kind, the pull
   request, `D`, one row per criterion with its result and the URL of the run it used, and the
   `git diff --stat` since the previous final tag of `.github/`, `scripts/`, `.release-it.json` and
   `Makefile`, with a `::warning::` when it is not empty: release tooling changes are what the
   criteria cannot judge, because whoever changes them changes the criteria. For a hotfix it also
   shows `git diff --stat M^1 D` and the number of commits of `M^1..D`, with a `::warning::` above
   20 changed files.
7. **Fresh criteria at the token step.** Re-running only the `release-it` job would reuse an old
   `release-criteria` result. The `release-it` job therefore runs `release-criteria.sh` again,
   read-only and without the token, as the step just before the one that holds `RELEASE_TOKEN`, and
   stops if it fails.
8. The criteria are assistance, not a control. A pull request merged into `dev` and then `main`
   can change `release.yml`, `ci.yml` or the workflows of the long runs; such a change is in the
   released tree and in the summary of decision 2.6. The control is the approval.
9. **§ 7 items that stay human**, covered by the one approval:
   - Security reviews: every pull request of the release that touches `shared/protocol/`, the
     uplink, masking or authentication was merged with an approved `security-reviewer` review; no
     open **Gate** item in the ROADMAP (in tables, not machine-readable).
   - The CHANGELOG "Unreleased" notes: accurate, breaking changes first, upgrade steps. They become
     the published release notes with no later review (decision 4.1), so upgrade notes must be in
     them before the release pull request is merged.
   - Documentation up to date (docs/08, the user guide, SECURITY.md supported versions, ROADMAP,
     CONTEXT.md).
   - The GitHub settings the guard cannot read: `RELEASE_TOKEN` not expired and absent at
     repository level, merge methods, the `main` and `dev` rulesets (`CI result` pinned to the
     GitHub Actions source, Code Owners review; rollout steps 1 and 6), private vulnerability
     reporting, and the agents' identity of decision 6.1.
   - The release tooling changes listed by decision 2.6, and, for a hotfix, the whole hotfix diff
     and that the hotfix path is warranted.

   The other § 7 items become automated: CI and the end-to-end and I2 tests (2.3), the holdout seed
   (2.3), compatibility (2.3), advisories (2.4), and the "after publishing" checks (decision 4).
10. **Release record.** After `npx release-it --ci`, in the same step (the git credential is removed
    by its `trap`), the `release-it` job looks up, with `RELEASE_TOKEN`, the release whose tag is
    `V`, requires exactly one (a draft), and writes its id to the job outputs. A later job
    `release-record` (no environment, `contents: read`) uploads the artifact `release-record`
    holding `{version, merge_commit, release_commit, release_id}`, which `publish.yml` reads
    (decisions 3.2 and 4.1).

### 3. `publish.yml`
1. The `release` environment loses its required reviewers and keeps its deployment rule (tags
   `[0-9]*.[0-9]*.[0-9]*` only). The jobs `build`, `manifest`, `release-assets` and the new
   `publish-release` keep `environment: release`. One gate job for everything was rejected: the
   deployment rule applies only to jobs that declare the environment, and it would leave the
   signing jobs outside it.
2. **Final versions.** The `prepare` job (`timeout-minutes: 30`; its checkout with
   `fetch-depth: 0`; permissions `contents: read`, `actions: read`, `pull-requests: read`) checks,
   before any build:
   - the tag ref `refs/tags/V` is an annotated tag object (as release-it makes it,
     `tagAnnotation`) whose message is `DataBastion V` and whose target is `GITHUB_SHA` (`T`);
   - `T` is an ancestor of `origin/main`;
   - `T` has one parent `P`, its subject is exactly `chore(release): V`, its author and committer
     e-mail are the release identity (`vars.RELEASE_GIT_EMAIL`, or the owner's noreply address as
     in `release.yml`), and it carries a `Signed-off-by` trailer;
   - the tree of `T` equals the tree obtained by applying `node scripts/bump-version.mjs V` and
     `node scripts/changelog-release.mjs changelog V` (the `after:bump` hooks of `.release-it.json`,
     with the pinned Rust toolchain and the agent dependencies fetched, as in `release.yml`) to `P`,
     at the date of `T`;
   - `P` has two parents and is the `merge_commit_sha` of a merged pull request into `main`;
   - the `release.yml` run with `path == .github/workflows/release.yml`, `event == push`,
     `head_branch == main` and `head_sha == P` completed with `success` (`prepare` polls every 20 s
     for up to 20 minutes, since release-it pushes the tag before it creates the draft); its jobs
     `release-criteria`, `release-it` and `release-record` concluded `success`; its approvals
     (`GET /actions/runs/{id}/approvals`) include one `approved` for `release-it`; and its artifact
     `release-record` names `V`, `P` and `T`.

   A final-version tag pushed by hand is therefore refused by the reviewed `publish.yml`. None of
   this stops the holder of `RELEASE_TOKEN` or an administrator, who can tag a commit whose
   `publish.yml` has none of these checks (decision 6). For final versions, `release-assets`
   requires the draft of the release record and no longer creates one.
3. **Pre-release tags** (`X.Y.Z-…`, pushed by a maintainer) keep a human approval through a new job
   `prerelease-approval`, in a new environment `release-prerelease`: required reviewers, deployment
   rule tags `[0-9]*.[0-9]*.[0-9]*-*` only; `permissions: {}`, one step. Exact conditions:
   - `prepare` sets its output `prerelease` to exactly `true` or `false` and fails otherwise;
   - `prerelease-approval` runs `if: needs.prepare.outputs.prerelease != 'false'`, so that an empty
     or unexpected value runs the gate rather than skipping it;
   - `build` runs `if: always() && needs.prepare.result == 'success' && (needs.prerelease-approval.result == 'success' || (needs.prerelease-approval.result == 'skipped' && needs.prepare.outputs.prerelease == 'false'))`;
   - `release-assets` and `publish-release` require `needs.<job>.result == 'success'` for each job
     they need (`deb` may be `skipped` only when no agent image is built), instead of
     `!failure() && !cancelled()`.

   `prepare` also checks, for pre-releases: an annotated tag that GitHub reports as verified
   (`git tag -s`, RELEASE.md § 3), a commit that is an ancestor of `origin/dev` or `origin/main`,
   and `X.Y.Z` greater than the latest final tag.
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
   before. Today this residual covers agents too (Context); decision 6.1 removes that part.

### 4. Automatic publication of final releases
1. A new job `publish-release` (`needs: [prepare, manifest, deb, release-assets, install-test]`,
   each `success`; runs only when `needs.prepare.outputs.prerelease == 'false'` and the repository
   variable `RELEASE_AUTO_PUBLISH` is `true`, rollout step 6; `environment: release`;
   `permissions: contents: write`, `actions: read`; `timeout-minutes: 10`) publishes the draft,
   after these checks:
   - exactly one release has the tag `V`; its id is the `release_id` of the release record
     (decision 2.10); it is a draft, is not a pre-release, and its tag resolves to `GITHUB_SHA`;
   - its title is exactly `V` and its body exactly the output of
     `node scripts/changelog-release.mjs notes V` at `T`, so that a draft swapped or edited after
     release-it is not published;
   - its assets are exactly six, each `uploaded` and non-empty: `SHA256SUMS`,
     `SHA256SUMS.cosign.bundle`, `image-digests.txt`, `databastion-deploy-V.tar.gz`,
     `databastion-agent_V_amd64.deb`, `databastion-agent_V_arm64.deb` (the files `release-assets`
     writes when both images are built; a release missing an image is not published automatically);
     their ids and API `digest` values are recorded;
   - `SHA256SUMS`, downloaded, lists exactly the four other files and `sha256sum -c` passes on the
     downloaded assets; `cosign verify-blob` of `SHA256SUMS` with its bundle passes with the exact
     identity `…/publish.yml@refs/tags/V`, the GitHub issuer, trigger `push`, the repository and
     `--certificate-github-workflow-sha` set to `GITHUB_SHA`;
   - `image-digests.txt` holds exactly two lines `ghcr.io/<owner>/databastion-{console,agent}:V@sha256:<64 hex>`,
     each digest passes `cosign verify` with the same options, and each resolves without registry
     credentials (the GHCR packages are public).
2. It then runs `gh release edit V --draft=false`, with `--latest` when `V` is the highest final
   tag, `--latest=false` otherwise, using `GITHUB_TOKEN`. That token can publish a release with
   `contents: write`; the tag exists already, so no tag is created; and no workflow needs to run on
   publication (none listens to `release` events, and events caused by `GITHUB_TOKEN` start no
   workflow anyway). No other token is added to `publish.yml`.
3. **Gap between check and publication.** After publication, the job lists the release again: the
   same id, title and body, and asset ids and `digest` values equal to those verified. Otherwise it
   sets the release back to a draft (`--draft=true`) and fails. GitHub immutable releases are
   enabled before the first release with the new workflows (rollout step 1), so that a published
   release's assets and tag cannot change afterwards.
4. Assets are still only ever attached to a draft (ADR-0034 decision 7): `release-assets` keeps
   refusing a published release, and `publish-release` uploads nothing.
5. Pre-releases stay drafts, published by a maintainer after review (RELEASE.md § 5).
6. If `publish-release` fails or does not run (`RELEASE_AUTO_PUBLISH` not `true`), the draft stays a
   draft. The maintainer re-runs the job, or checks the items of decision 4.1 by hand (RELEASE.md
   lists them) and publishes it.

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
1. **Hard gate: agents use a separate identity.** Option A protects against agents only when all of
   these hold; the `release` reviewers and the hand publication stay until they do (rollout
   step 6):
   - agents act as a separate identity: a GitHub App, or a machine user with the *Write* role (not
     *Admin*, not *Maintain*);
   - that identity is in no bypass list (the tag ruleset, `main`, `dev`) and is not a required
     reviewer of `release-it` or `release-prerelease`;
   - its token has no *Administration*, *Environments*, *Secrets* or *Variables* write and no
     *Deployments* write;
   - the agent harness checks this at the start of every session: it reads the tag ruleset and the
     `main` ruleset and refuses to work unless both report `current_user_can_bypass == "never"` and
     the repository does not report `permissions.admin: true` for its credential.

   Approving pending deployments requires the token's user to be a required reviewer, with a
   classic token with `repo` or a fine-grained token with *Deployments* write; `GITHUB_TOKEN` and
   App installation tokens cannot approve (to confirm in rollout step 6). **While agents hold an
   administrator credential, as on 2026-10-24, option A gives no protection against them**: they
   can tag any commit, push to `main`, approve `release-it` and edit the environments.
2. Actors, once decision 6.1 holds:

   | Actor | Before | After |
   |-------|--------|-------|
   | Can merge into `dev` (an agent's identity, CI green, no required review) | Code on `dev`; no release | Same. It can also dispatch the long runs and, by merging workflow edits, make them pass trivially: visible in the released tree and in the summary of decision 2.6 |
   | Can merge into `main` | `release.yml` waits for the `release-it` approval; then three `release` approvals and a manual publication, all by the same human | `release.yml` evaluates the criteria, then waits for the one approval; after it, signed and published with no other pause. Edits of `release.yml` or `publish.yml` merged into `main` cannot reach `RELEASE_TOKEN` without the approval |
   | Holds `RELEASE_TOKEN` (or a compromised step of the `release-it` job reads it) | Pushes to `main` and tags any commit with a `publish.yml` of its choice (without environments): signed artifacts | Same. With the reviewed `publish.yml`, a final tag it creates is refused unless an approved `release.yml` run and its release record exist for its parent (decision 3.2); an edited `publish.yml` is not stopped |
   | Administrator (the maintainer's account, or any token of it, agent sessions included today) | Self-approves every environment; can push any tag | Same. With `RELEASE_ALLOW_ADMIN_BYPASS` true, can also bypass the one approval |
   | Has *Write* | Can edit the notes of a published release | Same: immutable releases lock the assets and the tag, not the notes |
3. **What the approval still protects.** `RELEASE_TOKEN` is readable only by a job in `release-it`,
   on `main`, after the approval, so the release commit and the tag of the release path need a
   human. It does not protect against an administrator or the token holder pushing a tag directly
   (only the tag ruleset limits that, ADR-0034 decision 3).
4. **`RELEASE_ALLOW_ADMIN_BYPASS`.** With one approval left, an administrator bypass removes the last
   forced pause. The single maintainer approves as a required reviewer (*Prevent self-review* off)
   and does not need the bypass: the variable is removed and *Allow administrators to bypass* is
   unchecked on `release-it`, `release` and `release-prerelease` in rollout step 6.
5. **Recommended future work: a GitHub App instead of `RELEASE_TOKEN`** (ADR-0034 decision 4, its own
   ADR). Its token is minted in the job, limited to this repository and revoked when the job ends,
   so a dependency of release-it that reads it gets a token valid for minutes instead of the
   owner's long-lived administrator token; the app, not *Repository admin*, sits in the bypass lists
   of `main` and of the tag ruleset. The private key stays an environment secret of `release-it`,
   seen only by the minting step.

### 7. Rollout
Settings changes and merges happen in this order, so that every release in between works with the
workflows it runs (the old `publish.yml` refuses a `release` environment without reviewers):
1. The maintainer creates the `release-prerelease` environment (required reviewers, administrator
   bypass unchecked, deployment rule *Tag* `[0-9]*.[0-9]*.[0-9]*-*`), enables GitHub immutable
   releases, and pins `CI result` to the GitHub Actions source in the `main` and `dev` rulesets.
2. The implementation is merged into `dev` (`release.yml`, `publish.yml`, `ci.yml` `detect` and
   `e2e-compat` on pushes to `main`, `load.yml` input checks and `run-name`,
   `check-holdout-seed.sh`, `release-criteria.sh`, `check-release-settings.sh` and its tests,
   RELEASE.md), with a `security-reviewer` review. The `release` environment keeps its reviewers:
   the guard warns.
3. Dry run: `release-criteria.sh` against the 0.9.0 merge commit `6b26b05`, read-only. Expected: the
   fuzz and load criteria fail (their runs were on earlier commits, Context), and so does the CI
   criterion (no end-to-end job ran on that push to `main`); the others pass.
4. A pre-release tag on `dev` (`X.Y.Z-rc.N` of the next version): `prepare` passes its checks, the
   `prerelease-approval` gate prompts (and still the three `release` jobs), the draft stays a draft,
   `cosign verify` with the exact identity passes.
5. The next regular release runs the new workflows from `main`: criteria, one `release-it` approval,
   the three `release` prompts still; `RELEASE_AUTO_PUBLISH` is not set yet, so the maintainer
   publishes by hand after checking decision 4.1.
6. It starts with confirming decision 6.1: the agents' identity changed, the maintainer's credential
   gone from agent sessions, the harness self-check green, and whether that identity can approve
   deployments tested on a throwaway environment. Only then does the maintainer remove the required
   reviewers of `release`, remove `RELEASE_ALLOW_ADMIN_BYPASS`, uncheck the administrator bypass on
   the three environments, enable *Require review from Code Owners* on `main` and `dev`, and set
   `RELEASE_AUTO_PUBLISH` to `true`. Every later tag, hotfixes included, runs the new `publish.yml`.
7. RELEASE.md: § 5 (regular release steps 4 to 6, pre-release, hotfix criteria; the paragraph on a
   pre-release computed by release-it removed, such a title is refused), § 6 (the
   `release-prerelease` environment, the `release` environment without reviewers,
   `RELEASE_AUTO_PUBLISH`, the agents' identity, the residual risks with decision 6), § 7 (the
   automated items marked as checked by `release-criteria` or `publish-release`, the human items of
   decision 2.9, the Code Owners setting as it stands), and a transition note removed after step 6.

## Consequences
- Once rolled out, a final release needs one human action, the `release-it` approval; then about an
  hour unattended. The maintainer no longer reviews the draft: the release notes are final when the
  release pull request is merged.
- A regular release needs the fuzz, load, engine matrix and advisories runs on the release head or
  on a commit that differs from it only in documentation: after the last code merge, they are
  dispatched again (0.9.0 would have needed new fuzz and load runs). The 0.8.0 and 0.9.0 practice of
  gates read off earlier heads ends.
- The approval is requested only after the CI run on the push of `M` to `main`, which now runs every
  end-to-end job and the compatibility job.
- `dev` must contain the previous release and its hotfixes before a release pull request; a hotfix
  branch must be up to date with `main`.
- Hotfixes are faster (no long runs) and limited to patch versions; their review is the approver's.
- A final-version tag pushed by hand is refused by `publish.yml`; a release whose `publish-release`
  checks fail stays a draft.
- The criteria and the publication checks read the GitHub API with `GITHUB_TOKEN`; an API outage
  fails the release, which is re-run.
- Until decision 6.1 holds, the agents' power over releases is the administrator's, as today.

## Rejected alternatives
- **Option B, no human approval**: an agent merging into `main`, or a stolen token, would produce a
  signed and published release with no pause (maintainer decision of 2026-10-24).
- **Status quo** (four approvals and a manual publication): the same human approves each time, so
  the later prompts add little control (Context) and are approved without being read.
- **Keep the `release` reviewers, automate only the publication**: two human steps for no control
  an edited `publish.yml` could not drop.
- **Environment chosen by expression on the three jobs**: decision 3.3.
- **One gate job for every version, signing jobs without environment**: decision 3.1.
- **Trust the pull request's CI and PR-check results**: a pull request with head `dev` into another
  base fakes them (decision 2.3); the `Release version` job also runs the pull request's code.
- **A labeled override for missing criteria**: decision 2.5.
- **A custom deployment protection rule** (a GitHub App answering for `release` from outside the
  repository): it would hold even against an edited `publish.yml`, but it is a service to host and
  secure; to reconsider with the GitHub App of decision 6.5.

## Security review of 2026-10-24
Verdict: sound after changes. Each finding, and how this revision addresses it:
- **H1** (blocking): the agents' credential acts as the administrator `Yil00`, with ruleset bypass
  `always` on the tag ruleset and `main`. Recorded in the Context. Decision 6.1 is now a hard gate:
  a separate identity with *Write* only, in no bypass list and no reviewer list, with no
  administration, environment, secret, variable or deployment write, and a harness self-check on
  `current_user_can_bypass` and `admin`; the approval permission is marked "to confirm". Decision
  1.3 states that option A gives no protection against agents meanwhile. Rollout step 6 starts
  with that confirmation, and the `release` reviewers and the hand publication
  (`RELEASE_AUTO_PUBLISH` unset) stay until then.
- **M1**: pull request CI and PR-check results could be faked by a pull request into another base.
  Decision 2.3 accepts only the `push` run on `main` at `M` (or a `workflow_dispatch` run on the
  tree of `D`), checking path, event and branch, with a bounded poll, and evaluates the PR checks
  from the merged code. The unpinned `CI result` source (N2) and the Code Owners setting are rollout
  items (steps 1 and 6).
- **M2**: advisories are qualified by the same tree rule as the long runs, and the 72-hour bound
  applies to each job's `started_at` (decision 2.4).
- **M3**: the hotfix checks are stated as catching honest mistakes only; the summary shows the
  hotfix diff and commit count, with a warning above 20 files, and the approver reads the whole
  diff (decisions 2.5, 2.6, 2.9).
- **M4**: `publish-release` identifies the release by the id of the release record, requires one
  release for the tag and the exact title and notes, checks the assets again after publication and
  reverts to a draft on a mismatch; immutable releases are enabled in rollout step 1; editable notes
  are in decision 6.2 (decisions 2.10, 4.1, 4.3).
- **L1**: `git diff --no-renames --name-status`, and why `dev/holdout/` is allowed (decision 2.4).
- **L2**: the `release-it` job runs the criteria again before the token step (decision 2.7).
- **L3**: numeric load inputs checked, a `run-name` from `toJSON(inputs)` compared exactly
  (decision 2.4).
- **L4**: `prepare` checks the path, event and branch of the approved run and the version of its
  release record, and that `T` is exactly the version and changelog hooks applied to `P`; stated as
  not stopping the `RELEASE_TOKEN` holder (decision 3.2).
- **L5**: an exact `prerelease` output and gate conditions, `prepare` at 30 minutes above its
  20-minute poll, strict `needs` results (decisions 3.2, 3.3, 4.1).
- **L6**: rollout step 6 starts with the H1 confirmation.
- **N1**: the Context records that the signing OIDC token is not tied to environments.
- **N2**: the `main` ruleset's `CI result` with no source pinned: rollout step 1.

## Open questions
Each with a proposed answer, for the maintainer.
1. **Which differences keep a long run valid?** Proposed: `docs/`, root `*.md` and `dev/holdout/`
   only (decision 2.4); not tests or any path under `agent/` or `console/` (0.8.0's test-only fix
   #270 would have needed new runs: accepted).
2. **Age bounds.** Proposed: 7 days for fuzz, load and engine matrix; 72 hours for advisories, whose
   result depends on the date; both on each job's `started_at`.
3. **Required load legs.** Proposed: the five of decision 2.4 with default parameters; the SQL
   Server 2019 / 2025 and Extended Events load runs stay measurements, not criteria.
4. **Hotfix criteria.** Proposed: decisions 2.3 and 2.5 only, patch versions only, no override
   label, a warning above 20 changed files; the next regular release runs the long runs on code
   that includes the hotfix.
5. **Agents' identity (hard gate, decision 6.1).** Proposed: a GitHub App installed on this
   repository only (Contents, Pull requests, Issues and Actions write; no Administration,
   Environments, Secrets, Variables or Deployments write), in no bypass list and no reviewer list,
   with the harness self-check; a *Write* machine user if an App does not fit the agent tooling.
   Until it is in place, the `release` reviewers and the hand publication stay.
6. **`RELEASE_ALLOW_ADMIN_BYPASS`.** Proposed: removed in rollout step 6, on the three environments;
   it is not needed by a single maintainer who is a required reviewer.
7. **GitHub App for `RELEASE_TOKEN`.** Proposed: its own ADR, after this rollout, before a second
   maintainer or any widening of agent permissions.
8. **GitHub immutable releases.** Proposed: enabled in rollout step 1, before the first release with
   the new workflows and before any automatic publication.
9. **Code Owners review on `main` and `dev`.** Proposed: enabled in rollout step 6, once agents have
   their own identity, so that the maintainer's review is required on the CODEOWNERS paths (the
   protocol registry); before that, the maintainer's own account opens the pull requests and could
   not approve them. RELEASE.md § 7 records the setting as it stands until then.
10. **CI wait.** Proposed: the criteria job waits up to 140 minutes for the `push` run on `main`
    (the longest `ci.yml` run with every end-to-end job, plus a margin); to adjust after the first
    releases.
