---
title: "refactor: CI workflow reduction & restructure"
type: refactor
status: completed
date: 2026-05-29
origin: docs/brainstorms/2026-05-29-ci-workflow-reduction-requirements.md
shipped_in: PR #1 (bundled with feat/multi-connection per user request)
---

# refactor: CI workflow reduction & restructure

## Summary

Restructure the repo's six GitHub Actions workflows to (1) add `concurrency: cancel-in-progress` on every workflow so rapid PR pushes stop spawning N parallel runs, (2) drop redundant matrix dimensions in `ci.yml` (Fedora Check/Clippy/Docs, standalone Check, Docs-matrix-of-three), (3) split the resulting `ci.yml` into four concern-shaped files (`lint.yml`, `test.yml`, `boundary.yml`, `security.yml`) so PR check rows group by failure type, (4) extract the repeated Rust setup stanza (`checkout` + `rust-toolchain` + `rust-cache`) into a reusable `_rust-setup.yml` workflow consumed by every CI caller, (5) collapse the six install-sanity jobs to a single matrix job and move the cron from daily to weekly, and (6) add a path filter so doc-only PRs skip the slow Test job while keeping cheap green-signal checks. Result: ≥25% wall-clock feedback reduction, ≥30% YAML line reduction, no coverage loss.

---

## Problem Frame

CI feedback on this repo is slow, fires too often, and is hard to maintain. See [origin §Problem](../brainstorms/2026-05-29-ci-workflow-reduction-requirements.md) for the full evidence trail. Three concrete symptoms drive this plan:

- **No workflow has `concurrency: cancel-in-progress`.** Every PR push spawns a fresh full CI run while previous runs are still chewing through. On the 4-cycle fix sequence this PR just went through, ~76 jobs ran in serial across the cycles for results that were immediately superseded.
- **`ci.yml` runs 14 jobs per push** across a three-OS matrix (macOS, Ubuntu, Fedora-41) for Check / Clippy / Test / Docs. The slowest job gates merge. Several matrix dimensions are redundant — Fedora Check/Clippy/Docs produce the same answers as Ubuntu because they exercise the same source under the same Rust toolchain.
- **941 lines across 6 workflow files.** The Rust setup stanza (`actions/checkout` + `dtolnay/rust-toolchain` + `Swatinem/rust-cache`) is duplicated across ~14 jobs. `ci.yml` mixes lint, test, boundary, and security under one workflow name, so a single failed lint job reports as "CI failed" with no concern-level grouping.

---

## Requirements

Sourced from [origin §Goals](../brainstorms/2026-05-29-ci-workflow-reduction-requirements.md):

| ID | Requirement |
|----|-------------|
| R1 | Cut wall-clock feedback time on PR pushes by ≥ 25% on the median sample PR. |
| R2 | Eliminate rapid-push job duplication via `concurrency: cancel-in-progress` on every workflow, conditioned to not cancel pushes to `main`. |
| R3 | Reduce YAML maintenance surface by ≥ 30% via reusable-workflow extraction of the Rust setup stanza. |
| R4 | Make failure signals concern-shaped: a lint failure reads as "Lint failed", test as "Test failed", boundary as "Boundary failed", security as "Security failed". |
| R5 | Preserve all load-bearing coverage: multi-OS `cargo test` (macOS + Ubuntu + Fedora-tester-user), three `cargo xtask check-*-leak` boundary checks, `cargo-deny`, integration tests, install-sanity for all six install methods. |
| R6 | Doc-only PRs (changes confined to `**/*.md`, `LICENSE`, `CHANGELOG.md`) skip the slow Test job while keeping cheap signal checks (Lint, Boundary, Security) green. |
| R7 | `install-sanity.yml`'s six install-method jobs collapse to a single matrix job; cron moves from daily to weekly. |

---

## Key Technical Decisions

### D-1. File-naming convention: bare concern names

The four split files are named `lint.yml`, `test.yml`, `boundary.yml`, `security.yml` — not `ci-lint.yml` / `ci-test.yml`. Bare names render as `Lint / Clippy (ubuntu-latest)` in the PR check list; the leading `Lint /` (the workflow `name:` field) provides natural concern-grouping without repeating "CI" in every row. This matches the convention used by tokio, ratatui, clap, serde, and most major Rust crates with split CI files. Reusable workflows are prefixed with `_` (e.g. `_rust-setup.yml`) per the loose community convention signalling "called via `workflow_call`, not directly triggered".

### D-2. Concurrency-cancel scoped to PR refs only

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

The conditional `cancel-in-progress` is the critical detail: pushes to `main` are NEVER cancelled by subsequent main pushes — only PR-ref runs cancel each other. Group key includes `github.ref` so each PR has its own queue independent of other PRs and main.

### D-3. Path filtering scope: only `Test` skips on doc-only PRs

Doc-only PRs (changes confined to `**/*.md`, `LICENSE`, `CHANGELOG.md`) skip `test.yml`. They KEEP running `lint.yml` (fmt + clippy + docs — rustdoc still validates intra-doc links if the doc change touches a Rust doc comment), `boundary.yml` (cheap xtask greps; ~5s each), and `security.yml` (cargo-deny on Cargo.lock).

Rationale for keeping Lint/Boundary/Security: doc-only PRs need *some* green signal in the PR check list — a PR with zero checks running looks broken. Lint + Boundary + Security combined run in ~30 seconds on Ubuntu; the saving is purely Test wall-clock (the slowest matrix). Path filtering applies to **filename-only patterns**, not paths-inside-content — any change to `Cargo.toml`, `Cargo.lock`, `.github/**`, or `**/*.rs` triggers the full run.

### D-4. `Cargo.toml` changes always trigger full CI

A `version = "0.3.2"` bump is structurally indistinguishable from a dependency rev or feature-flag change at the path-filter level. Defaulting to "any `Cargo.toml` touch runs full CI" trades runner-minutes on rare pure-version-bump commits for correctness — accidental dep changes hidden in a "version-only" commit get caught. The cost is small (version-bump commits are infrequent and release-plz already automates them).

### D-5. Keep Fedora `test` job; drop Fedora variants of Check / Clippy / Docs

Fedora `test` exercises the non-root `tester` user code path (via `useradd tester` + `su - tester`) — that's genuine coverage Ubuntu Test (which runs as the default GitHub Actions user with sudo) does not replicate. Fedora Check / Clippy / Docs do NOT exercise different paths from Ubuntu — same toolchain, same source, same lint set, same rustdoc output. Drop those three; keep `test-fedora`.

### D-6. Standalone `Check` jobs are absorbed into `Test`

`cargo test` runs the same compile pass as `cargo check`. The standalone Check jobs in current `ci.yml` are pure duplicates of work `cargo test` already does. Dropping them saves three jobs (macOS, Ubuntu, Fedora) per push with zero coverage loss. Fast-fail behaviour stays acceptable because cargo's incremental build produces compile errors before linking the test binaries.

### D-7. `integration-tests.yml`, `release.yml`, `release-plz.yml`, `dependabot-auto-merge.yml` are out of scope

Per [origin §Non-goals](../brainstorms/2026-05-29-ci-workflow-reduction-requirements.md). These workflows have correct existing shape — `integration-tests.yml` is already a single soft-gated job, the release plumbing is orthogonal to the CI feedback loop, and the auto-merge bot is tiny single-purpose. They still receive the `concurrency:` block from U1 but no other changes.

---

## Output Structure

After this plan lands, `.github/workflows/` looks like:

```
.github/workflows/
├── _rust-setup.yml          (NEW — reusable workflow, called via workflow_call)
├── lint.yml                 (NEW — Format + Clippy + Docs)
├── test.yml                 (NEW — Test matrix macOS + Ubuntu + Fedora)
├── boundary.yml             (NEW — three xtask check-*-leak jobs)
├── security.yml             (NEW — cargo-deny-action)
├── integration-tests.yml    (unchanged shape; gains concurrency block only)
├── install-sanity.yml       (collapsed: 6 jobs → 1 matrix job, daily → weekly)
├── release.yml              (unchanged shape; gains concurrency block only)
├── release-plz.yml          (unchanged shape; gains concurrency block only)
└── dependabot-auto-merge.yml (unchanged shape; gains concurrency block only)
```

`ci.yml` is **deleted** — its jobs migrate into the four new concern files.

---

## Implementation Units

### U1. Add concurrency-cancel to every workflow

**Goal:** Stop rapid PR pushes from spawning parallel CI runs. Net effect should be immediately visible — push three commits within 30 seconds, observe two cancellations in the GitHub Actions UI.

**Requirements:** R2

**Dependencies:** none — this is the lowest-risk standalone change; could ship as its own PR ahead of everything else if a fast win is wanted.

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/integration-tests.yml`
- Modify: `.github/workflows/install-sanity.yml`
- Modify: `.github/workflows/release-plz.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/dependabot-auto-merge.yml`

**Approach:**
- Add the `concurrency:` block from D-2 to each workflow's top level (sibling of `on:`, `env:`, `jobs:`)
- The group-key + cancel-in-progress predicate is identical across files — copy it verbatim. The `name:` field of each workflow makes the group unique already (it's interpolated into the group string)
- Do NOT add `concurrency:` inside individual jobs — workflow-level is correct here

**Patterns to follow:** GitHub Actions [concurrency docs](https://docs.github.com/en/actions/using-jobs/using-concurrency). No prior pattern in this repo to mirror.

**Test scenarios:**
- Smoke test (manual, post-merge): create a draft PR, push three commits within 30 seconds, verify in the GitHub Actions UI that the first two runs show "Canceled" and only the third runs to completion. Covers R2.
- Smoke test (manual, post-merge): push three commits to `main` within 30 seconds (via a no-op branch fast-forward), verify all three runs complete — no cancellation on main pushes. Guards D-2's PR-only-cancel conditional.

**Verification:** Push to the feature branch → GitHub Actions tab shows the previous run transitioning to "Canceled" within ~10 seconds of the new push.

---

### U2. Reduce `ci.yml` matrix in place (Fedora drops + Check removal + Docs Linux-only)

**Goal:** Drop the redundant matrix dimensions identified in D-5 and D-6. After this unit `ci.yml` still exists (the file split is U4); it just has fewer jobs.

**Requirements:** R5

**Dependencies:** none (could land in parallel with U1)

**Files:**
- Modify: `.github/workflows/ci.yml`

**Approach:**
- Delete jobs: `check` (matrix), `check-fedora`, `clippy-fedora`, `docs-fedora`
- Change `docs` matrix to single-OS (`ubuntu-latest` only)
- Keep: `fmt`, `clippy` (macOS + Ubuntu matrix), `test` (matrix), `test-fedora`, three `check-*-leak`, `security`

**Patterns to follow:** None — straight YAML edits.

**Test scenarios:**
- After PR opens: `gh pr checks <N>` shows exactly 7 jobs from `ci.yml` instead of 14 (Format + Clippy ×2 OS + Test ×3 OS + Docs ×1 + Boundary ×3 + Security). Covers R5.
- Existing passing PR — re-run CI and confirm the trimmed matrix still goes green end-to-end (no test depending on a dropped job's side effects).

**Verification:** Open any PR after U2 lands → CI runs ~half the jobs, all still pass.

---

### U3. Create reusable `_rust-setup.yml` workflow

**Goal:** Net-new file that bundles the repeated Rust setup stanza. Has no callers yet — U4 wires it in. Standalone PR is fine; it adds dead code temporarily but reviews cleanly in isolation.

**Requirements:** R3

**Dependencies:** none

**Files:**
- Create: `.github/workflows/_rust-setup.yml`

**Approach:**
- Reusable workflow with `on.workflow_call.inputs`:
  - `toolchain` (string, default `"1.91.0"`)
  - `components` (string, default `""`) — passed through to `dtolnay/rust-toolchain@master`'s `components:` input (e.g. `"clippy"`, `"rustfmt"`)
  - `container` (string, default `""`) — when non-empty, run on a container image (e.g. `"fedora:41"`) and execute the Fedora bootstrap (`dnf install -y ca-certificates curl gcc gcc-c++ git make pkgconf-pkg-config which`)
- Steps in order: container-bootstrap-if-needed → `actions/checkout@v4` → `dtolnay/rust-toolchain@master` with `toolchain` + `components` → `Swatinem/rust-cache@v2`
- Export NO outputs — the workflow is purely a setup-stanza factory

**Patterns to follow:** GitHub Actions [reusable workflow docs](https://docs.github.com/en/actions/using-workflows/reusing-workflows). The setup stanza already exists 14× in `ci.yml`; this just consolidates it.

**Test scenarios:**
- Standalone PR (just this unit): `gh pr checks` shows U3's commit triggers nothing new (the workflow is never called yet). No regression on existing checks.

**Verification:** PR diff shows ONE new file, ~30 lines. CI on the PR runs the existing trimmed `ci.yml` (post-U2) unchanged.

---

### U4. Split `ci.yml` into `lint.yml`, `test.yml`, `boundary.yml`, `security.yml`

**Goal:** Delete `ci.yml`. Migrate its remaining jobs (post-U2) into four concern-shaped files, each ≤ 80 lines, each consuming `_rust-setup.yml` from U3.

**Requirements:** R3, R4

**Dependencies:** U2 (matrix already trimmed before split), U3 (reusable workflow exists)

**Files:**
- Create: `.github/workflows/lint.yml`
- Create: `.github/workflows/test.yml`
- Create: `.github/workflows/boundary.yml`
- Create: `.github/workflows/security.yml`
- Delete: `.github/workflows/ci.yml`

**Approach:**
- `lint.yml` (`name: Lint`) — jobs: `fmt` (single), `clippy` (macOS + Ubuntu matrix), `docs` (Ubuntu). Each job calls `_rust-setup.yml` then runs the lint command.
- `test.yml` (`name: Test`) — jobs: `test` (macOS + Ubuntu matrix with VPN tool install), `test-fedora` (with non-root tester-user setup; can't fully delegate to `_rust-setup.yml` because the bootstrap differs)
- `boundary.yml` (`name: Boundary`) — three jobs: `check-subprocess`, `check-platform-leak`, `check-protocol-leak`. Each calls `_rust-setup.yml` then runs the xtask.
- `security.yml` (`name: Security`) — single job: `EmbarkStudios/cargo-deny-action@v2`. No Rust toolchain needed; doesn't call `_rust-setup.yml`.
- Each new file gets the `concurrency:` block from D-2.
- Each new file gets `on:` mirroring the original `ci.yml` (`push: branches: [main]`, `pull_request: branches: [main]`).
- Carry `env: { CARGO_TERM_COLOR: always }` to each file.
- Carry `RUSTDOCFLAGS: -D warnings` env on the `docs` job in `lint.yml`.

**Patterns to follow:** Open-source Rust precedent — tokio's `ci.yml` is split into `loom.yml` / `miri.yml` / `cross-check.yml` / etc; ratatui has `lint.yml` + `test.yml`; clap has `ci.yml` split by concern in `.github/workflows/`.

**Test scenarios:**
- After merge: `gh pr checks` on a fresh PR shows four workflow groups in the PR check list ("Lint / ...", "Test / ...", "Boundary / ...", "Security") instead of a single "CI" parent. Covers R4.
- After merge: trigger a deliberate fmt failure → only "Lint / Format" reports red; Test/Boundary/Security stay green and complete. Covers R4 from the negative side.
- Total job count per PR push after U4 = 7 (same as post-U2) + 0 new — the split is structural, not additive.

**Verification:** `wc -l .github/workflows/*.yml` drops from 941 baseline by ≥ 30% (target ≥ 660 line count); `ci.yml` is gone; four new files each ≤ 80 lines.

---

### U5. Collapse `install-sanity.yml` jobs to a matrix; cron daily → weekly

**Goal:** Six near-identical install-method jobs (cargo install, shell installer, static binary, Arch, Homebrew, npm) become one matrix-parameterised job. Cron moves from `0 6 * * *` to `0 6 * * 1` (Mondays at 06:00 UTC).

**Requirements:** R5, R7

**Dependencies:** none (independent of `ci.yml` work)

**Files:**
- Modify: `.github/workflows/install-sanity.yml`

**Approach:**
- Define matrix entries with the install method as one dimension and OS as another. Each entry carries an `install_command` (e.g. `cargo install vortix`, `brew install Harry-kp/tap/vortix`, etc.) and a `version_source` (crates.io API, GitHub release tag, package manager's lag-tolerant version).
- Some methods are OS-restricted: `arch-linux` is Ubuntu-container-only; `static-binary` is Linux-only; `homebrew` runs on both. Use matrix `exclude:` to handle the restrictions.
- The post-install assertions (verify `--version`, verify `--help`, verify `sudo` access) are identical across methods — extract to a single sequence of steps after the install step.
- Cron: change `cron: "0 6 * * *"` to `cron: "0 6 * * 1"`.
- Keep `on: release: [published]` and `workflow_dispatch:` triggers.

**Patterns to follow:** Matrix-with-`include:` is the standard GitHub Actions pattern for "N different install paths, same verification". See `actions/cache`'s own install-sanity for an example.

**Test scenarios:**
- After merge: trigger `workflow_dispatch` manually → matrix runs the six install methods, all pass, total job count = 6 (parameterised) instead of 6 (separate).
- Wait one week post-merge → confirm Monday cron fired and Tuesday did not.

**Verification:** `install-sanity.yml` line count drops from 253 to ≤ 130. The six install methods all still verify the binary works.

---

### U6. Add path filtering for doc-only PRs

**Goal:** PRs that only touch `**/*.md`, `LICENSE`, or `CHANGELOG.md` skip `test.yml`. Lint, Boundary, Security continue running so the PR has green signal.

**Requirements:** R6

**Dependencies:** U4 (the new files must exist)

**Files:**
- Modify: `.github/workflows/test.yml`

**Approach:**
- Add `paths-ignore:` to the `on.pull_request:` and `on.push:` triggers of `test.yml` only:
  ```yaml
  on:
    pull_request:
      branches: [main]
      paths-ignore:
        - "**/*.md"
        - "LICENSE"
        - "CHANGELOG.md"
    push:
      branches: [main]
      paths-ignore:
        - "**/*.md"
        - "LICENSE"
        - "CHANGELOG.md"
  ```
- `paths-ignore` is GitHub Actions' negative filter — the workflow does NOT run when EVERY changed file matches. A mixed PR touching one `.md` and one `.rs` triggers normally.
- DO NOT add `paths-ignore` to `lint.yml`, `boundary.yml`, `security.yml` — they keep green signal.
- DO NOT add it to `Cargo.toml`-only changes (D-4).

**Patterns to follow:** [GitHub Actions paths-ignore docs](https://docs.github.com/en/actions/using-workflows/triggering-a-workflow#using-filters).

**Test scenarios:**
- Open a PR that touches ONLY `README.md` → `gh pr checks` shows Lint, Boundary, Security all green; Test does NOT appear in the check list. Covers R6.
- Open a PR that touches `README.md` AND `Cargo.lock` → Test DOES run (mixed-touch case).
- Open a PR that touches `Cargo.toml` only (a synthetic version bump) → Test DOES run (D-4).

**Verification:** A pure docs-only PR completes CI in ≤ 60 seconds wall-clock (Lint + Boundary + Security only); a mixed PR still runs the full matrix.

---

## Scope Boundaries

### Deferred to Follow-Up Work
- Per-platform reusable test workflow (test setup currently lives inline in `test.yml` and replicates VPN-tool install per OS) — extractable later but the install step is meaningfully OS-specific and the duplication is small.
- Custom GitHub Actions composite action wrapping the boundary checks — pure DRY for three single-step jobs, low value.

### Outside this plan's identity
- Changes to `integration-tests.yml`, `release.yml`, `release-plz.yml`, `dependabot-auto-merge.yml` beyond the `concurrency:` block addition.
- Self-hosted runners or paid runner tiers (per origin §Non-goals).
- New check types — no new lints, no new test layers, no new platform coverage.
- Branch protection configuration. Branch protection is currently absent (`gh api repos/.../branches/main/protection` returns `Branch not protected`); when it's added later, the check-name rename from this plan needs a one-time migration note, not a code change here.

---

## Verification Strategy

**Smoke tests (manual, post-merge):**

1. **Concurrency-cancel verification** (U1) — Push three feature-branch commits within 30 seconds. Observe in the GitHub Actions UI: previous runs transition to "Canceled" within ~10 seconds of the new push. Push three `main` commits within 30 seconds (e.g. via `git push --force-with-lease` on a no-op merge). Observe all three complete to confirm D-2's main-ref guard.
2. **Job-count reduction** (U2, U4) — On any post-U4 PR, `gh pr checks` should show ≤ 9 total jobs (was 14 in `ci.yml` + 1 integration; should be 7 from the split + 1 integration after U4).
3. **Per-concern failure signal** (U4) — Deliberately push a fmt-violating commit. PR check list shows red on "Lint / Format" specifically, not "CI / Format". Other concern workflows stay green and complete.
4. **YAML line-count reduction** (U4) — `wc -l .github/workflows/*.yml | tail -1` shows total ≤ 660 lines (was 941). Target: ≥ 30% reduction per R3.
5. **Doc-only PR fast path** (U6) — Open a PR touching only `README.md`. Test workflow does not appear in check list; Lint, Boundary, Security complete in ≤ 60 seconds.
6. **Mixed-touch PR full path** (U6) — Open a PR touching `README.md` AND `Cargo.lock`. All workflows run normally.
7. **Install-sanity matrix** (U5) — Manually `workflow_dispatch` install-sanity post-merge. Matrix expands to 6 entries, all pass. Confirm next Monday's cron run fires; confirm no Tuesday run.

**Wall-clock measurement (R1, success criterion 3 from origin):**

Pick 5 representative PRs from the last 30 days (mix of lib changes, multi-file refactors, doc tweaks). Re-run their CI on the new shape. Median wall-clock should drop ≥ 25% vs the median on the old `ci.yml` shape.

**No coverage loss verification (R5):**

Build a coverage matrix table comparing pre-/post-restructure: every `cargo test` invocation, every `cargo xtask` boundary check, every install verification path should map to at least one job in the new shape. Done as part of U4's PR description.

---

## System-Wide Impact

- **Interaction graph:** Four new workflows each call `_rust-setup.yml`. The setup workflow is the sole point of toolchain version management — changing Rust 1.91 to 1.92 becomes a one-line edit in `_rust-setup.yml` instead of 14 edits across `ci.yml`.
- **Error propagation:** None — these are pure YAML/orchestration changes. No runtime code paths affected.
- **State lifecycle risks:** `rust-cache` keys are derived per-job from `Cargo.lock` + toolchain; the reusable-workflow invocation gives each consuming job its own cache slot. Verify no accidental cache collision after U4 lands (first run after merge will be a cold cache — expected and acceptable).
- **API surface parity:** PR check-list rendering changes. A required-status-check rule (none exist today) keyed on the old name `CI / Format` would break and need migration to `Lint / Format`. Document the rename in commit body.
- **Cross-platform parity:** Matrix coverage preserved per D-5 — macOS + Ubuntu + Fedora-tester-user `cargo test` still runs.
- **Cargo xtask boundary checks:** Still run in CI via `boundary.yml` (one job per xtask command), unchanged behavior.

---

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Concurrency-cancel accidentally fires on `main` pushes due to malformed group key, killing legitimate main-CI runs | Low | Med | D-2's `cancel-in-progress` is conditional on `github.event_name == 'pull_request'`. U1's test scenarios include the main-push case. |
| Check-name rename (`CI / X` → `Lint / X` etc.) breaks future branch protection rules | Low (no protection today) | Low | No branch protection currently configured (`gh api .../branches/main/protection` returns `Branch not protected`). Document the new check names in U4's commit body. |
| Path-filter on `**/*.md` accidentally skips Test for a doc-only PR that someone EXPECTED to test | Med | Low | Mitigation = clear naming and PR template hint: "If this PR needs Test to run despite being doc-only, touch any non-doc file." Easy escape hatch. |
| Reusable workflow extraction (U3) introduces a subtle cache-key collision or toolchain-version drift | Low | Med | First post-U4 PR is the canary: cold-cache build expected, but if the toolchain version is wrong or the components input is broken, lint/test will fail immediately on the canary, not silently later. |
| Dropping Fedora Check/Clippy/Docs (D-5) misses a Fedora-specific stdlib/libc regression at lint time | Low | Low | Fedora Test still runs (catches behavioral regressions); the lint pass on Fedora was historically never the sole failure source. |
| Weekly install-sanity (vs daily) delays detection of a same-day packaging break (e.g. Homebrew tap update breaks `brew install`) | Low | Low | `on: release` trigger still fires per release. Weekly cron is purely drift detection — same-day breaks are caught via the release-trigger path. |
| `install-sanity` matrix collapse loses per-install-method visibility in the GitHub UI | Low | Low | Matrix jobs render as `Installation Sanity / install (cargo-install, ubuntu-latest)`, `... (homebrew, macos-latest)` etc. — same granularity, fewer top-level workflow rows. |
| U4's per-concern split creates four new workflow rows in the PR check list; some users may prefer fewer rows | Low | Low | The four-row arrangement IS the goal (R4). If feedback says it's noisier, fold `boundary.yml` and `security.yml` back into one `static-checks.yml` in a follow-up. |

**Dependencies between units:**

```
U1 ─┐
U2 ─┼─→ (independent landings possible)
U3 ─┘
         U4 (needs U2 done, U3 created)
                 │
                 └─→ U6 (path filtering)

U5 ─→ (independent)
```

U1, U2, U3, U5 can each ship as separate PRs in any order. U4 ships after U2 and U3 land. U6 ships after U4. Most natural sequencing: U1 first (immediate pain relief, lowest risk), then U2 (visible job-count drop), then U3 (sets up U4), then U4 (the big restructure), then U6 (capstone), with U5 slotted in any time.

---

## Alternative Approaches Considered

- **Minimal-only approach (origin Approach 1).** Just U1 + U2; skip the file split, reusable workflow, install-sanity collapse, path filtering. Rejected during brainstorm because it leaves the maintenance-burden pain (origin §Problem item 3) untouched while solving only the rapid-push pain.
- **Standard cleanup (origin Approach 2).** U1 + U2 + path filtering + install-sanity weekly cron, but no file split or reusable workflow. Rejected during brainstorm because it leaves the YAML duplication and the per-concern signal problem in place.
- **Fold install-sanity into `ci.yml`.** Move the install verification into the main CI workflow gated by an `if: github.event_name == 'release'`. Rejected: install-sanity is genuinely a different concern (packaging vs source correctness), the daily/weekly cron only makes sense on its own workflow, and merging it would create the same single-monolithic-file problem this plan is solving.
- **Self-hosted runners.** Address slow wall-clock by paying for faster runners. Rejected as out-of-scope per origin §Non-goals — this is open source on free GitHub Actions; runner-cost optimization isn't the lever.

---

## Documentation Plan

- After U1 lands: update `docs/ci-parity.md` with a one-line note about concurrency-cancel ("rapid-push commits will cancel the previous CI run on the same PR").
- After U4 lands: update `docs/ci-parity.md`'s command set to reflect the new check names (`Lint / Clippy` etc.), and update `CLAUDE.md`'s reference if it names specific check rows.
- After U6 lands: document the path-filter behavior in `docs/ci-parity.md` (one short paragraph).
- No new docs are created — all updates land in existing files.
