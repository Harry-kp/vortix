---
title: CI workflow reduction & restructure
date: 2026-05-29
status: ready-for-plan
type: refactor
---

# CI workflow reduction & restructure

## Problem

CI feedback on this repo is slow, fires too often, and is hard to maintain. Concrete symptoms observed:

- **Triggers too many times.** No workflow has a `concurrency: cancel-in-progress` block, so every push to a PR spawns a fresh full CI run while previous runs are still chewing through. On a rapid push burst (e.g. the 4 fix-and-push cycles this PR just went through), N parallel runs queue up and burn runner-minutes for results that will be immediately superseded.
- **Slow wall-clock feedback.** `ci.yml` runs 14 jobs per push: Check / Clippy / Test / Docs each across three OSes (macOS, Ubuntu, Fedora-41), plus Format, three boundary checks, and Security Audit. The slowest job in the matrix gates merge.
- **Maintenance burden.** 941 lines across 6 workflow files. The Rust setup stanza (`actions/checkout` + `dtolnay/rust-toolchain` + `Swatinem/rust-cache`) is duplicated across ~14 jobs. `ci.yml` mixes concerns (lint + test + boundary + security) under one workflow name, so a single failed lint job reports as "CI failed" with no concern-level grouping.

The 4-cycle PR experience is the most recent evidence: each cycle, CI showed a fan-out of red across multiple jobs that were really one underlying lint issue. Triage cost was proportional to the number of jobs, not the number of root causes.

## Goals

1. Cut wall-clock feedback time on PR pushes — fewer redundant jobs in the critical path.
2. Eliminate the rapid-push job duplication by adding concurrency-cancel everywhere.
3. Reduce YAML maintenance surface — extract the repeated Rust setup stanza into a reusable workflow.
4. Make failure signals concern-shaped — a lint failure reads as "lint failed", a test failure reads as "test failed", a boundary-check failure reads as "boundary failed". Currently they all just say "CI failed".
5. Keep the actual coverage matrix that's load-bearing for this codebase — multi-OS test (macOS + Linux), real-subprocess integration (privileged container), boundary enforcement (xtask), and packaging verification (install-sanity).

## Non-goals / Out of scope

- **`integration-tests.yml` restructuring.** It's already a single soft-gated job; the file boundary makes sense as-is. Leave it alone.
- **`release.yml` and `release-plz.yml`.** Orthogonal to CI feedback loop. Out of scope.
- **Adding new check types.** This is a reduction, not a feature expansion. No new lints, no new test layers, no new platform coverage.
- **Self-hosted runners or paid runner tiers.** This is open source on free GitHub Actions; runner-cost optimization is not the lever.

## Scope (what's in)

### 1. Concurrency-cancel across every workflow

Add to every workflow file:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

Critical detail: `cancel-in-progress` is conditioned on `pull_request` so that pushes to `main` are never cancelled by subsequent main pushes — only PR-ref runs cancel each other.

### 2. Drop redundant matrix dimensions in `ci.yml`

- **Fedora variants of Check, Clippy, Docs:** drop. Fedora and Ubuntu are the same Linux family for the purposes of these checks; clippy fires the same lints, rustdoc emits the same warnings, `cargo check` succeeds or fails identically. Keep **Fedora Test** — it exercises the non-root `tester` user path that Ubuntu Test does not.
- **Standalone Check jobs:** drop entirely. `cargo test` runs the same compile pass; Check is a duplicate.
- **Docs matrix:** collapse to Linux-only. Rustdoc lints (`rustdoc::broken_intra_doc_links` etc.) fire on source content, not host platform.

Net job count for `ci.yml`: 14 → ~7 (Test ×3 OS, Clippy ×2 OS, Format, Docs ×1, Boundary ×3, Security).

### 3. Split `ci.yml` into per-concern files

Replace the single 202-line `ci.yml` with concern-shaped workflows, each ≤80 lines:

- `lint.yml` — Format + Clippy matrix + Docs
- `test.yml` — Test matrix (macOS / Ubuntu / Fedora)
- `boundary.yml` — the three `cargo xtask check-*-leak` jobs
- `security.yml` — `cargo-deny-action`

Each file has one concern; a failure on `lint.yml` reads as "lint failed" in the PR check list, distinct from `test failed` or `boundary failed`. Triage cost drops.

### 4. Extract reusable Rust setup workflow

Create `.github/workflows/_rust-setup.yml` as a [reusable workflow](https://docs.github.com/en/actions/using-workflows/reusing-workflows) bundling the repeated three steps:

```yaml
on:
  workflow_call:
    inputs:
      toolchain: { type: string, default: "1.91.0" }
      components: { type: string, default: "" }   # e.g. "clippy" or "rustfmt"
      container: { type: string, default: "" }     # e.g. "fedora:41"
```

Each consuming workflow becomes a thin caller. The Fedora-bootstrap (`dnf install -y ...`) lives behind the `container` input. Estimated YAML reduction: ~300 lines across the four CI files.

### 5. Collapse `install-sanity.yml` to a matrix

6 jobs today (cargo install, shell installer, static binary, Arch, Homebrew, npm) each do the same skeleton: install vortix → assert `--version` matches → assert `--help` works. Collapse to a single matrix job parameterized by install-method.

Daily cron → **weekly cron** (`0 6 * * 1`). The install paths (crates.io, Homebrew tap, npm package, Arch repo) don't break daily on a stable release line; weekly observability is sufficient. Keep `on: release` and `workflow_dispatch` triggers as-is.

### 6. Path filtering on `ci.yml` successors

PRs that only touch `docs/**` / `**/*.md` / `LICENSE` / `CHANGELOG.md` skip the Test workflow. Lint still runs (catches broken intra-doc links from a code-doc change). Boundary still runs (cheap, and a stale doc claim might reference a moved file). Security still runs.

Define the path filter in one place (the reusable setup workflow's caller) so the rule doesn't drift across files.

## Success criteria

1. **Concurrency-cancel verified.** Push three consecutive commits to a PR within 30 seconds; observe only the final commit's CI run completes, the first two cancel within ~10 seconds of the next push.
2. **Job count per PR push drops by ≥ 5.** Today: 14 (ci.yml) + 1 (integration). After: ≤ 9 (concern-split) + 1 (integration).
3. **Wall-clock feedback on the typical PR (lib-only change) drops by ≥ 25%.** Measured as time-to-all-required-checks-green on the median of 5 sample PRs after the change vs the median of the 5 PRs before.
4. **Per-concern failure signal.** Open a PR that has a lint-only failure; PR check list shows "Lint / Clippy (ubuntu-latest)" as the failing item, not "CI". A reviewer who has never seen the codebase before can name the failing concern in ≤ 5 seconds of looking at the check list.
5. **YAML line count reduction.** `wc -l .github/workflows/*.yml` total drops by ≥ 30% vs the 941-line baseline.
6. **No coverage loss.** Every assertion run today (cargo test on macOS / Ubuntu / Fedora-tester-user, three xtask boundary checks, cargo-deny, integration, install-sanity for all 6 install methods) still runs on the new shape — just shaped differently across files.

## Dependencies / Assumptions

- **GitHub-hosted Actions runners (`ubuntu-latest`, `macos-latest`, `fedora:41` container) remain free for public repos.** True at time of writing; no plan-side concern.
- **Reusable workflows are available in this account's plan.** They are, on public repos via the free tier.
- **No branch protection currently keys on specific check names.** Verified via `gh api repos/.../branches/main/protection` returning `Branch not protected`. If protection is added later, the check-name rename in §3 needs migration steps; see Risks.
- **`Swatinem/rust-cache@v2` behavior is unchanged when invoked from a reusable workflow.** Standard usage; not expected to regress.
- **The Fedora `test` job's tester-user code path is genuinely load-bearing.** If it's an accident of history with no real coverage value, the whole Fedora job can drop and §2 becomes more aggressive. Verify with the maintainer before planning.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Concurrency-cancel on `main` accidentally fires due to misconfigured group key, killing legitimate main-CI runs | Low | Med | Condition `cancel-in-progress` on `github.event_name == 'pull_request'` exactly as specified in §1. Test by pushing two commits to a feature branch + watching only PR runs cancel; main pushes complete. |
| Check-name rename in §3 breaks future branch protection rules that key on `CI / ...` | Low (no protection today) | Low | Document the new check names in a migration note when branch protection is configured. Don't pre-emptively add aliases. |
| Path-filter on `docs/**` accidentally skips CI for a doc PR that ALSO touches `Cargo.lock` or `.github/**` | Med | Med | Use a *negative* glob — trigger when ANY file outside `docs/**` is touched. Test with a mixed-touch PR before merging the change. |
| Reusable workflow extraction introduces a subtle behavioral diff (e.g. `rust-cache` key collision across consumers) | Low | Med | Verify each consuming workflow runs once after extraction; compare green/red signal to pre-change baseline on 3 sample PRs. |
| Dropping Fedora Check/Clippy/Docs misses a Fedora-specific stdlib/libc regression at lint time | Low | Low | Fedora Test still runs and would catch behavioral regression. The lint pass on Fedora was rarely if ever the only failure source historically. |
| Daily → weekly install-sanity misses a same-day packaging break (e.g. Homebrew tap rebuild that breaks `brew install`) | Low | Low | `on: release` trigger still fires per release; the weekly cron is purely a drift detector. Same-day break is caught by the release-trigger path. |
| `install-sanity` matrix collapse loses the per-install-method visibility in the GitHub UI | Low | Low | Matrix-job names render as `install / cargo-install (ubuntu-latest)`, `install / homebrew (macos-latest)` etc. — same per-method granularity, fewer top-level rows. |

## Outstanding questions

These are answerable during planning, not blocking the brainstorm:

1. **File-naming convention.** `lint.yml` / `test.yml` / `boundary.yml` / `security.yml` — or namespaced like `ci-lint.yml` / `ci-test.yml`? Affects how the PR check list groups visually.
2. **Reusable workflow location.** `.github/workflows/_rust-setup.yml` (leading underscore as a "private" convention) or a more conventional name? GitHub doesn't enforce a convention; readability is the only criterion.
3. **Path filter scope.** Should `Cargo.toml` changes (which COULD be a docs-only metadata bump) trigger full CI? Default yes (any manifest change might affect compile/lint output), but `version` bumps are pure metadata. Worth a 1-paragraph decision at plan time.
4. **Fedora job consolidation.** Could `test-fedora` move to a single Fedora "platform-coverage" job that runs lint + test + docs against the Fedora container, gated by a separate trigger (weekly cron + manual dispatch)? Trades fast-feedback Fedora coverage for slower-feedback Fedora drift detection.

## References

- Authoritative source-of-truth for CI commands and traps: [`docs/ci-parity.md`](../ci-parity.md). The local command set should still match CI after this restructure.
- The 4-cycle PR that prompted this brainstorm: [PR #1](https://github.com/harshit-chaudhary07/vortix/pull/1) (commits `21c84c6` through `61142d2` for the failure cycles).
- Open-source Rust precedent for the target shape: tokio, ratatui, clap — all run fmt/clippy/docs once on Linux, fan-out test matrix only.
