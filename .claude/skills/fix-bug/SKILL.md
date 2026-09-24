---
name: fix-bug
description: End-to-end bug fix for the vortix repo — reproduce with a failing test, fix at the root, pass the full CI parity check, open a PR, review it, watch CI, and squash-merge when everything is green. Use whenever the user hands over a bug (GitHub issue number or URL, pasted error, log excerpt, screenshot of the TUI, or "X is broken") and wants it fixed, even if they don't say "PR" or "merge".
---

# Fix a vortix bug end to end

The user invoked this to get from a bug report to a merged fix without
supervision. Invoking it authorizes: creating a branch, committing, pushing
that branch, opening a PR, and squash-merging it once the gate below passes.
It does not authorize `sudo`, force-pushes, pushing to `main`, or touching
other branches or PRs. Read `CLAUDE.md` first; it is the rulebook for this repo.

## 1. Understand the report

- Issue number/URL: `gh issue view <n> --comments`. Otherwise use what the user pasted.
- Write down, in one or two lines: the observed behaviour, the expected
  behaviour, and the platform (macOS / Linux) if known.
- Use CLAUDE.md's "Where things live" table to find the owning module, then
  trace the real flow end to end before forming a theory. `rg` every caller of
  the function you suspect.

If the report is too vague to reproduce and the code gives no strong lead, ask
the user one precise question instead of guessing.

## 2. Branch

```bash
git fetch origin && git switch -c fix/<short-slug> origin/main
```

If the working tree has unrelated changes, stop and tell the user rather than
carrying them onto the branch.

## 3. Reproduce with a failing test

A fix without a test that failed first is a guess. Put the test where the
behaviour is owned:

- Engine decisions (routes, DNS, firewall, conflicts, phase changes):
  `control/plan.rs` or `control/state.rs` unit tests.
- Parsing: tests next to `wireguard/parser.rs` / `openvpn/parser.rs`.
- TUI rendering: `App::new_test()` + `App::set_tunnels_for_test` /
  `app::connection::test_view`, render to a `TestBackend`, assert on the text.
- CLI/JSON: `crates/vortix/tests/suite/` — add a `mod` line to `suite/main.rs`
  or the file silently never runs.

Run it and confirm it fails for the reason in the report:
`cargo test -p vortix <test_name>`.

If the bug needs a real kernel, VPN server or terminal and no automated test
can express it, say so, reproduce it live instead (step 5), and add a P0
workflow only if nothing automated can ever cover it.

## 4. Fix at the root

- Fix once where every caller's path meets, not in the caller the report
  happened to name. Grep for sibling paths with the same flaw.
- Prefer deleting or simplifying over adding guards. No new dependency, trait,
  builder or `#[allow]` to make it pass.
- Keep user-visible behaviour identical apart from the bug.
- Linux-only code: you cannot run it; the Linux cross-clippy in `ci-local.sh`
  compiles it and CI's integration tests run it.

Re-run the new test (now passing) and the module's tests.

## 5. Verify

```bash
scripts/ci-local.sh
```

It must end with `All checks passed.` Paste the tail as evidence; "passes
locally" without output doesn't count. Fix every failure, including ones that
look unrelated to your change.

If the change affects runtime behaviour on macOS (connect, routes, DNS, kill
switch, TUI frames) and the tmux session `vxrun` exists, check it live as
CLAUDE.md describes: `cargo build -p vortix`, run `./target/debug/vortix` in
window 0, and confirm the fix in a captured frame plus host state from window 1.
If `vxrun` is missing, skip the live check and say so in the PR.

## 6. Commit and open the PR

```bash
git add <files you changed>          # never .DS_Store, never profiles or keys
gitleaks protect --staged --redact
git commit                           # conventional subject, e.g. "fix: ..."
git push -u origin HEAD
gh pr create --base main --title "<same subject>" --body "<body>"
```

Commit message: a `fix:` subject under ~70 chars, a body explaining the root
cause and why the fix is at the right place, ending with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

PR body: **Problem** (link the issue with `Fixes #<n>`), **Root cause**,
**Fix**, **Tests** (the new test and the `ci-local.sh` result), **Live check**
(what was observed, or why it was skipped). End it with
`🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## 7. Review

Review the PR diff as a skeptical reviewer would: run the `/code-review` skill
if it is available, otherwise read `gh pr diff` and check correctness, missed
sibling callers, test strength, and CLAUDE.md rules (boundaries, kill switch
vocabulary, no plan IDs in comments, no stray `#[allow]`). Fix real findings
with new commits, re-run `scripts/ci-local.sh`, and push.

## 8. Watch CI

```bash
gh pr checks --watch
```

For a failure: `gh run view <run-id> --log-failed`, fix the cause (Linux
failures usually come from `cfg(target_os = "linux")` code or integration
scripts under `tests/integration/`), push, and watch again. Don't retry a
flaky-looking job more than once without finding why it failed.

## 9. Merge

`main` has no branch protection, so this gate is the only one. Merge only when
all of these hold:

- every entry in `gh pr checks` is `pass` (none pending, none failing);
- the review in step 7 has no unresolved findings;
- the new test failed before the fix and passes after.

```bash
gh pr merge --squash --delete-branch
```

If any condition can't be met, don't merge. Leave the PR open and tell the
user exactly what is blocking.

## 10. Report

Tell the user in a few short lines: the root cause, the fix, the PR link, the
CI result, whether it was merged, and anything noticed but not fixed.
