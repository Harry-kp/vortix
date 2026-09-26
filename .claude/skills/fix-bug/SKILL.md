---
name: fix-bug
description: End-to-end bug fix for the vortix repo — reproduce with a failing test, fix at the root, pass the full CI parity check, verify live on macOS and the Linux lab, review, open a PR, watch CI, and squash-merge when everything is green. Use whenever the user hands over a bug (GitHub issue number or URL, pasted error, log excerpt, screenshot of the TUI, or "X is broken") and wants it fixed, even if they don't say "PR" or "merge".
---

# Fix a vortix bug end to end

The user invoked this to get from a bug report to a merged fix without
supervision: create a branch, commit, push it, open a PR, and squash-merge once
the gate in step 11 passes. Never `sudo` on the Mac, force-push, push to `main`,
or touch other branches or PRs. Read `CLAUDE.md` first; it is the rulebook.

`git push` and `gh pr merge` still ask for approval (`.claude/settings.json`).
Keep it to one push and one merge: finish both reviews (step 8) and
`scripts/ci-local.sh` before the first push. If a prompt is denied or nobody
answers, stop and report the branch name and the exact command left to run.

**Several issues at once:** one branch and one PR for all of them, with one
commit per issue (each ending `Fixes #<n>`). Run steps 1–8 per issue and
commit it before starting the next; push and open the PR once, after the last.
Merge that PR with `gh pr merge --rebase --delete-branch` so every issue keeps
its own commit on `main`.

## 1. Understand the report

- Issue number/URL: `gh issue view <n> --comments`. Otherwise use what the user pasted.
- Write down, in one or two lines: observed behaviour, expected behaviour,
  platform (macOS / Linux) if known.
- Use CLAUDE.md's "Where things live" table to find the owning module, then
  trace the real flow end to end before forming a theory. `rg` every caller of
  the function you suspect.

If the report is too vague to reproduce and the code gives no strong lead, ask
the user one precise question instead of guessing.

## 2. Branch

```bash
git fetch origin && git switch -c fix/<short-slug> origin/main
```

Ignore `.DS_Store` and `target/`. If the working tree has any other unrelated
changes, stop and tell the user rather than carrying them onto the branch.

## 3. Reproduce it live

Before any test or theory, make the bug happen for real, with the released
build the reporter used (`cargo install vortix --version <v> --root <tmp>` or
the release's shell installer into a scratch folder) and the same inputs.
Record the exact error or frame. A live run also shows what the report
missed: in #330 the import error was the reported symptom, but the live
connect showed the same limit made the tunnel look handshake-less and then
invisible to Vortix.

- Use a scratch config directory (`vortix -C <tmp>`) so real profiles and
  state are untouched.
- Prefer the Linux lab for anything that connects. When the bug needs a
  profile shape nobody has, derive it from a lab profile with a script that
  never prints the file, keep it on that machine with mode 600, and delete it
  (and any staged copy) when done. Real endpoints and keys stay out of the
  repo, logs and chat.
- If it truly cannot happen outside CI or a user's machine, say so and why.

## 4. Capture it in a failing test

A fix without a test that failed first is a guess. Put the test where the
behaviour is owned:

- Engine decisions (routes, DNS, firewall, conflicts, phase changes):
  `control/plan.rs` or `control/state.rs` unit tests.
- Parsing: tests next to `wireguard/parser.rs` / `openvpn/parser.rs`.
- TUI rendering: `App::new_test()` + `App::set_tunnels_for_test` /
  `app::connection::test_view`, render to a `TestBackend`, assert on the text.
- CLI/JSON: `crates/vortix/tests/suite/` — add a `mod` line to `suite/main.rs`
  or the file silently never runs.

One test per symptom seen live. Run them against the unchanged code and
confirm each fails for the reason seen live: `cargo test -p vortix <name>`.
Only a real kernel, terminal or VPN server that no test can stand in for goes
to P0 instead.

## 5. Root cause

Write down, in a few lines, why each symptom happens: the file and line, and
why that code exists. `rg` every copy of the rule (limits, checks, parsers are
often duplicated) and every place that stores or re-reads the same data. The
fix follows from this; do not start it until every live symptom is explained.

## 6. Fix at the root


- Fix once where every caller's path meets, not in the caller the report
  happened to name. Grep for sibling paths with the same flaw.
- Prefer deleting or simplifying over adding guards. No new dependency, trait,
  builder or `#[allow]` to make it pass.
- Keep user-visible behaviour identical apart from the bug.
- Linux-only code (`linux/`, `cfg(target_os = "linux")`) is compiled locally
  only by the Linux cross-clippy in `ci-local.sh`; run its tests on the lab
  laptop (step 7).

Re-run the new tests (now passing) and the module's tests, then repeat the
live reproduction from step 3 with this build: it must now pass.

## 7. Verify

```bash
scripts/ci-local.sh
```

It must end with `All checks passed.` Paste the tail as evidence; "passes
locally" without output doesn't count. Fix every failure, including ones that
look unrelated to your change.

**Linux lab** (CLAUDE.md, "Live testing (Linux)"): apply the branch there and
run the tests, which also runs Linux-only code for real:

```bash
# a function, not a variable: the shell here is zsh, which does not split $L
lab() { ssh -i ~/.ssh/vortix_lab_ed25519 -o BatchMode=yes harrykp@192.168.1.97 "$@"; }
lab 'cd ~/vortix && git fetch -q origin main && git checkout -q -f -B lab FETCH_HEAD'
git diff origin/main -- crates scripts | lab 'cd ~/vortix && git apply --index'
lab 'cd ~/vortix && umask 022 && cargo build -p vortix && cargo test -p vortix'
```

The lab's login umask is 002. Tests build config dirs with `tempfile`, which
inherits it, and the owned-file checks refuse a group-writable directory, so
without `umask 022` about 20 file-safety tests fail for reasons unrelated to
the change.

**Live check** when the change affects runtime behaviour (connect, routes, DNS,
kill switch, TUI frames), on both machines:

- macOS: tmux `vxrun` (window 0 TUI, window 1 root shell). If it is missing,
  skip and say so in the PR. Send `q` to window 0 first in case an old TUI
  holds the lifecycle lock, then run
  `/Users/harshitchaudhary/Documents/personal/vortix/target/debug/vortix`.
- Linux: `lab 'cd ~/vortix && sudo -n env SUDO_UID=1000 SUDO_GID=1000
  SUDO_USER=harrykp ./target/debug/vortix …'` for CLI checks; drive the TUI
  with `lab 'tmux send-keys -t vxlinux:1 …'` and read it with
  `lab 'tmux capture-pane -p -t vxlinux:1'`.

Behaviour must match on both; a Linux-only difference is a bug, not a quirk.

Safety, so a check never cuts off this session:
- Note the kill switch mode first and restore it at the end; disconnect every
  tunnel you started. Never leave `vpn-only` on without a live tunnel.
- On the lab, never connect a profile that routes `192.168.0.0/16` (it carries
  SSH to the laptop).
- Use WireGuard or profiles with saved credentials. If a credential prompt
  appears, skip that check and note it in the PR — credentials are typed by
  the user.

## 8. Review before committing

Two passes over `git diff origin/main` (staged and unstaged), both required:

1. **Simplicity (mandatory):** run the `ponytail:ponytail-review` skill on the
   diff. Apply every `delete`/`yagni`/`shrink` finding, or say in the PR why
   it stays. A fix that grew a second mechanism "to be safe" usually shows up
   here; keep the one that covers every path.
2. **Correctness:** run `/code-review` if available, otherwise read the diff
   and check correctness, missed sibling callers, test strength, and CLAUDE.md
   rules (boundaries, kill switch vocabulary, no plan IDs in comments, no stray
   `#[allow]`).

Fix real findings, then re-run `scripts/ci-local.sh`. Commit only after both
passes; if a later change lands on the branch, review that change the same way.

## 9. Commit, push once, open the PR

```bash
git add <files you changed>          # never .DS_Store, profiles or keys
git commit                           # the pre-commit hook runs fmt, clippy, gitleaks, tests
git push -u origin HEAD
gh pr create --base main --title "<same subject>" --body "<body>"
```

Commit message: a `fix:` subject under ~70 chars, a body explaining the root
cause and why the fix is at the right place, ending with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

PR body: **Problem** (`Fixes #<n>` closes the issue; no labels needed),
**Root cause**, **Fix**, **Tests** (the new test and the `ci-local.sh` result),
**Live check** (macOS and Linux: what was observed, or why it was skipped).
End it with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## 10. Watch CI

```bash
gh pr checks --watch
```

For a failure: `gh run view <run-id> --log-failed`, fix the cause (Linux
failures usually come from `cfg(target_os = "linux")` code or scripts under
`tests/integration/`), re-run step 7, push, watch again. A failure that does
not reproduce locally or on the lab gets one `gh run rerun <run-id> --failed`;
if it fails again it is real — fix it or stop and report. Never merge over a
red check.

## 11. Merge

`main` has no branch protection, so this gate is the only one. Merge only when
all of these hold:

- every `gh pr checks` row is `pass` or `skipping` — none `fail`, `pending` or
  `cancel` (release and dependabot jobs always show `skipping`);
- the review in step 8 has no unresolved findings;
- the new test failed before the fix and passes after.

```bash
gh pr merge --squash --delete-branch
```

Never use `--auto`: with no required checks it merges immediately. If any
condition can't be met, leave the PR open and tell the user what is blocking.

## 12. Report

Tell the user in a few short lines: the root cause, the fix, the PR link, the
CI result, whether it was merged, and anything noticed but not fixed.
