---
name: release-qa
description: Pre-release QA for vortix — run the P0 release gate (CI gate, smoke set, risk pass from the diff since the last tag, exploratory pass) live in the TUI and CLI on macOS and the Linux lab, fix what breaks with a regression test per finding, log results in P0.md, and end with a go/no-go report. Use whenever the user is about to cut a release, asks to "test everything before release", wants manual or QA-style testing of the live TUI, or asks for release confidence, even if they don't say "P0" or "release-qa".
---

# Release QA

The user wants high confidence that the next release works for a real person
on both platforms. `docs/manual-testing/P0.md` is the plan and owns every
workflow, pass signal and safety rule. This skill is how to run it. Read
`CLAUDE.md` and P0.md's "Strategy" and "Safety rules" before touching a
machine.

## 0. Before anything

- Note the state you must restore on both machines: the kill-switch mode
  (`vortix killswitch`), the theme (`grep theme ~/.config/vortix/config.toml`),
  and whatever tunnels are up (normally none).
- Check the harness: `tmux list-windows -t vxrun` on the Mac (ask the user to
  create it if it is missing), and `ssh` to the lab. Never run `sudo` on the Mac.
- `git describe --tags --abbrev=0` gives the last tag. Then
  `git diff --stat <tag>..HEAD -- crates/` plus P0.md's risk map tell you
  which areas pass 3 covers.
- Create one task per pass and per P0 area so the user can follow along.

## 1. Gate

`scripts/ci-local.sh --quick` on the Mac. On the lab: sync the branch, then
`umask 022 && cargo build -p vortix && cargo test -p vortix` (the `fix-bug`
skill has the exact `lab()` function and `git apply` sync). Stop on red.

## 2–4. Smoke, risk, explore

Walk the P0.md smoke set on both machines, then the risk-mapped workflows,
then about 15 minutes per machine trying to break what changed. Run the whole
file when the engine, a firewall or DNS backend, or a protocol layer changed
broadly.

Keep a running results table in `target/qa-results.md` (ID, check, macOS,
Linux, note), updated after each area rather than at the end. That way a lost
context or an interruption loses nothing.

Harness lessons that each cost time in an earlier run:

- **Write multi-step probes as a bash script in `$CLAUDE_JOB_DIR/tmp` and run
  the script in the root pane.** The Mac root shell is zsh with aliases:
  `wg`, `k` and `ls` do surprising things, and an aliased `wg` started a
  watcher that had to be stopped with Ctrl-C. Use full paths
  (`/opt/homebrew/bin/wg`, `/bin/ps`, `/usr/bin/grep`).
- **Kill-switch checks:** follow P0.md's safety rules literally. Put the probe
  and the `killswitch off` in the same script with `trap … EXIT`. Block for
  seconds on the Mac, and do longer blocks only on the lab. Take a
  no-VPN baseline probe first: `1.1.1.1` is unreachable from the home LAN, so
  "blocked" against it proves nothing.
- **Quit the TUI (`q`) before CLI lifecycle checks.** It holds the lifecycle
  lock. Profiles imported while the TUI runs are not seen until it restarts.
- **After a rebuild, restart the TUI** before retesting. An old binary still
  running is the usual reason a fix "didn't work".
- **Read evidence from logs as well as frames:** `~/.config/vortix/logs/` (by
  date) and `~/.config/vortix/run/*.log` (OpenVPN). Count secret-shaped
  matches, never print them, and redact public IPs in anything you report.
- **Frames:** redact before quoting; cut columns (`cut -c…`) to read one panel;
  use `grep -a` because frames contain braille, which grep treats as binary.

## When something fails

Treat every finding as a bug fix, on the release branch:

1. Decide whether it is real: rerun it, and check that the fixture and probe
   can actually fail. A vacuous or wrong probe is a harness bug; fix the step
   in P0.md instead.
2. Write the test that fails for the reported reason where the behaviour is
   owned (`control/`, `app/tests.rs`, render tests; see `fix-bug` step 3).
   Confirm it is red.
3. Fix at the root. If the TUI and CLI disagree, one of them kept its own copy
   of a rule the engine owns: delete the copy and read the snapshot (P0-39).
4. Green test, then `cargo clippy --all-targets`, then re-verify live on both
   machines. Run the mandatory `ponytail:ponytail-review` on the diff, then
   make one `fix:` commit per finding.
5. Log it: `FAIL→fixed` in the results table, plus the one-line cause.

Anything you decide not to fix (by design, or needing a product call) goes in
the report as open, with its user-visible effect. It is never silently dropped.

## Finish

1. Restore both machines to the state noted in step 0 and prove it: no
   tunnels, the kill-switch mode, empty pf anchor / nft table, the theme.
2. Update P0.md's results log with this run: one row per area, the fixed
   findings, and the open ones. Fix any workflow whose expectation turned out
   stale. Add a workflow only for something no automated test can catch.
3. Run `scripts/ci-local.sh` (the full run, with release build) and the lab tests
   again on the final branch.
4. Push once, open one PR (one commit per finding plus the P0.md update),
   watch `gh pr checks`, and rebase-merge only when every row is `pass` or
   `skipping`. Push and merge need the user's go-ahead unless they already
   gave it for this run.
5. Report to the user in short points:
   - **Verdict:** go or no-go.
   - **Covered:** what was tested on each machine.
   - **Fixed:** each finding, with its commit.
   - **Open:** what remains and its impact.
   - **Not run:** anything skipped, and why.
