---
name: autopilot
description: One tick of Vortix's automated lifecycle — resume unfinished work, keep main and open PRs green, triage new issues, build the next approved or bug issue end to end with fix-bug, prepare a release for the maintainer's approval, and verify it after it ships. Run it on a loop (`/loop /autopilot`); use it whenever the user asks to "run the project", "work the backlog", "keep going on your own" or "autopilot", even if they name no issue.
---

# Autopilot

Vortix runs itself except for two decisions the maintainer keeps:

1. **Ideation:** what gets built. Only bugs and issues labelled `approved` are built. Ideas wait
   as `proposal` until the maintainer labels them `approved` or `deferred` (or decides in a
   `/ideate` session).
2. **Release:** what ships. Autopilot prepares the release PR and says what is in it. Only the
   maintainer merges it; a hook refuses a Claude merge of any PR labelled `release`.

Everything between is automatic. Read `CLAUDE.md` first: every rule there binds each step
here.

## State lives on GitHub

| Label | Meaning | Set by |
|---|---|---|
| `proposal` | An idea waiting for the maintainer's yes or no | autopilot, `/ideate` |
| `approved` | Build it | the maintainer |
| `in-progress` | Autopilot is working on it; at most one issue at a time | autopilot |
| `blocked` | Waiting on a person; the latest autopilot comment says who and for what | autopilot |

`bug`, `enhancement`, `priority`, `security`, `deferred` and `good first issue` keep their
meanings. Never remove a label the maintainer set.

## One tick

Do the first step below that has work, finish that one unit, report, and stop. One unit per
tick keeps the work serial: one branch, one PR, nothing racing.

**0. Preflight.** On `main` with a clean tree (`git status`); `gh auth status` shows
`Harry-kp` active; the lab answers (`ssh … true`); tmux `vxrun` exists. A missing machine
does not stop the tick, but a step that needs it does: the live checks in `fix-bug`, and
`release-qa`. Skip those steps and name the missing machine in the report.

**1. Resume.** An issue or PR labelled `in-progress`: continue it where the branch and its
PR show it stopped.

**2. Main is red.** The latest `main` run of any workflow failed (`gh run list --branch main
--limit 10`): `fix-bug` with the failing run as the report. A flake gets one
`gh run rerun --failed` first.

**3. Open PRs.** Oldest first:
- Autopilot's own: failing checks or unanswered review comments → fix, push, re-check.
- A contributor's: run the `reviewer` agent on it. Clean and green → merge
  (`gh pr merge --squash --delete-branch`) and thank them. Findings → one review comment with
  all of them. Changes to `.github/`, `scripts/`, `Cargo.toml` dependencies, `unsafe`,
  subprocess calls or network destinations → `blocked` for the maintainer, never merged by
  autopilot.
- Dependabot majors (minors merge themselves): green and the changelog breaks nothing Vortix
  uses → merge; otherwise `blocked`.

**4. Release.** Follow "Release" below when it applies.

**5. Triage.** Each open issue with no autopilot comment and none of the state labels:
- A bug: reproduce it (`fix-bug` step 3). Not enough to go on → ask the reporter one precise
  question and label `blocked`. Reproduced → leave it for step 6 with a comment saying so.
- An idea or feature request: label `proposal` and comment with the problem it solves, the
  evidence that users hit it, the smallest version worth building, what it costs (code, TUI
  density, upkeep) and a recommendation. No building.
- A question: answer it with links to the docs; close it when answered.
- A duplicate: close it, linking the original.

**6. Build.** The next buildable issue: open, not `deferred`, `blocked`, `proposal` or
`good first issue` (left for contributors). Order: `security`, then `priority`, then other
bugs, then `approved` features; oldest first within each. Label it `in-progress`, then run
`/fix-bug <n>` (its "Approved feature" section covers features). After the merge, remove
`in-progress`. Two failed attempts at the same step → `blocked` with what was tried and what
is needed.

**7. Propose.** Nothing above had work and fewer than three `proposal` issues are open: open
one well-argued proposal from real signals (reactions and comments on open issues, repeated
questions, `deferred` items whose reason has changed). Never build it.

Nothing to do anywhere: report that in one line.

## Release

**When:** release-plz's PR (label `release`) is open, `main` holds a user-visible change since
the last tag, nothing is `in-progress`, and either a `security` or `priority` fix has merged
or the last release is 7 or more days old.

**Freeze first.** From here until the release PR merges, merge nothing else into `main`:
release-plz rewrites the changelog on every push. The freeze is on while the release PR branch
carries a `docs: user-facing changelog` commit.

1. Run `release-qa` on `main`. A no-go finding is fixed through `fix-bug` before the freeze
   starts; if one appears after, fix it on the release branch the way `release-qa` says.
2. Run `release-changelog`; it writes the changelog onto the release PR.
3. Comment on the release PR, titled **What ships in vX.Y.Z**, with:
   - the changelog section;
   - the QA verdict and anything not run;
   - every commit by someone other than the maintainer or autopilot;
   - anything known and not fixed.

   Then send a push notification: "vX.Y.Z is ready for your review: <PR link>".
4. The maintainer merges, or comments. A comment is a change request: address it, update the
   **What ships** comment, and notify again.

**After it ships** (a new tag, and the release PR merged):
- Check the release page for all assets.
- Check the install channels: `P0_TAG=vX.Y.Z P0_SMOKE=0 scripts/p0-vms.sh` on the lab.
- A failure is a `priority` bug. Open it and fix it through `fix-bug`.
- Comment the result on the release PR. Issues fixed in the release are closed by their PRs.

## Rules

- Stop and ask rather than guess. Label the item `blocked`, write the question as a comment,
  and move on to other work. Don't wait.
- Notify the maintainer only at the two gates, or when every remaining item is blocked on them.
- Any comment that asks something of the maintainer mentions @Harry-kp.
- Never merge a PR labelled `release` or `proposal`, never force-push, and never push to
  `main`. `.claude/settings.json` denies or guards each of these.

## Report

One line per tick: what was done, with the link, and what comes next. Example:
`Built #354 (help mentions h/l): PR #361 merged. Next: triage #362.`

## Running it

In a tmux window on the Mac, next to `vxrun`:

```bash
cd ~/Documents/personal/vortix && claude
/loop /autopilot
```

The loop paces itself: it is short while there is work and long when the queue is empty. The
lab and `vxrun` must be up for live checks and release QA.
