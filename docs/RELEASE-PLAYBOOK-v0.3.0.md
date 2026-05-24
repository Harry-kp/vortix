# Release Playbook — Vortix v0.3.0

Maintainer runbook for shipping the architectural migration v1 bundle
(PR #201) as **v0.3.0** via a two-stage **RC → GA** rollout.

This document is **specific to v0.3.0**. The steady-state release flow
lives in [`RELEASING.md`](../RELEASING.md) and is unchanged. Use this
playbook for v0.3.0 because of its blast radius (six plans, 28 commits,
+15.6k LOC, 155 files, 400+ existing users). Future major-impact
releases may copy from this file as a template.

---

## TL;DR

```
merge PR #201 → cut v0.3.0-rc.1 tag → soak 5–7 days with discussion #184
              → merge release-plz auto-PR → cargo-dist ships v0.3.0
```

Total elapsed time, best case: **8 days** (1d merge + RC + 5d soak + 1d
final smoke + 1d GA). Worst case (RC blocker → patch → RC2): **+5 days
per RC iteration**.

---

## Stage 0 — Pre-merge checklist

Run all of these locally on the branch tip of `refactor/architectural-migration-v1`
**before** clicking merge on PR #201.

### 0.1 Branch hygiene

```sh
git fetch origin
git status                          # clean working tree
git log origin/main..HEAD --oneline # confirm 28+ commits, none surprising
```

### 0.2 Full local CI mirror

```sh
cargo fmt --all -- --check
cargo build --workspace --all-targets
cargo test --workspace
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo run -p xtask -- check-subprocess
cargo run -p xtask -- check-platform-leak
cargo run -p xtask -- check-protocol-leak
```

All eight must be green. Anything failing here will fail in GitHub
Actions too — fix it before the merge.

### 0.3 Local smoke against the dev binary

```sh
cargo build -p vortix
env PATH=/usr/bin:/bin bash scripts/smoke-v0.3.0.sh dev
```

Expect at least **10 PASS, 0 FAIL** (1 SKIP for secrets is acceptable
in a sandboxed env without keyring access).

### 0.4 Manual surface walk

Spin up a scratch config and run, in order:

```sh
mkdir -p /tmp/vortix-smoke && cd /tmp/vortix-smoke
export XDG_CONFIG_HOME=$PWD/config XDG_DATA_HOME=$PWD/data
# Drop a fake wireguard profile so migrate has something to do
mkdir -p $XDG_CONFIG_HOME/vortix/profiles
echo "[Interface]" > $XDG_CONFIG_HOME/vortix/profiles/test.conf

# Startup auto-migration runs implicitly — log "Migrated 1 profile(s)…"
vortix info                             # expect: 1 profile + Session journal path
ls $XDG_CONFIG_HOME/vortix/profiles/    # expect: test.conf + test.meta.toml
vortix status --brief                   # expect: disconnected (no panic)
vortix show test --raw --inline-secrets # expect: file contents (no stored secret note)

# Env override
VORTIX_SKIP_MIGRATION=1 vortix status   # expect: log line about skip
```

### 0.5 PR #201 description has the rollout block

Confirm the PR description includes a "Rollout" section pointing at
this playbook. If absent, add it before merging:

```md
## Rollout

Ships as **v0.3.0** via an RC → GA two-stage rollout. Read
[`docs/RELEASE-PLAYBOOK-v0.3.0.md`](docs/RELEASE-PLAYBOOK-v0.3.0.md)
for the maintainer runbook and [`docs/MIGRATION.md`](docs/MIGRATION.md)
for the user-facing guide.
```

### 0.6 GitHub Actions secrets sanity

Without leaking the values, confirm in the repo settings that these
are still present (last verified during v0.2.2 release):

- `CARGO_REGISTRY_TOKEN` — crates.io publish
- `RELEASE_PLZ_TOKEN` — release-plz PR auth
- `NPM_TOKEN` — npm publish (if changed since v0.2.2, the npm step
  will fail)

---

## Stage 1 — Merge PR #201

**Use a regular merge commit, not squash.** The 28-commit history is a
durable record of the architectural plans; collapsing it loses the
plan-to-commit traceability that the conventional-commit messages
provide.

```sh
# Via gh CLI
gh pr merge 201 --merge

# Or via the GitHub web UI: "Create a merge commit"
```

After the merge:

1. Watch the `release.yml` workflow run (it triggers on tag push, not
   on main push, so it won't run yet — but watch the regular `ci.yml`
   to confirm a fresh main rebuild passes).
2. Watch the `release-plz.yml` workflow. It should open a new PR named
   something like `release-plz-2026-XX-XX` within a few minutes.

---

## Stage 2 — Verify the release-plz auto-PR

The release-plz PR is the **GA tag trigger** later in this flow. Open
it and verify:

1. **Title** mentions `v0.3.0` (not `v0.2.3` or `v0.3.1`).

   If it proposes a patch bump instead of minor, that means release-plz
   didn't honor `refactor!:` as breaking. Edit the version in
   `crates/vortix/Cargo.toml` (and any lockfile diff) manually in the
   release-plz PR's branch, push the fix, and let it re-run.

2. **CHANGELOG.md diff** lists every conventional-commit subject from
   the 28 commits, grouped by type. Read it end-to-end. If anything is
   miscategorized or missing, the fix is on the commit-message side —
   accept it as-is and consider it lessons-learned for future plans.

3. **Cargo.toml version field** updated to `0.3.0` for the `vortix`
   package.

**Do not merge this PR yet.** It is the GA trigger and only fires
*after* the RC soak passes.

---

## Stage 3 — Cut `v0.3.0-rc.1`

The RC tag is manual — release-plz won't bump to a pre-release on its
own. cargo-dist already understands `-rc.N` suffixes and marks the
GitHub Release as a prerelease.

```sh
git checkout main
git pull origin main
git tag -a v0.3.0-rc.1 -m "Release candidate for v0.3.0 — architectural migration v1"
git push origin v0.3.0-rc.1
```

Watch the `release.yml` workflow. It should:

- Build artifacts for all six target triples in `dist-workspace.toml`
- Create a GitHub Release marked **Pre-release**
- Skip the Homebrew tap and npm publish jobs (or, depending on
  cargo-dist version, run them with prerelease tags — verify in the
  workflow log)

Sanity-check the release page:

```sh
gh release view v0.3.0-rc.1
```

Confirm: `isPrerelease: true`, six binary archives attached, shell
installer (`vortix-installer.sh`) attached, checksums present.

### RC GitHub Release body template (plan 014 U5)

cargo-dist auto-generates a Release with a default body. Edit the
body via the GH web UI or `gh release edit v0.3.0-rc.1 --notes "$(cat
<<EOF ... EOF)"` and paste:

````md
Release candidate for **v0.3.0** — the architectural migration v1 ship.

- **Soak period:** YYYY-MM-DD to YYYY-MM-DD (5–7 days)
- **For testers:** install via any channel below, then run:
  ```sh
  bash <(curl -sL https://raw.githubusercontent.com/Harry-kp/vortix/main/scripts/smoke-v0.3.0.sh) 0.3.0-rc.1
  ```
  Report results on [discussion #184](https://github.com/Harry-kp/vortix/discussions/184).

**What changed:** [v0.3.0 release notes](https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-RELEASE-NOTES.md) (60s read)
**Upgrade guide:** [docs/MIGRATION.md](https://github.com/Harry-kp/vortix/blob/main/docs/MIGRATION.md)
**FAQ:** [docs/v0.3.0-FAQ.md](https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-FAQ.md)

**Roll back:** `cargo install vortix --version 0.2.2 --force`

Target promote-to-GA date: **YYYY-MM-DD** (revised if blockers surface).
````

Only the YYYY-MM-DD placeholders need filling. Everything else is
canonical.

---

## Stage 4 — Post to discussion #184 (RC soak)

Use this comment template in
[discussion #184](https://github.com/Harry-kp/vortix/discussions/184):

````md
# v0.3.0-rc.1 is available for testing

Hi all — this release candidate carries the full architectural migration
v1 bundle (six plans, 30+ commits). Before promoting to v0.3.0 I'd like
a 5–7 day soak across as many Linux distros as possible.

## What changed

Engine FSM (internal) + session journal, encrypted secret store. One
new top-level subcommand (`vortix secrets`); existing CLI unchanged. Existing commands (`up`, `down`, `status`, `list`, `import`,
`killswitch`, …) unchanged. Full details:

- [Release notes](https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-RELEASE-NOTES.md) — 60s read
- [FAQ](https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-FAQ.md) — common upgrade questions
- [Upgrade guide](https://github.com/Harry-kp/vortix/blob/main/docs/MIGRATION.md)

## Install (pick one)

Shell installer (any Linux):
```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Harry-kp/vortix/releases/download/v0.3.0-rc.1/vortix-installer.sh | sh
```

cargo (any platform with Rust):
```sh
cargo install vortix --version 0.3.0-rc.1
```

## What to test

1. Run the smoke script:
   ```sh
   bash <(curl -sL https://raw.githubusercontent.com/Harry-kp/vortix/main/scripts/smoke-v0.3.0.sh) 0.3.0-rc.1
   ```
   Expect ~10 PASS, 0 FAIL, ≤1 SKIP.
2. Connect to your usual VPN profile and confirm `up`, `status`, `down`
   work as on v0.2.x.
3. Try the new bits: `vortix info` should show a `Session journal:`
   line, and `vortix secrets set creds/test` should accept a secret
   from stdin without panicking.
4. Skim the [FAQ](https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-FAQ.md)
   — anything that surprises you is worth raising here.

## Reply on this thread if

- Anything diverges from v0.2.x behavior
- The startup migration logs anything other than success
- A command panics
- The smoke script reports any FAIL

## Roll back

```sh
cargo install vortix --version 0.2.2 --force
```

Migration leftovers (`.meta.toml` sidecars, `secrets.enc`) are inert to
v0.2.x — no cleanup needed.

Targeted promotion to v0.3.0 GA: **YYYY-MM-DD** (update with concrete
date 5–7 days out).
````

### Soak gates

| Day | Action |
|---|---|
| 0 | Post above. Subscribe to your own thread to catch replies. |
| 1 | Reply to first three commenters individually to encourage engagement. |
| 3 | If zero engagement: ping `@Harry-kp` in the thread + tag one or two known Linux testers from prior `[platform: linux]` issue commenters. |
| 5 | Decision point — see triage matrix below. |
| 7 | Hard ceiling for "no engagement" path; proceed with reduced confidence (maintainer judgment). |

### Soak triage matrix

Anything reported during soak falls into one of these buckets:

| Symptom | Bucket | Action |
|---|---|---|
| `thread 'main' panicked` anywhere | **Blocker** | Full stop. Reproduce locally, patch fix on main, cut `v0.3.0-rc.2`, restart soak from day 0. |
| `migrate: failed: N` with non-EACCES error | **Blocker** | Same as above — the migration's non-fatal contract was the whole point of plan 007 U3. |
| WireGuard `vortix up` works on v0.2.2 but fails on RC, same profile | **Blocker** | Almost certainly a regression. Stop and bisect. |
| OpenVPN `vortix up` works on v0.2.2 but fails on RC, same profile | **Blocker** | Bisect; likely the SecretStore/auth-file precedence ordering. |
| New CLI subcommand (`engine`/`journal`/`secrets`/...) fails on a specific distro | **Non-blocker if additive** | Triage but ship; file an issue, fix in `v0.3.1`. The existing `up`/`down`/`status` path is the production surface. |
| Settings/figment errors on a specific distro | **Investigate** | Read the error. If it's a missing `XDG_CONFIG_HOME`, that's a tester env problem. If it's a deserialization panic, that's a blocker. |
| Tester says "looks fine" with no specifics | **Soft positive** | Count toward "at least one per platform" target. Ask what they ran specifically. |
| Crickets | **Apply day-7 ceiling** | After 7 days with no engagement, promote anyway and watch the post-GA window extra closely. |

### Pre-GA confirmation gate

Before promoting, you must have **at least one positive smoke-test
confirmation** from each of:

- macOS x86_64
- macOS arm64
- Linux x86_64

(Linux arm64 desirable but not blocking — there's no easy public
tester base for it.)

If you can't get all three after 7 days, write a one-paragraph
"acknowledged gap" note in the GA release notes and proceed.

---

## Stage 5 — Promote to GA (`v0.3.0`)

Once the soak gate passes:

```sh
# Switch to main, pull latest (which now includes the release-plz PR
# branch state if you haven't merged it yet).
git checkout main
git pull origin main
```

Open the release-plz PR you held in Stage 2. Confirm it still proposes
`v0.3.0` and the CHANGELOG diff is unchanged.

### 5.1 Inject CHANGELOG preamble before merge (plan 014 U4)

Before merging the release-plz PR, edit its `CHANGELOG.md` diff to add
a curated preamble between the `## [0.3.0] - YYYY-MM-DD` heading and
the first `### Features` (or other group) block. The auto-generated
per-commit bullets read like a developer changelog; a 5–6 line
preamble frames the scale of the bundle for users skimming the file.

Exact text to paste:

```md
> **Architectural migration v1.** This release lands six coordinated
> plans: Cargo workspace split, `CommandRunner` port, capability ports
> + `Platform` aggregate, `Tunnel` trait + per-protocol crates, Engine
> FSM + JSONL session journal, and a layered Config / `ProfileStore` /
> `SecretStore`. Existing CLI commands, profiles, and killswitch state
> are preserved unchanged. See [v0.3.0 release notes](docs/v0.3.0-RELEASE-NOTES.md)
> and [upgrade guide](docs/MIGRATION.md).
```

Commit the edit to the release-plz PR branch (via the GitHub web UI
or a local `git commit --amend` if you've checked out the branch),
then merge.

**Note on future release-plz runs:** release-plz preserves manually-
edited content between its structural markers (`## [version]`,
`### group`) on subsequent regenerations. If a future run wipes the
preamble, the canonical text above is the source — re-paste from
there.

### 5.2 Merge

```sh
gh pr merge <release-plz-pr-number> --merge
```

Merging triggers:

1. release-plz publishes to crates.io (`cargo publish`)
2. release-plz pushes the `v0.3.0` git tag
3. The tag push triggers cargo-dist's `release.yml`
4. cargo-dist builds for all six targets, attaches archives,
   publishes shell installer, and runs the Homebrew + npm publish
   jobs

Watch all three workflows. Expected total wall-clock: ~25–40 minutes.

### 5.3 GA GitHub Release body template (plan 014 U5)

cargo-dist auto-generates a Release on the `v0.3.0` tag. Replace its
body via `gh release edit v0.3.0 --notes "$(cat ...)"` or the web UI:

````md
**v0.3.0** ships the architectural migration v1 bundle — six
coordinated plans, ~16k LOC. Every existing CLI command, profile, and
killswitch state is preserved unchanged.

- [What changed](https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-RELEASE-NOTES.md) — 60s read
- [Upgrade guide](https://github.com/Harry-kp/vortix/blob/main/docs/MIGRATION.md)
- [FAQ](https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-FAQ.md)

Thanks to the RC testers in [discussion #184](https://github.com/Harry-kp/vortix/discussions/184)
who soaked this for N days.

**Install:** `cargo install vortix`, `brew install vortix`, or
`npm install -g @harry-kp/vortix`.
**Roll back if needed:** `cargo install vortix --version 0.2.2 --force`.
````

Only the soak-day-count placeholder (`N days`) needs filling.

### Post-publish verification

```sh
# crates.io
cargo search vortix                                # should list 0.3.0

# GitHub release
gh release view v0.3.0                             # isPrerelease: false

# npm
npm view @harry-kp/vortix versions --json | tail   # should include 0.3.0

# Homebrew tap (may lag 30–60 min)
brew tap Harry-kp/homebrew-tap
brew info vortix                                   # should show 0.3.0
```

If any channel lags more than 60 minutes:

- **crates.io:** check the workflow log. Most likely `CARGO_REGISTRY_TOKEN`
  expired — regenerate at https://crates.io/me, store in repo
  secrets, re-run the publish job (no new tag needed).
- **npm:** same — `NPM_TOKEN` expired. Regenerate at https://www.npmjs.com/settings/USERNAME/tokens
  and re-run the npm publish job.
- **Homebrew:** check the `Harry-kp/homebrew-tap` repo for the auto-PR.
  If it didn't open, the tap workflow may need manual nudging — open
  an issue on the tap repo.

### Real-binary smoke

Reinstall locally via the freshly published channel and re-run:

```sh
cargo install vortix --force                       # 0.3.0 from crates.io
which vortix                                        # confirm path
bash scripts/smoke-v0.3.0.sh 0.3.0
```

Expect **10 PASS, 0 FAIL, 1 SKIP**.

---

## Stage 6 — Post-GA monitoring (0–48h)

For the 48 hours after the v0.3.0 tag, watch:

| Signal | Where | Threshold for concern |
|---|---|---|
| Bug-labeled issues mentioning v0.3.0 | `gh issue list -l bug --search "0.3.0"` | 1 critical OR 3 non-critical → investigate immediately |
| crates.io download spike (the new version pulling) | https://crates.io/crates/vortix | Should climb above v0.2.2 within 7 days; lack of climb is bad sign |
| npm download count | `npm view @harry-kp/vortix` | Same expectation |
| Comments in discussion #184 about GA | discussion thread | Any new "this broke X" comment after promotion |
| `vortix bug-report` outputs landing on issues | new issues with the report header | Read each; the journal path it includes is the diagnostic gold |

Set up a saved search:

```
gh search issues "0.3.0 is:open" -R Harry-kp/vortix --json number,title,createdAt
```

Run this hourly during the first 12 hours, then daily through the
48-hour window.

### No public announcement for 72h

Do not announce v0.3.0 on Twitter, Hacker News, Reddit, or other
amplifiers until **72 hours** post-GA with no reported issues. The
first 72 hours are for catching regressions, not amplifying installs.

### Broadcast templates — embargoed until 72h post-GA (plan 014 U6)

When the embargo clears, paste from the templates below rather than
composing under pressure. Tone is neutral ("ships", "is out") rather
than hype ("biggest", "game-changing") because hype dates fast and
hype around an architectural refactor lands wrong anyway.

**Each template links to `docs/v0.3.0-RELEASE-NOTES.md` as the
canonical "what changed?" source.** If a template's wording feels off
for the moment, edit the venue copy — never the release notes — so
the canonical source stays stable for late-arriving readers.

#### Twitter / Bluesky (≤280 chars)

```
Vortix v0.3.0 is out — architectural migration v1.

Engine FSM, session journal, encrypted secret store, six new CLI
subcommands. Existing profiles & commands work unchanged.

What's new → https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-RELEASE-NOTES.md
```

Char count: ~265. Bluesky's 300-char limit is comfortable; Twitter at
280 fits with the URL.

#### Mastodon (500 chars)

```
Vortix v0.3.0 — architectural migration v1 shipped.

Highlights:
• Engine FSM + JSONL session journal
• Encrypted secret store (keyring + AES fallback)
• Six new CLI subcommands (engine, journal, settings, secrets,
  migrate, export)
• Existing profiles, commands, and killswitch all unchanged

Terminal UI for WireGuard/OpenVPN with real-time telemetry, leak
detection, and killswitch. ~15MB RAM, keyboard-driven.

https://github.com/Harry-kp/vortix
```

#### Hacker News "Show HN"

```
Title: Show HN: Vortix v0.3.0 — TUI for WireGuard/OpenVPN with real-time telemetry

Body:
Vortix is a terminal UI for managing WireGuard and OpenVPN with live
telemetry, killswitch, and IPv6/DNS leak detection. v0.3.0 just shipped
after an architectural migration — Engine FSM, JSONL session journal,
encrypted secret store, one new additive subcommand (`vortix secrets`).

Background: I built this because the existing options (wg show,
NetworkManager, Tunnelblick) either lacked real-time telemetry or
required a GUI. Vortix runs at ~15MB RAM, sub-500ms startup, is fully
keyboard-driven, and works over SSH.

What's in 0.3.0:
https://github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-RELEASE-NOTES.md

Source / install:
https://github.com/Harry-kp/vortix
```

Title is 80 chars — under HN's limit. The "Show HN" prefix is the
convention for tool releases.

#### Reddit (r/selfhosted, r/linux, r/rust)

Same content, different rhythm — 3–4 paragraphs rather than HN's
single block. Use the HN body as the starting point, then split:

- Paragraph 1: what Vortix is (one sentence) + what v0.3.0 ships
- Paragraph 2: why it exists (the "Why Vortix" framing from the
  README), what it's good at
- Paragraph 3: install commands for the major channels, link to
  v0.3.0 release notes
- Subreddit-specific tag: `[Tool Release]` on r/selfhosted,
  `[Project]` on r/rust, no tag on r/linux

Don't post the same content to all three subreddits in the same hour —
space them by a day or two. Reddit's cross-posting heuristics will
shadow-ban otherwise.

#### Anti-pattern: do NOT post

- Anything before 72h post-GA with no reported issues
- A hype thread without a link to the release notes
- A long-form blog post — defer that until v0.3.x has stabilised
  (likely after v0.3.1 patches)
- Channels you don't personally maintain (Mastodon instances you
  don't have an account on, Discord servers you're not a member of)

---

## Stage 7 — Rollback procedures

Three escalation levels, picked by severity.

### Level 1 — Cosmetic / non-blocking

Symptom: a non-blocking issue that won't cause data loss or "can't
start vortix at all" but should be fixed.

Action: open a fix PR on main with `fix:` prefix; release-plz will
roll a `v0.3.1` patch within 6 hours of merge.

### Level 2 — Functional regression

Symptom: some path that worked on v0.2.x doesn't work on v0.3.0 (e.g.,
a specific WireGuard config fails to connect, a specific platform
panics on startup).

Actions, in order:

1. **Yank from crates.io** to stop new installs:
   ```sh
   cargo yank --version 0.3.0 vortix
   ```
   Yanking does not delete; it prevents resolver-default installs.
   Users who already installed v0.3.0 are unaffected.

2. **Pin the GitHub Release to prerelease again** so the cargo-dist
   shell installer falls back to v0.2.2:
   ```sh
   gh release edit v0.3.0 --prerelease
   ```

3. **Post to discussion #184** with the rollback command:
   ```
   cargo install vortix --version 0.2.2 --force
   ```

4. **Ship `v0.3.1` within 12 hours** with the fix. Re-run the soak
   only if the fix changes user-visible behaviour; otherwise a fast
   patch promotion is fine.

### Level 3 — Data corruption (hypothetical)

Symptom: a user reports vortix v0.3.0 destructively rewrote one of
their existing files (a `.conf`, an `.auth`, a `settings.toml`).

This should not happen. The migration is read-then-write-new-file
across the board (sidecars are new files; the `OvpnTunnel` ephemeral
auth file is deleted post-spawn; `settings.toml` is read-only at
runtime; the journal only ever writes to `sessions/`).

If it does happen:

1. **Cannot downgrade published registries.** crates.io, npm, and
   Homebrew are append-only.

2. **Yank** (`cargo yank --version 0.3.0 vortix`) and edit the
   GitHub Release to prerelease.

3. **Ship `v0.3.1` immediately** that detects the corruption case
   and refuses to start with a directive — e.g.:
   ```
   ERROR: detected v0.3.0 migration artifact at <path>. Refusing
   to start. Restore from backup or delete the artifact and re-run.
   ```

4. **Post a pinned issue + discussion #184 update** with concrete
   restoration instructions for the specific corruption.

5. **Post-mortem in `docs/` repo** — the v0.3.0 plan series claimed
   no destructive writes; a Level 3 event means that claim was
   wrong, and the post-mortem documents how it slipped past the RC
   soak.

---

## Stage 8 — Optional after promotion: issue triage sweep

Plan 007 U7. Run this 24–48 hours **after** GA promotion, not before
— the comments reference "v0.3.0" and premature posting confuses
users if the release slips.

### Close as resolved (verify each)

```sh
gh issue close 177 --comment "Resolved by the architectural migration v1 bundle in v0.3.0. Typed errors land via \`ProcessError\`/\`TunnelError\`/\`SecretStoreError\` (thiserror enums in \`vortix-core\`). Secret masking ships via the \`SecretStore\` API; auth files are now optional and replaced by \`vortix secrets set creds/<profile>\`. See [docs/MIGRATION.md](https://github.com/Harry-kp/vortix/blob/main/docs/MIGRATION.md). Reopen if any specific subitem isn't covered."

gh issue close 31 --comment "The new Engine FSM in v0.3.0 treats \`Connecting\` and \`Connected{health}\` as distinct states — \`Connected\` now requires an actual \`TunnelUp\` event, not just process spawn. Verified manually against an unreachable server: connection stays in \`Connecting\` rather than reporting Connected. Closing as resolved; reopen if you can repro with v0.3.0."
```

### Comment but keep open

```sh
gh issue comment 161 --body "v0.3.0 ships the FSM slot for this — \`Connected { health: HealthState }\` is in \`crates/vortix-core/src/engine/state.rs\`. Remaining work is wiring telemetry to populate \`health\` (handshake age, RX/TX deltas) from the existing \`NetworkStats\` capability. Good follow-up for v0.3.x."

gh issue comment 171 --body "Data model now exists: \`\${XDG_DATA_HOME}/vortix/sessions/*.jsonl\` with 30-day/30-file retention. The path is surfaced via \`vortix info\`; users tail it with \`tail -f\` + \`jq\`. Remaining work is a TUI view that reads multiple sessions. Tagging as good-first-issue post-v0.3.0."

gh issue comment 190 --body "DNS port abstraction now exists (\`vortix-core::ports::dns::DnsResolver\`). Adding a \`networkd\`/\`resolved\` backend means a new impl under \`crates/vortix-platform-linux/\`. Significantly easier to land post-v0.3.0 than before."

gh issue comment 168 --body "Per-process socket VPN-routing check is independent of the migration. The new \`vortix-platform-{macos,linux}\` crates are the right place to put a \`SocketAudit\` port if/when picked up."

gh issue comment 166 --body "Sits on the platform port layer the migration just established (see #168). Easier to land now."

gh issue comment 162 --body "v0.3.0 introduces three xtask lints (\`check-subprocess\`, \`check-platform-leak\`, \`check-protocol-leak\`) — those are structural. The integration tests this issue asks for are still missing and now easier to add per-platform with the \`MockRunner\` / \`MockPlatform\` infra in \`vortix-process\` and \`vortix-core::ports::*::mock\`."
```

### Leave alone

#191, #172, #170, #169, #167, #164, #158, #153, #36, #17, #16, #15 —
not migration-adjacent. No comment needed.

### Verify after

```sh
gh issue list --state open | wc -l   # 2 lower than pre-sweep
gh issue list --state closed --search "closed:>$(date -v-1d +%Y-%m-%d)" -l bug
```

---

## Reference: success metrics

These are the targets the v0.3.0 rollout aims for:

- **Zero P0 incidents** in the 7 days post-GA (P0 = "vortix won't start
  after upgrade").
- **At least one positive smoke confirmation** per platform (macOS x86_64,
  macOS arm64, Linux x86_64).
- **At least 50% of v0.2.x download share migrates to v0.3.x within 30
  days.** Track via `cargo download` stats and npm download counts.
- **No emergency `v0.3.1` cut within 48h.** A scheduled `v0.3.1` for
  accumulated fixes is fine; an emergency hotfix is a soak failure in
  retrospect.
- **#177 and #31 closed** with no reopens within 14 days.

---

## When in doubt

- The plan: [`docs/plans/2026-05-24-007-feat-rollout-architectural-migration-v1-plan.md`](plans/2026-05-24-007-feat-rollout-architectural-migration-v1-plan.md)
- The user-facing guide: [`docs/MIGRATION.md`](MIGRATION.md)
- Steady-state release docs: [`RELEASING.md`](../RELEASING.md)
- The bundle's surface map: [`docs/architecture-migration-v1.md`](architecture-migration-v1.md)
- Pre-existing Linux tester base: [discussion #184](https://github.com/Harry-kp/vortix/discussions/184)
