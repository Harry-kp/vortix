---
id: 2026-05-24-cli-surface-cleanup
title: "CLI surface cleanup — collapse five new subcommands into existing surface"
status: complete
type: requirements
created: 2026-05-24
revised: 2026-05-24
related:
  - 2026-05-24-engine-fsm-event-journal-requirements.md
  - 2026-05-24-config-profile-secret-stack-requirements.md
  - 2026-05-24-architectural-completion-requirements.md
posture: preemptive
---

# CLI surface cleanup — collapse five new subcommands into existing surface

> **Note on revision.** An earlier version of this document recommended
> removing only `vortix engine` and keeping `journal`, `secrets`,
> `migrate`, `settings`, `export`. Re-audit against a stricter test
> ("does this earn a top-level slot in the CLI namespace?") flipped
> five of those six verdicts. This version reflects the corrected
> conclusion. Only `vortix secrets` earns its top-level slot; the
> other four fold into existing commands or are dropped.

## Problem frame

PR #201 introduced six new CLI subcommands as part of plans 005 and 006:
`engine`, `journal`, `settings`, `secrets`, `migrate`, `export`. Each
was added because it exercised genuinely new architecture — the FSM,
the JSONL journal, the figment-layered settings, the sidecar
migration, the encrypted secret store, the inline-secret export.

But "exercises new architecture" is the wrong test for "deserves a
top-level CLI slot." Top-level commands set what vortix *is* in a
user's mental model. Real estate in the CLI namespace is precious —
every top-level verb a user has to learn is a tax on the product's
ergonomics.

The stricter test: **does this subcommand represent a real ongoing
workflow** (a verb users reach for repeatedly), **with its own noun**
(not a modifier on an existing one), **that they'd reach for without
docs prompting them to**? If any of those three fails, the surface
should be a flag on an existing command, or shouldn't exist at all.

Applied to the six new subcommands:

| Subcommand | Earns top-level? | Why |
|---|---|---|
| `vortix engine {status,connect,disconnect}` | No | Pure duplicate of `up`/`down`/`status`. |
| `vortix journal {path,tail}` | No | `path` is *info* (no verb), `tail` is a worse `tail -f`. |
| `vortix settings` | No | Diagnostic for figment precedence; once-a-year tool. |
| `vortix migrate` | No | Diagnostic for a process that runs at startup; edge-case retry. |
| `vortix export <p>` | No | Duplicate of `show --raw`; the novel `--inline-secrets` is a flag. |
| `vortix secrets {set,get,delete}` | **Yes** | New noun (`creds/<id>`), ongoing workflow (set/rotate/delete), canonical surface for the encrypted store. |

Only one new subcommand earns its slot. The other five fold into
existing commands or are dropped entirely. **The underlying
architecture they exercised — FSM, journal, layered settings, sidecar
migration, inline-secret writer — all stays untouched.** Only the
user-facing CLI verbs are reorganised.

## Goals

1. v0.3.0 ships with the minimum new CLI surface area that does
   justice to the architecture work: one new subcommand (`secrets`)
   plus targeted flag additions to existing commands.
2. Every piece of new architecture stays accessible — none of it is
   buried where users can't reach it. The reorganisation is about
   *which CLI verb* exposes the feature, not whether it's exposed.
3. Update every v0.3.0 announcement artifact (RELEASE-NOTES, FAQ,
   MIGRATION, README, release playbook, smoke script) to reflect the
   collapsed surface.
4. Leave a clear historical record so future contributors understand
   why subcommands introduced in PR #201 were removed in the same PR.

## Non-goals (explicit)

- **Remove `vortix secrets`.** It earns its slot. Real new noun,
  recurring user workflow, no equivalent in the existing surface.
- **Edit the underlying architecture.** `EngineHandle`, `Engine<T>`,
  `Connection` FSM, `Journal`, `Settings`, `migrate_legacy_profiles`,
  the `--inline-secrets` writer — all stay. The cleanup is bounded
  to the user-facing CLI layer.
- **Retroactively edit plans 005 and 006.** They are historical
  records. The primary contributions (architecture in `vortix-core`
  and `vortix-config`) survive intact. The plan docs gain a brief
  "CLI surface revised before ship" note pointing at this brainstorm.
- **Write a CLI stability policy document.** With this cleanup, the
  v0.3.0 surface introduces exactly one new top-level verb. Premature
  governance.

## Detailed re-audit of each new subcommand

### `vortix engine {status, connect, disconnect}` — REMOVE

Same observable behavior as `vortix up`/`down`/`status`, different
internal code path. Introduced in PR #201, never released, no users.
No deprecation pathway needed.

### `vortix journal {path, tail}` — REMOVE, fold `path` into `info`

`vortix journal path` is *information*, not a verb. Users who need
the path use it to point external tools at the file — that's a
"where's the thing" question. `vortix info` already answers
"where's-the-thing" questions for other paths (config dir, profile
dir, etc.); the journal session path belongs in the same output.

`vortix journal tail [N]` is a worse `tail -f` plus a worse `jq`.
Shell tools already do this better. Users who want to watch the
journal can `tail -f $(vortix info | grep session)` or similar. The
CLI was paying a top-level slot for convenience that wasn't
significantly more convenient.

**Action:** drop the `journal` subcommand entirely. `vortix info`
gains a line `Session journal: /path/to/sessions/<iso>-<pid>.jsonl`
in its output.

### `vortix settings [--json]` — REMOVE, optional `info --settings` flag

`settings` answers "what config values are active after the figment
layering?" — a real question, but a debugging question. Reach
frequency is once-a-year, not once-a-week. Users with an immediate
config question read their `settings.toml`; the resolved-stack view
is only needed when debugging weird precedence behavior.

**Action:** drop the `settings` subcommand. If retained at all, add a
`--settings` flag to `vortix info` that appends the resolved stack
to existing output. Default behavior of `vortix info` stays
unchanged.

### `vortix migrate` — DROP

The sidecar backfill runs at every startup (idempotent, non-fatal).
Explicit re-trigger is needed in two cases:

1. Startup migration logged "failed" for some files; user fixed the
   underlying issue (perms, etc.) and wants to retry. Workaround:
   restart vortix. Cost: 100ms.
2. User set `VORTIX_SKIP_MIGRATION=1` and wants to manually run it.
   Workaround: unset and restart.

Both cases are edge cases. Top-level CLI real estate isn't worth
spending on them.

**Action:** drop the `migrate` subcommand entirely. The behavior is
unchanged (still runs at startup); the explicit re-trigger goes away.

### `vortix export <profile> [--inline-secrets]` — REMOVE, fold flag into `show`

`vortix show <profile> --raw` already streams raw config bytes to
stdout. The novel piece is `--inline-secrets`, which appends a
`# vortix-secret:<base64>` trailing comment when a stored secret
exists for the profile. That's a flag, not a verb.

**Action:** drop the `export` subcommand. Add a `--inline-secrets`
flag to `vortix show` (already has `--raw`).

### `vortix secrets {set, get, delete}` — KEEP

Survives the stricter test:

- **Real ongoing workflow.** Users who opt into the encrypted store
  set credentials when adding profiles, rotate them periodically,
  and delete them when removing profiles. Recurring.
- **Own noun.** `creds/<profile_id>` is a separate identity space
  from profiles themselves — secrets can exist without a
  corresponding profile, and a profile may not have credentials.
- **Reached without doc prompting.** A user who needs to store a
  credential reaches for "secrets," not for a flag on `import`. The
  noun maps cleanly onto the mental model.

**Action:** keep as-is. The only new top-level subcommand in v0.3.0.

## Requirements

| ID | Requirement |
|----|-------------|
| R1 | The `Commands::Engine`, `Commands::Journal`, `Commands::Settings`, `Commands::Migrate`, `Commands::Export` arms in `crates/vortix/src/cli/args.rs` are removed, along with their helper enum types (`EngineOp`, `JournalOp`). |
| R2 | The corresponding `handle_engine`, `handle_journal`, `handle_settings`, `handle_migrate`, and `handle_export` functions in `crates/vortix/src/cli/commands.rs` are removed along with their dispatch arms. |
| R3 | `vortix info` output gains a `Session journal` line carrying the path returned by `vortix_core::journal::global_journal().map(|j| j.session_path())`, or `(disabled)` when the journal has disk persistence off. |
| R4 | `vortix show <profile> --raw` accepts a new `--inline-secrets` flag that triggers the secret-inlining writer (existing code from plan 006 U5 — `handle_export`'s base64-trailing-comment behaviour moves into the `show --raw` path). |
| R5 | `Commands::Secrets { op: SecretsOp }` and `handle_secrets` stay unchanged. |
| R6 | Every type in `vortix-core::engine::*`, `vortix-core::journal::*`, and `vortix-config::*` stays `pub` and unchanged. Plans 009/010/011 depend on this surface. |
| R7 | `docs/v0.3.0-RELEASE-NOTES.md` is rewritten to describe one new subcommand (`secrets`) plus flag additions, not "six new subcommands." |
| R8 | `docs/MIGRATION.md`, `docs/v0.3.0-FAQ.md`, `README.md` are updated to match the collapsed surface. |
| R9 | `docs/RELEASE-PLAYBOOK-v0.3.0.md` templates (RC body, GA body, discussion #184 post, broadcast templates) are updated to drop references to removed subcommands and reflect the cleaner surface. |
| R10 | `scripts/smoke-v0.3.0.sh` smokes the new surface: `vortix info` (verify journal path present), `vortix show <profile> --raw --inline-secrets` (verify flag accepted), `vortix secrets {set,get,delete}` (already covered). |
| R11 | `docs/architecture-migration-v1.md` gains a brief "CLI surface revised before ship" note pointing at this brainstorm. |
| R12 | All workspace gates stay green: `cargo build --workspace --all-targets`, `cargo test --workspace`, `cargo clippy --all-targets -- -D warnings`, three xtask lints, `bash scripts/smoke-v0.3.0.sh dev`. |
| R13 | The cleanup lands as a single, clearly-titled commit (e.g., `refactor(cli): collapse five new subcommands into existing surface`). Body explains the duplicate/diagnostic/modifier test that drove each removal. |

## Decisions

1. **The stricter test wins.** "Useful" is not enough to earn a
   top-level CLI slot. The test is real ongoing workflow + own noun
   + reach-without-prompting. Apply this test to every future
   subcommand proposal too.

2. **Architecture and CLI are separate concerns.** All the new
   architecture stays (`EngineHandle`, `Journal`, `Settings`,
   `SecretStore`). What changes is which CLI verbs expose it. The
   ones that don't earn a slot fold into existing commands as flags
   or fold into `info` as output.

3. **No deprecation needed.** Every removed subcommand was introduced
   in PR #201 and has never reached a user. Zero installed base.

4. **`vortix info` becomes the canonical "where is the thing" surface.**
   It already shows config paths, versions, profile count. Adding the
   session-journal path is a natural extension. The optional
   `--settings` flag adds the resolved figment stack for
   debugging-only consumers.

5. **`vortix show --raw --inline-secrets` is the canonical
   profile-export surface.** Two flags modify what `show` outputs;
   the verb stays `show`.

## Assumptions

- No internal code outside `crates/vortix/src/cli/` constructs the
  removed `Commands::*` enum variants. Verifiable at planning time
  with a grep.
- Plans 009 (lifecycle hooks), 010 (IPC layer), 011 (privilege
  separation), 012 (CI integration tests), 013 (socket audit) do not
  depend on the removed CLI surface. Each builds on `vortix-core`
  internal APIs (`EngineHandle`, `Journal`, etc.) which stay.
- The smoke script's existing checks for `vortix engine status`,
  `vortix migrate`, `vortix journal path`, `vortix settings` can be
  replaced with equivalent checks against the surviving surface
  without losing coverage of the underlying behavior.

## Success criteria

- `vortix --help` shows ONE new subcommand (`secrets`) — not six.
- `vortix info` output includes the session-journal path.
- `vortix show <profile> --raw --inline-secrets` outputs the config
  with a trailing `# vortix-secret:<b64>` comment when a stored
  secret exists.
- `vortix engine --help`, `vortix journal --help`,
  `vortix settings --help`, `vortix migrate --help`,
  `vortix export --help` all return "unrecognized subcommand."
- The v0.3.0 announcement narrative reads: "Existing CLI unchanged.
  One new subcommand (`vortix secrets`) for the new encrypted
  credential store. Everything else is internal architecture you
  don't have to think about."
- All workspace gates green.

## Out of scope (worth noting for future work)

- A CLI stability policy document. With this cleanup, there's no
  contested surface to govern. Add when a real future flag-decision
  surfaces.
- Removing the legacy `VpnEngine` code path so `up`/`down`/`status`
  route through `EngineHandle` internally. Multi-day refactor;
  scope as its own plan alongside plan 010 (IPC) when the
  maintenance pain shows up.
- Adding a `--settings` flag to `vortix info`. Considered, decided
  optional — only add if a user actually surfaces a figment-precedence
  question that needs debugging. Until then, the resolved stack lives
  in the figment-load `tracing` output.

## What happens next

1. `/ce-plan` against this requirements doc produces an executable
   plan with concrete units for each removal/fold operation.
2. The plan lands as a single commit inside PR #201 alongside the
   rest of v0.3.0.
3. v0.3.0 ships per the existing playbook with the disciplined CLI
   surface.
