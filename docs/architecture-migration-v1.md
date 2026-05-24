---
date: 2026-05-24
title: "Architectural migration v1 — six-plan bundle status"
type: docs
---

# Architectural migration v1 — six-plan bundle status

PR #201 lands a coordinated architectural migration covering six plans
(`docs/plans/2026-05-24-001-*` through `2026-05-24-006-*`). This document
summarises what's in the PR, what's deferred, and where consumers should
look for the new primitives.

## What landed

### Plan 001 — Cargo workspace split
- Eight workspace crates established. Eighth-plus crate
  `vortix-protocol-openvpn` lands in plan 004.
- All shared types live under `crates/vortix-core/`.

### Plan 002 — `CommandRunner` port (subprocess unification)
- `vortix_core::ports::process::CommandRunner` trait + `CommandSpec` /
  `CommandOutcome` / `ProcessError` / `PrivilegeReq` / `Kind`.
- `vortix_process::{RealRunner, MockRunner}` concrete impls.
- Process-global runner installed by `main.rs`; consumers call
  `vortix_process::run_to_output(spec)`.
- `cargo xtask check-subprocess` CI lint bans direct
  `std::process::Command::new` outside `vortix-process`.

### Plan 003 — Capability ports + `Platform` aggregate
- Five ports in `vortix_core::ports::*`: `Killswitch`, `DnsResolver`,
  `Interface`, `NetworkStats`, `RouteTable`.
- Per-OS impls relocated into `vortix-platform-{macos,linux}` crates;
  cycle with `vortix-core` removed.
- `Platform` aggregate lives in the binary
  (`crates/vortix/src/platform/aggregate.rs`) per the
  cycle-avoidance decision noted in plan #003.
- `MockPlatform` variants for testing.
- Process-global platform installed by `main.rs`; consumers call
  `crate::platform::current_platform()`.
- `cargo xtask check-platform-leak` CI lint bans `cfg(target_os = ...)`
  outside platform crates + a small allowlist.

### Plan 004 — `Tunnel` port + per-protocol crates
- `vortix_core::ports::tunnel::Tunnel` trait + `TunnelHandle` /
  `TunnelStatus` / `TunnelCapabilities` / `TunnelError`.
- `vortix-protocol-wireguard::WgTunnel` and a new
  `vortix-protocol-openvpn::OvpnTunnel` crate; ~400 lines of WG/OVPN
  lifecycle code relocated out of the engine/app.
- `TunnelKind` aggregate in `crates/vortix/src/tunnel.rs` with
  `WireGuard`/`OpenVpn`/`Mock` variants.
- One routing function `tunnel_for(protocol, ...) -> TunnelKind` —
  engine + app now do a single match on protocol.
- `cargo xtask check-protocol-leak` CI lint bans `wg`/`wg-quick`/`openvpn`
  string literals outside the matching protocol crate.

### Plan 005 — Engine FSM + event journal + `EngineHandle`
- `vortix_core::engine::Connection` — 5-variant FSM
  (`Disconnected{last_failure}` / `Connecting` /
  `Connected{health,details}` / `Reconnecting` / `Disconnecting`).
- 15-variant `EngineEvent` schema + `EventEnvelope { schema_version: u32 }`.
- `Engine<T: Tunnel>` with `handle(input) -> Vec<EngineEvent>`. Sync FSM,
  wrapped by an async actor in plan 005 U4.
- `vortix_core::journal::Journal` — JSONL persistence at
  `${XDG_DATA_HOME}/vortix/sessions/<ISO>-<pid>.jsonl`, broadcast +
  in-memory tail, 30-day / 30-file retention.
- `EngineHandle::Local(LocalHandle)` wraps the FSM in a `spawn_blocking`'d
  actor; `execute(input)` / `snapshot()` / `subscribe()` API.
- `EngineHandle` constructed in `main.rs` and stashed on
  `App.engine_handle` (non-load-bearing today; `Deref<VpnEngine>` still
  drives the TUI).
- `impl Tunnel for TunnelKind` so the binary can instantiate
  `Engine<TunnelKind>` once the integration units finish.
- Live profile resolver — the engine handle reads sidecars via
  `FsProfileStore` so any plan-005 consumer calling
  `handle.execute(Connect{id})` sees the user's actual profiles.
- `vortix bug-report` attaches the current session's journal path + the
  last 10 event kinds.
- New CLI: `vortix journal {path,tail [N]}` — surfaces the session
  file + in-memory tail for debugging.

### Plan 006 — Config + secret stack
- `vortix_config::Settings` — figment-layered (defaults → system file →
  user file → `VORTIX_*` env). `EngineSettings` / `JournalSettings` /
  `UiSettings` sub-sections.
- `vortix_config::profile_store::ProfileStore` + `FsProfileStore` with
  sidecar TOML metadata at `<profiles_dir>/<name>.meta.toml`.
- `vortix_config::secret_store::SecretStore` + `LayeredSecretStore` —
  keyring-first with AES-256-GCM + argon2id encrypted-file fallback.
- `vortix_config::migrate_legacy_profiles(profiles_dir)` — idempotent
  one-shot backfill of `.meta.toml` sidecars for pre-migration
  `.conf` / `.ovpn` files. Runs implicitly at every binary start.
- `main.rs` calls `Settings::load()` (figment) and seeds the global
  `Journal` from `[journal]`.
- New CLI commands surfacing the stack:
  - `vortix export <profile> [--inline-secrets]` — stream raw config to
    stdout. `--inline-secrets` reserved for plan 006 U5.
  - `vortix migrate` — explicit invocation of the sidecar migration with
    stats output.
  - `vortix settings` — print the resolved Settings stack as TOML
    (or JSON via `--json`).
  - `vortix secrets {set,get,delete} <id>` — manage SecretStore entries.
- `vortix list --json` now includes optional `profile_id` and `group`
  fields from sidecars.

## Completed in final integration push

The four units originally deferred from plans 005 and 006 landed during
the final integration session on this branch. The bundle on PR #201
now carries every planned unit:

### Plan 005
- **U5 — App restructure** (commit `dd029fe`). `App: Deref<VpnEngine>`
  removed; ~400 callsites across the TUI / app rewritten to read state
  via explicit `app.engine.X` / `self.engine.X` access. No
  behavioural change; the engine surface is now visible.
- **U6 — CLI on `EngineHandle`** (commit `0d89afe`). `Engine` gained a
  `tunnel_factory` so it can rebuild the correct protocol per
  `Connect`. The new `vortix engine {status,connect,disconnect}` CLI
  exercises the full handle path. Existing `vortix up/down/status` are
  unchanged.
- **U7 — Telemetry actor split** (commit `1389cc3`). A tokio task in
  `main.rs` subscribes to the journal broadcast and nudges the
  telemetry worker on `TunnelUp`; `App::handle_telemetry` emits
  `EngineEvent::IpChanged` into the journal.

### Plan 006
- **U5 — `Tunnel` + `SecretStore` integration** (commit `be9ea6f`).
  `OvpnTunnel::with_secret_provider` takes a callback that materialises
  auth bytes into an ephemeral 0600 file at `up()` time; the file is
  deleted after the daemon forks. `tunnel_for_with_secrets` in
  `crates/vortix/src/tunnel.rs` wires it up against the layered
  `SecretStore`. `vortix export --inline-secrets` now actually inlines
  via a `# vortix-secret:<base64>` trailing comment.
- **CLI fix** (commit `3a9429a`). `Journal::open` in `handle_engine`
  now runs inside the tokio runtime context so the writer task spawn
  no longer panics on `vortix engine status` invocations.

## Distribution posture (single crate, single npm)

**Permanent architectural invariant.** vortix ships exactly one
crates.io artifact (`vortix`) and exactly one npm package
(`@harry-kp/vortix`). Every other crate in this workspace is internal
infrastructure and carries `publish = false` + `version = "0.0.0"`.
This is not a "yet" — it's the final shape. The Cargo workspace exists
for source-organisation and compile-time enforcement (module
boundaries, port discipline, cycle prevention), not as a publishing
vehicle.

What this implies for future plans:

- **No new crate at the workspace level may be `publish = true`.**
  Plans 009–013 and any future plan must add new functionality inside
  an existing internal crate or behind the binary's `vortix` surface.
  Splitting `vortix-cli` and `vortix-tui` into separate libraries
  (mentioned as deferred-in-principle in the workspace-split brainstorm)
  is **not** a publish event; if it ever happens, those would also be
  `publish = false`.
- **No `vortix-core` "library" identity.** External consumers who want
  the API surface vendor or fork. The internal crates are unstable by
  design — every plan revises their public types without semver
  ceremony.
- **release-plz config stays single-package.** The `[[package]] name =
  "vortix"` entry in `release-plz.toml` is load-bearing. Any future
  change that attempts to add a second `[[package]]` entry is a
  regression of this invariant.
- **cargo-dist config stays single-binary.** `members =
  ["cargo:crates/vortix"]` in `dist-workspace.toml` is load-bearing.
  No second binary, no library publish.
- **Enforcement at the Cargo level.** Cargo refuses
  `cargo publish -p <internal-crate>` with "package has `publish = false`"
  — verified by acceptance example AE3 in the workspace-split
  brainstorm. This is the cheap-mistake guard.

If a future need surfaces that would justify reconsidering, that's a
new brainstorm with explicit weight given to:
(a) the maintenance tax of versioning an internal crate independently,
(b) the SemVer commitment a published library implies,
(c) whether the proposed consumer can vendor the source instead.
Until then, treat this as a hard invariant. Reviewers should reject
any PR that adds `publish = true` to a non-binary crate without an
accompanying brainstorm doc that explicitly revisits this section.

## Deferred-subsystems bundle (plan 015, phases A–E)

Per the maintainer's direction, plans 009–013 (originally documented
as deferred multi-week subsystems) execute in PR #201 alongside the
v0.3.0 migration. Plan 015 is the orchestration layer; per-subsystem
plan docs remain the design records.

| Phase | Plan | Status | Commit |
|---|---|---|---|
| A — Lifecycle hooks | 009 | ✅ shipped | `ee5b099` |
| B — CI integration tests | 012 | ✅ shipped (Ubuntu only) | `1cbfa90` |
| C — Socket audit port | 013 | ✅ shipped (Linux + macOS) | `82ba6a4` |
| D — IPC layer / daemon | 010 | ✅ shipped (skeleton + wire contract); engine routing → v0.3.x | `a7796d1` |
| E — Privilege separation | 011 | ✅ shipped (docs + threat model); enforcement → v0.3.x | `f8f97e9` |

**Honest scope framing.** Each phase ships the architecture + happy-
path implementation. Hardening corners (full daemon engine routing,
`SO_PEERCRED` enforcement, macOS integration parity, OpenVPN
integration test, OpenVPN-with-real-server cert fixtures) are
documented as v0.3.x follow-ups in the relevant commit bodies +
`SECURITY.md` + the per-phase plan docs. v0.3.0 ships valuable
working code on every track; "complete" in the multi-quarter sense
each plan was originally sized for grows in v0.3.x.

## CLI surface revised before ship

A pre-ship re-audit (brainstorm:
[`docs/brainstorms/2026-05-24-cli-surface-cleanup-requirements.md`](brainstorms/2026-05-24-cli-surface-cleanup-requirements.md))
applied a stricter test to the six new subcommands introduced during
plans 005 and 006: *does this earn a top-level slot in the CLI
namespace?* Five didn't.

**Removed before v0.3.0 ship:**

- `vortix engine {status,connect,disconnect}` — pure duplicate of
  `up`/`down`/`status`, never released, no installed base
- `vortix journal {path,tail}` — folded; the session path now surfaces
  via `vortix info` output, tailing happens via shell tools
- `vortix settings` — dropped; the resolved figment stack is rare
  diagnostic surface, users read their own `settings.toml`
- `vortix migrate` — dropped; backfill runs at startup, re-trigger is
  restart-vortix
- `vortix export <p> [--inline-secrets]` — folded; the
  `--inline-secrets` flag moved onto `vortix show <p> --raw`

**Surviving new top-level subcommand:**

- `vortix secrets {set,get,delete}` — earns its slot. Real new noun,
  recurring user workflow.

**Underlying architecture is unchanged.** `EngineHandle`, `Engine<T>`,
`Connection` FSM, `Journal`, `EventEnvelope`, `Settings`,
`migrate_legacy_profiles`, the secret-inlining writer — every line of
code the removed subcommands exercised stays in place and is used
internally (and by future plans 009–013). Only the user-facing CLI
verbs were collapsed.

## CI gates currently enforced

```
cargo xtask check-subprocess        # plan 002 — no raw Command::new outside vortix-process
cargo xtask check-platform-leak     # plan 003 — no cfg(target_os) outside platform crates
cargo xtask check-protocol-leak     # plan 004 — no wg/openvpn strings outside protocol crates
cargo build --workspace --all-targets
cargo test --workspace              # 425+ tests, 0 failures
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS=-D warnings cargo doc --no-deps
```

## File map (quick reference)

| Concept | Location |
|---|---|
| Subprocess port | `crates/vortix-core/src/ports/process.rs` |
| Subprocess impls | `crates/vortix-process/` |
| Capability ports | `crates/vortix-core/src/ports/{killswitch,dns,interface,network_stats,route_table}.rs` |
| Capability impls | `crates/vortix-platform-{macos,linux}/` |
| Platform aggregate | `crates/vortix/src/platform/aggregate.rs` |
| Tunnel port | `crates/vortix-core/src/ports/tunnel.rs` |
| Tunnel impls | `crates/vortix-protocol-{wireguard,openvpn}/` |
| TunnelKind aggregate | `crates/vortix/src/tunnel.rs` |
| Engine FSM | `crates/vortix-core/src/engine/{state,event,input,fsm,handle}.rs` |
| Event journal | `crates/vortix-core/src/journal/` |
| Settings | `crates/vortix-config/src/settings.rs` |
| ProfileStore | `crates/vortix-config/src/profile_store.rs` |
| SecretStore | `crates/vortix-config/src/secret_store.rs` |

## Rollout

PR #201 ships as **v0.3.0** via a two-stage RC → GA rollout (plan
[`2026-05-24-007-feat-rollout-architectural-migration-v1-plan.md`](plans/2026-05-24-007-feat-rollout-architectural-migration-v1-plan.md)).

- **Users upgrading from v0.2.x:** read
  [`docs/MIGRATION.md`](MIGRATION.md). The TL;DR is "upgrade is
  automatic, your profiles work, nothing you have to do." Includes
  rollback instructions and the `VORTIX_SKIP_MIGRATION=1` escape hatch.
- **Maintainers cutting the release:** follow
  [`docs/RELEASE-PLAYBOOK-v0.3.0.md`](RELEASE-PLAYBOOK-v0.3.0.md) — the
  RC tag procedure, soak with discussion #184, GA promotion, and the
  three-level rollback playbook.
- **RC smoke testers:** run
  [`scripts/smoke-v0.3.0.sh`](../scripts/smoke-v0.3.0.sh) against your
  installed binary; report any FAIL to the discussion thread.
