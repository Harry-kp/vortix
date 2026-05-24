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

## What's deferred

These units require surgery the maintainer should drive in subsequent
PRs with live-VPN testing:

### Plan 005
- **U5 (full) — App restructure** — remove `App: Deref<VpnEngine>` and
  rewire ~20 files of TUI / app code to read state via `engine_handle`.
- **U6 — CLI uses `EngineHandle`** — every CLI command currently uses
  the legacy `VpnEngine` path; migrating them onto `EngineHandle::execute`
  changes their concurrency model.
- **U7 — Telemetry actor split** — telemetry becomes a `subscribe()`-only
  consumer of `EngineEvent`s; the in-process channels collapse.

### Plan 006
- **U5 — `Tunnel` + `SecretStore` integration** — `OvpnTunnel` writes a
  temp auth file; that path will materialise from `SecretStore::get`
  rather than reading from disk. Touches live-VPN auth flow.
- **U6 partial — `--inline-secrets` inlining** — the CLI flag is wired,
  but actually materialising stored secrets into the export depends on
  U5.

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
