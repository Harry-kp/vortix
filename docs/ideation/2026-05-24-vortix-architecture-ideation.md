---
date: 2026-05-24
topic: vortix-target-architecture
focus: Architectural refactor of vortix — find gaps, identify target architecture that handles current features cleanly and accommodates upcoming roadmap easily (daemon, hooks, profile groups, Windows, multi-protocol, split tunneling, audit logging, encryption, team management). Performance and extensibility are the goals, not new features.
mode: repo-grounded
---

# Ideation: vortix Target Architecture

This is the **target architecture** vortix should migrate toward — a coherent set of seven architectural moves that, taken together, make current features cleaner and every roadmap item additive. Each idea is independently valuable, but the survivors reinforce each other into one direction.

## Grounding Context

### Current state (vortix v0.2.2, post-"CLI First")

- Rust 1.75+, single binary, dual-mode: TUI (ratatui + crossterm) default + headless CLI (clap)
- Single-crate layout: `src/{main,lib}.rs`, `cli/`, `app/` (TUI), `engine/` (`VpnEngine` recently extracted from `App`), `core/` (killswitch, importer, scanner, telemetry, network_monitor, downloader), `platform/{macos,linux}/`, `state/`, `ui/`, `theme.rs`, `config.rs` (26 KB), `utils.rs` (35 KB)
- `App` embeds `VpnEngine` via `Deref`/`DerefMut` — convenient but porous
- `color_eyre` for errors; JSON envelope (`{ok, command, data, error, next_actions}`) for CLI output; semantic exit codes 0-6
- Profiles imported as WireGuard `.conf` files into a config directory; protocol set is currently WireGuard-only
- Tests: sparse `app/tests.rs` + a few in `tests/`; no subprocess seam, so integration tests need real `wg`/`wg-quick` and root
- No `docs/solutions/` yet
- No `xtask`; release-plz workflow has recently been fragile (recent commit history)

### Known architectural pain (direct evidence from codebase scan)

- `utils.rs` (35 KB) and `config.rs` (26 KB) are god-files — every contributor touches them
- Scattered `#[cfg(target_os = "…")]` blocks across `core/`, `engine/`, `cli/`; no unified `Platform` trait
- Subprocess calls (`wg`, `wg-quick`, `ip`, `networksetup`, `pfctl`) are inline at the call site — testing requires real binaries + root
- `core/` modules mutate state directly; interdependent
- State machine assertions weak: warnings like "IP unchanged" fire every 30s instead of once per session; retry has no upper bound; reconnect isn't rename-safe
- `App ⇆ VpnEngine` Deref boundary leaks — daemon mode can't tell which fields belong to the engine
- Errors via `color_eyre` throughout, which is a presentation choice masquerading as a library type

### Roadmap pressure (what the target architecture must accommodate easily)

- **v0.3.0** — auto-connect on startup, daemon mode, lifecycle hooks (pre/post connect), profile groups
- **v1.0** — split tunneling, Windows support, multi-protocol (OpenVPN + IKEv2 alongside WireGuard), config encryption, audit logging, centralized team management

### External research (background)

- `enum_dispatch` for closed-set static dispatch (5-10× faster than `Box<dyn Trait>`)
- Native AFIT (Rust 1.75+) vs `async_trait` macro — AFIT for non-`dyn`, `async_trait` only when `dyn` is needed
- matklad large-workspace pattern: flat `crates/` + virtual manifest + `xtask`
- Hexagonal / ports-and-adapters for Rust CLIs (howtocodeit.com)
- rustup's `Process` abstraction for testable side effects
- gluetun (Go) factory + provider-agnostic loop pattern
- `figment` + `directories` + `keyring` v3 stack for layered config and secrets
- LSP/DAP as prior art for engine-with-clients wire protocols

## Topic Axes

1. Layering & crate boundaries
2. Protocol & platform adapters
3. State machine & async/concurrency model
4. Configuration, secrets & persistence
5. Testability & observability

---

## Ranked Ideas

Ordering reflects **foundation-first**: each later idea is materially easier once the earlier ones land. Confidence reflects how well-evidenced the move is; complexity reflects implementation burden inside the current vortix codebase.

### 1. `CommandRunner` / `Process` port — every subprocess flows through one trait

**Description:** Introduce `trait CommandRunner { async fn run(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError>; }` (modeled on rustup's `Process`). Every call to `wg`, `wg-quick`, `openvpn`, `ip`, `networksetup`, `pfctl`, `iptables`, `nft`, `route`, `defaults` flows through it. Production binds `RealRunner`; tests bind `MockRunner` (scripted responses + invocation log). Add a CI grep that fails the build if `std::process::Command::new` or `tokio::process::Command::new` appears outside the runner module. Structured logging of every subprocess invocation is a one-line addition in `RealRunner`, giving audit logging almost for free downstream.

**Axis:** Testability & observability

**Basis:** `direct:` known gap — "Subprocess calls (wg-quick, openvpn, ip, networksetup) not behind a CommandRunner — tests need real binaries and root." `external:` rustup's `Process` abstraction; the `mapped_command` crate; `assert_cmd`/`assert_fs` pattern from rust-cli book. Cross-frame consensus: every ideation frame independently surfaced this move (Pain, Inversion, Assumption-breaking, Leverage, Cross-domain, Constraint-flipping).

**Rationale:** This is the single highest-leverage move on the entire list. It is the precondition for unit-testing connection flows, lifecycle hooks (which are *just more CommandRunner calls*), audit logging (one decorator), dry-run mode, Windows port (Mock the differences without root), and the FSM (idea 3) becoming exercisable in CI. Without this, every other refactor has to keep deferring "we'll test it later."

**Downsides:** Migration is incremental but touches every callsite. Audit must include shell-spawning helpers that aren't obvious `Command::new` (e.g., `sudo`, helpers in `core/scanner`). Async trait shape decision (native AFIT vs `async_trait`) needs to be settled up front because the trait will be everywhere.

**Confidence:** 95%
**Complexity:** Low–Medium (incremental file-by-file)
**Status:** Brainstormed — see `docs/brainstorms/2026-05-24-commandrunner-port-requirements.md`

---

### 2. Cargo workspace split: `vortix-core` + adapter crates + frontend crates + `xtask`

**Description:** Move from single crate to a flat matklad-style workspace with a virtual root manifest:

```
Cargo.toml                 (virtual; no [package])
crates/
  vortix-core/             pure library — FSM, types, ports, traits, event schema; zero TUI/process/clock deps
  vortix-platform-macos/
  vortix-platform-linux/
  vortix-platform-windows/ (stub; lights up the trait checklist)
  vortix-protocol-wireguard/
  vortix-protocol-openvpn/  (future)
  vortix-protocol-ikev2/    (future)
  vortix-config/           figment+directories+keyring binding
  vortix-cli/              clap, command dispatch, JSON envelope
  vortix-tui/              ratatui frontend
  vortix-daemon/           (future) long-lived `vortixd`
  xtask/                   release/packaging/signing/codesigning in Rust
```

`vortix-core` knows nothing about stdout, the filesystem, the clock, env vars, ratatui, or specific OS APIs — those come in through ports the adapters implement. Folder name equals crate name (avoids rename drift). `version = "0.0.0"` on the internal crates (`vortix-core`, adapters) prevents accidental publish-coupling with the user-facing `vortix-cli`. The compiler enforces that "TUI cannot import platform internals" and "core cannot import a TUI framework."

**Axis:** Layering & crate boundaries

**Basis:** `external:` matklad's "Large Rust Workspaces" pattern + Cargo `xtask` convention. `direct:` "Single crate; no boundary enforcement between layers" and god-file pain in `utils.rs`/`config.rs` (when god-files are split across crates they cannot regrow as easily); Windows + daemon + multi-protocol all on roadmap — each one wants its own dependency footprint.

**Rationale:** Crate boundaries are the only fence Rust enforces automatically. Without them, the `core/` interdependency and porous App/Engine boundary keep reasserting themselves no matter how many traits are introduced. This is the structural fix that makes everything else stick: god-files cannot survive the split, Windows compiles only `vortix-platform-windows`, library/FFI consumers don't pull in `ratatui`, and per-crate test binaries shrink CI time. `xtask` also lets release scripting move out of fragile YAML.

**Downsides:** One big refactor with broad surface area. release-plz config needs to learn the workspace topology. Public-API surface decisions (what is `pub` from `vortix-core` vs internal) need care — getting this wrong calcifies. Some files will straddle crates during migration.

**Confidence:** 90%
**Complexity:** Medium (mechanical but wide)
**Status:** Brainstormed — see `docs/brainstorms/2026-05-24-cargo-workspace-split-requirements.md`

---

### 3. Engine as a deterministic FSM that emits an event journal as the single source of truth

**Description:** Replace ad-hoc state mutation in `core/` with an explicit finite-state machine on `Connection`: `Idle → Connecting → Connected → Degraded → Reconnecting → Disconnecting → Failed`, with **named modes plus explicit reversion arrows** (aviation-autopilot pattern — APPR reverts to HDG on signal loss, never to "off"). Every transition returns `(NextState, Vec<EngineEvent>)`. The events are the only durable record of what happened, persisted to an append-only journal (jsonl or sled) and broadcast on a `tokio::sync::broadcast` channel.

Subscribers are independent:
- TUI repaints on `TunnelUp`/`HandshakeStale`/`KillswitchTriggered`
- Telemetry aggregates from the journal instead of polling raw counters
- Audit logging is `journal.append(event)` once at the FSM exit
- Lifecycle hooks (v0.3.0) subscribe with a filter
- The JSON envelope's `next_actions` field is generated from the current `Mode`

Built on top of `CommandRunner` (idea 1), the FSM is fully exercisable in unit tests by feeding it command outcomes and asserting transitions.

The retry budget, "IP unchanged" warning dedup, and rename-safe reconnect (track interface by stable ID) all live in one match arm instead of being scattered.

**Axis:** State machine & async/concurrency model

**Basis:** `direct:` known gaps — "State machine: needs retry cap, dedupe of 'IP unchanged' warnings (fires every 30s), rename-safe reconnect"; "`core/` modules interdependent; mutate state directly." `external:` gluetun's loop architecture (Go); SCADA tagged-points model for telemetry with quality flags; aviation mode-annunciator pattern; event-sourcing references.

**Rationale:** Almost every roadmap item is a subscriber to an event journal, not new engine code. Audit logging is the journal. Lifecycle hooks are filtered subscribers. Daemon-to-TUI reattach (idea 4) is "replay the recent tail." Telemetry stops being a polled side channel. The user-visible bug ("IP unchanged" every 30s) becomes a one-line dedup in the transition function. State machine correctness can be property-tested without root.

**Downsides:** Designing the event schema upfront is hard to get right and expensive to evolve once journals are on disk in user installs — needs a schema version field from day one. Property-testing the FSM requires investment that the team hasn't paid yet. Some current "do it now" call sites become "emit a `Command`, the FSM acts on the next tick" — a small mental model shift for contributors.

**Confidence:** 85%
**Complexity:** Medium–High
**Status:** Brainstormed — see `docs/brainstorms/2026-05-24-engine-fsm-event-journal-requirements.md`

---

### 4. Daemon-first architecture with a typed `EngineHandle`; CLI/TUI/library/daemon are all clients of the same engine

**Description:** Treat the daemon as the canonical product; CLI invocations and the TUI are *clients*. Today's `App: Deref<Target=VpnEngine>` is the symptom of a leaky boundary — `App` and `VpnEngine` are the same object pretending not to be.

The target shape:

- `EngineHandle` is a typed Command/Query API (`execute(EngineCommand) -> EngineEvent stream`, `query(EngineQuery) -> Snapshot`)
- In-process today: handle wraps an `Arc<Engine>` and a `broadcast::Receiver<EngineEvent>`
- Out-of-process tomorrow: same handle wraps a Unix socket / Windows named pipe carrying the same `EngineCommand`/`EngineEvent` types serialized (a versioned wire protocol — LSP-precedent)
- `vortix up <profile>` either talks to a running `vortixd` or spawns-and-talks transparently
- The TUI subscribes to events and renders snapshots; it never holds mutable engine state
- A future system tray, Tauri wrapper, MCP server, or Raycast extension is *just another client*

Long-lived loops (telemetry, network monitor, killswitch supervision) live only in the daemon, eliminating per-command cold starts and giving `vortix status` sub-10ms latency. The library exposes pure pull functions (`sample_now() -> Snapshot`) so non-daemon use stays viable for embedded contexts (idea 2's `vortix-core`).

**Axis:** State machine & async/concurrency model (with crate-boundary implications)

**Basis:** `direct:` roadmap names daemon mode (v0.3.0), auto-connect, lifecycle hooks, and team management — all of which need *continuous* ownership of state. The current "fresh process per command" forces every operation to re-acquire locks, re-read config, and re-derive truth. `external:` LSP/DAP as the canonical "engine-with-clients" pattern; gluetun's daemon loop; `containerd`/`ctr` CLI-as-thin-client model; CDN control-plane / data-plane split.

**Rationale:** This is the structural decision that makes daemon mode, auto-connect, lifecycle hooks, audit logging, team management, and any third-party integration into a *single* mechanism instead of five parallel ones. The Deref smell goes away because `App` no longer wraps the engine — it consumes it through a typed channel. Replacing the in-process handle with an IPC handle later is mechanical because the contract is already the same shape.

**Downsides:** Sync (`Arc<Mutex>`) vs async (channel + reducer) handle shape locks in the concurrency model for years — needs a deliberate decision. Daemon lifecycle (auto-start, auto-stop, version skew between CLI and daemon) is real new surface. Single-shot CLI invocations now have one extra hop (spawn-and-connect or attach), which has to stay fast.

**Confidence:** 80%
**Complexity:** High
**Status:** Brainstormed — Phase A merged into `docs/brainstorms/2026-05-24-engine-fsm-event-journal-requirements.md` (R23-R30); Phase B (daemon process) deferred — see `docs/brainstorms/2026-05-24-daemon-engine-handle-requirements.md`

---

### 5. `Tunnel` trait with `enum_dispatch` over a closed protocol set

**Description:** Define one trait that every VPN protocol implements:

```
trait Tunnel {
    async fn up(&mut self, profile: &Profile, plat: &dyn Platform, cmd: &dyn CommandRunner) -> Result<TunnelHandle, TunnelError>;
    async fn down(&mut self, handle: TunnelHandle, ...) -> Result<(), TunnelError>;
    async fn status(&self, handle: &TunnelHandle, ...) -> Result<TunnelStatus, TunnelError>;
    fn parse_profile(&self, raw: &[u8]) -> Result<Profile, ParseError>;
    fn capabilities(&self) -> TunnelCapabilities;
}
```

Use the `enum_dispatch` crate (or hand-coded enum + match) over `enum TunnelKind { WireGuard(Wg), OpenVpn(Ovpn), Ikev2(Ike), Mock(MockTunnel) }`. Each protocol lives in its own crate (idea 2's `vortix-protocol-*`) with an isolated dependency footprint. The engine routes `ProfileId → TunnelKind` and never branches on protocol. The `MockTunnel` variant unlocks integration tests that don't need real network.

Protocol *capabilities* (split tunnel, IPv6, configurable MTU, kill-switch type) are declared as a typed struct returned by `capabilities()`, letting the engine negotiate feature × profile × protocol × platform before any side effect.

**Axis:** Protocol & platform adapters

**Basis:** `external:` `enum_dispatch` crate (5–10× faster than `Box<dyn Trait>` for closed sets); native AFIT for traits that don't need `dyn`-compatibility; gluetun's factory + provider-agnostic tunnel-manager split; ProtonVPN-cli's hardcoded `subprocess.run(["openvpn", ...])` as the explicit anti-pattern to avoid. `direct:` roadmap names OpenVPN + IKEv2 + multi-protocol (v1.0).

**Rationale:** Without this, the second protocol gets bolted on with conditionals and the third one is a rewrite. With it, the compiler enforces that every protocol implements every operation, and adding StrongSwan or a userspace `boringtun` tunnel is one file plus one enum variant. Lifecycle hooks fire at trait boundaries identically for all protocols. The `MockTunnel` variant is what makes idea 3's FSM testable end-to-end.

**Downsides:** `enum_dispatch` adds a macro dependency; ABI is closed-set by construction (no runtime third-party plugin tunnels). If the team ever wants runtime-loaded provider plugins, this design has to change. AFIT vs `async_trait` is a real trade-off — AFIT is more efficient but not `dyn`-compatible, which interacts with idea 4's handle design.

**Confidence:** 90%
**Complexity:** Medium
**Status:** Brainstormed — see `docs/brainstorms/2026-05-24-tunnel-trait-enum-dispatch-requirements.md`

---

### 6. Platform organized by **capability ports**, not OS folders

**Description:** Reorganize `platform/` around the operations vortix actually needs, not around the operating systems that provide them:

```
crates/vortix-core/src/ports/
  killswitch.rs         trait Killswitch
  dns.rs                trait DnsResolver
  route_table.rs        trait RouteTable
  network_monitor.rs    trait NetworkMonitor
  split_tunnel.rs       trait SplitTunnel
  tun_device.rs         trait TunDevice
  privilege.rs          trait PrivilegeEscalation
  secrets.rs            trait SecretStore

crates/vortix-platform-macos/src/
  killswitch_pf.rs           impl Killswitch via pfctl
  dns_scutil.rs              impl DnsResolver
  route_table_route.rs       impl RouteTable
  ... etc.

crates/vortix-platform-linux/src/
  killswitch_nftables.rs
  killswitch_iptables.rs     (alt impl, runtime-selected)
  ...

crates/vortix-platform-windows/src/   (stub for now)
  killswitch_wfp.rs
  ...
```

Each capability is a trait with per-OS implementations as siblings. The OS doesn't own the file — the capability does. Each `vortix-platform-*` crate gates `#[cfg(target_os)]` at the *crate level*, so application code outside `vortix-platform-*` never contains `cfg` blocks.

A `PlatformCapabilities` struct exposed by each adapter declares what it can actually do (e.g., Linux split tunneling supported, macOS not yet) so the engine can fail-loud before partial execution.

**Axis:** Protocol & platform adapters

**Basis:** `direct:` "Platform code is scattered `cfg(target_os='…')` blocks; no unified `Platform` trait." `external:` hexagonal architecture / ports-and-adapters; "Master Hexagonal Architecture in Rust" (howtocodeit.com); the `directories` crate as a prior example of capability-shaped abstraction (one trait, three OS impls). `reasoned:` Windows port + split tunneling together force a matrix of (capability × OS), and organizing by OS would create six files re-implementing the same capability differently.

**Rationale:** Today, every platform feature (split tunneling, Windows, IPv6) means hunting `cfg` blocks across `core/` and `platform/`. After this, Windows support is "implement seven capability traits in one crate." Cross-platform feature parity becomes a visible matrix (a `PlatformCapabilities` struct per OS) instead of buried inconsistencies. The capability-trait set is also the smallest stable contract `vortix-core` (idea 2) needs from the adapter layer.

**Downsides:** Some capabilities don't carve cleanly — Linux has multiple firewalls (nftables / iptables / firewalld) and the right one is runtime-detected, not compile-time-selected. The trait set's surface needs deliberate design; getting it wrong means re-doing every OS impl. Capability granularity is a judgment call (one big trait vs many small ones).

**Confidence:** 85%
**Complexity:** Medium
**Status:** Brainstormed — see `docs/brainstorms/2026-05-24-capability-ports-platform-requirements.md`

---

### 7. Layered config stack (`figment` + `directories`) + indexed `ProfileStore` + OS `keyring` for secrets

**Description:** Three distinct concerns, three distinct mechanisms:

- **Settings** (preferences, theme, defaults): layered via `figment` — defaults < system file < user file (XDG/macOS-Library/Windows-AppData via `directories` crate) < env vars (`VORTIX_*`) < CLI flags. Resolved once at startup into an immutable `Settings`.
- **Profiles** (the data — WireGuard/OpenVPN/IKEv2 configs): records in a `ProfileStore` trait backed by SQLite or `redb`. Each profile is content-addressed (hash-as-id), with metadata (group membership, source, last-used, version). Importing the same `.conf` twice is a no-op by hash. The directory-of-`.conf` layout becomes one possible *backend* for `ProfileStore`, not the canonical truth.
- **Secrets** (WireGuard private keys, OpenVPN credentials, future team tokens): in OS-native storage via `keyring` v3 (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows). Profiles hold `SecretRef` handles, not the secret material itself. The 26 KB `config.rs` collapses to a few hundred lines of figment providers + serde structs.

Future capabilities ride this layer naturally: profile groups are a column on the store, profile versioning (immutable versions + a HEAD pointer, Postgres MVCC analog) is an extension of the store schema, and a `ProfileSource` trait (LocalFs / HttpFleet / Git / S3 / KeyringSealed) sits in front of the store as a pull-through cache for team management.

**Axis:** Configuration, secrets & persistence

**Basis:** `direct:` "config.rs (26 KB) — god-file"; roadmap names config encryption, profile groups, audit logging, team management — none of which can bolt onto a 26 KB monolith that conflates layered config with secrets with runtime state. `external:` figment + directories + keyring stack (well-known Rust ecosystem trio); the rustup `Cfg` god-struct as the explicit anti-pattern; content-addressed storage / MVCC versioning from Git and Postgres.

**Rationale:** Roadmap items collapse to "use this layer." Config encryption is "use keyring," not a project. Team management is "implement `ProfileSource::HttpFleet`," not a refactor. Profile groups is a column. WireGuard private keys stop being on disk in plaintext (a security risk the team has not yet had to defend in a review). Windows port inherits Credential Manager for free.

**Downsides:** Three integrations to land (figment, ProfileStore, keyring). User data migration from the current directory-of-`.conf` layout needs care. SQLite as a dependency adds binary size; `redb` is leaner but younger. `keyring` v3 behavior varies across Linux desktops (Secret Service must be running) — needs a graceful encrypted-file fallback for headless servers.

**Confidence:** 80%
**Complexity:** Medium–High
**Status:** Brainstormed — see `docs/brainstorms/2026-05-24-config-profile-secret-stack-requirements.md` (file-based ProfileStore, not SQLite, per user redirect)

---

## Cross-Cutting Pattern: The Coherent Target Architecture

These seven survivors aren't independent — they compose into one direction. Reading the survivors as a single architectural statement:

> `vortix-core` is a pure library defining the FSM, event schema, and capability ports. The engine FSM emits an event journal; subscribers (TUI, audit log, telemetry, hooks) read it. The daemon owns the engine and the long-lived loops; CLI/TUI/library/FFI all talk to it through a typed `EngineHandle`. Every subprocess goes through `CommandRunner`. Protocols are an `enum_dispatch` set; platforms are capability ports with per-OS implementations. Profiles live in an indexed store with secrets in OS keyring.

Roadmap items become additive in this architecture:

| Roadmap item | Becomes |
|---|---|
| Daemon mode (v0.3.0) | The default topology — CLI/TUI are clients already |
| Lifecycle hooks (v0.3.0) | Filtered subscribers on the event journal |
| Profile groups (v0.3.0) | A column on `ProfileStore` |
| Auto-connect (v0.3.0) | A daemon subscriber to a `Settings.autoconnect` query |
| Audit logging (v1.0) | The event journal, already on disk |
| OpenVPN / IKEv2 (v1.0) | New `TunnelKind` enum variants in new crates |
| Split tunneling (v1.0) | A capability port; some platform impls return `Unsupported` |
| Windows (v1.0) | One new `vortix-platform-windows` crate; zero changes elsewhere |
| Config encryption (v1.0) | Already done — secrets are in `keyring` |
| Team management (v1.0) | A `ProfileSource::HttpFleet` impl |

## Suggested sequencing (foundation-first)

This is not a plan — that belongs in `ce-plan` — but the surface-level dependency shape:

1. **CommandRunner** (idea 1) — unblock testing of everything else
2. **Workspace split** (idea 2) — set the boundaries
3. **FSM + event journal** (idea 3) — once `vortix-core` exists with `CommandRunner`, the engine refactor has somewhere to live
4. **Daemon-first + `EngineHandle`** (idea 4) — depends on 2 and 3
5. **`Tunnel` trait** (idea 5) — can land alongside 4 once `vortix-core` exists
6. **Capability ports** (idea 6) — alongside 5
7. **Config stack** (idea 7) — independent of the others; could land in parallel with 1–3

---

## Rejection Summary

Eighteen merged candidates did not survive. Reasons:

| # | Idea | Reason rejected |
|---|------|-----------------|
| M3 | Kill `utils.rs`/`config.rs` god-files; ban via CI lint | **Folded into M1** — the workspace split forces them apart by construction; the CI lint is a fine convention but is a consequence, not a standalone architectural move |
| M4 | Engine speaks a versioned wire protocol (LSP-style) | **Folded into M14 (idea 4)** — the typed `EngineHandle` *is* the contract; serializing it across a socket is a downstream extension, not a separate architectural decision |
| M5 | Errors as a typed `thiserror` protocol; color_eyre only at the binary edge | **Folded into M2/M4** — the workspace split and the typed `EngineHandle` both force errors to be a serializable type, naturally retiring `color_eyre` from the library |
| M8 | Userspace tunnel adapters (boringtun, wireguard-go) | **Folded into idea 5** — the `Tunnel` trait already admits userspace impls; whether to *ship* one is a feature decision, not an architecture decision |
| M9 | Capability manifest per protocol/profile/platform | **Folded into ideas 5 and 6** — `TunnelCapabilities` and `PlatformCapabilities` are typed structs returned by each adapter, mentioned in both surviving ideas |
| M10 / M25 | Plan/Apply derivations (Nix/Terraform-style typed `Action` enum) | **Future extension of idea 3** — once the FSM returns `(NextState, Vec<Event>)`, returning `Vec<Action>` for pre-execution validation is a natural next step; not foundational on day one |
| M13 | Typestate connection lifecycle (`Connection<Disconnected>` → `<Connecting>`) | **Subsumed by idea 3** — explicit FSM with a typed `Mode` enum captures the safety win without the typestate-through-async-channel headaches; typestate adds friction when state must travel through `mpsc::send` |
| M15 | Erlang/OTP supervisor tree with restart strategies | **Folded into idea 4** — the daemon owns the supervised loops; explicit `one_for_one`/`rest_for_one` strategies can be a design detail inside `vortix-daemon` without being a separate idea |
| M16 | Pull-based telemetry; no background threads | **Reconciled in ideas 3 + 4** — the library exposes pull-based functions; the daemon owns the loops. Pull-only as a standalone constraint contradicts daemon-first; the combination is consistent |
| M19 | Profile versioning (MVCC immutable versions + HEAD pointer) | **Future extension of idea 7** — `ProfileStore` can grow versioning later; not foundational, and risks scope creep into rollback UX which is feature work |
| M20 | Profile groups as DAW track+send architecture | **Belongs in `ce-brainstorm` of the profile-groups feature** — the analogy is sharp but the architectural commitment is "groups are a column," not a particular sharing/override semantic |
| M21 | `ProfileSource` trait with multiple backends | **Future extension of idea 7** — pull-through-cache topology adds value once team management is being built; on day one a single LocalFs backend is fine |
| M23 | `inventory` crate for distributed command/hook/importer registration | **Premature** — vortix's size makes match-arm dispatch tables fine; `inventory` adds linker-trick complexity that pays off only at much larger plugin counts |
| M24 | `docs/solutions/` ADR-lite + per-port `ARCHITECTURE.md` + CI lint | **Process, not architecture** — strongly recommended alongside this refactor, but the *technical* target architecture is the seven survivors; ADR practice is the *meta* layer that documents them |

All five topic axes have at least one survivor — no axis-coverage gaps to flag.

---

## Confidence Notes

The strongest evidence is for ideas 1, 2, 5, and 6 — they have direct gaps in vortix today, well-known external patterns (rustup, matklad, hexagonal, enum_dispatch), and predictable migration paths. Idea 3 is also well-evidenced but more invasive (the FSM design is a deliberate one-shot decision). Idea 4 (daemon-first) has the highest payoff but the most surface area and the most decisions to lock in — it benefits from landing 1–3 first. Idea 7 is straightforward in design but has the most external integrations (figment, sqlite/redb, keyring, data migration), so its complexity is in the *integration* phase, not the *design* phase.

The conscious choice is to **anchor on testability (idea 1) and boundaries (idea 2) first** — those make every later refactor *de-risked* by giving them somewhere to land and somewhere to be exercised.
