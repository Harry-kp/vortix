---
date: 2026-05-24
title: "refactor: Introduce Tunnel trait + enum_dispatch over closed protocol set"
status: active
type: refactor
origin: docs/brainstorms/2026-05-24-tunnel-trait-enum-dispatch-requirements.md
prerequisite: docs/plans/2026-05-24-003-refactor-capability-ports-platform-plan.md
---

# refactor: Introduce Tunnel trait + enum_dispatch over closed protocol set

## Summary

Define a single `Tunnel` trait in `vortix-core::ports::tunnel` with five methods (`up`, `down`, `status`, `parse_profile`, `capabilities`) and dispatch via `enum TunnelKind { WireGuard(WgTunnel), OpenVpn(OvpnTunnel), Mock(MockTunnel) }` (via `enum_dispatch`). Migrate both currently-supported protocols (WireGuard via `wg-quick`, OpenVPN via the `openvpn` subprocess) into per-protocol crates: `vortix-protocol-wireguard` (existed as stub since plan #001; populated here) and a **new** `vortix-protocol-openvpn` crate created in this PR. The engine's connection lifecycle (currently sprawled across `src/engine/connection.rs`) loses its per-protocol match arm; it routes once via `profile.protocol → TunnelKind` and never branches on protocol again. Pure behavior-neutral refactor — same subprocess invocations, same OpenVPN log-polling cadence, same auth-file handling. IKEv2 and userspace WireGuard deferred entirely.

---

## Problem Frame

After plans #001–#003 land:
- The workspace exists with eight crates plus the (about-to-be-added) `vortix-protocol-openvpn`.
- Every subprocess flows through `CommandRunner` (plan #002).
- Platform-OS code is behind capability-port traits in `vortix-core::ports::*` (plan #003).
- BUT: protocol-specific logic (the entire `wg-quick` / `openvpn` invocation sequences, the OpenVPN log-polling for connection state, auth-file lifecycle, PID-file management) all still lives in `crates/vortix/src/engine/connection.rs` (669 lines) and `crates/vortix/src/engine/mod.rs` (525 lines) behind a `match profile.protocol { WireGuard => ..., OpenVPN => ... }` block.

This match-arm sprawl is the structural reason v1.0 multi-protocol (IKEv2) cannot land cleanly. A third protocol multiplies the match arms across every engine method. This PR makes protocol an *adapter* concern, not a control-flow concern.

---

## Key Technical Decisions

- **Five-method trait** per brainstorm R1: `up`, `down`, `status`, `parse_profile`, `capabilities`. No `reload`, `metrics`, `prepare`, or `validate_profile`. YAGNI for v1.
- **`enum_dispatch` over `enum TunnelKind { WireGuard(WgTunnel), OpenVpn(OvpnTunnel), Mock(MockTunnel) }`,** `#[non_exhaustive]` from day one. Adding IKEv2 later is one new variant + one new crate, no changes outside.
- **Both WireGuard AND OpenVPN migrate in this PR.** OpenVPN is real working code today (auth file handling, PID lifecycle, log polling), not a future-stub. Splitting the migration across PRs would create a two-protocol-handling-model intermediate state worse than today. (Origin: brainstorm Key Decisions.)
- **Per-protocol opaque `ParsedProfile`** (`Box<dyn ParsedProfile>` inside the unified `Profile` type). Each protocol owns its config format. Engine sees only `id`, `display_name`, `protocol_kind`. (Origin: brainstorm R8.)
- **`TunnelHandle` is a struct** carrying `profile_id, interface_name, pid: Option<u32>, started_at, kind: TunnelKindTag` (per brainstorm R4).
- **`TunnelStatus`** carries `peers_or_state: Box<dyn ProtocolStatus>`, `bytes_rx, bytes_tx, last_handshake: Option<SystemTime>, observed_at`. (Origin: brainstorm R5.)
- **`TunnelCapabilities`** is a struct of booleans returned `const` from each impl: `supports_split_tunnel`, `supports_ipv6`, `mtu_configurable`, `supports_reconnect_without_disconnect`, `requires_root`, `userspace`. (Origin: brainstorm R6, R7.)
- **MockTunnel lives in `vortix-core::ports::tunnel::mock`** — same pattern as MockRunner from plan #002 and the MockX impls from plan #003. Co-located with the trait to avoid cyclic-dep issues across protocol crates.
- **IKEv2 deferred entirely.** No `vortix-protocol-ikev2` stub. (Origin: brainstorm Scope Boundaries.)
- **Userspace WireGuard (boringtun, wireguard-go) deferred.** v1 of `vortix-protocol-wireguard` is kernel-`wg-quick` only. (Origin: brainstorm Scope Boundaries.)
- **Behavior-neutral refactor.** Same subprocess invocations, same auth-file lifecycle, same log-polling, same error messages. The only observable change is internal organization. (Origin: brainstorm Key Decisions.)
- **Big-bang single PR.** (Origin: brainstorm R10, R11.)

---

## Implementation Units

### U1. Define `Tunnel` trait + supporting types in `vortix-core::ports::tunnel`

**Goal:** Establish the trait surface and types.

**Requirements:** R1, R2, R3, R4, R5, R6, R7, R8

**Dependencies:** Plans #001–#003 complete.

**Files (new):**
- `crates/vortix-core/src/ports/tunnel.rs`: `Tunnel` trait, `TunnelKind` enum (with `WireGuard(WgTunnel)`, `OpenVpn(OvpnTunnel)`, `Mock(MockTunnel)` variants gated under `enum_dispatch`), `TunnelHandle`, `TunnelStatus`, `TunnelCapabilities`, `TunnelError`, `ParseError`, `ParsedProfile` trait (for per-protocol opaque), `Profile` unified type, `ProfileId` type, `TunnelKindTag` enum, `ProtocolStatus` trait.
- `crates/vortix-core/src/ports/tunnel/mock.rs`: `MockTunnel` struct.

**Files (modifications):**
- `crates/vortix-core/src/lib.rs`: re-export the public types under `pub use ports::tunnel::*;`.
- `crates/vortix-core/Cargo.toml`: confirm `enum_dispatch` and `thiserror` already present (from plans #001/#003).
- `crates/vortix-core/src/ports/mod.rs`: add `pub mod tunnel;`.

**Approach:**
- Trait shape (directional, not implementation): `trait Tunnel { async fn up(&mut self, profile: &Profile, plat: &Platform, runner: &CommandRunner) -> Result<TunnelHandle, TunnelError>; async fn down(&mut self, handle: TunnelHandle, plat: &Platform, runner: &CommandRunner) -> Result<(), TunnelError>; async fn status(&self, handle: &TunnelHandle, runner: &CommandRunner) -> Result<TunnelStatus, TunnelError>; fn parse_profile(&self, raw: &[u8]) -> Result<ParsedProfile, ParseError>; fn capabilities(&self) -> TunnelCapabilities; }`.
- `MockTunnel` follows the same scriptable-expectations builder pattern as `MockRunner` (plan #002 U3) and `Mock*` ports (plan #003 U5).

**Test scenarios:**
- `crates/vortix-core/tests/tunnel_mock.rs`:
  - **Happy path:** Build `MockTunnel::with_default_success()`; call `up()`, assert returns `TunnelHandle`.
  - **Error path:** Script `MockTunnel` with `up()` → `Err(HandshakeFailed)`. Call up; assert error matches.

**Verification:** Trait + types compile in `vortix-core`. `MockTunnel` works end-to-end with scripted expectations.

---

### U2. Populate `vortix-protocol-wireguard` with `WgTunnel` impl

**Goal:** Move WireGuard logic from the engine into its own crate, behind the trait.

**Requirements:** R10, R14, R15

**Dependencies:** U1

**Files (modifications to `crates/vortix-protocol-wireguard/`):**
- `Cargo.toml`: add `vortix-core = { path = "../vortix-core" }, vortix-process = { path = "../vortix-process" }, tokio = { workspace = true }, tracing = { workspace = true }, thiserror = { workspace = true }`.
- `src/lib.rs` (replacing the empty stub): module structure: `pub mod tunnel; pub mod parser; pub mod status;`. Re-export `WgTunnel`.
- `src/tunnel.rs`: `WgTunnel` struct + `impl Tunnel for WgTunnel`. Methods relocate from `crates/vortix/src/engine/connection.rs::connect_wireguard` and related code (lines 238–290 ish).
- `src/parser.rs`: parses `.conf` files into `WgParsedProfile { interface, peers, dns, ... }`. Logic relocated from the existing `crates/vortix/src/core/importer.rs` and similar.
- `src/status.rs`: parses `wg show <iface>` output into `WgStatus { peers: Vec<PeerInfo>, ... }`. Today, this parsing lives in `crates/vortix/src/core/scanner.rs`; the WG-specific pieces relocate.
- `src/error.rs`: `WgTunnelError` (impl `Into<TunnelError>`).

**Files (modifications to `crates/vortix/src/engine/`):**
- `engine/connection.rs`: REMOVE the WireGuard match arm and its supporting code. The `wg-quick up <iface>` invocation, the kill/pkill logic for WG processes, the wg-show status parsing — all gone (relocated to `vortix-protocol-wireguard`).

**Approach:**
- The `WgTunnel::up` method:
  1. Apply DNS via `plat.dns.apply(parsed.dns_servers, &runner).await` (from plan #003's port).
  2. Run `wg-quick up <iface>` via `runner.run(...).await`.
  3. Parse `wg show <iface>` for the resulting interface state.
  4. Return `TunnelHandle { profile_id, interface_name, pid: None /* wg-quick doesn't leave a long-running process */, started_at, kind: TunnelKindTag::WireGuard }`.
- The `WgTunnel::down` method:
  1. Run `wg-quick down <iface>` via runner.
  2. Restore DNS via `plat.dns.restore(&runner).await`.
- `WgTunnel::status` runs `wg show <iface>` and parses.
- `WgTunnel::parse_profile` consumes a `.conf` file's raw bytes; returns a `ParsedProfile` whose underlying box holds `WgParsedProfile`.
- `WgTunnel::capabilities()` returns the const: `TunnelCapabilities { supports_split_tunnel: false, supports_ipv6: true, mtu_configurable: true, supports_reconnect_without_disconnect: true, requires_root: true, userspace: false }`.

**Test scenarios:**
- `crates/vortix-protocol-wireguard/tests/wg_tunnel.rs`:
  - **Happy path — up:** Mock `wg-quick up corp-iface` → success; mock `wg show corp-iface` → fixture stdout. Call `wg_tunnel.up(profile, &platform, &runner).await`. Assert returned handle has expected `interface_name`.
  - **Error path — wg-quick fails:** Mock `wg-quick up` → `NonZeroExit(1, "Address already in use")`. Assert `Err(WgTunnelError::HandshakeFailed)`.
  - **Down + DNS restore:** After successful up, call `down`. Assert `wg-quick down corp-iface` called; assert `platform.dns.restore` called.
  - **parse_profile:** Pass a fixture `.conf` byte string. Assert returned `ParsedProfile` carries the expected pubkey, endpoint, allowed-IPs.

**Verification:** `vortix-protocol-wireguard` builds standalone. WG tests pass. `rg 'wg-quick\|wg show' crates/vortix/src/` returns zero matches (no WG-specific subprocess code outside the protocol crate).

---

### U3. Create `vortix-protocol-openvpn` crate + `OvpnTunnel` impl

**Goal:** A new workspace crate for OpenVPN, populated by relocating the existing OpenVPN logic.

**Requirements:** R10, R12, R13

**Dependencies:** U1

**Files (new):**
- `crates/vortix-protocol-openvpn/Cargo.toml`: same dep set as `vortix-protocol-wireguard` (`vortix-core`, `vortix-process`, tokio, tracing, thiserror). `publish = false, version = "0.0.0"`.
- `crates/vortix-protocol-openvpn/src/lib.rs`: `pub mod tunnel; pub mod parser; pub mod log_poll; pub mod auth;`.
- `crates/vortix-protocol-openvpn/src/tunnel.rs`: `OvpnTunnel` struct + `impl Tunnel for OvpnTunnel`. Relocates from `crates/vortix/src/engine/connection.rs::connect_openvpn` (today around lines 520–650).
- `crates/vortix-protocol-openvpn/src/parser.rs`: parses `.ovpn` files (existing logic relocated from `crates/vortix/src/core/importer.rs` if present).
- `crates/vortix-protocol-openvpn/src/log_poll.rs`: the OpenVPN log-polling logic for "connection established" detection. Relocated from `crates/vortix/src/engine/connection.rs` (the polling loop after the daemon spawn).
- `crates/vortix-protocol-openvpn/src/auth.rs`: auth-user-pass file handling, ownership-fix logic. Relocated from `crates/vortix/src/engine/connection.rs` (around lines 520–540) and `crates/vortix/src/config.rs::fix_ownership`.

**Files (modifications):**
- Workspace root `Cargo.toml`: add `"crates/vortix-protocol-openvpn"` to `[workspace] members`.
- `crates/vortix/src/engine/connection.rs`: REMOVE the OpenVPN match arm — daemon spawn, log polling, kill/pkill for OVPN processes, auth-file management. All gone.
- `crates/vortix/Cargo.toml`: add `vortix-protocol-openvpn = { path = "../vortix-protocol-openvpn" }` to `[dependencies]`.

**Approach:**
- `OvpnTunnel::up`:
  1. Materialize the auth file at a temp location (existing logic — write `username\npassword\n` to a file, chmod 0600).
  2. Build the `openvpn` command line: `--config <profile.ovpn> --daemon --log-append <log_path> --writepid <pid_path> --auth-user-pass <auth_path>` etc.
  3. Spawn detached via `runner.spawn_detached(...)`.
  4. Poll the log file for `Initialization Sequence Completed` (existing logic with the existing timeout/interval constants — `OVPN_LOG_POLL_MS`, `OVPN_ERROR_LOG_TAIL_LINES`).
  5. Apply DNS via `plat.dns.apply(...)`.
  6. Return `TunnelHandle { profile_id, interface_name: parsed_from_log, pid: Some(pid_from_pidfile), started_at, kind: OpenVpn }`.
- `OvpnTunnel::down`: read pid from handle, `runner.run(CommandSpec::oneshot("kill", vec!["-9", &pid.to_string()]))`, restore DNS, cleanup temp auth file.
- `OvpnTunnel::status`: today's status detection — parse log file tail? Check if PID is alive? Existing approach preserved.
- `OvpnTunnel::parse_profile`: parses `.ovpn` files.
- `OvpnTunnel::capabilities()`: `TunnelCapabilities { supports_split_tunnel: false, supports_ipv6: true, mtu_configurable: false, supports_reconnect_without_disconnect: false, requires_root: true, userspace: false }` — verify against actual OpenVPN behavior during implementation.

**Test scenarios:**
- `crates/vortix-protocol-openvpn/tests/ovpn_tunnel.rs`:
  - **Happy path — up:** Mock `openvpn --daemon ...` → DetachedSpawn returning pid 12345. Mock `kill -0 12345` → exit 0 (alive). Mock the log-file (write a fixture file with "Initialization Sequence Completed" line). Call up; assert handle has pid=12345.
  - **Error path — daemon exit:** Mock `openvpn --daemon` → success (exit 0); mock log file → fixture with "AUTH_FAILED". Assert log-poll detects failure, returns `Err(OvpnTunnelError::AuthFailed)`.
  - **Error path — timeout:** Mock log file → never writes "Initialization Sequence Completed". Mock `tokio::time::pause()` to advance clock past `OVPN_CONNECT_TIMEOUT_SECS`. Assert `Err(OvpnTunnelError::ConnectionTimeout)`.
  - **Down:** Successful up; call down. Assert `kill -9 12345` called; assert temp auth file deleted; assert DNS restored.
  - **Auth file cleanup on early failure:** Up fails before completing; verify temp auth file is cleaned up.

**Verification:** `vortix-protocol-openvpn` builds standalone. OVPN tests pass. `rg 'openvpn' crates/vortix/src/` returns zero matches (no OVPN-specific subprocess code outside the protocol crate). Log-polling cadence matches the existing `OVPN_LOG_POLL_MS` constant.

---

### U4. Engine routes `profile.protocol → TunnelKind` once

**Goal:** Establish the single routing function; remove protocol branching from the engine lifecycle code.

**Requirements:** R10

**Dependencies:** U1, U2, U3

**Files (modifications):**
- `crates/vortix/src/engine/mod.rs`:
  - Add a `fn tunnel_for(profile: &Profile) -> TunnelKind` (or similar) — the SINGLE place that match-branches on protocol. Returns:
    - `Protocol::WireGuard → TunnelKind::WireGuard(WgTunnel::new())`
    - `Protocol::OpenVPN → TunnelKind::OpenVpn(OvpnTunnel::new())`
  - The engine's `connect`/`disconnect`/`status` methods now:
    1. Look up profile.
    2. Get `TunnelKind` via `tunnel_for(&profile)`.
    3. Delegate to `tunnel.up(&profile, &platform, &runner).await` (or `down`/`status`).
    4. Observe the resulting `TunnelHandle` and state.
- `crates/vortix/src/engine/connection.rs`: this file shrinks dramatically. Today 669 lines; post-refactor it holds only the engine's lifecycle orchestration (state transitions, retry logic, killswitch coordination) — no protocol-specific code.

**Approach:**
- The engine holds an active `Option<TunnelKind>` field — set when `up` succeeds, cleared on `down`. Storing the TunnelKind alongside the handle simplifies access to capabilities/status methods.
- Capability negotiation at the engine level: before invoking `tunnel.up`, the engine reads `tunnel.capabilities()` and validates against requested feature flags (e.g., split tunneling) — fails fast with `EngineError::CapabilityUnsupported`. (Today no feature requires this; the check is wired in for idea 3's FSM later.)

**Test scenarios:**
- `crates/vortix/src/engine/tests/routing.rs`:
  - **WireGuard routing:** Profile with `protocol = WireGuard`. Assert `tunnel_for(...)` returns `TunnelKind::WireGuard(...)`.
  - **OpenVPN routing:** Profile with `protocol = OpenVPN`. Assert `TunnelKind::OpenVpn(...)`.
  - **Engine connect via routed tunnel:** Use `MockTunnel` to script up success; verify engine reaches `Connected` state. (Test substitutes `TunnelKind::Mock(...)` via a test-only constructor.)

**Verification:** `rg 'match.*profile\.protocol' crates/vortix/src/engine/` returns exactly one match (the routing function). All other engine code is protocol-agnostic.

---

### U5. Add `xtask check-protocol-leak` CI lint

**Goal:** Enforce that protocol-specific subprocess names don't appear outside their protocol crates.

**Requirements:** R13, R15

**Dependencies:** U1, U2, U3, U4

**Files (modifications):**
- `crates/xtask/src/main.rs`: add `CheckProtocolLeak` subcommand. Looks for protocol-specific binary names (`wg`, `wg-quick`, `openvpn`) outside their respective crates.
  - Pattern: search for string literals matching `"wg"`, `"wg-quick"`, `"openvpn"` in `CommandSpec::oneshot(...)` or `.program = "..."` patterns.
  - Allowlist: `crates/vortix-protocol-wireguard/**` for `wg` / `wg-quick`; `crates/vortix-protocol-openvpn/**` for `openvpn`.
  - Allowlist: explicit `// xtask:allow-protocol-leak: <reason>` annotations.
- `.github/workflows/ci.yml`: add `cargo xtask check-protocol-leak` to lint job.

**Approach:**
- Same `ignore`-crate-based walker as plans #002 U9 and #003 U6.

**Test scenarios:**
- `crates/xtask/tests/protocol_leak.rs`:
  - **Happy path:** Workspace with no protocol leaks. Exit 0.
  - **Error path:** Add a `CommandSpec::oneshot("wg", ...)` call in `crates/vortix/src/utils.rs`. Exit 1.

**Verification:** `cargo xtask check-protocol-leak` exits 0 on post-migration workspace.

---

## Verification Strategy

- `cargo build --workspace --all-targets --locked` succeeds.
- `cargo test --workspace --all-targets` passes.
- `cargo xtask check-protocol-leak` exits 0.
- `rg 'Command::new\("wg' crates/ | rg -v 'crates/vortix-protocol-wireguard/'` → zero matches.
- `rg 'Command::new\("openvpn' crates/ | rg -v 'crates/vortix-protocol-openvpn/'` → zero matches.
- `cargo metadata` reports 9 workspace members (the original 8 from plan #001 + `vortix-protocol-openvpn`).
- Manual smoke test: connect to a WG profile, observe identical behavior. Connect to an OVPN profile (if available), observe identical log-poll cadence and connection establishment timing.

---

## Risks & Mitigations

- **OpenVPN's `--daemon` semantics on macOS vs Linux.** Daemonization paths differ slightly; today's code handles both. Mitigation: preserve the existing platform-conditional invocation lines verbatim during relocation.
- **Auth-file ownership-fix logic depends on `SUDO_USER`.** When running `sudo vortix up`, the daemon spawns as root and writes the auth file owned by root; today's `fix_ownership` chowns it to the invoking user so the OpenVPN daemon can read it. Mitigation: preserve `fix_ownership` (or call its successor in `vortix-config` per idea 7) from inside `OvpnTunnel::up`.
- **`OvpnTunnel`'s log-polling correctness.** Today's polling depends on specific log message strings (`Initialization Sequence Completed`, `AUTH_FAILED`). Mitigation: preserve the existing regex/match patterns; document them as fixture inputs in the test suite.
- **Protocol crates depend on `vortix-process` for `CommandRunner`** — verify no circular deps.
- **`Box<dyn ParsedProfile>` heap allocation per profile load.** Acceptable — profiles are loaded rarely.

---

## Scope Boundaries

- **IKEv2 / IPSec support** — out of scope. No `vortix-protocol-ikev2` crate created.
- **Userspace WireGuard (boringtun, wireguard-go)** — out of scope.
- **Split tunneling implementation** — out of scope. Capability flag declared `false` for both protocols.
- **MTU tuning UI** — out of scope.
- **Profile import format expansion** (NetworkManager / Tunnelblick / .mobileconfig) — out of scope.
- **`Tunnel::reload` / `Tunnel::metrics`** — not in trait.
- **Per-protocol diagnostic CLI commands** (`vortix wg show`, `vortix ovpn log`) — out of scope.
- **Behavior changes of any kind** — out of scope. Pure refactor.

### Deferred to Follow-Up Work

- IKEv2 lands as a sibling PR when v1.0 IKEv2 ROADMAP work begins.
- Userspace WG when Windows-native or locked-down environments need it.

---

## Outstanding Questions

### Resolve Before Planning

(None.)

### Deferred to Implementation

- Exact `TunnelHandle` field set (mechanical).
- Whether `Box<dyn ProtocolStatus>` should support downcasting via `as_wireguard()` / `as_openvpn()` for per-protocol introspection. Recommend: yes for v1 introspection (TUI shows WG peer list, OVPN route table).
- Verify `supports_reconnect_without_disconnect` boolean for OpenVPN against actual behavior during implementation.
- Whether to migrate `src/state/profile.rs`'s `VpnProfile` type into `vortix-core::profile::Profile` as part of this PR or defer to idea 7. Recommend: relocate the type (it's a `Tunnel`-trait input) but defer schema changes to idea 7.
- Mock-tunnel scripting API surface — builder vs declarative struct vs YAML. Mechanical.
- Exact regex strings for OpenVPN log-poll success/failure detection — preserve from existing code.
