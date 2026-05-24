---
date: 2026-05-24
topic: tunnel-trait-enum-dispatch
---

# `Tunnel` Trait + `enum_dispatch`

## Summary

Define a single `Tunnel` trait with five methods (`up`, `down`, `status`, `parse_profile`, `capabilities`) and dispatch over a closed `enum TunnelKind { WireGuard(WgTunnel), OpenVpn(OvpnTunnel), Mock(MockTunnel) }` via the `enum_dispatch` macro. Each impl lives in its own crate per idea 2 (`vortix-protocol-wireguard`, `vortix-protocol-openvpn`). The engine routes `profile.protocol → TunnelKind` once and never branches on protocol again, replacing today's per-protocol match-arm sprawl in `src/engine/connection.rs`. Both currently-supported protocols (WireGuard via `wg-quick`, OpenVPN via the `openvpn` subprocess) migrate in this PR; IKEv2 and userspace-WireGuard are deferred. Each impl consumes idea 1's `CommandRunner` for I/O, emits idea 3's `EngineEvent`s on transitions, and declares its capabilities so the engine can negotiate features (split tunnel, IPv6, MTU) before any side effect.

---

## Problem Frame

`src/engine/connection.rs` (669 lines) contains the connection lifecycle for *both* supported protocols. The protocol decision is a large match arm: WireGuard runs `wg-quick up <iface>` with kill-pid bookkeeping; OpenVPN spawns `openvpn --daemon` with auth-file handling, PID-file tracking, and log-polling for the connection state. The two paths share almost nothing in structure but live side-by-side, sharing only the same surrounding state-mutation code.

This wedded-together shape has three costs that compound on the v1.0 ROADMAP.

**Adding IKEv2 is a refactor, not a feature.** v1.0 ROADMAP commits to "multi-protocol (IKEv2/IPSec + WireGuard + OpenVPN)." With the current shape, the third protocol means a third match arm with a third set of side effects sprinkled through the connection lifecycle, alongside whatever auth/PID/log scaffolding it needs. Each new protocol multiplies the size of the per-protocol code surface in the central engine file. Testing each protocol requires hand-mocking subprocess interactions because there's no protocol-abstracting seam.

**Userspace WireGuard is unreachable.** Windows support (v1.0) almost certainly needs userspace WG (`wireguard-go`, BoringTun, or Cloudflare's `boringtun` Rust crate) because `wg-quick` is Linux/macOS-only. Locked-down environments (corporate machines without root, Docker minimal images without WG kernel modules) also benefit. With the current monolithic-engine shape, "two ways to run WireGuard" means two parallel code paths under one match arm — unmaintainable.

**Capability negotiation cannot exist.** Split tunneling (v1.0) needs to know whether the active protocol on the active platform supports it. IPv6 leak prevention needs to know whether the tunnel even carries IPv6. MTU tuning needs to know whether the protocol allows configuration. Today these are scattered conditionals inferred at call sites (`if protocol == Protocol::WireGuard && cfg!(target_os = "linux") …`). With no typed capability surface, the TUI cannot grey out unsupported features and the engine cannot fail loud before partial execution.

A single `Tunnel` trait fixes all three by making protocol an *adapter* concern, not a control-flow concern in the engine. The engine knows nothing about WireGuard or OpenVPN beyond `profile.protocol → TunnelKind`. The trait's capability surface gives the engine a typed view of what each protocol can do on each platform. Adding a third protocol becomes a fourth crate; adding userspace WireGuard becomes a fifth `TunnelKind` variant. Neither change touches the engine's lifecycle code.

---

## Actors

- A1. **Contributor adding IKEv2 support (future)** — wants to write one crate (`vortix-protocol-ikev2`) implementing one trait, with no other files touched outside the workspace's enum-dispatch wiring.
- A2. **Contributor implementing split tunneling (v1.0)** — needs to query each tunnel's capability surface before deciding whether to engage; needs failure events when an unsupported combination is requested.
- A3. **Contributor writing a test for the engine** — wants `TunnelKind::Mock(MockTunnel)` to script success/failure scenarios without setting up real `wg`/`openvpn`.
- A4. **End user running the connect path** — observes no behavior change in v1 of this refactor. Same `wg-quick` and `openvpn` subprocesses, same connection latency, same telemetry. Only the internal organization changes.
- A5. **Future userspace-WireGuard adapter author** — wants to add `TunnelKind::WireGuardUserspace(WgUserspaceTunnel)` as a sibling variant, sharing zero code with the kernel impl, in its own future crate.
- A6. **Engine (idea 3's FSM)** — calls `tunnel.up()` during `Connecting`, `tunnel.down()` during `Disconnecting`, `tunnel.status()` during periodic ticks. Routes by `profile.protocol → TunnelKind` via the enum-dispatch.

---

## Key Flows

- F1. **Engine connects via WireGuard**
  - **Trigger:** FSM is in `Connecting`; `profile.protocol == Protocol::WireGuard`.
  - **Actors:** A6
  - **Steps:**
    1. Engine looks up the profile, constructs `TunnelKind::WireGuard(wg_tunnel)`.
    2. Engine calls `tunnel.up(&profile, &platform, &runner).await`.
    3. `WgTunnel::up` invokes the `CommandRunner` to run `wg-quick up <iface>`, parses the result, returns `Ok(TunnelHandle { profile_id, interface_name, pid: None, started_at, kind: WireGuard })` or a typed error.
    4. Engine emits `TunnelUp { handle }` event; transitions FSM to `Connected`.
  - **Outcome:** Connection up; same observable behavior as today.
  - **Covered by:** R1, R2, R5, R6, R8

- F2. **Engine connects via OpenVPN**
  - **Trigger:** FSM is in `Connecting`; `profile.protocol == Protocol::OpenVPN`.
  - **Actors:** A6
  - **Steps:**
    1. Engine looks up the profile, constructs `TunnelKind::OpenVpn(ovpn_tunnel)`.
    2. Engine calls `tunnel.up(...)`.
    3. `OvpnTunnel::up` writes auth file if needed, spawns `openvpn --daemon` via `CommandRunner`, polls the OpenVPN log for connection success (today's polling logic, just relocated), returns `Ok(TunnelHandle { profile_id, interface_name, pid: Some(pid), started_at, kind: OpenVpn })`.
    4. Engine emits `TunnelUp { handle }`; transitions FSM to `Connected`.
  - **Outcome:** Connection up; same observable behavior as today, log-polling and auth-file lifecycle preserved.
  - **Covered by:** R1, R2, R5, R6, R8

- F3. **Capability-gated feature attempt**
  - **Trigger:** User runs `vortix split-tunnel add 192.168.1.0/24` against an active connection.
  - **Actors:** A2, A4
  - **Steps:**
    1. Engine reads the active `TunnelKind`'s `capabilities()` (cached at connect time on the handle).
    2. `caps.supports_split_tunnel` is `false` for v1 of both protocols.
    3. Engine returns `Err(EngineError::CapabilityUnsupported { capability: "split_tunnel", protocol: "wireguard", platform: "macos" })` without invoking any platform op.
    4. CLI's JSON envelope serializes the error; `next_actions` includes `"see ROADMAP v1.0 for split tunneling status"`.
  - **Outcome:** User gets a fast, clear, structured error. TUI greys out split-tunnel controls when an unsupporting tunnel is active.
  - **Covered by:** R9, R10

- F4. **Test exercising connect failure**
  - **Trigger:** Contributor adds `engine::tests::wireguard_address_in_use_failure`.
  - **Actors:** A3
  - **Steps:**
    1. Test constructs an engine with `TunnelKind::Mock(MockTunnel::with_script(...))` where the script returns `Err(TunnelError::HandshakeFailed("Address already in use"))`.
    2. Test calls `engine_handle.execute(EngineCommand::Connect { profile_id }).await`.
    3. FSM transitions through `Connecting → Disconnected { last_failure: Some(...) }`. The journal records the failure.
    4. Test asserts on the recorded events.
  - **Outcome:** Test runs in under 50ms with no real `wg`, no root, no network. Failure modes from real-world bug reports become reproducible scenarios.
  - **Covered by:** R7, R11

---

## Requirements

**The trait**

- R1. Define `trait Tunnel` in `vortix-core::ports::tunnel` with exactly five methods:
  - `async fn up(&mut self, profile: &Profile, plat: &Platform, runner: &CommandRunner) -> Result<TunnelHandle, TunnelError>`
  - `async fn down(&mut self, handle: TunnelHandle, plat: &Platform, runner: &CommandRunner) -> Result<(), TunnelError>`
  - `async fn status(&self, handle: &TunnelHandle, runner: &CommandRunner) -> Result<TunnelStatus, TunnelError>`
  - `fn parse_profile(&self, raw: &[u8]) -> Result<ParsedProfile, ParseError>`
  - `fn capabilities(&self) -> TunnelCapabilities`
- R2. The trait is non-`dyn`-compatible by construction (native AFIT). Dispatch is via an `enum_dispatch`-driven `enum TunnelKind { WireGuard(WgTunnel), OpenVpn(OvpnTunnel), Mock(MockTunnel) }` that implements the trait via macro-generated match arms.
- R3. The enum is `#[non_exhaustive]` from day one. Adding a new variant (`Ikev2`, `WireGuardUserspace`, future protocols) is additive; external consumers that pattern-match must include a `_` arm.

**The handle and status types**

- R4. `TunnelHandle` is a struct with: `profile_id: ProfileId`, `interface_name: String`, `pid: Option<u32>`, `started_at: Instant`, `kind: TunnelKindTag`. `TunnelKindTag` is a unit-only enum (no payloads) used for cheap "what protocol is this?" checks. The handle is `Clone + Send + Sync`.
- R5. `TunnelStatus` carries: `peers_or_state: Box<dyn ProtocolStatus>` (per-protocol opaque), `bytes_rx: u64`, `bytes_tx: u64`, `last_handshake: Option<SystemTime>` (None for OpenVPN), `observed_at: Instant`. The opaque protocol-status field is queried for protocol-specific introspection (WG peer list, OpenVPN route table); a small unified surface is sufficient for the engine.

**Capabilities**

- R6. `TunnelCapabilities` is a struct with: `supports_split_tunnel: bool`, `supports_ipv6: bool`, `mtu_configurable: bool`, `supports_reconnect_without_disconnect: bool`, `requires_root: bool`, `userspace: bool`. All `bool` fields; future additions are append-only.
- R7. Each `TunnelKind` returns a constant `TunnelCapabilities` value from `capabilities()` for v1 (no per-instance variation). For v1 of this PR: WireGuard returns `{ supports_split_tunnel: false, supports_ipv6: true, mtu_configurable: true, supports_reconnect_without_disconnect: true, requires_root: true, userspace: false }`. OpenVPN returns `{ supports_split_tunnel: false, supports_ipv6: true, mtu_configurable: false, supports_reconnect_without_disconnect: false, requires_root: true, userspace: false }`. Numbers are illustrative; planner verifies against actual behavior.

**Profile parsing**

- R8. The unified `Profile` type (already exists at `src/state/profile.rs` as `VpnProfile`; migrates to `vortix-core`) carries: `id: ProfileId` (SHA-256 of WG pubkey or OpenVPN cert), `display_name: String`, `protocol: Protocol`, `parsed: ParsedProfile`. `ParsedProfile` is a sealed-via-`Box<dyn>` per-protocol opaque struct — engine treats as opaque except via specific `Profile`-level accessors.
- R9. Each `Tunnel` impl owns its own parser. `WgTunnel::parse_profile` parses `.conf` files; `OvpnTunnel::parse_profile` parses `.ovpn` files. The engine never branches on profile format.

**Engine routing**

- R10. The engine's connect path is `profile.protocol → TunnelKind` (a small match in one place, the engine-tunnel-routing module). No engine code outside that one routing function branches on `profile.protocol`. After construction, the engine holds a `TunnelKind` and never re-decodes the protocol.

**Capability negotiation**

- R11. Before invoking any side effect on the tunnel, the engine validates requested-feature × capability. Mismatch returns `EngineError::CapabilityUnsupported { capability, protocol, platform }` and emits a `CapabilityCheckFailed` event into the journal. The TUI subscribes to the broadcast and greys out controls whose capability is unsupported on the active tunnel.

**OpenVPN migration**

- R12. The existing OpenVPN code in `src/engine/connection.rs` (auth-file handling, PID-file lifecycle, log-polling for connection success) moves into `crates/vortix-protocol-openvpn/src/lib.rs` behind `OvpnTunnel::up` / `::status` / `::down`. Behavior is preserved: same log-poll cadence, same auth-file ownership-fix logic, same error-tail extraction.
- R13. After this PR, no `openvpn` subprocess is invoked outside `crates/vortix-protocol-openvpn/`. Verified by `rg 'openvpn' crates/ -t rust` returning matches only inside that crate's module.

**WireGuard migration**

- R14. The existing WireGuard code in `src/engine/connection.rs` (`wg-quick up/down`, `wg show` parsing, PID-kill bookkeeping) moves into `crates/vortix-protocol-wireguard/src/lib.rs`. Behavior is preserved.
- R15. After this PR, no `wg`/`wg-quick` subprocess is invoked outside `crates/vortix-protocol-wireguard/`. Verified similarly.

**MockTunnel for testing**

- R16. `MockTunnel` is a scriptable test fixture. Tests construct a `MockTunnel` with: ordered list of `(method, scripted_outcome)` expectations, optional handshake-delay simulation, optional periodic-status drift simulation. Returns scripted outcomes in order; panics with a clear diagnostic on unmatched calls.
- R17. `MockTunnel::with_default_success()` is a convenience constructor producing a tunnel that succeeds at `up`/`down` and reports a healthy `status` — sufficient for the majority of engine tests.

**Crate organization** (consistent with idea 2)

- R18. `vortix-protocol-wireguard` and `vortix-protocol-openvpn` are day-one workspace members; both depend on `vortix-core` (for the trait, types, errors) and `vortix-process` (for `CommandRunner`) and nothing else from the workspace. Neither has TUI or platform-internal deps.
- R19. `vortix-protocol-ikev2` is **not** created in this PR. No stub crate.
- R20. The `Mock(MockTunnel)` variant lives in `vortix-core::ports::tunnel::mock` (NOT in a separate `vortix-protocol-mock` crate) because it's used by tests across many crates; co-locating it with the trait avoids cyclic-dep gymnastics.

---

## Acceptance Examples

- AE1. **Covers R1, R2.** When a contributor adds a new protocol crate (`vortix-protocol-strongswan`) implementing the `Tunnel` trait, then the only files outside that crate that need to change are: workspace `Cargo.toml` (add the member), `vortix-core::ports::tunnel` (add the enum variant), and one engine routing function (add the match arm for `Protocol::Ikev2 → TunnelKind::StrongSwan`). No engine lifecycle code is touched.

- AE2. **Covers R3.** When `cargo build` compiles against an external crate that pattern-matches `TunnelKind` exhaustively, then the build fails with a `#[non_exhaustive]` error directing the consumer to add a wildcard arm.

- AE3. **Covers R11.** Given an engine in `Connected` state with `TunnelKind::WireGuard` and `capabilities().supports_split_tunnel == false`, when `engine_handle.execute(EngineCommand::SplitTunnelAdd { … }).await` is called, then the result is `Err(EngineError::CapabilityUnsupported { capability: "split_tunnel", … })`, a `CapabilityCheckFailed` event is journaled, and no platform op is invoked (verified by no `MockRunner` calls).

- AE4. **Covers R13, R15.** After this PR, `rg 'Command::new\("(wg|wg-quick|openvpn)"' crates/` returns matches only inside `crates/vortix-protocol-wireguard/` and `crates/vortix-protocol-openvpn/`. No protocol-specific subprocess names appear in the engine or anywhere else.

- AE5. **Covers R12, R14.** End-to-end: a user runs `vortix up <wireguard-profile>` and `vortix up <openvpn-profile>` after this PR, then observes the same connection latency, same telemetry, same kill-switch behavior, same log output as before. The migration is observably behavior-neutral.

- AE6. **Covers R16.** When a test constructs `MockTunnel::with_script([(Method::Up, Err(TunnelError::HandshakeFailed))])` and feeds it through the engine, then the FSM transitions `Connecting → Disconnected { last_failure: Some(HandshakeFailed) }`, the journal records the failure, and the test passes in under 100ms wall-clock without root or real `wg`/`openvpn`.

- AE7. **Covers R8, R9.** When the engine invokes `wg_tunnel.parse_profile(corp_wg_bytes)`, then the result is `Ok(ParsedProfile)` carrying a WireGuard-specific opaque body; the engine code path that consumed it does not need to know the body's internal shape.

- AE8. **Covers R10.** When the engine connects, then a `grep 'match profile.protocol'` over the engine crates returns exactly one match (the single routing function in the engine-tunnel-routing module). No engine code outside that function branches on protocol.

---

## Success Criteria

- A future contributor adding IKEv2 support touches at most three files outside `crates/vortix-protocol-ikev2/`: the workspace `Cargo.toml`, the `TunnelKind` enum, and one engine routing function. The IKEv2 implementation itself is self-contained.
- A future contributor adding userspace WireGuard (`boringtun`-backed) adds one new `TunnelKind` variant; the engine routing function gains one match arm (`Profile::with_userspace_flag → TunnelKind::WireGuardUserspace`). Zero changes to `WgTunnel` or to `OvpnTunnel`.
- Split tunneling (v1.0) lands as TUI controls that are greyed-out when the active `TunnelKind.capabilities().supports_split_tunnel == false`, and as engine-side validation that fast-fails the request with a typed error before any side effect.
- After this PR, every connect-path bug becomes reproducible in a CI test using `MockTunnel` + idea 1's `MockRunner` + idea 3's FSM — no root, no real binaries.
- `src/engine/connection.rs` (669 lines today) is materially smaller after this refactor; most of its content has relocated to the per-protocol crates.

---

## Scope Boundaries

- **IKEv2 / IPSec support** is out of scope. No `vortix-protocol-ikev2` crate is created in this PR. Adding IKEv2 later involves one new crate + one new enum variant + one new match arm in the engine's routing function. The trait's design accommodates it without further changes.
- **Userspace WireGuard (`boringtun`, `wireguard-go`)** is out of scope. v1 of `vortix-protocol-wireguard` is kernel-`wg-quick` only. Userspace lands later as a sibling variant when Windows-native WG or locked-down environments need it.
- **Split tunneling implementation** is out of scope. The capability *flag* is part of `TunnelCapabilities`; the actual split-tunnel logic lives in idea 6's platform ports and a separate v1.0 ROADMAP PR.
- **MTU tuning UI / config** is out of scope. The `mtu_configurable` capability flag is declared; runtime MTU configuration lands when there's user pressure.
- **Profile import format expansion** is out of scope. Each protocol's `parse_profile` accepts the same raw format it accepts today (`.conf` for WG, `.ovpn` for OpenVPN). NetworkManager / Tunnelblick / iOS `.mobileconfig` importers are separate work.
- **`Tunnel::reload`** (live config reload without disconnect) is not in the trait. Reconnect handles it. The capability flag `supports_reconnect_without_disconnect` signals to the engine whether reconnect involves a brief tunnel-down period.
- **`Tunnel::metrics`** (rich per-tick metrics) is not in the trait. The telemetry actor (per idea 3) periodically calls `status` and derives metrics from `TunnelStatus`.
- **Per-protocol diagnostic CLI commands** (`vortix wg show`, `vortix ovpn log`) are out of scope. Future feature; not part of this refactor.
- **Behavior changes** of any kind are out of scope. This PR is a pure refactor: same subprocess invocations, same auth-file handling, same log-polling cadence, same error messages. The only observable change is internal organization.

---

## Key Decisions

- **Five methods on the trait: `up`, `down`, `status`, `parse_profile`, `capabilities`.** No `reload`, no `metrics`, no `prepare`, no `validate_profile`. Reconnect covers reload; telemetry derives metrics; `parse_profile` covers validation by returning a typed error. YAGNI.
- **`enum_dispatch` over a `#[non_exhaustive]` closed enum**, mirroring idea 1's `CommandRunner` and idea 4's `EngineHandle`. Static dispatch, AFIT-compatible, no `Box<dyn>` allocations on the hot path.
- **Per-protocol opaque `ParsedProfile`.** Each protocol owns its config schema. The engine sees only `id`, `display_name`, `protocol_kind`. Speculative unified-config schemas always lose to per-protocol realities.
- **OpenVPN migrates in this PR (not deferred).** OpenVPN is real working code today, not a future-stub. Leaving it as a match-arm while WireGuard moves to the trait would be worse than today.
- **IKEv2 is deferred entirely — no stub crate.** Empty placeholder crates are roadmap performance, not commitment. The architecture supports an additive third protocol cleanly when v1.0 ROADMAP work begins.
- **Userspace WireGuard is deferred.** `vortix-protocol-wireguard` ships kernel-only via `wg-quick`. A second variant lands when there's pressure (Windows-native, locked-down environments).
- **`MockTunnel` lives in `vortix-core::ports::tunnel::mock`**, not in a separate crate. Tests across many crates need it; co-locating with the trait avoids cyclic-dep issues.
- **Behavior-neutral refactor.** Zero observable user-facing changes. Same subprocess invocations, same connection latency, same telemetry, same error messages. Internal organization changes only.

---

## Dependencies / Assumptions

- **Idea 1 (`CommandRunner`) lands before this PR.** Each `Tunnel` impl consumes the runner; without it, the impls would need their own subprocess abstraction.
- **Idea 2 (workspace split) lands before this PR.** Each protocol crate is a workspace member.
- **Idea 3 (FSM + journal + EngineHandle) lands before this PR** (or alongside, as a combined PR). The FSM owns the protocol-routing function; events emitted by tunnel transitions land on the FSM's broadcast channel.
- **Idea 6 (capability ports) is a forward dependency** — the `Tunnel::up` signature takes `&Platform`, but the `Platform` type's exact shape is defined in idea 6. This PR can either land first with a minimal `Platform` placeholder, or wait for idea 6. Recommend the latter; idea 6 is brainstormed next.
- **The `enum_dispatch` crate** plays cleanly with native AFIT. The planner verifies with a sanity test; if it doesn't, a hand-coded match-arm dispatch is the fallback (mechanical).
- **`Box<dyn ProtocolStatus>` in `TunnelStatus`** adds one heap allocation per `status()` call. Per-tick telemetry calls `status` at ~10s cadence; the allocation cost is negligible.
- **OpenVPN's log-polling cadence and auth-file ownership-fix logic** preserve exact current behavior. Verified by running existing manual-test workflows pre- and post-refactor.

---

## Outstanding Questions

### Resolve Before Planning

(None — all material decisions resolved in the synthesis.)

### Deferred to Planning

- [Affects R4][Technical] Exact `TunnelHandle` field set, including whether `pid` should be `Option<NonZeroU32>` for clarity that `0` is not a valid PID. Mechanical; planner picks.
- [Affects R5][Technical] Shape of the `Box<dyn ProtocolStatus>` field — whether the trait has methods like `as_wireguard()` / `as_openvpn()` for downcasting, or whether per-protocol introspection goes through a sibling protocol-specific API. Mechanical.
- [Affects R7][Technical] Verifying the exact capability flag values for WireGuard and OpenVPN as they exist today — `supports_reconnect_without_disconnect` for OpenVPN is unclear without testing.
- [Affects R8][Technical] Whether the existing `VpnProfile` type at `src/state/profile.rs` is migrated as-is to `vortix-core::profile` or restructured to add the `id: ProfileId` field. Almost certainly the latter; planner picks the migration steps.
- [Affects R16][Technical] Test-ergonomic surface of `MockTunnel`'s scripting API — fluent builder vs `from_yaml(...)` vs a procedural macro. Mechanical preference.
- [Affects R12][Technical] Whether the existing `core/scanner.rs` parses `wg show` output today; if so, that parsing logic relocates to `vortix-protocol-wireguard` as part of `WgTunnel::status` implementation. Mapping detail.
