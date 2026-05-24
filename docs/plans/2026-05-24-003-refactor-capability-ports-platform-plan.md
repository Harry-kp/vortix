---
date: 2026-05-24
title: "refactor: Promote platform traits to capability ports in vortix-core"
status: active
type: refactor
origin: docs/brainstorms/2026-05-24-capability-ports-platform-requirements.md
prerequisite: docs/plans/2026-05-24-002-feat-commandrunner-port-plan.md
---

# refactor: Promote platform traits to capability ports in vortix-core

## Summary

Promote vortix's existing informal `Firewall` / `NetworkStatsProvider` traits (today at `crates/vortix/src/platform.rs`, transitionally landed there by plan #001) into a first-class capability-port system in `vortix-core::ports::*` with five day-one ports: `Killswitch` (renamed from `Firewall`), `DnsResolver`, `Interface`, `NetworkStats`, `RouteTable`. Each port is a trait in `vortix-core`; per-OS impls live in `vortix-platform-{macos,linux}` (already crates per plan #001, already routed through `CommandRunner` per plan #002). An aggregate `struct Platform` carrying one field per port (each an `enum_dispatch` enum over OS variants) is constructed once at startup; the rest of the codebase consumes the aggregate without `cfg(target_os)` branching. **Resolves the transitional two-way path dependency** between the platform crates and the binary crate that plan #001 documented as cleanup-deferred — `Firewall`, `KillSwitchError`, and related types move from `crates/vortix/src/platform.rs` and `crates/vortix/src/core/killswitch.rs` into `vortix-core`; platform crates lose their dependency on `vortix`. Pure structural refactor with zero behavior change.

---

## Problem Frame

After plans #001 and #002 land:
- The workspace has eight crates; platform-OS code lives in `vortix-platform-{macos,linux}`.
- All subprocess invocations flow through `CommandRunner` (idea 1).
- A **transitional two-way path dep** exists: `vortix-platform-{macos,linux}` depend on `vortix` (for `Firewall`, `KillSwitchError`, `LogLevel`, constants); `vortix` depends on the platform crates (cfg-gated). This is documented as "cleanup-deferred" in plan #001's U3.
- The `Firewall` trait and `KillSwitchError`/`Result` types live at `crates/vortix/src/platform.rs` and `crates/vortix/src/core/killswitch.rs` — wrong home for shared port types.
- DNS, Interface, RouteTable, NetworkStats lack trait abstractions today (only `Firewall` and `NetworkStatsProvider` were promoted to traits historically).

This plan finishes the capability-port story by:
1. **Moving trait definitions** into `vortix-core::ports::*` (their natural home).
2. **Adding the missing port traits** (`DnsResolver`, `Interface`, `RouteTable` — `NetworkStats` and `Killswitch` already exist as informal traits and just relocate).
3. **Reorganizing per-OS impls** under the capability-port shape (per-OS files implementing the relevant trait).
4. **Building the aggregate `Platform` struct** with `enum_dispatch`-driven enum carriers.
5. **Removing the cyclic dep** by making the platform crates depend only on `vortix-core` and `vortix-process` (not `vortix`).

The downstream payoff (v1.0 ROADMAP):
- Windows support becomes "implement five traits in one new crate"
- Split tunneling becomes "add one new port"
- IPv6 leak protection becomes "extend the existing ports' capability methods"

---

## System-Wide Impact

- **End users:** Zero observable change. Same subprocess invocations (same `iptables` / `pfctl` / `scutil` / `ip` / `route` commands), same backend selection logic.
- **Contributors implementing v1.0 Windows support:** Touch zero code in `vortix-core::engine`, `vortix-protocol-*`, `vortix-cli`, `vortix-tui`. Add one crate (`vortix-platform-windows`) with five impl structs and one new variant per port enum.
- **Engine and tunnel impls:** Take `&Platform` (the aggregate) by reference; access ports via `platform.killswitch.engage(config, &runner).await`. No `cfg(target_os)` anywhere outside `crates/vortix-platform-*` and the single `Platform::detect_current()` constructor.
- **Dependency graph:** `vortix-platform-{macos,linux}` no longer depend on `vortix` (cycle removed). They depend on `vortix-core` (for trait definitions) and `vortix-process` (for `CommandRunner`).
- **CI:** `cargo build --workspace` still passes; the `rg 'cfg(target_os)' crates/vortix-core/ crates/vortix-cli/ crates/vortix-tui/ crates/vortix-process/` check from the brainstorm's R12 enforced as a CI lint (via `xtask check-platform-leak` — added in this PR).

---

## Key Technical Decisions

- **Five day-one ports: `Killswitch`, `DnsResolver`, `Interface`, `NetworkStats`, `RouteTable`.** Exactly the set with concrete code today. The deferred three (`SplitTunnel`, `TunDevice`, `PrivilegeEscalation`) wait for their driving features (v1.0 split tunneling, idea 5's userspace WG, idea 4 Phase B's daemon). (Origin: brainstorm R1.)
- **`Killswitch` is the new name for `Firewall`.** Clarifies intent: vortix's use of host-firewall infrastructure is specifically as a killswitch. The existing `Firewall` trait at `crates/vortix/src/platform.rs` becomes `Killswitch` at `crates/vortix-core/src/ports/killswitch.rs`. (Origin: brainstorm Key Decisions.)
- **Aggregate `struct Platform` with per-field `enum_dispatch` enums.** Same closed-set pattern as `CommandRunner`, future `TunnelKind`, future `EngineHandle`. `struct Platform { killswitch: KillswitchKind, dns: DnsResolverKind, interface: InterfaceKind, network_stats: NetworkStatsKind, route_table: RouteTableKind }`. AFIT-compatible, no `Arc<dyn Trait>` heap allocations. (Origin: brainstorm R4, R5.)
- **`Platform::detect_current()` is the only place that branches on OS in `vortix-core`.** Verified by `xtask check-platform-leak` (added in this PR as a CI gate). (Origin: brainstorm R12.)
- **Runtime backend selection preserved unchanged.** `IptablesFirewall::detect_backend()` (existing in `crates/vortix-platform-linux/src/firewall.rs` after plan #001) keeps its iptables-first preference. Equivalent runtime probing for DNS resolver selection (`systemd-resolved` → `resolvconf` fallback) added if not already present. (Origin: brainstorm R7.)
- **The existing Linux firewall preference order (`iptables` over `nft`) is preserved verbatim.** Re-examining the preference is a follow-up concern flagged in the brainstorm but not in scope. (Origin: brainstorm Key Decisions.)
- **No Windows crate today.** Matches idea 5's IKEv2 deferral and plan #001's no-stub-crates policy. The architecture supports an additive Windows port. (Origin: brainstorm R10 + Scope Boundaries.)
- **No explicit `*Capabilities` structs for the five ports today.** Booleans on impl structs (or implicit in the trait method set) suffice. Explicit capability structs land with the feature that needs them (e.g., `SplitTunnel` will probably need one). (Origin: brainstorm Scope Boundaries.)
- **`crates/vortix/src/core/killswitch.rs` business logic relocates to `crates/vortix-core/src/killswitch/` (new module).** Logic/surface split preserved: business decisions (when to engage, allow-rules to apply, recovery on crash) live in `vortix-core::killswitch`; OS-specific commands live in `vortix-platform-*::firewall_*.rs`. (Origin: brainstorm R9.)
- **Trait method shape: each method takes `&CommandRunner` as the last argument** (per plan #002's `CommandRunner`). All trait methods are `async`. Matches idea 5's planned `Tunnel::up(profile, plat, runner)` signature.
- **Trait sealing.** Use the `#[non_exhaustive]` attribute on each port trait combined with a sealed-supertrait pattern (`pub trait Killswitch: SealedKillswitch`) so new methods can be added without breaking external impls. (Origin: brainstorm R3; mechanism deferred to ce-work.)
- **Migration is big-bang.** All five ports + platform impl reorganization + cycle removal in one PR. Behavior-neutral. (Origin: brainstorm R10, R11.)

---

## Implementation Units

### U1. Move `Killswitch` (renamed `Firewall`) trait + error types into `vortix-core::ports::killswitch`

**Goal:** Establish the first capability port. Resolves the two-way path dep for the killswitch concern.

**Requirements:** R1, R3, R9

**Dependencies:** Plan #002 complete (`vortix-core::ports::process` exists, `CommandRunner` is the runner type).

**Files (new):**
- `crates/vortix-core/src/ports/killswitch.rs`: the `Killswitch` trait, `KillswitchConfig`, `KillswitchError`, `KillswitchStatus`.
- `crates/vortix-core/src/killswitch/mod.rs`: the business-logic module (relocated from `crates/vortix/src/core/killswitch.rs`).

**Files (moves):**
- `crates/vortix/src/core/killswitch.rs` → `crates/vortix-core/src/killswitch/state.rs` (state-management business logic; the `KillSwitchState` type, allow-rules, recovery-on-crash logic).
- `crates/vortix/src/state/killswitch.rs` → `crates/vortix-core/src/state/killswitch.rs` (the state type for the FSM, used by idea 3).
- Existing `Firewall` trait at `crates/vortix/src/platform.rs` → `crates/vortix-core/src/ports/killswitch.rs` as `Killswitch` (renamed).
- Existing `KillSwitchError` / `Result` from `crates/vortix/src/core/killswitch.rs` → `crates/vortix-core/src/ports/killswitch.rs` as `KillswitchError` and a top-level `Result` alias.

**Files (modifications):**
- `crates/vortix-platform-macos/src/firewall.rs`: rename struct from `PfFirewall` to `PfctlKillswitch` (or `MacosPfKillswitch`); change `impl Firewall for PfFirewall` → `impl Killswitch for PfctlKillswitch`. Update `use vortix::platform::Firewall` → `use vortix_core::ports::killswitch::Killswitch`. The actual `pfctl` subprocess calls (through `runner` per plan #002) are unchanged.
- `crates/vortix-platform-linux/src/firewall.rs`: rename `IptablesFirewall` to `LinuxFirewallKillswitch` (or keep the name; the brainstorm doesn't mandate); same trait-impl swap. The `detect_backend()` runtime probe stays.
- `crates/vortix-platform-{macos,linux}/Cargo.toml`: replace `vortix = { path = "../vortix" }` with `vortix-core = { path = "../vortix-core" }, vortix-process = { path = "../vortix-process" }`. The two-way path dep is broken for killswitch.
- `crates/vortix/src/platform.rs`: remove the `Firewall` trait definition (now in core). Remove `KillSwitchError` reference. Keep the cfg-gated `pub use vortix_platform_macos as macos;` etc., re-exports for now (cleaned up further in later units).
- `crates/vortix/src/core/killswitch.rs`: gut to a re-export shim `pub use vortix_core::killswitch::*;` for backwards-compat during migration; remove at the end of the PR.

**Approach:**
- The relocation is a `git mv` with content adjustments to align with the new module structure. The actual killswitch logic (insert this rule, then this rule, restore on cleanup) does not change.
- Naming: prefer descriptive impl names (`PfctlKillswitch`, `LinuxFirewallKillswitch`) over OS-tagged names (`MacosKillswitch`) so the implementation mechanism is visible. The enum variant carries the OS tag.

**Patterns to follow:**
- Existing `Firewall` trait at `crates/vortix/src/platform.rs` (informal trait with `engage`/`disengage`/`is_engaged`/`status` methods) — the new `Killswitch` trait keeps the same method shape, just takes `&CommandRunner` per-call.
- `thiserror` for `KillswitchError` (matches `ProcessError` from plan #002).

**Test scenarios:**
- `crates/vortix-platform-linux/tests/killswitch.rs`:
  - **Happy path:** MockRunner scripts `which iptables` → exit 0, `iptables -L ...` → success. Construct `LinuxFirewallKillswitch::new(&runner).await`. Assert backend detected as iptables.
  - **Edge case — runtime fallback:** MockRunner scripts `which iptables` → exit 1, `which nft` → exit 0. Assert backend detected as nftables.
  - **Error path — no firewall:** Both `which` calls exit 1. Assert `Err(KillswitchError::NoBackendAvailable)`.
  - **Engage happy path:** Backend is iptables (mocked). Mock all `iptables` rule-insertion calls succeed. Call `killswitch.engage(config, &runner).await`. Assert ok.
- `crates/vortix-platform-macos/tests/killswitch.rs`:
  - **Happy path:** MockRunner scripts all `pfctl` commands → success. Call `engage`. Assert ok.

**Verification:** `vortix-platform-{macos,linux}` no longer depend on `vortix` (verify `cargo tree -p vortix-platform-linux` shows no `vortix` dep). The trait lives in `vortix-core::ports::killswitch`.

---

### U2. Define `DnsResolver`, `Interface`, `NetworkStats`, `RouteTable` ports + impl moves

**Goal:** Add the remaining four port traits and relocate their existing impls.

**Requirements:** R1, R2, R3

**Dependencies:** U1

**Files (new):**
- `crates/vortix-core/src/ports/dns.rs`: `DnsResolver` trait + `DnsConfig`, `DnsResolverError`.
- `crates/vortix-core/src/ports/interface.rs`: `Interface` trait + `InterfaceInfo`, `InterfaceError`.
- `crates/vortix-core/src/ports/network_stats.rs`: `NetworkStats` trait + `BytesCounter`, `NetworkStatsError`. (Promotes the existing informal `NetworkStatsProvider`.)
- `crates/vortix-core/src/ports/route_table.rs`: `RouteTable` trait + `Route`, `RouteTableError`.

**Files (modifications inside platform crates):**
- `crates/vortix-platform-macos/src/dns.rs` (the existing `scutil`/`networksetup` code): impl the `DnsResolver` trait. Rename struct to `ScutilDnsResolver` or `MacosDns`.
- `crates/vortix-platform-macos/src/interface.rs`: impl `Interface`. Rename to `MacosInterface`.
- `crates/vortix-platform-macos/src/network.rs` (the existing `netstat -ib` code): impl `NetworkStats`. Rename to `NetstatStats` or `MacosNetworkStats`.
- New: `crates/vortix-platform-macos/src/route_table.rs`: impl `RouteTable` via the `route` command. Code may already exist scattered in `crates/vortix/src/core/network_monitor.rs` or `core/scanner.rs` — relocate here.
- Equivalent for `crates/vortix-platform-linux/` (impls of all four ports).
- Update each platform crate's `Cargo.toml` to depend only on `vortix-core` and `vortix-process`.
- Update each platform crate's `lib.rs` to `pub use` the impl structs.

**Files (modifications to existing core code that already does DNS / interface / network monitoring):**
- `crates/vortix/src/core/network_monitor.rs`: today its `ip route show default` and `route -n get default` calls were migrated through `CommandRunner` in plan #002. Now those calls move into the platform `RouteTable` impl. The remaining business logic (polling cadence, link-state detection) stays as a consumer of the `RouteTable` and `Interface` ports.
- `crates/vortix/src/core/scanner.rs`: the scanner observes system state; pieces of it (e.g., `wg show` parsing) belong to `vortix-protocol-wireguard` per idea 5 — out of scope for this PR. The platform-level interface listing pieces stay as a consumer of the `Interface` port.

**Approach:**
- Each port trait has a small focused API:
  - `Killswitch::{engage, disengage, is_engaged, status}` (per U1)
  - `DnsResolver::{apply(servers, search_domains, runner), restore(runner), current(runner)}`
  - `Interface::{list(runner), get(name, runner), set_mtu(name, mtu, runner), get_ip(name, runner)}`
  - `NetworkStats::{get_total_bytes(runner), get_interface_bytes(name, runner)}`
  - `RouteTable::{list(runner), add(dest, gw, iface, runner), remove(dest, gw, iface, runner), default_gateway(runner)}`
- Each port carries minimal types: `Killswitch` has a `KillswitchConfig { allow_lan: bool, allow_dns: bool, allow_ipv4: bool, allow_ipv6: bool }`; `DnsConfig` has `servers: Vec<IpAddr>, search_domains: Vec<String>`. Keep them minimal — extend when a feature demands it.

**Patterns to follow:**
- The existing `NetworkStatsProvider` trait at `src/platform/mod.rs` (now in `crates/vortix/src/platform.rs` post-#001) — its `get_total_bytes() -> (u64, u64)` method is the start. Promote that method to the new `NetworkStats::get_total_bytes(runner)` async method.
- macOS uses `netstat -ib`, Linux uses `/proc/net/dev` parsing — existing code already implemented.

**Test scenarios:**
- Per-port, per-OS mock-driven tests in each platform crate's `tests/` directory.
- `crates/vortix-platform-linux/tests/dns.rs`:
  - **Happy path:** MockRunner scripts `which systemd-resolve` → exit 0 → backend = resolved. Call `apply([1.1.1.1, 8.8.8.8], [], &runner).await`. Assert success.
  - **Edge case — fallback:** `which systemd-resolve` → exit 1, `which resolvconf` → exit 0. Backend = resolvconf.
  - **Error path:** Both backends unavailable. `Err(DnsResolverError::NoBackend)`.
- `crates/vortix-platform-macos/tests/network_stats.rs`:
  - **Happy path:** MockRunner scripts `netstat -ib` → returns fixture stdout with realistic byte counts. Assert `get_total_bytes()` returns expected `(rx, tx)` tuple.

**Verification:** All four ports exist with macOS and Linux impls. Existing telemetry/network-monitor code consumes the ports instead of subprocess-direct.

---

### U3. Build the `Platform` aggregate + `enum_dispatch` carriers

**Goal:** Construct the aggregate that the engine and tunnel impls consume.

**Requirements:** R4, R5, R6

**Dependencies:** U1, U2

**Files (new):**
- `crates/vortix-core/src/platform.rs` (note: same name as the existing `crates/vortix/src/platform.rs`; the latter is gutted in U4): defines `enum KillswitchKind`, `enum DnsResolverKind`, etc., one enum per port. Each enum has `Macos(MacosImpl)` and `Linux(LinuxImpl)` variants under `cfg(target_os = "...")`. The `enum_dispatch` macro generates the trait impl for each enum.
- Define `struct Platform { killswitch: KillswitchKind, dns: DnsResolverKind, interface: InterfaceKind, network_stats: NetworkStatsKind, route_table: RouteTableKind }`. Methods: `Platform::detect_current(runner: &CommandRunner) -> Result<Self, PlatformError>`, `Platform::for_test() -> Self` (uses `Mock(...)` variants — to be added in U5).

**Files (modifications):**
- `crates/vortix-core/Cargo.toml`: add `enum_dispatch = { workspace = true }` to `[dependencies]`. Target-gated `vortix-platform-macos` (`cfg(target_os = "macos")`) and `vortix-platform-linux` (`cfg(target_os = "linux")`) deps.

**Approach:**
- `Platform::detect_current(runner)` uses `cfg!(target_os = "...")` to pick the OS, then constructs each port's impl. For Linux, the impl constructors run their backend probes (via the runner) — e.g., `LinuxFirewallKillswitch::detect(runner).await?` returns the impl with the chosen backend stored.
- The aggregate is `Clone + Send + Sync` so it can be passed by value to engine, tunnel impls, and futures.

**Patterns to follow:**
- Same `enum_dispatch` pattern as `CommandRunner` from plan #002.

**Test scenarios:**
- `crates/vortix-core/tests/platform_aggregate.rs`:
  - **Happy path:** `Platform::detect_current(&mock_runner).await` succeeds on the current OS (test mocks the backend probes). Assert all five ports are populated.
  - **Edge case — probe failure:** Mock the killswitch backend probes to all fail. Assert `Err(PlatformError::KillswitchProbeFailed)`.

**Verification:** `Platform::detect_current()` returns the right impl variants for the running OS. The aggregate compiles cleanly.

---

### U4. Remove the transitional two-way path dep in `crates/vortix`

**Goal:** Clean up the cycle that plan #001 documented as deferred.

**Requirements:** R5, R6, brainstorm Dependencies/Assumptions

**Dependencies:** U1, U2, U3

**Files (modifications):**
- `crates/vortix/src/platform.rs`: gutted. No more trait definitions, no more OS dispatch logic. Replace with a thin `pub use vortix_core::platform::Platform;` re-export for callers that referenced `vortix::platform::Platform` (deprecate the re-export with a doc note; remove in a future PR).
- `crates/vortix/src/core/killswitch.rs`: removed. Replace with a thin re-export shim `pub use vortix_core::killswitch::*;` if any callers still reference `vortix::core::killswitch::...`.
- `crates/vortix/src/lib.rs`: remove the `pub mod platform;` line (or keep the thin re-export module).
- `crates/vortix-platform-{macos,linux}/Cargo.toml`: confirm no `vortix = ...` dep. Each depends only on `vortix-core` and `vortix-process`. The reverse direction (`vortix` depends on the platform crates) stays — that's normal for a binary crate consuming libraries.

**Approach:**
- Use `cargo tree --no-default-features -p vortix-platform-linux` to verify no `vortix` in the dep tree.
- Any remaining `use vortix::*` in the platform crates fails to compile after the dep removal — the build surfaces them.

**Test scenarios:**
- *Test expectation: none — pure scaffolding cleanup; behavior covered by previous units.*
- Verification: `cargo tree -p vortix-platform-linux | grep -E '\bvortix\b' | grep -v 'vortix-core\|vortix-process'` returns no matches.
- Verification: `cargo tree -p vortix-platform-macos | grep ...` same as above.
- Verification: `cargo build --workspace` succeeds.

**Verification:** No two-way path dep. The architecture matches the brainstorm's intent.

---

### U5. Add `Mock(...)` variants to each port's enum + test fixtures

**Goal:** Make `Platform::for_test()` work end-to-end so engine and tunnel tests can construct a fake platform.

**Requirements:** R4, brainstorm Acceptance Example AE7 (Platform::for_test())

**Dependencies:** U1, U2, U3

**Files (new):**
- `crates/vortix-core/src/ports/killswitch.rs` — add `MockKillswitch` struct (or `mock` submodule) with a scriptable expectations pattern matching `MockRunner` from plan #002. Add `Mock(MockKillswitch)` variant to `KillswitchKind`.
- Equivalent for the other four ports: `MockDnsResolver`, `MockInterface`, `MockNetworkStats`, `MockRouteTable` and corresponding enum variants.
- Modify `Platform::for_test()` to return a `Platform` with all `Mock(...)` variants populated with default-success behavior.

**Files (modifications):**
- `crates/vortix-core/src/platform.rs`: implement `Platform::for_test()`.

**Approach:**
- Each `Mock*` impl follows the same builder pattern as `MockRunner`: ordered expectations, panic on mismatch, invocation log accessible via `mock.invocations()`.
- Co-located in `vortix-core` (not a separate `vortix-platform-mock` crate) per the brainstorm — avoids cyclic-dep gymnastics for tests across crates.

**Test scenarios:**
- `crates/vortix-core/tests/platform_for_test.rs`:
  - **Happy path:** Construct `Platform::for_test()`. Call `platform.killswitch.engage(default_config, &runner).await`. Assert ok. Verify `platform.killswitch.invocations()` recorded the call.
  - **Integration scenario:** Build a test fixture exercising all five ports in sequence. Assert each receives the expected call.

**Verification:** `Platform::for_test()` returns a fully mocked aggregate. Engine tests (in idea 3's PR later) consume this fixture.

---

### U6. Add `xtask check-platform-leak` CI lint

**Goal:** Enforce the brainstorm's R12 ("no `cfg(target_os)` outside `vortix-platform-*` and `Platform::detect_current`").

**Requirements:** R12

**Dependencies:** U1, U2, U3, U4

**Files (modifications):**
- `crates/xtask/src/main.rs`: add a `CheckPlatformLeak` subcommand. Walk the workspace; flag `cfg(target_os = ...)` occurrences in any file other than:
  - `crates/vortix-platform-macos/**`
  - `crates/vortix-platform-linux/**`
  - `crates/vortix-platform-windows/**` (future-proof)
  - `crates/vortix-core/src/platform.rs` (the single `detect_current` constructor)
  - Lines with an explicit `// xtask:allow-platform-cfg: <reason>` annotation.
- `.github/workflows/ci.yml`: add `cargo xtask check-platform-leak` to the lint job.

**Approach:**
- Mirror `xtask check-subprocess` structure from plan #002's U9 — use the `ignore` crate, walk the tree, regex match `cfg\(target_os\s*=`, filter allowed paths, exit 1 on violations.

**Test scenarios:**
- `crates/xtask/tests/platform_leak_check.rs`:
  - **Happy path:** Fixture with no `cfg(target_os)` outside platform crates. Exit 0.
  - **Edge case — annotated allow:** Fixture has `cfg(target_os = "linux")` with `// xtask:allow-platform-cfg: necessary platform-specific compile-time gate` on the same line. Exit 0.
  - **Error path:** Fixture has unannotated `cfg(target_os = "macos")` in `crates/vortix/src/engine/foo.rs`. Exit 1 with file:line in stderr.

**Verification:** `cargo xtask check-platform-leak` exits 0 on the post-migration workspace. Introducing a deliberate `cfg(target_os)` in any non-platform crate causes CI failure.

---

### U7. Update consumers to take `&Platform` instead of branching on OS

**Goal:** Migrate engine/, app/, cli/, core/ code to consume the aggregate.

**Requirements:** R4, R12

**Dependencies:** U1–U6

**Files (modifications):**
- `crates/vortix/src/engine/connection.rs`: methods that today branch on OS (any remaining `cfg(target_os)` blocks) become method calls on `platform.killswitch.engage(...)`, `platform.dns.apply(...)`, etc. The engine holds `platform: Platform` as a field (passed in at construction alongside the `runner` from plan #002).
- `crates/vortix/src/engine/mod.rs`: same.
- `crates/vortix/src/core/network_monitor.rs`: existing OS-branching for `ip` vs `route` commands becomes `platform.route_table.default_gateway(&runner).await`.
- `crates/vortix/src/core/scanner.rs`: parts that observe interface state become `platform.interface.list(&runner).await`.
- `crates/vortix/src/app/mod.rs`: `App::new` accepts `platform: Platform` and threads it to `VpnEngine::new(config, config_dir, runner, platform)`. `App::new_test()` constructs `Platform::for_test()`.
- `crates/vortix/src/main.rs`: constructs the platform via `Platform::detect_current(&runner).await?` after constructing the runner.

**Approach:**
- This is the largest behavior-adjacent unit. Every callsite that today says `if cfg!(target_os = "macos") { … macos-specific } else { … linux-specific }` becomes `platform.<port>.<method>()`. Most of these were already abstracted in plans #001 and #002 — this unit finishes the remaining cases.

**Test scenarios:**
- *Test expectation: per-callsite migration; tests at the consuming module level using `Platform::for_test()`.*
- `crates/vortix/src/engine/tests/connection_platform_tests.rs`:
  - **Happy path:** Construct engine with `Platform::for_test()` and `MockRunner` scripting the relevant subprocess calls. Exercise `engine.connect(profile)`. Assert killswitch was engaged via the mocked platform's invocation log.

**Verification:** `rg 'cfg\(target_os' crates/vortix/src/` (excluding `crates/vortix/src/platform.rs` if the thin re-export remains) returns zero matches. `cargo xtask check-platform-leak` passes.

---

## Verification Strategy

End-to-end checks:
- `cargo build --workspace --all-targets --locked` succeeds on macOS and Linux.
- `cargo test --workspace --all-targets` passes — all existing tests + new port-mock tests.
- `cargo tree -p vortix-platform-linux | grep -v 'vortix-core\|vortix-process' | grep '^[│ ]*├──.*vortix'` returns no matches (no `vortix` dep).
- Same for `vortix-platform-macos`.
- `cargo xtask check-platform-leak` exits 0.
- Manual smoke test: connect via WireGuard on macOS dev machine; kill switch engages identically to pre-PR; disconnect; kill switch disengages.
- The same smoke test on a Linux machine if available (CI runs Linux build).

---

## Risks & Mitigations

- **Trait surface drift between OS impls.** Each impl might implement the same trait method with slightly different semantics (e.g., macOS `Killswitch::is_engaged` might rely on a marker file while Linux checks `iptables -L`). Mitigation: doc-comment the trait methods with semantic requirements; review impls against the docs before merging.
- **`Killswitch::engage` partial-failure semantics.** If macOS pfctl fails after applying some rules, what state is the system in? Today's code has cleanup logic; preserve it. Mitigation: per-OS impl docs explicitly note partial-failure behavior. Engine's FSM (idea 3) treats `Killswitch::engage` as either fully-succeeded or fully-failed.
- **`Platform::detect_current(runner)` is async; main.rs needs to `.await` it before constructing the engine.** Mitigation: simple sequential init in `#[tokio::main] async fn main()`.
- **`MockKillswitch` invocation-log shape may drift from `MockRunner`'s.** Mitigation: same builder API + same assertion helpers; ce-work picks the exact module organization.
- **Engine touches more than the five ports.** E.g., the engine may today have logic that's actually OS-specific but doesn't cleanly fit one port (e.g., `sysctl net.ipv4.ip_forward` to enable forwarding). Mitigation: discover during U7; either extend an existing port's trait or punt to a follow-up if the boundary is unclear.

---

## Scope Boundaries

- **`SplitTunnel`, `TunDevice`, `PrivilegeEscalation` ports** — out of scope. Each lands with its driving feature.
- **`vortix-platform-windows` crate** — out of scope. Created when v1.0 Windows ROADMAP work begins.
- **Explicit `*Capabilities` structs per port** — out of scope. Booleans on impls or implicit-in-trait-method-set suffice. Added when a feature needs them.
- **Re-examining the iptables/nftables preference order** — out of scope. Preserved verbatim.
- **`SCDynamicStore`-based NetworkMonitor on macOS** — out of scope. Current `netstat -ib` polling preserved.
- **Behavior changes of any kind** — out of scope. Pure structural refactor.
- **Renaming or restructuring `vortix-core::killswitch` business logic beyond relocation** — out of scope.

### Deferred to Follow-Up Work

- Adding `Capability(CapName)` variants to `PrivilegeReq` (idea 1's outstanding question) when capability-based privilege actually lands on Linux.
- Iptables → nftables preference flip — separate small commit with its own justification.
- `vortix-platform-mock` crate extraction if the in-core mocks grow large enough to warrant separation.

---

## Outstanding Questions

### Resolve Before Planning

(None.)

### Deferred to Implementation

- Exact `KillswitchConfig` field set — today's `Firewall` trait passes the config; verify shape by reading the existing call.
- Whether `DnsResolver::apply` should take `Vec<IpAddr>` or `&[IpAddr]` — mechanical signature choice.
- Whether to factor `PlatformError` into per-port errors (`KillswitchError`, `DnsError`, etc.) or one umbrella `PlatformError` enum. Recommend per-port (matches the trait-per-port shape).
- Exact sealing mechanism (`#[non_exhaustive]` attribute vs sealed-supertrait pattern). Both work; planner picks.
- Whether to add a `Platform::with_runner(runner)` constructor for convenience (vs always passing `&runner` per-call). Mechanical.
- Whether `Mock*` impls should live in a `mock` submodule per port or in a single top-level `crates/vortix-core/src/ports/mock.rs`. Mechanical.
