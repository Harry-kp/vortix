---
date: 2026-05-24
topic: capability-ports-platform
---

# Capability Ports for Platform

## Summary

Promote vortix's existing informal `Firewall` / `NetworkStatsProvider` traits (today at `src/platform/mod.rs`) into a first-class capability-port system in `vortix-core::ports::*` with five day-one ports: `Killswitch` (renames `Firewall`), `DnsResolver`, `Interface`, `NetworkStats`, `RouteTable`. Each port is a trait; per-OS implementations live in `vortix-platform-macos` and `vortix-platform-linux` as today's `src/platform/{macos,linux}/{firewall,dns,interface,network}.rs` files relocated and grouped. An aggregate `struct Platform` carrying one field per port (each an `enum_dispatch` enum over the OS variants) is constructed once at startup; the rest of the codebase consumes that aggregate without referencing the OS. Linux runtime backend selection (iptables vs nft, systemd-resolved vs resolvconf) is preserved exactly as today. Pure structural refactor — same subprocess invocations, same backend selection logic, zero observable behavior change for users.

---

## Problem Frame

vortix's current platform code lives at `src/platform/{linux,macos}/` with parallel-shaped files in each OS folder: `dns.rs`, `firewall.rs`, `interface.rs`, `network.rs`. Two informal trait-like seams already exist at `src/platform/mod.rs` — `Firewall` (used by `linux/firewall.rs` and `macos/firewall.rs`) and `NetworkStatsProvider` (used by `macos/network.rs`). The remaining capabilities (DNS, interface, route table) have no trait abstraction; they're called by `#[cfg(target_os = "...")]`-gated code paths scattered across `src/core/`, `src/engine/`, and `src/cli/`.

This organization carries three costs that compound on v1.0 ROADMAP commitments.

**Windows support is structurally impossible without a refactor.** v1.0 ROADMAP commits to Windows. Today's "organize by OS folder" pattern means a Windows port adds 4–7 new files in `src/platform/windows/` mirroring the existing folders, plus a sprinkle of new `cfg(target_os = "windows")` blocks across `src/core/` and `src/engine/` for every place that conditionally branches on OS. The set of capabilities that need to work on Windows is the same set already partially abstracted by `Firewall` and `NetworkStatsProvider` — extending those abstractions to cover DNS, interface, route table, and network monitor gives Windows one clear checklist instead of an unbounded grep.

**Split tunneling has nowhere to live.** v1.0 ROADMAP also commits to split tunneling. Split tunneling is a *capability* — different OSes implement it through different mechanisms (Linux: routing tables + nftables marks; macOS: `pfctl` rules + route monitor; Windows: Windows Filtering Platform). Without a capability-port system, the natural shape (a `SplitTunnel` trait with per-OS impls) cannot be added — it would have to either grow inside the existing `Firewall`/`NetworkStatsProvider` traits (semantically wrong) or invent its own scattered `cfg` block pattern (the problem v1.0 is supposed to solve).

**Backend selection logic is invisible to the rest of the codebase.** `IptablesFirewall::detect_backend()` already picks between `iptables` and `nft` at runtime, and equivalent logic exists for DNS resolver selection. But the rest of the codebase doesn't know this — it sees `Firewall::engage()` and assumes a single implementation. When a contributor adds a new platform feature, they have no convention for "is this a runtime-detected backend, or is it OS-determined?" A capability-port system makes the convention explicit: ports are traits, impls choose backends at construction, callers consume the chosen impl through the aggregate.

This is a structural refactor, not a feature delivery. After it lands, *adding* Windows support is one new crate implementing the same five trait set. *Adding* split tunneling is one new port. The architectural cost of every v1.0 platform work item is bounded by "implement the trait" instead of "grep, sprinkle, hope."

---

## Actors

- A1. **Contributor implementing v1.0 Windows support** — wants one crate (`vortix-platform-windows`) to write, with one checklist of capability impls (Killswitch via Windows Filtering Platform, DnsResolver via Win32 IP helper, etc.). Zero `cfg(target_os = "windows")` blocks outside the crate.
- A2. **Contributor implementing v1.0 split tunneling** — wants to add one new port (`SplitTunnel`) and three per-OS impls. The engine code that *uses* split tunneling references the port, not the OS.
- A3. **Contributor adding a new Linux distro that ships only `nft`** — runtime backend probe picks the nftables impl automatically; the contributor doesn't touch `src/` at all if their distro has standard `nft` tooling.
- A4. **Engine (idea 3's FSM)** — calls `platform.killswitch.engage(...)` during `Connecting → Connected`, `platform.dns.apply(...)` similarly, `platform.network_stats.get_total_bytes()` periodically. Never branches on OS.
- A5. **Tunnel impls (idea 5)** — `WgTunnel::up(profile, plat: &Platform, runner)` consumes ports from the aggregate (DNS apply, route addition, interface configuration). Same for OpenVPN. Tunnels are platform-agnostic.
- A6. **End user** — observes zero change. Same killswitch behavior, same DNS handling, same connection latency.

---

## Key Flows

- F1. **Engine engages killswitch during connection**
  - **Trigger:** FSM is transitioning `Connecting → Connected`; tunnel handshake succeeded.
  - **Actors:** A4
  - **Steps:**
    1. Engine calls `platform.killswitch.engage(KillswitchConfig { allow_lan: true, allow_dns: true, ...}, &runner).await`.
    2. The active `KillswitchKind` enum variant dispatches to either `MacosPfKillswitch::engage` or `LinuxFirewallKillswitch::engage` (no enum branching by the engine).
    3. The Linux impl, constructed at startup with `backend: FirewallBackend::Iptables`, runs the appropriate `iptables` commands through `CommandRunner`.
    4. Result returns; engine emits `KillswitchEngaged` event into the journal.
  - **Outcome:** Same killswitch behavior as today; engine has no awareness of macOS vs Linux vs iptables vs nft.
  - **Covered by:** R1, R2, R3, R6, R7

- F2. **Platform aggregate construction at startup**
  - **Trigger:** `main.rs` or `vortix-daemon::main.rs` starts.
  - **Actors:** A4
  - **Steps:**
    1. Code constructs `Platform::detect_current()` (or `Platform::for_macos()` / `Platform::for_linux()` if explicitly named, e.g., in tests).
    2. The constructor invokes each port's `detect_or_default()` to pick an OS-specific impl variant. For Linux, this runs the backend-probe sequence (`which iptables`, `which nft`, etc.) and stores the chosen backend on the impl.
    3. The aggregate is wrapped in an `Arc<Platform>` and passed to the engine / handle / tunnel impls.
  - **Outcome:** Platform aggregate ready for use; backend selection happened once.
  - **Covered by:** R4, R5, R6

- F3. **Adding Windows support (future, v1.0)**
  - **Trigger:** Contributor begins v1.0 Windows port work.
  - **Actors:** A1
  - **Steps:**
    1. Contributor creates `crates/vortix-platform-windows/` with `Cargo.toml` and `lib.rs`.
    2. For each of the five day-one ports, contributor adds one impl struct in its own file (`killswitch_wfp.rs`, `dns_winhelper.rs`, `interface_iphelpapi.rs`, `network_stats_iphelpapi.rs`, `route_table_iphelpapi.rs`).
    3. Contributor adds one new variant per `*Kind` enum in `vortix-core::ports::*` (e.g., `KillswitchKind::Windows(WfpKillswitch)`).
    4. `Platform::detect_current()` gains a `cfg(target_os = "windows")` branch in one place.
  - **Outcome:** Windows ports without touching any code in `vortix-core::engine`, `vortix-protocol-*`, `vortix-cli`, or `vortix-tui`. The capability surface stays the same; only the impls multiply.
  - **Covered by:** R8

---

## Requirements

**Port trait set**

- R1. Define five port traits in `vortix-core::ports::`:
  - `trait Killswitch` (replaces today's `Firewall`): `engage(config, runner)`, `disengage(runner)`, `is_engaged(runner)`, `status(runner)`. Configures host-firewall rules to block all non-VPN traffic.
  - `trait DnsResolver`: `apply(servers, search_domains, runner)`, `restore(runner)`, `current(runner)`. Manipulates the system DNS configuration.
  - `trait Interface`: `list(runner)`, `get(name, runner)`, `set_mtu(name, mtu, runner)`, `get_ip(name, runner)`. Read/write of OS-level network interface state for the VPN's tun/wireguard interface.
  - `trait NetworkStats` (today's `NetworkStatsProvider`, kept): `get_total_bytes(runner)`, `get_interface_bytes(name, runner)`. Read-only counters of bytes through a given interface for telemetry.
  - `trait RouteTable`: `list(runner)`, `add(destination, gateway, interface, runner)`, `remove(...)`, `default_gateway(runner)`. Manipulates the OS routing table.
- R2. Each trait method is `async` (native AFIT). All I/O flows through the `&CommandRunner` argument (idea 1).
- R3. Each trait is `#[non_exhaustive]`-via-sealed-trait pattern (i.e., methods can be added without breaking impls) — practically, this means the trait is `pub` but with private supertrait bounds or `#[must_use]` discipline. Planner picks the exact sealing mechanism.

**Dispatch and aggregate**

- R4. Each port has a closed enum carrier in `vortix-core::ports::<port>`: `enum KillswitchKind { Macos(PfKillswitch), Linux(LinuxFirewallKillswitch) }`. Dispatched via `enum_dispatch`, same pattern as ideas 1, 4, 5, Tunnel trait. `Mock(MockX)` variant is added per port for testability — same fixture pattern as idea 5's `MockTunnel`.
- R5. The aggregate is `struct Platform` in `vortix-core::platform` (or `vortix-core::ports`) holding one field per port: `killswitch: KillswitchKind`, `dns: DnsResolverKind`, `interface: InterfaceKind`, `network_stats: NetworkStatsKind`, `route_table: RouteTableKind`. The struct is `Send + Sync + Clone` (clones share `Arc`-backed inner state where impls need it).
- R6. `Platform` provides constructors: `detect_current()` (uses `cfg(target_os = "...")` to pick the OS in one place — the constructor function — and probes for backend availability for the chosen OS), `for_test()` (constructs the aggregate using `Mock(...)` variants of every port), `from_kinds(...)` (explicit construction for advanced cases).

**Backend selection (Linux)**

- R7. For Linux, the per-port constructors implement runtime backend probing as today (`IptablesFirewall::detect_backend()` for killswitch, equivalent for DNS resolver selection). The detected backend is stored on the impl struct at construction time. The current Linux firewall preference order (`iptables` first, `nft` fallback) is **preserved verbatim** in this refactor — re-examining the preference is out of scope.

**Cross-platform consistency**

- R8. For each port, the macOS and Linux impls expose the same logical behavior at the trait surface, even when the OS mechanism differs (e.g., `Killswitch::engage` blocks all non-tunnel traffic regardless of whether `pfctl` or `iptables` is doing it). When a behavior cannot be replicated cleanly on one OS, the port's documentation explicitly names the divergence.

**`vortix-core::killswitch` business logic**

- R9. The killswitch business-logic module (today `src/core/killswitch.rs`, 233 lines) relocates to `vortix-core::killswitch` and consumes the `Killswitch` port for OS surface. The logic/surface split is preserved: business decisions (when to engage, what allow-rules to apply, recovery on crash) live in `vortix-core`; OS-specific firewall commands live in `vortix-platform-*`.

**Migration scope (big-bang)**

- R10. The migration lands as a single PR. All five port traits are defined in `vortix-core` in the same PR. All existing code in `src/platform/{macos,linux}/` relocates to `crates/vortix-platform-{macos,linux}/`. All callsites that today reference `crate::platform::Firewall` etc. switch to `&Platform` or to specific `platform.killswitch.xxx()` access.
- R11. The PR is **behavior-neutral**. Same subprocess invocations (the existing iptables / pfctl / scutil / networksetup / ip / route command lines), same backend selection logic, same error handling. The only observable difference is internal organization — no new tests pass that didn't before, no old tests break.
- R12. After this PR, `rg 'cfg\(target_os\)' crates/vortix-core/ crates/vortix-cli/ crates/vortix-tui/ crates/vortix-process/ crates/vortix-protocol-*` returns zero matches. The only `cfg(target_os)` blocks remaining live inside `crates/vortix-platform-*` crates (where they belong) or inside `Platform::detect_current()` (the single OS-routing constructor).

**`src/core/network_monitor.rs` migration**

- R13. The link-state monitoring code at `src/core/network_monitor.rs` (103 lines, runs `ip` and `route` subprocesses) becomes a consumer of `RouteTable::default_gateway()` and `Interface::list()` ports. The polling loop stays in `vortix-core` (or its appropriate consumer module); the subprocess calls go through the ports.

---

## Acceptance Examples

- AE1. **Covers R1, R5.** When a contributor opens the migrated codebase, then `vortix-core::ports` contains exactly five modules: `killswitch.rs`, `dns.rs`, `interface.rs`, `network_stats.rs`, `route_table.rs`. Each defines one trait + one enum carrier + (test variant) one `Mock` impl.

- AE2. **Covers R4, R6.** When the daemon (Phase B of idea 4) or the CLI main fn constructs `Platform::detect_current()`, then the returned struct holds the correct OS-specific variants for the running platform without any caller-side `cfg(target_os)`.

- AE3. **Covers R7.** When the Linux killswitch impl is constructed on a system with both `iptables` and `nft` installed, then the backend stored on the impl is `FirewallBackend::Iptables` (preserving today's preference) and subsequent `engage()` calls run `iptables` commands.

- AE4. **Covers R8.** When the engine engages the killswitch with `KillswitchConfig { allow_lan: true, allow_dns: true }`, then both the macOS impl and the Linux impl achieve the same logical behavior (LAN traffic permitted, DNS lookups permitted, all other non-tunnel traffic blocked), even though one uses `pfctl` and the other uses `iptables`.

- AE5. **Covers R12.** When `rg 'cfg\(target_os' crates/vortix-core/ crates/vortix-cli/ crates/vortix-tui/ crates/vortix-process/` runs after the migration, then it returns zero matches. The only remaining `cfg(target_os)` is in `crates/vortix-core/src/platform.rs::detect_current` (the single OS-routing constructor) and inside each `crates/vortix-platform-*` crate.

- AE6. **Covers R10, R11.** When a maintainer runs the existing manual test workflow (connect to a profile, observe killswitch engagement, observe DNS substitution, run `vortix down`, observe restoration) before and after the migration, then the observed behavior is identical: same logs at the same points, same connection latency, same recovery on crash.

- AE7. **Covers R4.** When a test constructs `Platform::for_test()`, then every port returns a `Mock(MockX)` impl that scripts predictable behavior; the test can assert on the recorded sequence of port calls (e.g., "engine engaged killswitch with these flags, then applied DNS to these servers") without root or real `iptables`.

- AE8. **Covers R13.** When `src/core/network_monitor.rs`'s migrated code wants the default gateway, then it calls `platform.route_table.default_gateway(&runner).await` instead of shelling out to `ip route` or `route -n get default` directly. The platform impl owns the subprocess call.

---

## Success Criteria

- A contributor implementing v1.0 Windows support writes one new crate (`vortix-platform-windows`) with five impl structs and adds five new enum variants. They touch zero code in `vortix-core::engine`, `vortix-protocol-*`, `vortix-cli`, or `vortix-tui`.
- A contributor implementing v1.0 split tunneling adds one new port (`SplitTunnel`) to `vortix-core::ports`, three impls (one per platform), and one new field on the `Platform` aggregate. The engine integration is one new call site that uses the new port.
- A contributor adding a new Linux distro support story (e.g., distros without `iptables`) does not touch `vortix-core` at all — they add a new `LinuxFirewallKillswitch` backend variant in `vortix-platform-linux` and update the runtime probe.
- After the migration, the v1.0 ROADMAP commits to multi-platform and split-tunneling are bounded by "implement the trait" rather than "grep + sprinkle."
- The current Linux killswitch backend preference (`iptables` over `nft`) is preserved; the question of whether to flip it lives in a separate small commit with its own justification.

---

## Scope Boundaries

- **Three deferred ports — `SplitTunnel`, `TunDevice`, `PrivilegeEscalation`** — are not added in this PR.
  - `SplitTunnel`: v1.0 ROADMAP feature; added when that work begins. The capability-port architecture trivially admits it.
  - `TunDevice`: only needed for userspace tunnels (boringtun, wireguard-go), deferred along with idea 5's userspace WireGuard deferral.
  - `PrivilegeEscalation`: privilege is the daemon's identity (Phase B of idea 4), already encoded as idea 1's `PrivilegeReq` on `CommandSpec`. Not a platform-surface concern.
- **`vortix-platform-windows` crate** is not created in this PR. Matches idea 5's IKEv2-deferral pattern and idea 2's no-stub-crates policy. Created when v1.0 Windows work begins.
- **Explicit per-port capability negotiation structs** (`KillswitchCapabilities`, `DnsCapabilities`, etc.) are not added in this PR. Booleans on impl structs or implicit-in-the-trait-method-set suffice for the five day-one ports. Explicit cap structs land when a feature (like `SplitTunnel`) needs the negotiation.
- **The existing Linux firewall preference order** (`iptables` over `nft`) is preserved verbatim. Re-examining the preference is a separate concern that lives in its own commit with its own justification.
- **Behavior changes of any kind** are out of scope. This PR is a pure refactor: same subprocess invocations, same backend selection logic, same error handling.
- **Renaming or restructuring the `vortix-core::killswitch` business-logic module** beyond relocating it from `src/core/killswitch.rs` is out of scope. Internal cleanup of its 233-line surface lives in follow-up work.
- **macOS network monitor backend choice** (e.g., `SCDynamicStore` vs `netstat -ib` for link state) is preserved as-is. Whether macOS should grow a `NetworkMonitor` port using `SCDynamicStore` instead of polling `netstat -ib` is a future question.

---

## Key Decisions

- **Five day-one ports: `Killswitch`, `DnsResolver`, `Interface`, `NetworkStats`, `RouteTable`.** The set that already has concrete code today plus what idea 5's tunnel impls need on day one. Excluded ports (`SplitTunnel`, `TunDevice`, `PrivilegeEscalation`) wait for their driving feature.
- **`enum_dispatch` aggregate with per-field closed enums.** Same pattern as ideas 1, 4, 5, Tunnel trait. AFIT-compatible, no `Arc<dyn Trait>` heap allocations, closed-set extensions are mechanical (one new enum variant per OS / per backend).
- **Runtime backend detection is preserved unchanged.** `IptablesFirewall::detect_backend()` (existing) keeps probing for iptables/nft; equivalent for DNS resolver selection. Backend lives on the impl struct, chosen at construction.
- **`Platform::detect_current()` is the only place that branches on OS in `vortix-core`.** Every other consumer takes `&Platform` and reads its fields. Verifiable via the `rg 'cfg(target_os)'` check in R12.
- **No Windows crate today.** Matches idea 5's IKEv2 deferral and idea 2's no-stubs policy. The architecture supports an additive Windows port; the actual port lands when v1.0 work begins.
- **`Killswitch` is the new name for `Firewall`.** "Firewall" is a generic OS concept; vortix's use of host-firewall infrastructure is specifically as a killswitch. The renaming clarifies intent for new contributors. (The existing `Firewall` trait at `src/platform/mod.rs` becomes the new `Killswitch` trait; the macOS pf-rule code in `src/platform/macos/firewall.rs` becomes `PfKillswitch`, etc.)
- **Behavior-neutral refactor.** Zero observable change for users. The PR's value is structural: bounding the cost of future platform work.
- **Big-bang migration in one PR.** All five ports, both OS impls, all relocations, all callsite updates in the same diff. Matches the user's pattern from ideas 1-5.

---

## Dependencies / Assumptions

- **Idea 2 (workspace split) lands before this PR.** `crates/vortix-platform-{macos,linux}/` need to exist as workspace members.
- **Idea 1 (`CommandRunner`) lands before this PR.** All port methods take `&CommandRunner`; the trait's interface depends on this type being available in `vortix-core::ports::process` or imported from `vortix-process`.
- **Idea 5 (`Tunnel` trait) may land before or after this PR.** If before, idea 5's `Tunnel::up(profile, plat: &Platform, runner)` signature is finalized with the real `Platform` type. If after, idea 5 uses a stub `Platform` placeholder that this PR later replaces. Recommend ordering: idea 2 → idea 1 → this (idea 6) → idea 5, so idea 5 gets the real `Platform` from day one.
- **`enum_dispatch` plays cleanly with AFIT in trait positions.** Planner verifies with a sanity build; hand-coded match-arm dispatch is the fallback.
- **The current `src/platform/mod.rs` traits (`Firewall`, `NetworkStatsProvider`)** are minimally invasive to promote. Their existing method signatures map cleanly to the new `Killswitch` / `NetworkStats` traits; the work is renaming + relocating, not redesigning.
- **`src/core/killswitch.rs` business logic and `src/platform/{linux,macos}/firewall.rs` OS adapters are already cleanly split** — the existing split is preserved at the crate boundary level. No internal restructuring beyond relocation.

---

## Outstanding Questions

### Resolve Before Planning

(None — all material decisions resolved in the synthesis.)

### Deferred to Planning

- [Affects R3][Technical] Exact sealing mechanism for `#[non_exhaustive]`-style trait evolution — whether to use a sealed-supertrait pattern, an `#[non_exhaustive]` attribute on the trait (Rust 2024+), or just method-addition discipline. Mechanical.
- [Affects R6][Technical] `Platform::detect_current()` strategy for hybrid platforms (Linux on WSL, FreeBSD with Linux compat layer, exotic distros without standard tooling). Default behavior: try the preferred backend's probe, fall through to alternates; if nothing works, return `Err(PlatformDetectError)`. Planner picks the exact fallthrough order.
- [Affects R1, R8][Needs research] Whether `Killswitch::status` should return a typed enum (`Engaged | Disengaged | Partial(reason) | Unknown`) or a richer report struct. Booleans-plus-message vs explicit-enum-variants — planner picks based on actual call-site needs.
- [Affects R13][Technical] Whether `src/core/network_monitor.rs` becomes its own port (`NetworkMonitor`) or stays as a consumer of `RouteTable` + `Interface`. If link-state detection (e.g., "Wi-Fi just dropped") needs its own abstraction beyond polling existing ports, a new port may emerge. Punt to planning when concrete migration is attempted.
- [Affects R7][Technical] Whether the chosen backend should be re-detected periodically (in case the user installs `nft` mid-session) or stay at construction-time. Stay at construction time is simpler and matches current behavior.
- [Affects R10][Technical] Exact `use` path migration sequence — what order to land file relocations in, how to keep the PR diff reviewable when ~10 files move and ~30 callsites update. Mechanical; planner picks.
