---
title: System-dependency reduction — minimize what users must install
date: 2026-05-30
status: ready-for-plan
type: refactor
---

# System-dependency reduction — minimize what users must install

## Problem

Vortix today shells out to ~20 system binaries across Linux + macOS. Some of these are unavoidable — `wg-quick`, `openvpn`, `iptables-restore`, `pfctl`, `nft` ARE the product behavior, vortix orchestrates them, doesn't re-implement them. But many others have Rust alternatives that would let users avoid installing extra packages:

- `curl` is shelled for every telemetry HTTP request, but vortix already pulls in `tokio` — a Rust HTTP client integrates naturally with the existing async runtime.
- `which` was shelled for binary-existence checks; the recent `binary_exists` fix walks `PATH` directly via `std::env::split_paths`. (Two residual `which` shell-outs remain in `cli/report.rs:266` and `cli/report.rs:293` — bug, included in scope.)
- `pbcopy` / `xclip` / `wl-copy` for clipboard handoff — the `arboard` crate covers every supported platform.
- `ifconfig`, `ip`, `netstat`, `lsof`, `scutil` for interface/route/socket/DNS inspection — every one has a libc or Rust-crate alternative (`libc::getifaddrs`, Apple's `system-configuration` crate, `/proc/<pid>/cmdline` reading, etc.).
- `ps` for finding wireguard-go processes — the `sysinfo` crate or `/proc` reading covers it.
- `ping` for latency probes — a raw ICMP socket via `socket2` is feasible; alternative is `surge-ping` crate.
- `kill`, `uname`, `sw_vers` — trivially replaced by `libc::kill`, `libc::uname`, `libc::sysctlbyname`.

The recent Fedora integration test caught one instance of this pattern hurting users (`which` not in minimal Fedora install → vortix falsely reports `wg-quick missing`). That's not an isolated bug; it's the symptom of a broader principle vortix should adopt: **don't shell out to a system binary when a Rust alternative exists.**

## Motivation: real-user cost of system deps

- Some users (security-conscious, minimal-install, container/embedded contexts) explicitly minimize what they install. Every dep vortix forces them to add is friction.
- Distro packaging varies: Fedora minimal lacks `which`, Alpine lacks `iputils-ping` by default, some BSDs lack `procps`. Every shell-out has a "works on Ubuntu, fails on $other_distro" failure mode.
- Failure modes from missing system deps are unfriendly: cryptic error from the missing binary, not a helpful nudge from vortix.
- Each shell-out is a process spawn + exec + IPC parse — measurable latency on the hot path (especially telemetry firing every few seconds). Rust-native alternatives are typically 10-100× faster.

## Goals

1. **Reduce the system-binary set vortix actually depends on to the irreducible runtime** — the binaries that ARE the product behavior (`wg-quick`, `openvpn`, `iptables-restore`, `nft`, `pfctl`, `resolvconf` when DNS scoping fires).
2. **Replace every other shell-out with a Rust stdlib or crate alternative** — the maximalist scope from the brainstorm dialogue. Binary growth of 1-2MB is accepted as a fair trade for fewer install-time failures.
3. **Use the async runtime vortix already has** — `tokio` is already in the dependency tree; HTTP requests use `reqwest` (async, integrates naturally) rather than adding a sync HTTP library like `ureq` (which would duplicate runtime machinery).
4. **No regression in observable behavior** — telemetry still works the same, killswitch still engages the same, interface inspection returns the same data shape. The change is mechanism-internal.

## Non-goals / Out of scope

- **Re-implementing kernel firewall via `libnftnl-rs` or similar.** Replacing `iptables-restore` / `nft` / `pfctl` shell-outs with native Rust netfilter bindings is a major architectural undertaking. The user-side cost of keeping these shell-outs is low (every Linux already has iptables; every macOS has pfctl); the engineering cost of replacing them is high. Defer indefinitely.
- **Reimplementing WireGuard or OpenVPN.** vortix orchestrates them; it doesn't replace them. `wg-quick` and `openvpn` binaries stay.
- **`resolvconf` direct-write fallback.** Race conditions with systemd-resolved on Linux; safer to keep the shell-out.
- **Expanded `check_dependencies()` nudge messages.** Separate onboarding-hardening concern. Tracked in a companion brainstorm; not this one.
- **Removing `kill`, `uname`, `sw_vers` shell-outs in `vortix doctor` / `vortix info`.** Diagnostic reporting only; very low traffic; not on any hot path. Stretch goal — include if trivial; defer if requires plumbing.
- **Binary-size optimization.** This work GROWS the binary by ~1-2MB (accepted trade). Shrinking it is a separate concern.

## Replacement map

The set vortix shells out to today, and the proposed alternative for each. Categorized by removal eligibility under maximalist scope.

### Replace under this scope

| Current shell-out | Used for | Replacement | Approximate cost |
|---|---|---|---|
| `curl` | Telemetry HTTP (`api.ipify.org`, IPv6 leak checks, etc.) | `reqwest` (async; consumes existing `tokio`) | ~500KB binary, ~5 crate deps |
| `ping` | Latency / health probes | Raw ICMP via `socket2` crate, or `surge-ping` | ~150KB; requires `CAP_NET_RAW` capability or root (vortix already runs root for tunnel ops) |
| `which` (residual in `cli/report.rs`) | Reporting binary paths | `std::env::split_paths` (same pattern as `utils::binary_exists`) | 0KB; pure stdlib |
| `pbcopy` / `xclip` / `wl-copy` | Clipboard handoff for "copy IP" action | `arboard` crate | ~100KB; cross-platform built-in |
| `ifconfig` (macOS) | Interface listing | `libc::getifaddrs` | 0KB; libc already a dep |
| `ip` (Linux) | Interface inspection (`ip addr show`) | `libc::getifaddrs` + parse `/sys/class/net/<iface>/` | 0KB; libc already a dep |
| `ps` | Finding wireguard-go process PID (Linux), socket auditing (macOS) | Linux: read `/proc/<pid>/cmdline` directly. macOS: libc `proc_listpids`. | 0KB; pure stdlib + libc |
| `netstat` (macOS) | Network statistics + route inspection | `system-configuration` crate (Apple-blessed binding) | ~200KB; covers multiple macOS deps |
| `lsof` (macOS) | Socket auditing | `system-configuration` crate (same as above) | (shared cost with netstat) |
| `scutil` (macOS) | DNS config inspection | `system-configuration` crate (same as above) | (shared cost) |
| `kill` | Process signal | `libc::kill` | 0KB; libc already a dep |

### Stay system-deps under this scope (unavoidable or low-value)

| Current shell-out | Used for | Why stays |
|---|---|---|
| `wg-quick`, `wg` | WireGuard runtime | IS the product behavior; vortix doesn't reimplement WG |
| `openvpn` | OpenVPN runtime | IS the product behavior |
| `iptables`, `iptables-restore`, `ip6tables-restore`, `nft` | Linux killswitch | Kernel firewall control; `libnftnl-rs` is a major architectural rewrite, deferred indefinitely |
| `pfctl` | macOS killswitch | Same — kernel firewall is tool-only access |
| `resolvconf` | DNS (conditional) | Direct-write to `/etc/resolv.conf` races with systemd-resolved |
| `uname`, `sw_vers` | OS detection in `vortix doctor` | Diagnostic reporting; not hot path; stretch goal — include if trivially `libc::uname` / `sysctl` available, defer otherwise |

## Key technical decisions

### HTTP client: `reqwest` (async), not `ureq` (sync)

vortix already depends on `tokio` (`tokio = { features = ["rt-multi-thread", "net", "io-util", "time"] }`) for the engine FSM actor model + the daemon IPC server. Adding `ureq` (sync HTTP) would mean pulling in a parallel sync-HTTP machinery that doesn't share the existing runtime. `reqwest` integrates natively with `tokio` — same runtime, same I/O reactor, no parallel scheduling. The ~500KB binary growth is essentially amortized against tokio's already-present footprint.

### macOS network/DNS introspection: `system-configuration` crate

Three current macOS shell-outs (`netstat`, `lsof`, `scutil`) all touch the same underlying System Configuration framework. The `system-configuration` crate is Apple-supported Rust bindings to that framework — single dep handles all three. Alternative would be hand-rolling FFI to SystemConfiguration.framework, which is more code, more maintenance, and more places for bugs. ~200KB shared cost across three replacements is fair.

### Linux interface inspection: split stdlib + libc, no crate

Two needs: list interfaces + inspect each one. `libc::getifaddrs` covers listing + per-interface info (MTU, IP). Where finer-grained Linux-specific data is needed (peer info, transmit stats), `/sys/class/net/<iface>/` is a flat directory of small files readable with `std::fs::read_to_string`. No crate needed.

### ICMP ping: `socket2` over `surge-ping`

`surge-ping` is a higher-level ping crate; nice ergonomics but pulls in additional async/timer machinery already covered by tokio. `socket2` is a thin libc-style wrapper around `SOCK_RAW`; vortix can hand-roll the ICMP packet construction (it's ~12 bytes of bit-twiddling) and reuse tokio's I/O reactor for the response wait. Smaller dep, more control, same outcome.

## Success criteria

1. **Replaceable-shell-out count drops to zero.** Every entry in the "Replace under this scope" table above gets removed; `git grep 'CommandSpec::oneshot' crates/vortix/src/` no longer matches `curl`, `ping`, `which`, `pbcopy`, `ifconfig`, `ip`, `ps`, `netstat`, `lsof`, `scutil`, `kill`.
2. **Behavior unchanged.** Every existing test continues to pass. The Fedora integration test that just landed (catching the `which` bug) now passes by default — minimal-install Fedora users no longer hit any false missing-dep error.
3. **Binary size growth ≤ 2MB.** Release-mode binary size delta on `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin` measured before/after; total growth budget is 2MB.
4. **No new boundary-check violations.** `cargo xtask check-platform-leak` / `check-protocol-leak` / `check-subprocess` all stay green. The Rust-crate replacements live in the same crate layers as their shell-out predecessors did.
5. **Documentation reflects the new state.** `docs/manual-testing/backlog.md` rows referencing system-binary dependencies (e.g., "verify `ping` blocks when killswitch engaged") are checked for accuracy; install instructions in `README.md` drop the references to deps that are no longer required.

## Dependencies / Assumptions

- **`reqwest` works with vortix's tokio configuration.** Verified by inspection: `tokio` has `rt-multi-thread` + `net` + `io-util` + `time` features which together cover what `reqwest`'s async runtime requires.
- **`socket2` SOCK_RAW works under the same root privileges vortix already requires** for tunnel operations. Vortix runs as root or via sudo for kernel firewall control; the same context allows raw ICMP sockets without additional `CAP_NET_RAW` capability gymnastics.
- **`arboard` covers every platform vortix supports.** macOS + Linux (X11 + Wayland) + Windows (stubbed per origin NG8 anyway). Verified by inspection of arboard's docs.
- **`system-configuration` covers every macOS data point currently fetched via `netstat`/`lsof`/`scutil`.** Specifically: route table inspection, socket listing per process, current DNS resolver configuration. Assumption needs verification at plan time — if it doesn't cover all three, fall back to libc bindings for the missing one.
- **Binary growth budget of 2MB is acceptable.** Confirmed in brainstorm dialogue. Stretch: if growth approaches 3MB, plan-time will re-evaluate whether `system-configuration` is worth the cost vs hand-rolled libc bindings.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `reqwest` async integration introduces subtle behavior differences from `curl` (timeout semantics, redirect handling, TLS verification) | Med | Med | Each telemetry call gets an explicit timeout in the `reqwest` configuration; redirect policy made explicit (not default); TLS verification stays at default (verify). Snapshot test the request/response shape during plan time. |
| Raw ICMP via `socket2` fails on systems where `CAP_NET_RAW` is required but vortix isn't running as root for the ping path | Low | Med | vortix's telemetry runs in the same process as tunnel ops, which already require root. Falls back to TCP-connect-to-port-443 (cheap liveness probe) if raw ICMP socket creation fails. |
| `system-configuration` crate doesn't cover all three macOS data points | Med | Med | Plan-time verification before committing. Fallback per data point: hand-rolled libc binding to SystemConfiguration.framework. Adds engineering cost but preserves outcome. |
| Binary growth exceeds 2MB budget | Low | Low | Strip + LTO + opt-level=z on release builds (most are already on). If still over budget, drop the lowest-value swap (probably `arboard` — clipboard is "copy IP" convenience, not core function). |
| `libc::getifaddrs` doesn't surface every field today's `ip addr show` parses (peer addrs, address scope, etc.) | Low | Low | The parsed fields used by vortix are: IP address (string), MTU (string). Both come from `getifaddrs` and `ifr_mtu` ioctl trivially. Verified by inspection of `parse_ip_addr_output()` in `vortix_platform_linux/interface.rs`. |
| Refactor surface area is large; review burden high; subtle bugs likely | High | Med | Land each replacement as a separate PR (planning concern). Integration tests catch behavioral regressions; the existing Fedora matrix is now a real catch-net. |

## Outstanding questions

Resolvable at plan time:

1. **One PR per replacement vs grouped by category vs single mega-PR?** Brainstorm recommends per-replacement for review-ability — each is a small bounded refactor that touches a specific shell-out plus its callers. Plan-time decision.
2. **Stretch: include `kill`, `uname`, `sw_vers` removals.** Trivially replaceable but low-value; depends on whether the PR sequence has natural slack at the end. Plan-time decision.
3. **Cross-cutting: should `vortix_process::CommandSpec::oneshot` gain a deprecation marker for the binaries removed?** Future contributors might re-add a shell-out where a Rust alternative exists. Hard-deprecating specific program names in `oneshot` (e.g., panic if `program == "curl"`) would prevent regression. Plan-time decision.
4. **Refactor sequence: replace highest-impact first (curl, which residual, pbcopy) or platform-by-platform (all macOS macros first, then all Linux)?** Plan-time decision; both shapes work.

## References

- The triggering finding: Fedora integration test catching the `which`-missing bug ([PR #1 commit `fcf9508`](https://github.com/harshit-chaudhary07/vortix/pull/1/commits/fcf9508)).
- Companion brainstorm: onboarding-hardening (`check_dependencies()` nudge expansion + integration tests that simulate fresh-OS install). Separate concern; not this brainstorm.
- Current dep-check function: [`crates/vortix/src/vpn_runtime/mod.rs:492`](../../crates/vortix/src/vpn_runtime/mod.rs).
- Subprocess wrapper used by all shell-outs: [`crates/vortix/src/vortix_process/`](../../crates/vortix/src/vortix_process/).
