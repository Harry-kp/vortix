---
title: "refactor: reduce system dependencies vortix forces users to install"
type: refactor
status: active
date: 2026-05-30
origin: docs/brainstorms/2026-05-30-system-dependency-reduction-requirements.md
---

# refactor: reduce system dependencies vortix forces users to install

## Summary

Replace every shell-out vortix can replace with a Rust stdlib or crate alternative, leaving only the irreducible product-behavior binaries (`wg-quick`, `openvpn`, `iptables-restore`/`nft`, `pfctl`, `resolvconf` conditional). Twelve replacements grouped into 13 implementation units across 7 phases, ordered by risk: pure-libc swaps first (zero behavioral change), then libc-based interface introspection, then macOS-specific APIs via the `system-configuration` crate, then clipboard, then the two high-risk swaps (HTTP via `reqwest`; raw ICMP via `socket2`), then a regression-guard xtask and documentation cleanup. Maximalist binary-size budget of ≤ 2MB growth; behavior-parity tests gate the high-risk units.

---

## Problem Frame

See [origin §Problem](../brainstorms/2026-05-30-system-dependency-reduction-requirements.md). vortix shells out to ~20 system binaries across Linux + macOS today. Many of these have well-established Rust alternatives — `curl` → `reqwest`, `which` → `std::env::split_paths`, `ifconfig`/`ip` → `libc::getifaddrs`, etc. The recent Fedora integration test catching the `which`-missing bug (PR #1 commit `fcf9508`) was the smoking gun: real users on minimal-install distros hit a class of false missing-dep errors that wouldn't exist if vortix didn't shell out to optional tools.

Beyond user friction, every shell-out is also a measurable latency cost on the telemetry hot path (process spawn + exec + stdout parse vs an in-process function call) and a parallel parsing surface (we re-parse `ip addr` output instead of consuming a typed struct from libc).

---

## Requirements

Sourced from [origin §Goals](../brainstorms/2026-05-30-system-dependency-reduction-requirements.md):

| ID | Requirement |
|----|-------------|
| R1 | Reduce shell-outs to the irreducible product-behavior set: `wg-quick`, `wg`, `openvpn`, `iptables`/`iptables-restore`/`ip6tables-restore`/`nft`, `pfctl`, `resolvconf` (conditional). Every other shell-out gets replaced. |
| R2 | Consume vortix's existing `tokio` runtime where async is needed. No parallel runtimes via sync HTTP libraries. |
| R3 | No regression in observable behavior — telemetry, killswitch, interface inspection, clipboard handoff all produce the same end-user output. |
| R4 | Binary-size growth ≤ 2MB (release build, x86_64-unknown-linux-gnu and aarch64-apple-darwin). |
| R5 | No new `cargo xtask check-*-leak` violations. Replacements live in the same crate layers as their shell-out predecessors. |
| R6 | Prevent regression: after a removed shell-out (e.g. `curl`) is gone, future code must not re-introduce it. Compile-time guard via xtask. |
| R7 | Documentation reflects the new state: install hints in `README.md` drop newly-unnecessary deps; `docs/manual-testing/backlog.md` rows referencing removed shell-outs are checked. |

---

## Key Technical Decisions

### D-1. HTTP via `reqwest` (async), not `ureq` (sync)

vortix already depends on `tokio` with the `rt-multi-thread`, `net`, `io-util`, `time` feature set — the prerequisites for `reqwest`'s async runtime. Adding `ureq` would mean pulling in parallel sync-HTTP machinery that doesn't share the existing reactor; `reqwest` consumes what's already there. ~500KB binary growth amortized against tokio's already-present footprint.

(Brainstorm dialogue: "if we have any binary installed, why install new one" — direct user mandate.)

### D-2. macOS network/DNS via `system-configuration` crate

Three current macOS shell-outs (`netstat`, `lsof`, `scutil`) all touch the underlying SystemConfiguration framework. The `system-configuration` crate provides Apple-supported Rust bindings to that framework. One dep covers all three replacements — ~200KB total. Alternative would be hand-rolling FFI to SystemConfiguration.framework: more code, more maintenance, more bug surface. Crate is the right call.

### D-3. Linux interface inspection: `libc::getifaddrs` + `/sys/class/net`, no crate

Two needs: list interfaces + inspect each one's MTU/IP. `libc::getifaddrs` covers listing + per-interface info. Linux-specific data (peer addresses, transmit stats) lives in `/sys/class/net/<iface>/` as flat files readable with `std::fs::read_to_string`. Both are already-present capabilities — no new dependency.

### D-4. ICMP ping via `socket2` + hand-rolled packet, not `surge-ping`

`surge-ping` is higher-level but pulls in additional async/timer machinery already covered by tokio. `socket2` is a thin libc wrapper around `SOCK_RAW`. ICMP packet construction is ~12 bytes of bit-twiddling; vortix can hand-roll it and reuse tokio's I/O reactor for response wait. Smaller dep, more control, same outcome.

### D-5. Clipboard via `arboard`

Single cross-platform crate. ~100KB. Replaces `pbcopy` (macOS), `xclip`/`wl-copy` (Linux). Industry-standard for this exact purpose.

### D-6. Compile-time regression guard via xtask

Add a `cargo xtask check-no-shell-regressions` command. Walks `crates/vortix/src/` for `CommandSpec::oneshot("<name>", ...)` calls where `<name>` matches the deprecated set (`curl`, `ping`, `which`, `pbcopy`, `xclip`, `wl-copy`, `ifconfig`, `ip`, `ps`, `netstat`, `lsof`, `scutil`, `kill`, `uname`, `sw_vers`). Fails the build if any reappear. Mirrors the existing `check-platform-leak` / `check-protocol-leak` / `check-subprocess` pattern, and gets wired into `.github/workflows/boundary.yml` alongside them.

### D-7. Stretch goals (`kill`, `uname`, `sw_vers`) included in this plan

Brainstorm said "include if trivial; defer if requires plumbing." Each is a 5-10 line `libc::kill` / `libc::uname` / `libc::sysctlbyname` swap. Including avoids a follow-up plan for trivial work.

### D-8. Replacement order: risk-ascending

PR sequence runs cheapest-and-safest first, riskiest last. Pure-libc swaps and the residual `which` ship before anything touching network I/O. Justification: a broken `kill` swap is obvious instantly; a broken `reqwest` swap might quietly change timeout semantics for telemetry and not surface for days.

---

## Implementation Units

Grouped by phase. Within a phase, units are independent; between phases, dependencies are noted. Each unit ships as its own PR for bounded review.

### Phase A — Pure stdlib / libc swaps (zero behavior risk)

### U1. Residual `which` shell-outs in `cli/report.rs`

**Goal:** Replace the two `cmd_stdout("which", &[name])` calls in `cli/report.rs` (lines 266 and 293) with the same `std::env::split_paths` pattern already used in `utils::binary_exists`. The earlier `utils::binary_exists` fix (PR #1) missed these — same `which`-missing bug class.

**Requirements:** R1

**Dependencies:** none

**Files:**
- Modify: `crates/vortix/src/cli/report.rs`
- Test: same file (`#[cfg(test)] mod tests`)

**Approach:**
- Extract `find_binary_path(name: &str) -> Option<PathBuf>` helper in `utils.rs` (parallel to `binary_exists`), returning the first matching path found in `$PATH`.
- Replace both `cmd_stdout("which", ...)` call sites with `utils::find_binary_path(name)`.
- Return the path as `String` to keep the calling sites' signatures stable.

**Patterns to follow:** `utils::binary_exists` (`crates/vortix/src/utils.rs:660`) — the PATH-walking + exec-bit check is already done; just return the path instead of `bool`.

**Test scenarios:**
- Finds a known-present Unix binary (`sh`) and returns a non-empty path
- Returns `None` for a known-absent binary (`vortix-nonexistent-xyz123`)
- Returned path actually exists and is executable

**Verification:** `vortix doctor` (or whatever command exercises the affected code path) outputs the same binary paths it did before the swap on Ubuntu; outputs accurate paths on a Fedora minimal container that doesn't have `which` installed.

---

### U2. `kill` shell-out → `libc::kill`

**Goal:** Replace the `kill` shell-out with `libc::kill(pid, signal)` direct call.

**Requirements:** R1

**Dependencies:** none

**Files:**
- Identify and modify the call site(s) of `kill` in `crates/vortix/src/` (grep `CommandSpec::oneshot("kill"` to enumerate)
- Test: same file(s)

**Approach:**
- Identify all callers of the `kill` shell-out. Most likely `vortix_process` or `vpn_runtime` for terminating spawned wg-quick / openvpn processes.
- Replace with `libc::kill(pid as libc::pid_t, signal)`. Wrap in `unsafe` (the call is FFI), and handle the return value (0 = success, -1 = errno).
- Preserve the existing error semantics: if the prior shell-out returned `Ok(())` on `kill` exit-0 and `Err(_)` on non-zero, the new code does the same.

**Patterns to follow:** Existing `libc::geteuid` usage in `vortix_platform_macos/firewall.rs:57` and `vortix_process/real.rs:277` for the unsafe-block / errno-check pattern.

**Test scenarios:**
- Spawn a long-running process, kill it via the new path, assert the process exits with the expected signal
- Kill a non-existent PID → returns `Err`, doesn't panic
- Kill returns success when the target process exists and the signal is deliverable

**Verification:** `cargo test --workspace` passes; manual: spawn vortix, connect a tunnel, disconnect; verify the underlying wg-quick/openvpn process is gone (`ps aux | grep wg-quick`).

---

### U3. `uname` / `sw_vers` shell-outs → `libc::uname` / `sysctlbyname`

**Goal:** Replace `uname` (Linux) and `sw_vers` (macOS) shell-outs in `cli/report.rs` diagnostic output with direct libc calls. Both are used by `vortix doctor` / `vortix info` for OS-info display.

**Requirements:** R1

**Dependencies:** none

**Files:**
- Modify: `crates/vortix/src/cli/report.rs`
- Test: same file

**Approach:**
- Linux: `libc::uname` populates a `utsname` struct; extract `sysname`, `release`, `version`, `machine` as `String` (handle C-string null termination via `CStr::from_ptr`).
- macOS: `libc::sysctlbyname("kern.osproductversion", ...)` for the OS version string. Or `libc::sysctl` with `[CTL_KERN, KERN_OSRELEASE]` keys. Either is a few-line FFI call.
- Wrap in `unsafe`, document the SAFETY invariant (the C structs are POD; the calls have no side effects).

**Patterns to follow:** Existing `libc::geteuid` unsafe-block pattern. For struct-returning FFI, `vortix_core/secret_file.rs` has the `libc::stat` example.

**Test scenarios:**
- Returns a non-empty OS name + version on every test platform (macOS, Ubuntu, Fedora)
- Returned strings don't contain trailing NUL bytes
- Doesn't panic on platforms where `sysctlbyname` is unavailable (Linux) or `uname` is unavailable (Windows — graceful fallback)

**Verification:** `vortix info` output (or whatever surface displays this) matches what `uname -a` / `sw_vers` would have shown.

---

### Phase B — libc-based interface introspection

### U4. Linux `ip addr show <iface>` → `libc::getifaddrs` + `/sys/class/net`

**Goal:** Replace the `cmd_output("ip", &["addr", "show", interface])` call in `vortix_platform_linux/interface.rs:74` with direct libc/sysfs reads. Same data fields out (IPv4 address, MTU).

**Requirements:** R1, R3

**Dependencies:** none

**Files:**
- Modify: `crates/vortix/src/vortix_platform_linux/interface.rs`
- Test: same file (existing `parse_ip_addr_output` tests + new fixtures)

**Approach:**
- `libc::getifaddrs()` returns a linked list of `ifaddrs` structs; walk it, filter by `ifa_name == interface`, extract IPv4 address from `ifa_addr` (cast to `sockaddr_in`).
- MTU comes from `/sys/class/net/<iface>/mtu` (one-line file). Read with `std::fs::read_to_string`.
- Remove the `cmd_output("ip", ...)` call and the `parse_ip_addr_output` helper (no longer needed — getifaddrs gives typed data).
- Keep `Interface::get_interface_info` signature `(String, String)` for caller-compat.

**Patterns to follow:** `libc::getifaddrs` is in libc's standard surface. Existing libc-FFI patterns in the repo: `vortix_platform_macos/firewall.rs:57` (geteuid), `vortix_core/secret_file.rs` (openat/fstat).

**Test scenarios:**
- Real WG interface (e.g. `wg0` in a netns) returns expected (IP, MTU) tuple
- Non-existent interface returns `(String::new(), String::new())` — matches current behavior
- Interface with no IPv4 address (only IPv6) returns empty IP, populated MTU
- `getifaddrs` failure (rare; out of memory) returns empty tuple gracefully

**Verification:** Existing `parse_ip_addr_output` tests deleted (replacement is typed; no parsing). New tests against a `getifaddrs` fixture (mock or netns). Manual: `vortix status` against an active WG tunnel shows the same IP/MTU as before.

---

### U5. macOS `ifconfig -l` → `libc::getifaddrs`

**Goal:** Replace the `ifconfig -l` shell-out in `vortix_platform_macos/interface_list.rs:23` with `libc::getifaddrs`. Same interface-list output.

**Requirements:** R1, R3

**Dependencies:** none

**Files:**
- Modify: `crates/vortix/src/vortix_platform_macos/interface_list.rs`
- Test: same file

**Approach:**
- `libc::getifaddrs()` works identically on macOS (BSD-derived).
- Walk the linked list, collect unique interface names. Return `Vec<String>` matching the current signature.
- Apple's `ifaddrs` may include each interface multiple times (one entry per address family); dedupe via `HashSet` before returning.

**Patterns to follow:** Same as U4 — getifaddrs is portable across Linux and macOS.

**Test scenarios:**
- Returns at least `["lo0", "en0"]` on a typical macOS runner
- Each name appears exactly once (dedupe works)
- Returns empty Vec on getifaddrs failure rather than panicking

**Verification:** `vortix list` on macOS shows the same interfaces as before. Manual smoke on Apple Silicon + Intel.

---

### U6. `ps -eo pid,args` → `/proc/<pid>/cmdline` (Linux) + `libc::proc_listpids` (macOS)

**Goal:** Replace the `ps` shell-out used for finding wireguard-go processes. Currently in `vortix_platform_linux/interface.rs:52` (Linux) and `vortix_platform_macos/socket_audit.rs` (macOS path; verify exact location at plan time).

**Requirements:** R1, R3

**Dependencies:** none

**Files:**
- Modify: `crates/vortix/src/vortix_platform_linux/interface.rs`
- Modify: macOS counterpart (path identified at plan time — likely `vortix_platform_macos/interface.rs`)
- Test: same files

**Approach:**
- **Linux:** iterate `/proc/[pid]/` directories via `std::fs::read_dir("/proc")`. For each numeric-named entry, read `/proc/<pid>/cmdline` (null-byte-separated arg vector). Match against "wireguard" + interface name. Return PID.
- **macOS:** `libc::proc_listpids(PROC_ALL_PIDS, 0, ...)` returns the active PID list. `libc::proc_pidpath(pid, ...)` returns the binary path. Filter for paths containing "wireguard" / "wg" + interface name.
- Both replace the prior `ps`-parsing logic with typed traversal — no string-splitting on whitespace.

**Patterns to follow:** Linux: `/proc` reading is standard stdlib + std::fs. macOS: `libc::proc_*` FFI is well-documented in the `libc` crate.

**Test scenarios:**
- Spawn a fake long-running process named `wireguard-go-test`, find its PID via the new path, kill it, assert it's gone
- Returns `None` when no matching process exists
- `/proc` traversal handles disappearing PIDs gracefully (race: a PID dir disappears between `read_dir` and `read_to_string`)
- `proc_listpids` failure returns `None` rather than panicking

**Verification:** Manual: bring up a WG tunnel via wireguard-go (userspace, not kernel) on macOS, run `vortix status`; PID column populates correctly.

---

### Phase C — macOS APIs via `system-configuration` crate

### U7. `netstat`, `lsof`, `scutil` shell-outs → `system-configuration` crate

**Goal:** Replace three macOS shell-outs in one bundled unit — they all touch the SystemConfiguration framework, and the `system-configuration` crate covers all three with one dep.

**Requirements:** R1, R3, R4

**Dependencies:** none

**Files:**
- Modify: `crates/vortix/src/vortix_platform_macos/network_stats.rs` (netstat)
- Modify: `crates/vortix/src/vortix_platform_macos/socket_audit.rs` (lsof)
- Modify: `crates/vortix/src/vortix_platform_macos/dns.rs` (scutil)
- Modify: `crates/vortix/Cargo.toml` (add `system-configuration = "X.Y"` as macOS-conditional dep)
- Test: each affected file

**Approach:**
- Add `system-configuration` to the macOS-conditional dependency section in `Cargo.toml`. The crate is well-maintained, ~200KB compiled.
- **netstat:** the crate's `network::SCNetworkInterface` API provides interface statistics. Replace `netstat -ib` parsing with typed reads.
- **lsof:** the crate's `network::SCDynamicStoreRef` provides current socket state. Replace `lsof -i` parsing.
- **scutil:** the crate's `network::SCDynamicStore` provides DNS resolver config. Replace `scutil --dns` parsing.
- Verify at plan-time that the crate covers all three data points actually consumed by the existing shell-out callers. If any one isn't covered, fall back to hand-rolled libc binding for the missing one (see Risk table).

**Patterns to follow:** No existing crate-binding-to-Apple-framework pattern in this repo. `system-configuration` is the established Rust binding; usage examples in its docs.

**Test scenarios:**
- Network stats: `network_stats::get_interface_stats("en0")` returns non-zero TX/RX byte counts on an active runner
- Socket audit: `socket_audit::active_listeners()` includes at least port 22 / 443 on a typical runner
- DNS: `dns::current_resolvers()` returns the same primary nameserver as `scutil --dns` on a system with a real DNS config
- Each call returns `Err` (not panic) when SystemConfiguration framework call fails (rare)

**Verification:** `cargo test -p vortix --lib vortix_platform_macos` continues to pass. Manual on a macOS runner: `vortix status --json` shows the same `network` + `security` sections as before the swap.

**Open question (plan-time):** confirm `system-configuration` crate covers all three data points. If `scutil --dns` data isn't reachable via the crate, plan-time decision: hand-roll a libc binding to `SCDynamicStoreCopyValue` for the DNS-specific bit.

---

### Phase D — Clipboard

### U8. `pbcopy` / `xclip` / `wl-copy` → `arboard` crate

**Goal:** Replace the platform-specific clipboard shell-outs in `app/helpers.rs:308` (and the parallel Linux dispatchers at line 339) with the cross-platform `arboard` crate.

**Requirements:** R1, R3, R4

**Dependencies:** none

**Files:**
- Modify: `crates/vortix/src/app/helpers.rs`
- Modify: `crates/vortix/Cargo.toml` (add `arboard = "X.Y"`)
- Test: `crates/vortix/tests/integration.rs` if there's an existing copy test, else inline in helpers.rs

**Approach:**
- Add `arboard` workspace-level (not platform-conditional — it handles all three internally).
- Replace the `pbcopy` / `xclip` / `wl-copy` dispatch with a single `arboard::Clipboard::new().set_text(...)`.
- The crate auto-detects X11 vs Wayland on Linux; no `WAYLAND_DISPLAY`-checking needed.
- Handle init failure (clipboard daemon unavailable in headless CI): return a soft error matching today's behavior — copy fails silently, no panic.

**Patterns to follow:** `arboard` docs have the standard `Clipboard::new()?` + `.set_text(...)?` pattern.

**Test scenarios:**
- `copy_to_clipboard("test string")` succeeds and the clipboard contains the string (on a runner with a display server; skip on headless)
- Headless environment (no display): returns soft error, doesn't panic
- Long string (1MB+): handles without truncation or panic
- Concurrent calls don't deadlock (clipboard impls vary in thread safety)

**Verification:** Manual: in TUI, focus a row with an IP, trigger "copy IP" action, paste into another app — value matches. On both macOS and Linux.

---

### Phase E — High-risk swaps (HTTP + ICMP)

### U9. `curl` → `reqwest` (telemetry HTTP)

**Goal:** Replace every `CommandSpec::oneshot("curl", ...)` call in `core/telemetry.rs` with `reqwest` async HTTP requests, consuming the existing tokio runtime. Preserve every observable behavior — timeouts, redirects, TLS verification, IPv4/IPv6 fallback.

**Requirements:** R1, R2, R3, R4

**Dependencies:** none (this is the riskiest unit; ship it after Phases A-D are stable)

**Files:**
- Modify: `crates/vortix/src/core/telemetry.rs` (six call sites: lines 223, 321, 386, 429, 603, 656)
- Modify: `crates/vortix/Cargo.toml` (add `reqwest = { version = "X.Y", default-features = false, features = ["rustls-tls", "json"] }` — `rustls-tls` to avoid pulling OpenSSL into the binary, `json` for the IP-API responses)
- Test: `crates/vortix/tests/telemetry_behavior_parity.rs` (new file)

**Approach:**
- Build a `reqwest::Client` once per telemetry session (or once-per-process via `OnceLock`); reuse the connection pool.
- For each call site: replace `CommandSpec::oneshot("curl", vec!["-s", "--max-time", N, url])` with `client.get(url).timeout(Duration::from_secs(N)).send().await`.
- For the JSON-returning IP API calls (`api.ipify.org`): use `.json::<ApiResponse>()` to deserialize directly into a typed struct rather than `String::from_utf8(out.stdout)` + manual parse.
- Preserve exit semantics: on error (timeout, network unreachable, non-2xx), return `None` or the same `Err` variant the prior code returned. No new error categories.

**Execution note:** Start with a failing behavior-parity test (see Test scenarios) before changing call sites. The HTTP swap is the unit with the highest behavior-drift risk; test-first locks the contract.

**Patterns to follow:** No existing `reqwest` usage in repo. Standard `reqwest` async patterns from the crate's docs. tokio integration is automatic (default `Tokio01` reactor).

**Test scenarios:**

*Behavior parity (new test file):*
- Mock HTTP server that returns 200 + IP — assert reqwest returns the same string as `curl -s` would have
- Mock server that hangs past timeout — assert reqwest returns timeout `Err` within the same window curl would have
- Mock server that 503s — assert behavior matches curl's exit code 22 (non-2xx) → `None` mapping
- Redirect (301) — assert reqwest follows the redirect (default policy) matching curl's `-L`-less default (no follow). **Plan-time decision: curl is invoked WITHOUT `-L` in the existing code, so reqwest must be configured `.redirect(Policy::none())` to match.**
- TLS — request `https://`; assert default cert verification on; assert untrusted CA → `Err`, no silent accept

*Edge cases:*
- Request to `localhost:9999` (no listener) → `Err`, not panic
- Concurrent requests don't share `tokio::Mutex` state in a way that serializes them
- Response body >1MB doesn't OOM (set explicit size limit if possible)

**Verification:** All existing telemetry tests pass. New behavior-parity test passes. Manual: connect a tunnel, observe `Latency: <ms>` and `Public IP: <ip>` populate as before in the TUI. Run on a network with curl removed (`rm /usr/bin/curl` in a test container) — telemetry still works.

---

### U10. `ping` → `socket2` raw ICMP

**Goal:** Replace the `CommandSpec::oneshot("ping", ...)` call in `core/telemetry.rs:603` with a raw ICMP socket via `socket2`. Hand-roll the ICMP echo request packet construction (~12 bytes); reuse tokio's I/O reactor for the response wait. Preserve the latency-measurement semantics.

**Requirements:** R1, R3, R4

**Dependencies:** U9 (reqwest landing first reduces the diff size of any cross-unit interactions on tokio integration)

**Files:**
- Modify: `crates/vortix/src/core/telemetry.rs`
- Modify: `crates/vortix/Cargo.toml` (add `socket2 = "0.5"`)
- Create: `crates/vortix/src/core/icmp.rs` (encapsulates the ICMP packet builder + socket setup)
- Test: `crates/vortix/tests/icmp_ping.rs` (new file)

**Approach:**
- ICMP packet structure: 8-byte header (type, code, checksum, identifier, sequence) + payload (optional). Echo Request = type 8. Hand-roll the bit-twiddling; ~30 lines of bounded code.
- Open a `socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))`. Set `Tokio`-compatible non-blocking mode. Wrap in `tokio::io::unix::AsyncFd` for reactor integration.
- Send the packet; await the echo reply; measure round-trip time.
- Fallback path: if raw socket creation fails (no CAP_NET_RAW, no root), fall back to a TCP connect to port 443 of the same target. Coarser-grained measurement but still gives a connectivity signal. Document this fallback in the public function's doc comment.

**Patterns to follow:** No existing raw-socket code in repo. `socket2` docs cover the SOCK_RAW + non-blocking-fd pattern.

**Test scenarios:**

*Behavior:*
- Ping `127.0.0.1` returns a finite RTT (≤ 5ms on every runner)
- Ping an unreachable host (e.g. `10.255.255.1`) returns timeout error within the configured budget
- Concurrent pings to multiple targets don't interfere (each gets its own socket OR they share with proper sequence-number tracking)

*Edge cases:*
- Raw socket creation fails (running as non-root in a non-CAP_NET_RAW context) → fall back to TCP-connect; assert fallback returns a finite "RTT" (TCP-handshake time)
- Packet checksum is correct — verify against the documented ICMP checksum algorithm
- Sequence number echoes back in the reply — assert match

**Verification:** `vortix status` shows `Latency: <ms>` populated as before. Manual on a runner that has CAP_NET_RAW removed: telemetry latency line shows a value (from the TCP fallback) rather than "n/a".

---

### Phase F — Regression guard

### U11. `cargo xtask check-no-shell-regressions`

**Goal:** Add a compile-time check that fails the build if any of the deprecated shell-out names (`curl`, `ping`, `which`, `pbcopy`, `xclip`, `wl-copy`, `ifconfig`, `ip`, `ps`, `netstat`, `lsof`, `scutil`, `kill`, `uname`, `sw_vers`) reappears in `CommandSpec::oneshot(...)` calls.

**Requirements:** R6

**Dependencies:** U1 through U10 (the check would fail if any deprecated call still existed)

**Files:**
- Modify: `crates/xtask/src/main.rs` (add the new subcommand)
- Modify: `.github/workflows/boundary.yml` (add a step invoking the new xtask)
- Test: `crates/xtask/tests/check_no_shell_regressions.rs` (new file)

**Approach:**
- Use the existing pattern from `check-platform-leak` / `check-protocol-leak` / `check-subprocess`. Walk `crates/vortix/src/` with `walkdir`, read each `.rs` file, regex-match for `CommandSpec::oneshot\("(curl|ping|which|...)"`.
- Allow `// xtask:allow-shell-regression: <reason>` annotations on legitimate exceptions (paralleling the existing `xtask:allow-protocol-leak` pattern).
- Output: `xtask check-no-shell-regressions: N violation(s)` if any matches; `ok` otherwise.
- CI: add a step `cargo xtask check-no-shell-regressions` to `boundary.yml`.

**Patterns to follow:** Existing xtask check commands in `crates/xtask/src/main.rs`. The `xtask:allow-*` annotation pattern is already used by `check-protocol-leak`.

**Test scenarios:**
- Clean tree (no deprecated names in source) → xtask exits 0 with `ok` message
- Source file contains `CommandSpec::oneshot("curl", ...)` → xtask exits non-zero, reports the file:line:program
- Source file contains the same with `// xtask:allow-shell-regression: documented reason` → xtask exits 0, doesn't flag the line
- Pattern only matches actual program names — `"curl-something"` doesn't match `"curl"`

**Verification:** `cargo xtask check-no-shell-regressions` exits 0 on the post-U10 tree. Manual: temporarily add `CommandSpec::oneshot("curl", vec![])` to any file, run xtask, observe failure with the right file/line. Remove, re-run, observe pass.

---

### Phase G — Documentation

### U12. README + manual-testing/backlog.md cleanup

**Goal:** Trim the install instructions in `README.md` to drop deps that vortix no longer requires. Audit `docs/manual-testing/backlog.md` rows that mention the removed system binaries (e.g. references to `iputils-ping`, `procps`).

**Requirements:** R7

**Dependencies:** U1 through U10

**Files:**
- Modify: `README.md`
- Modify: `docs/manual-testing/backlog.md`
- Modify: `tests/integration/Dockerfile` (Ubuntu) — drop `iputils-ping`, `procps` if they're no longer needed by vortix at runtime (they may still be needed by integration TEST SCRIPTS — verify before removing)
- Modify: `tests/integration/Dockerfile.fedora` — same audit

**Approach:**
- For each removed shell-out, check the `README.md` "Requirements" / "Installation" section for a mention of the corresponding system package. Remove if vortix no longer shells out to it.
- Walk `docs/manual-testing/backlog.md` rows for any check that asserts behavior derived from a now-removed shell-out. Either keep the row (the behavior still matters; it's just measured differently now) or delete (the row was asserting an implementation detail that no longer applies).
- Audit the test Dockerfiles: which packages were installed BECAUSE vortix shelled out to them, and are no longer needed? Test scripts (`killswitch.sh`, `wg_happy_path.sh`) may still use `ping` for assertions — those installs stay. Distinguish "needed by vortix" from "needed by test scripts."

**Patterns to follow:** Existing `README.md` install section. The convention in `docs/manual-testing/backlog.md` from earlier in this session: delete rows when behavior is automated; here, evaluate per-row whether the row is still meaningful.

**Test scenarios:** Test expectation: none — documentation-only changes. Verification is manual review.

**Verification:** `README.md` install instructions are accurate for the new state (a fresh user install includes only the truly-required deps). `docs/manual-testing/backlog.md` is internally consistent — no rows reference shell-outs that no longer exist.

---

## Scope Boundaries

### Deferred to follow-up work

- **`libnftnl-rs` / `nftnl-rs` firewall backend rewrite.** Replace `iptables-restore` / `nft` shell-outs with native Rust netfilter bindings. Real engineering value (smaller deps, faster transitions) but major architectural undertaking; iptables is installed on every Linux already, so user-side benefit is small. Defer indefinitely.
- **`resolvconf` direct-write fallback.** Could write `/etc/resolv.conf` directly to remove the resolvconf shell-out. Race conditions with systemd-resolved make this unsafe. Defer indefinitely.
- **Onboarding-hardening: expanded `check_dependencies()` nudges.** Separate brainstorm (not yet written — flagged in session notes as the companion to this work). Adds nudges for the IRREDUCIBLE deps that still stay (iptables, nft, pfctl, ip, ps, curl-equivalent for users who somehow need it). Different concern than removing optional deps; separate plan.
- **Binary-size optimization.** This plan GROWS the binary by ~1-2MB (accepted trade). Shrinking strategies (LTO tuning, opt-level=z, debug-symbol stripping, dependency trimming) are a separate concern.

### Outside this plan's identity

- **Reimplementing WireGuard or OpenVPN in Rust.** vortix orchestrates them; it doesn't replace them. `wg-quick` and `openvpn` binaries are product behavior, not removable deps.
- **Cross-platform parity on Windows.** Windows is stubbed per origin NG8; this plan doesn't change that.

---

## Verification Strategy

**Per-unit verification** is defined in each implementation unit's "Verification" field.

**Cross-cutting verification:**

1. **Binary-size budget (R4):** Measure `du -h target/release/vortix` before any U1-U10 PR merges and after U11 lands. Total growth must be ≤ 2MB on `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`.
2. **Boundary checks (R5):** `cargo xtask check-platform-leak` / `check-protocol-leak` / `check-subprocess` continue to pass after every unit. The new `check-no-shell-regressions` from U11 also passes from U11 onward.
3. **Regression prevention (R6):** After U11 lands, manually add a `CommandSpec::oneshot("curl", vec![])` somewhere, verify the xtask fails, remove.
4. **End-to-end smoke (R3):** Walk through `docs/manual-testing/backlog.md` after all units ship. Every row that was previously "manual because we wanted real behavioral assertion" should still pass when manually exercised. None of the removed shell-outs should make a row impossible to verify.

**Fedora regression check:** The recently-added Fedora integration leg should pass throughout. Each unit's PR should explicitly verify `Integration / fedora-41` is green before merging — Fedora minimal is the most likely environment to expose any subtle behavior change.

---

## System-Wide Impact

- **Cargo.toml dependency tree grows.** New crates: `reqwest`, `socket2`, `arboard`, `system-configuration` (macOS-only), `sysinfo` (if chosen for U6 instead of /proc reading). Net binary growth budgeted at ≤ 2MB.
- **`vortix_process::CommandSpec` usage drops by ~12 distinct binaries.** What remains is the irreducible set: wg-quick / wg, openvpn, iptables-restore / nft / pfctl, resolvconf (conditional), and the kernel-firewall control surface. Future contributors look at `oneshot` calls and see "this is genuinely the product behavior" — clearer signal.
- **Test Dockerfiles shrink.** `tests/integration/Dockerfile` and `Dockerfile.fedora` drop unnecessary installs (`iputils-ping`, `procps` if no longer needed by vortix; verify per-step).
- **`docs/manual-testing/backlog.md` rows change.** Some rows become obsolete (the underlying behavior is now in-process and unit-testable); some rows stay (the high-level behavioral assertion still matters; the measurement mechanism changed).
- **Boundary check surface grows by one.** `check-no-shell-regressions` joins the existing three. Standard pattern; no architectural change.
- **macOS-only conditional compilation grows.** `system-configuration` is macOS-only; U7's changes use `#[cfg(target_os = "macos")]` consistently.
- **Onboarding error message improvement.** The Fedora-without-`which` bug class disappears completely — vortix no longer shells out to `which` anywhere.

---

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `reqwest` async integration introduces subtle behavior differences from `curl` (timeout semantics, default redirect policy, TLS verification mode, IPv6 fallback) | Med | Med | U9 carries an explicit "behavior parity test" suite (mock server with timeout/redirect/TLS scenarios); test-first execution-note enforces locking the contract before swapping. Redirect policy explicitly `Policy::none()` to match curl's `-L`-less default. |
| `system-configuration` crate doesn't cover all three macOS data points (netstat, lsof, scutil) | Med | Med | U7's "Open question" calls out plan-time verification. Fallback per data point: hand-rolled libc binding to SystemConfiguration.framework. Adds engineering cost but preserves outcome. |
| Raw ICMP socket via `socket2` fails on systems without CAP_NET_RAW capability | Low | Med | U10 specifies a TCP-connect-port-443 fallback. Documented in the function's doc comment. Test scenario covers the fallback path. |
| Binary growth exceeds 2MB budget | Low | Low | Per-unit binary-size monitoring at PR review time. If approaching budget, drop `arboard` (lowest-value swap — clipboard is "copy IP" convenience, not core function). |
| `libc::getifaddrs` doesn't expose every field today's `ip addr show` parses (peer addresses, address scope, link MTU vs interface MTU) | Low | Low | The fields vortix actually consumes are IPv4 address (string) and MTU (string). Both come from getifaddrs + /sys; verified by inspection of `parse_ip_addr_output()`. |
| `arboard` fails on a runner without a display server (headless CI) | High | Low | U8's test scenario covers headless fallback; arboard returns an `Err` instead of panicking. The "copy IP" action is best-effort; failing silently in headless mode is acceptable. |
| Each PR's review is small individually, but the bundled stack (12 PRs over weeks) creates rebase friction | Med | Low | Ship Phase A units in any order (they're independent). Phase B-D depend only on the trivial Phase A landing first. Phase E (U9, U10) intentionally lands last — minimizes its rebase risk by being the smallest set of remaining-pending PRs. |
| Integration test changes silently break the Fedora coverage (the recently-added matrix leg) | Med | Med | Every PR explicitly verifies `Integration / fedora-41` green before merge. The matrix is hard-gated; CI blocks the merge if it fails. |
| Telemetry-hot-path latency degrades from `reqwest` overhead (connection pool warm-up, TLS handshake) | Low | Low | `reqwest::Client` is `OnceLock`-initialized; connection pool reused across calls. TLS session resumption keeps subsequent calls fast. Measure before/after via `vortix doctor --json` timing field, if it exists. |

**Dependencies between units:**

```
Phase A: U1 (which residual) │ U2 (kill) │ U3 (uname/sw_vers)  — all independent
                                          ↓
Phase B: U4 (Linux iface) │ U5 (macOS iface) │ U6 (ps)  — all independent
                                          ↓
Phase C: U7 (netstat/lsof/scutil bundled)
                                          ↓
Phase D: U8 (arboard clipboard)
                                          ↓
Phase E: U9 (curl → reqwest) ─→ U10 (ping → socket2 ICMP)
                                          ↓
Phase F: U11 (xtask check-no-shell-regressions)
                                          ↓
Phase G: U12 (docs + Dockerfile cleanup)
```

Phases land in order. Within a phase, units are independent and can ship in parallel. U10 follows U9 because both touch tokio integration and landing reqwest first reduces conflict surface. U11 must land last (or after every U1-U10) because it would fail if any deprecated name remained.

---

## Alternative Approaches Considered

- **One mega-PR removing everything at once.** Rejected — review burden is enormous; behavioral diff is huge; rollback granularity is poor (revert one mistake = revert all twelve replacements). Per-unit PR cadence wins on every axis except calendar speed.
- **Group by platform (all macOS first, then all Linux).** Considered but rejected — the high-risk swap (reqwest) is cross-platform, and locking it behind "finish all macOS work first" delays the highest-value test (HTTP behavior parity on every platform). Risk-ascending order beats platform-first.
- **Skip the xtask regression guard (U11).** Considered — saves one PR. Rejected because the entire point of this plan is preventing the class of bug (false missing-dep error from a shell-out to an optional tool) that prompted it. Without U11, a contributor could re-add `CommandSpec::oneshot("which", ...)` six months from now and nobody would notice until a Fedora user filed an issue.
- **Use `ureq` for HTTP instead of `reqwest`.** Rejected per the brainstorm: vortix already has tokio; adding ureq's parallel sync-HTTP machinery would duplicate the runtime. User mandate: "if we have any binary installed, why install new one."
- **Hand-roll FFI to SystemConfiguration.framework for U7 instead of the `system-configuration` crate.** Rejected as default — the crate is Apple-blessed Rust bindings, well-supported, and removes three shell-outs in one swap. Kept as the fallback if plan-time verification reveals data-point gaps.

---

## Documentation Plan

- **`README.md`:** install instructions trimmed (U12).
- **`docs/manual-testing/backlog.md`:** row-by-row audit for obsolete references to removed shell-outs (U12).
- **`docs/ci-parity.md`:** add `cargo xtask check-no-shell-regressions` to the documented command set after U11 ships.
- **`CLAUDE.md`:** add a brief note in the Architectural Boundaries section that vortix is "shell-out minimal — only iptables/nft/pfctl/wg-quick/openvpn/resolvconf survive; everything else uses native Rust." Future Claude sessions see the convention.
- **No new docs.** This plan generates no net-new documentation files; all updates land in existing files.

---

## Open Questions

Resolvable at execution time, not blocking the plan:

1. **U7 plan-time:** does `system-configuration` crate cover `scutil --dns`-equivalent data? If not, which libc fallback (most likely `SCDynamicStoreCopyValue` via raw FFI)?
2. **U6 plan-time:** macOS shell-out for `ps` — verify exact location. Brainstorm assumed `vortix_platform_macos/socket_audit.rs`; could be elsewhere. Grep at execution time.
3. **U10 plan-time:** does the TCP-connect-443 fallback degrade the telemetry latency display readably ("~handshake latency" rather than ICMP RTT)? UI may need a small annotation. Decide based on observed values.
4. **U9 plan-time:** rustls vs native-tls feature flag for reqwest. Rustls is the default in this plan (smaller binary, fewer system deps), but if some platform requires native-tls (e.g. corporate-CA cases), revisit. Most likely rustls is fine for the public-internet endpoints vortix hits.
5. **U12 plan-time:** what specific rows in `docs/manual-testing/backlog.md` change vs delete? Per-row decision; tracked during U12 execution.

---

## References

- Origin requirements: [`docs/brainstorms/2026-05-30-system-dependency-reduction-requirements.md`](../brainstorms/2026-05-30-system-dependency-reduction-requirements.md)
- Triggering incident: Fedora integration test catching the `which`-missing bug ([PR #1 commit `fcf9508`](https://github.com/harshit-chaudhary07/vortix/pull/1/commits/fcf9508))
- Existing xtask check pattern: [`crates/xtask/src/main.rs`](../../crates/xtask/src/main.rs) — `check-platform-leak`, `check-protocol-leak`, `check-subprocess`
- Subprocess wrapper used by all shell-outs: [`crates/vortix/src/vortix_process/`](../../crates/vortix/src/vortix_process/)
- Current dep-check function (deferred scope; companion brainstorm): [`crates/vortix/src/vpn_runtime/mod.rs:492`](../../crates/vortix/src/vpn_runtime/mod.rs)
