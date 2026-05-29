---
plan: docs/plans/2026-05-30-001-refactor-system-dependency-reduction-plan.md
session_paused: 2026-05-30
session_resumed: 2026-05-30 (vortix-multi-2)
units_complete: [U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12]
units_remaining: []
---

# Session state — system-dependency reduction plan COMPLETE

All 13 implementation units shipped on `feat/multi-connection`
(PR #1). See the per-unit commit list under "What's shipped" for
hashes. The original mid-execution pause notes below are preserved
for historical context.

## Resume-session epilogue (vortix-multi-2)

- **U7** (Phase C: scutil/networksetup/netstat/lsof): shipped as
  commit `4151ede`. system-configuration crate covers DNS; libc +
  hand-rolled libproc FFI covers netstat-ib (`if_data.ifi_*bytes`)
  and lsof (`proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`). Compile-time
  `size_of` asserts pinned every struct against the Apple SDK header
  (24/136/24/80/120/528/768/792 bytes). The previous attempt's API
  friction was real — solved by mirroring `<sys/proc_info.h>` exactly
  rather than struggling with `CFPropertyList::downcast`'s `*const
  c_void` conversion path.
- **U9** (curl → reqwest): shipped as commit `0767e4e`. Single
  `OnceLock<reqwest::blocking::Client>` with `Policy::none()` to match
  curl's no-`-L` default; rustls-tls to avoid OpenSSL; test-first
  parity coverage via a hand-rolled `std::net::TcpListener` mock
  server (no new test deps).
- **U10** (ping → socket2): shipped as commit `caf926a`. Unprivileged
  `SOCK_DGRAM + IPPROTO_ICMPV4` (works on macOS and Linux with the
  default `ping_group_range`). 8-byte ICMP packet + RFC 1071
  checksum, hand-rolled. TCP-connect-to-port-443 fallback when the
  ICMP socket can't be opened. No tokio integration needed — the
  telemetry workers were already `std::thread::spawn`-based.
- **U11** (xtask shell-regression guard): shipped as commit `6c45dec`.
  `cargo xtask check-no-shell-regressions` enforces 18-name forbidden
  list (`curl, ping, which, pbcopy, xclip, wl-copy, xsel, ifconfig,
  ip, ps, netstat, lsof, scutil, networksetup, kill, pkill, uname,
  sw_vers`) at PR time. Mirrors check-platform-leak's
  same/prev/next-line annotation parser. Wired into `boundary.yml`.
- **U12** (docs cleanup): shipped in this commit. README "Runtime
  dependencies" table no longer lists `curl`. Architecture notes
  describe the post-plan state (libc::getifaddrs, SCDynamicStore,
  rustls-tls, libproc, etc.). `tests/integration/Dockerfile` and
  `Dockerfile.fedora` drop `procps` / `procps-ng`. `docs/ci-parity.md`
  documents the new `cargo xtask check-no-shell-regressions` step.

## CI fixups along the way

Two ancillary commits were needed:

- `f7acc2b` `fix(ci): rustfmt + linux clippy regressions from U4/U6/U8`
  — pre-existing rustfmt / clippy issues in 4 files that the prior
  session's per-unit `-p vortix --lib` runs missed (ci-parity trap 1).
- `f9cce78` + `e5b13e3` `fix(deny): scope cargo-deny scan to platforms
  we ship` — the BSL-1.0 / CDLA-Permissive-2.0 license failures on
  the Security Audit job came from Windows-only transitive deps that
  cargo-deny was scanning regardless. Setting `[graph].targets` to the
  six triples `dist-workspace.toml` ships drops the dead-weight code
  from the audit scope without allow-listing licenses we never link.
  Locked the deny.toml + dist-workspace.toml dependency in a comment.

# Original mid-execution pause notes (historical)

Picking this up in a future session. **PR #1 is the active branch** (`feat/multi-connection`) and contains all completed units below as separate commits. Do NOT branch off `main` — the plan was bundled into PR #1 at the user's direction; continue on the same branch.

## What's shipped (7 of 13 units, all on PR #1)

| Unit | Commit | What changed |
|---|---|---|
| U1 | `15d4ab0` | Residual `which` shell-outs in `cli/report.rs` replaced via new `utils::find_binary_path()` (walks `$PATH` directly, mirrors `binary_exists`). |
| U2 | `46cc2a5` | Direct `kill -15 <pid>` shell-out in `vortix_protocol_openvpn/tunnel.rs` replaced with `libc::kill(libc::pid_t::try_from(pid)?, libc::SIGTERM)`. Pattern-matched pkill fallback was handled later in U6. |
| U3 | `8a023d2` | `uname -r` (Linux + macOS) and `sw_vers -productVersion` (macOS) in `cli/report.rs::get_os_info` replaced with `libc::uname` + `libc::sysctlbyname("kern.osproductversion")`. Deleted the now-unused `cmd_stdout` helper. |
| U4 | `e1cfb32` | `ip addr show <iface>` in `vortix_platform_linux/interface.rs` replaced with `libc::getifaddrs` (IPv4) + `/sys/class/net/<iface>/mtu` reads. Deleted the `parse_ip_addr_output` string parser. |
| U5 | `3dafb82` | `ifconfig -l` in `vortix_platform_macos/interface_list.rs` replaced with `libc::getifaddrs` walk (dedup via HashSet, sorted output). |
| U6 | `bb308ca` | Three things in one commit:<br>1. Linux `ps -eo pid,args` in `interface.rs::get_wireguard_pid` → `/proc/[pid]/cmdline` walk via new `find_pid_with_cmdline_substrings`.<br>2. macOS `ifconfig <iface>` + `ps -ax -o pid,command` in `interface.rs` → `libc::getifaddrs` (single walk extracting both IPv4 and `ifi_mtu` from `ifa_data`) + `libc::proc_listpids` + `libc::proc_pidpath` walk.<br>3. OVPN's `pkill -f` fallback in `vortix_protocol_openvpn/tunnel.rs` → cfg-gated dispatch to per-platform `find_all_pids_with_cmdline_substring` + `libc::kill` loop. Annotated with `xtask:allow-platform-cfg`. |
| U8 | `cfe420e` | `pbcopy` / `xclip` / `wl-copy` / `xsel` shell-outs in `app/helpers.rs::copy_ip_to_clipboard` replaced with `arboard` crate (`default-features = false` to skip image/x11rb/zune deps for clipboard image support we don't use). |

## What's remaining

### U7 — netstat / lsof / scutil → `system-configuration` crate (macOS bundle)

**Status:** Started, reverted clean due to API friction.

**Where the previous attempt stalled:**
- Added `system-configuration = "0.7.0"` as `[target.'cfg(target_os = "macos")'.dependencies]` — that part is fine.
- Started `dns.rs` rewrite to replace `scutil --dns` with `SCDynamicStoreCopyValue("State:/Network/Global/DNS")`.
- Got tangled in the `CFPropertyList::downcast` chain — the system-configuration 0.7 crate's `SCDynamicStore::get(key)` returns `Option<CFPropertyList>`, and walking into nested `CFArray<CFString>` requires several careful downcasts via `core_foundation::propertylist::CFPropertyList`. Specifically `CFDictionary::find` returns a raw `*const c_void` that doesn't directly satisfy `CFPropertyList`; the conversion path needs `wrap_under_get_rule` with explicit lifetime care.

**Honest scope reassessment surfaced during the attempt:** all four macOS shell-outs in this unit (scutil, networksetup, netstat, lsof) **ship preinstalled on every macOS install**. They are NOT an onboarding cost the way `which` (Fedora minimal) or `curl` (Alpine) are. Replacing them is engineering-elegance work, not user-pain work.

**Recommendation for next session:** Either:
- **Skip U7 entirely.** Keep the macOS shell-outs as-is; nobody is missing these tools. Spend the session on U9 + U10 + U11 + U12 (real user wins).
- **Do U7 narrowly** — only the scutil swap via `system-configuration` (using the verified API pattern from the apple/swift-system-configuration crate docs or its examples directory). Skip netstat (needs libc::getifaddrs ifa_data parsing) and lsof (needs libc::proc_pidfdinfo + PROC_PIDFDSOCKETINFO — substantial libproc work).

If proceeding, the working API pattern from system-configuration 0.7.0 examples:
```rust
use system_configuration::dynamic_store::SCDynamicStoreBuilder;
use system_configuration::core_foundation::propertylist::CFPropertyList;
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::string::CFString;
// SCDynamicStoreBuilder::new(...).build() returns Option<SCDynamicStore>; use `?`.
// SCDynamicStore::get(key: impl Into<CFString>) returns Option<CFPropertyList>.
// CFPropertyList::downcast::<CFDictionary>() returns Option<CFDictionary>.
// CFDictionary::find returns *const c_void; wrap via TCFType::wrap_under_get_rule
//   inside unsafe to convert to CFPropertyList, then downcast again.
```

The friction was around the `*const c_void` → typed CFPropertyList conversion. Recommended path: see the [system-configuration crate's examples directory](https://github.com/mullvad/system-configuration-rs/tree/main/system-configuration/examples) for a working get-DNS pattern before re-attempting.

### U9 — `curl` → `reqwest` (telemetry HTTP) — the big one

**Plan note:** this unit has an `Execution note: test-first`. Start with a failing behavior-parity test before changing call sites in `core/telemetry.rs`. Six call sites at lines 223, 321, 386, 429, 603, 656.

**Specific traps to handle:**
- Existing `curl -s` invocation does NOT pass `-L` — so reqwest must be configured `redirect(reqwest::redirect::Policy::none())` to match.
- Existing `curl --max-time N` maps to `.timeout(Duration::from_secs(N))` on the reqwest client builder, not per-request.
- Use `reqwest = { default-features = false, features = ["rustls-tls", "json"] }` to avoid pulling OpenSSL.
- Build `reqwest::Client` once per process via `OnceLock` to reuse the connection pool.
- New test file: `crates/vortix/tests/telemetry_behavior_parity.rs`. Stand up a mock server (try `mockito` or just `tokio::net::TcpListener` for a hand-rolled minimal HTTP responder) and assert reqwest's timeout, redirect-default, TLS verification behavior matches what curl returned.

### U10 — `ping` → `socket2` raw ICMP

**Plan note:** depends on U9 (both touch tokio integration). Hand-roll ICMP echo packet (~12 bytes). Fallback to TCP-connect-to-port-443 when raw socket creation fails (no CAP_NET_RAW).

**Specific traps to handle:**
- `socket2 = "0.5"` as a dep.
- Create file `crates/vortix/src/core/icmp.rs` for the packet construction + send/receive.
- Wrap socket in `tokio::io::unix::AsyncFd` for reactor integration.
- Compute ICMP checksum per RFC 792 — common one-liner in Rust examples.
- Test against `127.0.0.1` for the happy path. Test against `10.255.255.1` for the timeout path.
- Document the TCP-443 fallback in the public function's doc comment.

### U11 — `cargo xtask check-no-shell-regressions`

**Goal:** Add a compile-time guard. New xtask subcommand in `crates/xtask/src/main.rs` that greps `crates/vortix/src/` for `CommandSpec::oneshot("(curl|ping|which|pbcopy|xclip|wl-copy|ifconfig|ip|ps|netstat|lsof|scutil|kill|uname|sw_vers)"` and fails the build if any match exists.

**Specific traps:**
- Allow `// xtask:allow-shell-regression: <reason>` annotations (parallel to the existing `xtask:allow-protocol-leak` pattern). The pkill replacement in U6 used `xtask:allow-platform-cfg` for the cross-layer reach — the same shape works here for legitimate exceptions.
- After U7 (if done) or after U9/U10, the blocklist applies cleanly. Run `cargo xtask check-no-shell-regressions` to verify zero violations after each unit.
- Wire into `.github/workflows/boundary.yml` as a new step alongside the existing three boundary checks.

### U12 — README + Dockerfile + backlog.md cleanup

**Goal:** Audit install instructions and test fixtures.

**Specific items:**
- `README.md` "Requirements" section: drop deps no longer needed (`which`, `iputils-ping` once U10 ships, `procps` once U6's deferred scanner.rs ps work ships, etc.).
- `tests/integration/Dockerfile` + `Dockerfile.fedora`: drop `iputils-ping` once U10 ships, `procps` once U6 expansion ships. Keep what test scripts still need.
- `docs/manual-testing/backlog.md`: walk each row referencing a removed shell-out; either delete (behavior is now in-process and unit-testable) or keep (high-level behavioral assertion still matters).

## Recommended next-session sequence

1. **Decide on U7** (skip vs narrow-scutil-only) — read the "Honest scope reassessment" above before deciding.
2. **U9** (curl → reqwest) — biggest user win; substantial focus needed. Plan a dedicated session.
3. **U10** (ping → raw ICMP) — second-biggest; also substantial.
4. **U11 + U12** — small wrap-up after U9/U10.

The pause point is clean: PR #1 builds, tests pass, all boundary checks pass. Next session can resume without rebasing pain.

## Files that DON'T match the plan (out-of-scope shell-outs noted during execution)

- `crates/vortix/src/core/scanner.rs` has additional `ps -p <pid> -o etime=` and `ps -p <pid> -o args=` shell-outs that weren't in the brainstorm. Out of scope for U6; potential follow-up.
- `crates/vortix/src/vortix_process/orphan_scan.rs` has a `ps -eo pid=,comm=` shell-out for startup orphan detection. Out of scope for U6; potential follow-up.
- `crates/vortix/src/vortix_platform_macos/dns.rs` has two `networksetup` shell-outs as second-level DNS fallback. Brainstorm didn't list them. macOS-only system tool; preinstalled. Probably stays.
