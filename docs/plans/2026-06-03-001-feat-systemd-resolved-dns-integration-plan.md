---
title: "feat: systemd-resolved DNS integration — drop the resolvconf gate on resolved-native distros"
date: 2026-06-03
status: active
type: feat
origin: docs/brainstorms/2026-06-03-systemd-resolved-dns-integration-requirements.md
issue: https://github.com/Harry-kp/vortix/issues/190
---

# feat: systemd-resolved DNS integration

## Summary

When systemd-resolved is detected on Linux, vortix takes over per-link DNS itself via `resolvectl` instead of leaning on `wg-quick`'s `resolvconf` shim. Removes the missing-dep error for Omarchy / NixOS-with-resolved / default-Fedora users and lets each tunnel register its own DNS — including secondaries, which today have `DNS =` stripped and discarded.

## Problem Frame

WireGuard `.conf` files commonly include `DNS = …` directives. On Linux, `wg-quick up` honours that line by shelling out to `resolvconf`. On distros that use systemd-resolved without the `systemd-resolvconf` shim package (Arch / Omarchy, NixOS with `services.resolved.enable = true`, stock Fedora Workstation), there is no `resolvconf` binary on PATH — wg-quick fails at the DNS step.

Vortix today predicts that failure upstream: `vpn_runtime::check_dependencies` returns `"resolvconf (systemd)"` as missing whenever the `.conf` has `DNS =` AND `resolvconf_works()` returns false. The user is blocked before `wg-quick` runs. Their only escape today is installing a shim package on a system that already exposes systemd-resolved as a perfectly good DNS manager.

The fix uses systemd-resolved's own API: `resolvectl dns <iface> <ips>` (set per-link DNS) and `resolvectl domain <iface> '~.'` (mark a link as the default resolver). Both ship with `systemd` itself, present on every resolved-using distro by definition. The same primitive also fixes a secondary-tunnel correctness gap — today secondary tunnels have `DNS =` stripped entirely so only the primary owns system DNS; with resolvectl, each tunnel registers its own per-link DNS without competing for catchall resolution.

---

## Requirements Traceability

| Requirement | Source | Units |
|---|---|---|
| Dep-check passes on systemd-resolved hosts without resolvconf | R1 | U4 |
| DNS registered via resolvectl when the new path is selected | R2 | U2, U3 |
| Secondaries get per-link DNS, scoped non-authoritative | R3 | U2, U3 |
| Fall back to existing resolvconf path on non-resolved hosts | R4 | U3, U4 |
| Fail-open on resolvectl failure | R5 | U3 |
| Cleanup on disconnect is implicit | R6 | U3 (verification) |

See origin: `docs/brainstorms/2026-06-03-systemd-resolved-dns-integration-requirements.md`.

---

## Key Technical Decisions

### Single trigger gate, not three scattered checks

Today's `is_systemd_resolved()`, `resolvconf_works()`, and the implicit `binary_exists("resolvectl")` are split across `utils.rs` and `vortix_platform_linux/dns.rs`. A new `use_resolvectl_path()` helper (in `utils.rs`, alongside the existing detectors) ANDs the three signals — symlink check + `resolvectl` on PATH + `resolvectl --version` probe succeeds within 10s — so every caller (dep-check, WgTunnel::up) makes the same decision. Eliminates the failure mode where dep-check says "OK, no resolvconf needed" but `WgTunnel::up()` then takes the resolvconf path because it checked something subtly different.

Probe timeout matches the existing `resolvconf_works` shape (10s, mirroring the openvpn version-probe defense in `vpn_runtime/openvpn.rs`).

### Strip-then-set always when gate is true

Even on a primary tunnel, when the resolvectl path is selected the `DNS = …` line is stripped from the wg-quick-fed config copy. We do not want wg-quick to attempt `resolvconf` and fail — failure formatting varies by distro, partial-success states are hard to detect, and the interface can come up with `wg-quick up` still returning non-zero. Strip-first matches what secondaries already do; the new code owns the post-`up` `resolvectl` call.

Today the temp-config write only fires for secondaries. This decision generalises that path: when `use_resolvectl_path()` is true, the strip-and-temp-write fires for primaries too. The existing temp-write infra (`write_secondary_temp_config`, per-session subdir, mode `0o600`) handles it as-is — only the predicate for "should I strip" changes.

### Wiring point: `WgTunnel::up()` (protocol layer)

`WgTunnel::up()` calls into `vortix_platform_linux::dns::set_link_dns(...)` directly after the `wg-quick up` subprocess returns success. Precedent: `vortix_protocol_openvpn::tunnel.rs:859` already imports `vortix_platform_linux::interface::find_all_pids_with_cmdline_substring` under a `cfg(target_os = "linux")` gate annotated with `// xtask:allow-platform-cfg`. Protocol→platform is an established boundary direction.

The alternative — orchestrate from `vpn_runtime` after `Tunnel::up()` returns — would keep the protocol layer pure of platform-specific helper calls, but introduces a new Linux-specific seam at the engine layer for a feature that has no cross-protocol analogue. Rejected.

### No new `DnsManager` port; `DnsResolver` stays read-only

`vortix_core/ports/dns.rs` declares `DnsResolver` for read-only DNS server inspection. Its doc-comment anticipates `apply`/`restore` growth, but introducing the port now would be speculative — `set_link_dns` / `clear_link_dns` are Linux-only operations called only from the WireGuard up/down path. Mutating helpers live as free functions in `vortix_platform_linux/dns.rs` next to the existing read-only `LinuxDns::get_dns_server`. If macOS or Windows ever needs a peer feature, lift to a port then.

### Fail-open via `tracing::warn!`, no toast in v1

If `wg-quick up` succeeded the kernel interface exists, routes are installed, packets flow. A subsequent `resolvectl dns` failure means resolution falls back to the system default. Tearing the tunnel down because of a DNS-management failure over-rotates on a non-security concern.

v1 surfaces the failure as `tracing::warn!` only (default-off via `RUST_LOG`, on for debug builds). No toast, no new event type, no `TunnelHandle` warnings field. Upgrade path: if user feedback shows the silent log isn't enough, add a toast by piggybacking on the existing `Message::Toast` event in a follow-up. Not now — the carrying cost (event plumbing) is not earned by a fail-open mode that essentially never fires on healthy systems.

### No explicit cleanup on disconnect

Per `man systemd-resolved.service`: "interfaces … are automatically reset … when removed". `wg-quick down` removes the kernel interface via `ip link delete`, at which point resolved drops the link's DNS / domain registration. U3's verification step exercises this on at least one distro in the matrix; if a leak is observed at plan-execution time, add an unconditional `resolvectl revert <iface>` call to `WgTunnel::down()`.

---

## System-Wide Impact

- **Linux WireGuard connect path** — the primary surface that changes behavior. Tunnel up/down on Linux moves from "wg-quick handles DNS" to "vortix handles DNS via resolvectl, on resolved hosts". The fallback path is unchanged.
- **Dep-check** (`vpn_runtime::check_dependencies`) — its missing-dep verdict for resolved hosts flips from "needs resolvconf" to "no missing dep" when the new path is selectable.
- **Manual-testing backlog** — adds rows for the resolvectl path; one existing row referencing "install systemd-resolvconf" needs updating or replacing.
- **README** — Linux install instructions drop the resolvconf nudge for resolved distros.
- **No UI surface change** — Connection Details, Security Guard, sidebar render identically. No new sigil, no new panel, no new keybinding.
- **No protocol-leak boundary violations** — resolvectl is a systemd userspace tool, not a protocol binary (`wg`, `wg-quick`, `openvpn`). No `// xtask:allow-protocol-leak` annotations needed. New `cfg(target_os = "linux")` blocks in `vortix_protocol_wireguard/tunnel.rs` need `// xtask:allow-platform-cfg` annotations.

---

## Implementation Units

### U1. Capture-aware DNS strip helper

**Goal:** Refactor `strip_dns_directive` to return both the cleaned text AND the captured DNS IP list, so callers downstream can pass the IPs to `resolvectl`.

**Requirements:** R2, R3 (foundation).

**Dependencies:** None.

**Files:**
- `crates/vortix/src/vortix_protocol_wireguard/tunnel.rs` — rename / replace `strip_dns_directive` with `strip_and_capture_dns_directive(text: &str) -> (String, Vec<String>)`. Keep the case-insensitive matching and verbatim-preservation guarantees from today's helper.
- `crates/vortix/src/vortix_protocol_wireguard/tunnel.rs` (tests module) — extend existing strip tests with capture-list assertions; add new tests for the IP-parsing branches.

**Approach:**
- Single-pass scan over `text.split_inclusive('\n')`, same as today's helper. When a line matches the DNS directive, parse the RHS into a `Vec<String>` of IPs (comma-separated, whitespace trimmed, IPv4 + IPv6 both accepted, trailing `#`/`;` comments stripped) and append to the captured list. When the line doesn't match, append it verbatim to the output buffer.
- Captured list preserves source order across multiple `DNS =` lines (a `.conf` may have several).
- Helper is pure (no I/O); lives in the same module as today's `strip_dns_directive`.

**Patterns to follow:** Existing `strip_dns_directive` in `crates/vortix/src/vortix_protocol_wireguard/tunnel.rs`. The case-insensitive prefix-matching idiom (`.strip_prefix(|c: char| c == 'D' || c == 'd')` chain).

**Test scenarios:**
- Empty config → returns (`""`, `[]`).
- Config with no `DNS =` line → returns (input verbatim, `[]`).
- Config with single `DNS = 1.1.1.1` → returns (stripped, `["1.1.1.1"]`).
- Config with comma-separated `DNS = 1.1.1.1, 8.8.8.8` → returns (stripped, `["1.1.1.1", "8.8.8.8"]`).
- Config with multiple `DNS =` lines → captures every IP across lines in source order.
- Case-insensitive directive name: `dns = 1.1.1.1`, `Dns = 1.1.1.1`, `DNS = 1.1.1.1` all captured identically.
- Whitespace variation around `=`: `DNS=1.1.1.1`, `DNS =1.1.1.1`, `DNS  =  1.1.1.1` all captured identically.
- IPv6: `DNS = 2001:db8::1` captured as `["2001:db8::1"]`.
- Mixed IPv4+IPv6: `DNS = 1.1.1.1, 2001:db8::1` captures both in order.
- Trailing inline comment: `DNS = 1.1.1.1  # corp resolver` captures `["1.1.1.1"]` (comment dropped).
- `dns_search = corp.example.com` (looks DNS-ish but isn't the directive) → input preserved verbatim, no IPs captured.
- A `.conf` with NO `DNS =` lines but a `# DNS notes` comment → input preserved, no IPs captured (comment lines untouched).

**Verification:** Cargo tests pass. The strip-behavior of the renamed function is byte-identical to the previous `strip_dns_directive` for any input that contained DNS lines (verifiable by reusing existing strip-equivalence tests).

---

### U2. Linux resolvectl helpers and trigger gate

**Goal:** Add the platform-side primitives that U3 will call: a `set_link_dns` mutator, a `resolvectl_works` probe, and a single `use_resolvectl_path` trigger gate.

**Requirements:** R1, R2, R3 (foundation).

**Dependencies:** None (parallel with U1).

**Files:**
- `crates/vortix/src/vortix_platform_linux/dns.rs` — add `set_link_dns(iface: &str, ips: &[String], authoritative: bool) -> Result<(), DnsError>` (new free function) alongside the existing read-only `LinuxDns::get_dns_server`. Define a small `DnsError` enum if one doesn't already exist locally.
- `crates/vortix/src/utils.rs` — add `pub(crate) fn resolvectl_works() -> bool` next to the existing `resolvconf_works()`. Add `pub(crate) fn use_resolvectl_path() -> bool` that ANDs `is_systemd_resolved()` + `resolvectl_works()`. Both `cfg(target_os = "linux")` gated with `// xtask:allow-platform-cfg` annotations matching the existing helpers in this file.
- `crates/vortix/src/vortix_platform_linux/dns.rs` (tests) — unit tests for `set_link_dns` exercising both the authoritative and non-authoritative branches via the `CommandSpec` mockable test path used elsewhere in the crate.
- `crates/vortix/src/utils.rs` (tests) — unit tests for `resolvectl_works` and `use_resolvectl_path` covering binary-present / binary-missing / probe-timeout branches.

**Approach:**
- `set_link_dns(iface, ips, authoritative=true)` issues two `resolvectl` invocations via `CommandSpec::oneshot`: first `resolvectl dns <iface> <ip1> <ip2> ...`, then `resolvectl domain <iface> ~.`. Both wait synchronously with a short timeout (5s suggested; align with `resolvconf_works`'s 10s if the implementer prefers consistency). If either call exits non-zero, return `Err`; the caller is responsible for the fail-open `tracing::warn!`.
- `set_link_dns(iface, ips, authoritative=false)` issues only the first call (`resolvectl dns <iface> ...`). Secondary tunnels register DNS without claiming the catchall.
- `resolvectl_works()` mirrors `resolvconf_works()`: `binary_exists("resolvectl")` first (cheap), then `resolvectl --version` with a 10s `CommandSpec::timeout(...)`. Returns `true` only when both pass.
- `use_resolvectl_path()` returns `is_systemd_resolved() && resolvectl_works()`. Single accessor; all callers share it.

**Patterns to follow:**
- `resolvconf_works()` in `crates/vortix/src/utils.rs` for the probe shape (binary-check then version-probe with timeout).
- The existing read-only `resolvectl status` shell-out in `crates/vortix/src/vortix_platform_linux/dns.rs:23` for the `CommandSpec` invocation idiom.
- `// xtask:allow-platform-cfg` annotations on `is_systemd_resolved` (line ~945 in utils.rs).

**Test scenarios:**
- `resolvectl_works()` returns `true` when binary present and version probe succeeds.
- `resolvectl_works()` returns `false` when binary missing (no shell-out attempted).
- `resolvectl_works()` returns `false` when binary present but version probe times out.
- `resolvectl_works()` returns `false` when probe exits non-zero.
- `use_resolvectl_path()` returns `true` when both detectors pass.
- `use_resolvectl_path()` returns `false` when `is_systemd_resolved()` is false (resolvectl probe not attempted; cheap-fail-first).
- `use_resolvectl_path()` returns `false` when systemd-resolved present but `resolvectl_works()` false.
- `set_link_dns("wg0", &["1.1.1.1"], true)` issues `resolvectl dns wg0 1.1.1.1` then `resolvectl domain wg0 ~.` (assert via mocked CommandSpec recorder).
- `set_link_dns("wg0", &["1.1.1.1", "8.8.8.8"], false)` issues only the dns call with both IPs as args, no domain call.
- `set_link_dns("wg0", &["2001:db8::1"], true)` — IPv6 arg passed through.
- `set_link_dns` returns `Err` when the `dns` call exits non-zero (no `domain` call attempted).
- `set_link_dns` returns `Err` when the `domain` call exits non-zero (dns call already succeeded; partial state is acceptable, error returned).

**Verification:** Cargo tests pass. `cargo xtask check-platform-leak` stays green (new `cfg(target_os = "linux")` blocks carry annotations). `cargo xtask check-subprocess` accepts the new `resolvectl` invocations (resolvectl is not protocol-tagged).

---

### U3. Wire resolvectl into `WgTunnel::up()` and add fail-open handling

**Goal:** Tie U1 and U2 together — when `use_resolvectl_path()` is true, strip DNS from the user's `.conf`, run `wg-quick up` against the stripped copy, then register DNS via `set_link_dns` with primary/secondary scoping. Behavior on non-resolved Linux hosts is unchanged.

**Requirements:** R2, R3, R4, R5, R6.

**Dependencies:** U1 (capture-aware strip), U2 (platform helpers).

**Files:**
- `crates/vortix/src/vortix_protocol_wireguard/tunnel.rs` — modify `WgTunnel::up()`. Generalise the existing secondary-only strip-and-temp-write path so it ALSO fires for primary tunnels when `use_resolvectl_path()` returns true. After `wg-quick up` returns success, on the resolvectl path, call `vortix_platform_linux::dns::set_link_dns(iface, captured_ips, authoritative=!self.is_secondary)`. On error, emit `tracing::warn!` and continue; `up()` returns Ok.
- `crates/vortix/src/vortix_protocol_wireguard/tunnel.rs` (tests) — add integration-shaped tests using the existing `WgTunnel` test harness (which appears to mock CommandSpec). Cover the four-quadrant matrix below.

**Approach:**
- Inside `WgTunnel::up()`, compute `let on_resolved_path = cfg!(target_os = "linux") && utils::use_resolvectl_path();` at function entry (or equivalent). Annotate the `cfg` access with `// xtask:allow-platform-cfg: resolvectl path is Linux-only DNS plumbing`.
- Strip predicate becomes: `should_strip = self.is_secondary || on_resolved_path`. (Today: `self.is_secondary` only.) When `should_strip` is true, run today's temp-write path with the new `strip_and_capture_dns_directive` helper from U1; capture the IP list.
- After `wg-quick up` returns Ok, gate the new step on `on_resolved_path && !captured_ips.is_empty()`. Call `set_link_dns(&handle.interface_name, &captured_ips, !self.is_secondary)`. On `Err`, log `tracing::warn!(target: "vortix::wireguard", iface = %iface, err = %e, "resolvectl set_link_dns failed; tunnel is up but DNS not registered")` and proceed.
- `WgTunnel::down()` requires no change — `wg-quick down` removes the kernel interface and resolved drops the per-link state automatically (verified at execution time; if the manual-testing matrix reveals a leak, add an unconditional `resolvectl revert <iface>` call here in a follow-up commit, deferred from this unit).

**Patterns to follow:**
- The existing secondary-strip flow in `WgTunnel::up()` for the temp-write idiom (`write_secondary_temp_config`, basename preservation, mode `0o600`).
- `vortix_protocol_openvpn/tunnel.rs:859` for the cross-crate `cfg(target_os = "linux")` import-and-call pattern from a protocol crate.
- `tracing::warn!` invocations elsewhere in the wireguard module (e.g., the macOS `.name`-file warn at `tunnel.rs:227`).

**Test scenarios:**

*On systemd-resolved hosts (gate=true):*
- Primary tunnel + config has `DNS = 1.1.1.1`: strip fires, captured IP passed to `wg-quick up` (verify temp-file content), `set_link_dns(iface, ["1.1.1.1"], true)` called after up returns Ok.
- Secondary tunnel + config has `DNS = 1.1.1.1`: strip fires (existing path), `set_link_dns(iface, ["1.1.1.1"], false)` called after up returns Ok (was: stripped and discarded).
- Primary tunnel + config has NO `DNS =`: strip step still runs (no-op for the IP list, byte-identical config written to temp) — keeps the code path uniform; `set_link_dns` NOT called (empty captured list).
- `set_link_dns` fails post-`wg-quick up`: `up()` returns Ok with the TunnelHandle, tracing::warn! observed, tunnel-up side-effects (handle present) unchanged.

*On non-resolved Linux hosts (gate=false):*
- Primary tunnel: no strip, wg-quick up runs against the user's original config (byte-identical to today).
- Secondary tunnel: strip fires via the existing path, DNS discarded (byte-identical to today). `set_link_dns` NOT called.

*Cross-cutting:*
- Verify `cargo xtask check-platform-leak` stays green after the new `cfg(target_os = "linux")` block in `tunnel.rs` is annotated.
- Verify `cargo xtask check-protocol-leak` stays green — resolvectl is not a protocol binary.

**Execution note:** When implementing, write the integration-shaped tests for the four-quadrant gate matrix first; the wiring code is small but the gate combinations are where regressions hide. Test-first on this unit specifically.

**Verification:**
- Tests above pass on Linux CI lanes.
- macOS CI builds the crate (the `cfg(target_os = "linux")` gate compiles the new branch out on darwin).
- `cargo xtask check-platform-leak` green.
- Manual: on a real systemd-resolved host (Omarchy or Fedora), `vortix up <wg-profile-with-DNS>` connects without resolvconf installed; `resolvectl status <iface>` shows the DNS server registered; `resolvectl status <iface>` after `vortix down` shows no per-link DNS (R6).

---

### U4. Narrow the resolvconf gate in `check_dependencies`

**Goal:** Make the dep-check stop returning `"resolvconf (systemd)"` as missing when the new resolvectl path is available. Behavior on non-resolved hosts is unchanged.

**Requirements:** R1, R4.

**Dependencies:** U2 (the `use_resolvectl_path` helper is what we gate on).

**Files:**
- `crates/vortix/src/vpn_runtime/mod.rs` — modify the `Protocol::WireGuard` branch of `check_dependencies` around line 576. New shape: `if wireguard_config_has_dns(config_path) && !use_resolvectl_path() && !resolvconf_works()` → push the appropriate missing-dep label. Today the outer condition is `wireguard_config_has_dns && !resolvconf_works`; the `use_resolvectl_path` short-circuit is the only added clause.
- `crates/vortix/src/vpn_runtime/mod.rs` (tests, or wherever existing dep-check tests live) — add the four scenarios below.

**Approach:**
- Single boolean change. The existing inner `if is_systemd_resolved() { …"resolvconf (systemd)"… }` branch is preserved as the fallback message for the rare case where `is_systemd_resolved()` is true but `resolvectl_works()` is false (e.g., resolvectl service crashed, broken systemd install) — under those conditions the user does need the shim, and we still tell them so.

**Patterns to follow:** The existing OpenVPN version-probe branching in the same function (`Protocol::OpenVPN` arm) for the "feature-gate dep-check based on runtime probe" idiom.

**Test scenarios:**
- Config has DNS, host is resolved + resolvectl works → returns empty missing-dep list (was: returns `"resolvconf (systemd)"`).
- Config has DNS, host is resolved but resolvectl probe fails → returns `"resolvconf (systemd)"` (fallback, unchanged from today's resolved-host behavior).
- Config has DNS, host is NOT resolved + resolvconf missing → returns `"resolvconf"` (unchanged).
- Config has DNS, host is NOT resolved + resolvconf works → returns empty missing-dep list (unchanged).
- Config has NO DNS, any host → returns empty missing-dep list (unchanged on every path).

**Verification:** Tests above pass. The existing Ubuntu / Debian test lanes (where resolvconf is preinstalled) remain green with no changes required.

---

### U5. Manual-testing rows and README update

**Goal:** Document the new path so it can be verified by hand and so install instructions stop pointing at the obsolete workaround.

**Requirements:** Per origin Outstanding Questions #4 and #5.

**Dependencies:** U3 must land first so the rows describe shipping behavior.

**Files:**
- `docs/manual-testing/backlog.md` — add rows for: (a) Omarchy / Arch+resolved fresh-install WG connect with `DNS =` in the .conf, no resolvconf installed; (b) Fedora Workstation default WG connect with `DNS =`, no `openresolv` installed; (c) multi-tunnel on resolved (primary + secondary up, verify both interfaces have DNS registered via `resolvectl status`, only primary has `Default Route: yes`); (d) fail-open scenario (systemctl-stop resolved between wg-quick up and the resolvectl call, observe tracing::warn + tunnel stays up).
- `docs/manual-testing/backlog.md` — remove or update any existing row that instructs the tester to install `systemd-resolvconf` as a setup precondition for Arch / Fedora resolved hosts.
- `README.md` — Linux install instructions: remove the "you may need to install `systemd-resolvconf` / `openresolv`" line for Arch / Fedora users; add a one-liner noting that resolved-using distros are now first-class.

**Approach:**
- Match the existing manual-testing row format (one row per scenario, columns for setup / steps / pass signal). See `docs/manual-testing/multi-connection.md` referenced from CLAUDE.md for the density principle if a new file is needed instead of a backlog row.
- README touch is minimal — drop one line, add one line. No reorganization.

**Test scenarios:** None — docs-only unit. `Test expectation: none — manual-testing documentation and README content; verified by reviewer reading the diff.`

**Verification:** Reviewer can read the new manual-testing rows and execute them. `git grep "systemd-resolvconf"` in `README.md` returns no install-instruction context.

---

## Scope Boundaries

### In Scope

- Linux-only DNS path change driven by systemd-resolved detection.
- Behavior change in `WgTunnel::up()`, `vpn_runtime::check_dependencies`, and the strip helper.
- New helpers in `vortix_platform_linux/dns.rs` and `utils.rs`.
- Manual-testing rows and README update.

### Deferred for later

From the origin document:
- Full systemd-networkd integration (`.netdev` / `.network` unit files, `networkctl` orchestration). Separate brainstorm if demand surfaces.
- DNS-manager indicator on the Security Guard panel (density-via-signalling violation per CLAUDE.md).
- Per-tunnel domain-suffix split-DNS (no config slot exists for it in vortix today).
- NetworkManager-specific DNS path (wg-quick + NM-shipped shim already works).
- Direct `/etc/resolv.conf` writes (already a non-goal in `docs/brainstorms/2026-05-30-system-dependency-reduction-requirements.md`).
- macOS and Windows DNS-path changes.

### Deferred to Follow-Up Work

Plan-local items that may surface during implementation but should not block this plan:
- Lift `set_link_dns` / `clear_link_dns` into a `DnsManager` port if macOS or Windows ever needs a peer feature (no demand today).
- Upgrade the fail-open `tracing::warn!` to a user-visible toast if telemetry shows the silent log isn't surfacing real failures.
- Add an unconditional `resolvectl revert <iface>` call in `WgTunnel::down()` if U3's manual-testing matrix reveals a per-link leak.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `resolvectl_works()` probe hangs the connect on a wedged resolved/DBus. | Low | Med | 10s `CommandSpec` timeout. On timeout, `use_resolvectl_path()` returns false → falls back to today's resolvconf gate → user sees the existing missing-dep message. Strictly no worse than today. |
| Generalising the strip path to primaries on resolved hosts breaks an existing primary-DNS test. | Low | Low | U1's tests assert byte-equivalence of the strip behavior; U3's tests cover the four-quadrant gate matrix including "primary on non-resolved Linux = no strip" path. |
| `resolvectl` arg order or flag spelling differs across systemd versions (older Debian backports). | Low | Med | `resolvectl dns <iface> <ips...>` and `resolvectl domain <iface> ~.` are stable since systemd 229 (2016). All supported distros ship systemd ≥ 245. If older, the resolvectl probe in `resolvectl_works()` will either succeed (current syntax) or fail (path falls back to resolvconf). |
| `wg-quick up` on the resolvectl path takes longer than the existing 35s connect timeout because the strip-and-temp-write path adds latency. | Very low | Low | The strip/temp-write is already what secondaries do today with no observed latency issues. New work is two `resolvectl` calls (~10ms each on a healthy resolved). Connect timeout stays at 35s. |
| Resolved auto-clear on `ip link delete` doesn't fire on some distro variant. | Low | Low | Verified manually in U3's verification step. If reproduced, add the explicit `resolvectl revert <iface>` call in a follow-up — code site already identified (`WgTunnel::down`). |
| User has resolved running but `/etc/resolv.conf` is hand-edited to bypass it. | Low | Low | `is_systemd_resolved()` symlink check returns false → falls back to resolvconf path. User's bypass intent is preserved. No regression. |

---

## Outstanding Questions

Resolved during planning:

- **Single PR or split?** — Single PR. Units U1+U2+U3 deliver the behavior; U4 is a one-line gate change that without U3 would just make dep-check too lenient; U5 documents the shipped state. Splitting into landings doesn't reduce review burden meaningfully.
- **Where does resolvectl logic live?** — Free functions in `vortix_platform_linux/dns.rs`, no new port. See "No new `DnsManager` port" decision.
- **Wiring point?** — `WgTunnel::up()` in the protocol layer. See "Wiring point" decision.
- **Manual-testing rows?** — Covered in U5.
- **README update?** — Covered in U5.

Deferred to implementation:

- Exact subprocess timeout for `set_link_dns` calls (5s vs 10s) — implementer's call based on what feels right for the connect-success hot path.
- Whether to keep `strip_dns_directive` as a thin wrapper around `strip_and_capture_dns_directive` or replace its callers wholesale — depends on how many callers exist; trivial to discover at edit time.
- Whether `DnsError` already exists locally or needs a small new enum in `vortix_platform_linux/dns.rs` — file is small; quick to confirm.

---

## References

- Origin requirements: `docs/brainstorms/2026-06-03-systemd-resolved-dns-integration-requirements.md`
- Origin issue: https://github.com/Harry-kp/vortix/issues/190
- Existing strip helper: `crates/vortix/src/vortix_protocol_wireguard/tunnel.rs` (`strip_dns_directive`, `write_secondary_temp_config`).
- Existing detection helpers: `crates/vortix/src/utils.rs` (`is_systemd_resolved`, `resolvconf_works`, `wireguard_config_has_dns`).
- Existing dep-check site: `crates/vortix/src/vpn_runtime/mod.rs` (`Protocol::WireGuard` arm of `check_dependencies`, line ~576).
- Existing read-only resolvectl shell-out (precedent for the CommandSpec invocation idiom): `crates/vortix/src/vortix_platform_linux/dns.rs`.
- Cross-crate `cfg(target_os = "linux")` import precedent: `crates/vortix/src/vortix_protocol_openvpn/tunnel.rs:859`.
- Boundary checker behavior: `crates/xtask/src/main.rs` (`check_platform_leak`, `check_protocol_leak`).
- CLAUDE.md guidance: full CI parity before push (`docs/ci-parity.md`); density-via-signalling for UI; manual-testing-row convention.
- Companion prior brainstorm (DNS-direct-write non-goal): `docs/brainstorms/2026-05-30-system-dependency-reduction-requirements.md`.
