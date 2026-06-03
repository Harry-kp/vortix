---
title: systemd-resolved DNS integration — drop the resolvconf gate on resolved-native distros
date: 2026-06-03
status: ready-for-plan
type: enhancement
issue: https://github.com/Harry-kp/vortix/issues/190
---

# systemd-resolved DNS integration — drop the resolvconf gate on resolved-native distros

## Summary

When systemd-resolved is detected on Linux, vortix takes over per-link DNS itself via `resolvectl` instead of leaning on `wg-quick`'s `resolvconf` shim. This removes the missing-dep error for resolved-native distros (Omarchy, NixOS-with-resolved, default-Fedora) and lets each tunnel register its own DNS — including secondaries, which today get their `DNS =` line stripped entirely.

## Problem Frame

WireGuard `.conf` files commonly include `DNS = …` directives. On Linux, `wg-quick up` honours that line by shelling out to `resolvconf` to register the DNS server(s) for the new interface. On distros that use systemd-resolved as their DNS manager *without* the `systemd-resolvconf` shim package (Arch / Omarchy out-of-the-box, NixOS with `services.resolved.enable = true`, a stock Fedora Workstation that hasn't explicitly installed `openresolv`), there is no `resolvconf` binary on PATH. `wg-quick` errors at the DNS step and the user is stuck.

Vortix today predicts that failure and blocks the connect upstream in `vpn_runtime::check_dependencies`: when the `.conf` contains `DNS =` AND `resolvconf_works()` returns false, the user gets a `Missing tools: resolvconf (systemd)` error and the connect never runs. Their workaround is to install `systemd-resolvconf` (Debian-derived) or `openresolv` (Arch / Fedora) — a shim package on a system that already has a perfectly good DNS manager.

The user from #190 explicitly refuses that workaround: they don't want extra packages just to wrap a DNS API their distro already exposes. The systemd-resolved API in question is `resolvectl dns <iface> <ips>` (set per-link DNS) and `resolvectl domain <iface> '~.'` (mark the link as the default DNS resolver) — both first-party tools shipped with systemd, present on every resolved-using distro by definition.

Same primitive also unblocks a secondary-tunnel correctness gap: today vortix strips `DNS = …` from secondary configs entirely (only the primary may own system DNS via wg-quick's resolvconf path), so a user with two tunnels up loses the secondary's DNS server completely. With `resolvectl`, each tunnel can have its own per-link DNS registered, scoped so it doesn't compete with the primary's catchall resolver.

## Requirements

### R1 — Dep-check passes on systemd-resolved hosts without resolvconf

When `is_systemd_resolved()` is true AND `resolvectl` is on PATH AND a probe (`resolvectl --version` or equivalent) succeeds, the existing `resolvconf` missing-dep error must not fire — regardless of whether the user's `.conf` contains a `DNS = …` line. The connect proceeds.

### R2 — DNS registered via resolvectl when the new path is selected

After `wg-quick up <stripped-conf>` succeeds, vortix calls `resolvectl dns <iface> <ip1> <ip2> …` with the IP list parsed from the original (pre-strip) `DNS =` directive. For the primary tunnel, vortix also calls `resolvectl domain <iface> '~.'` so the link becomes the default catchall resolver, matching what `wg-quick`'s resolvconf path would have done.

### R3 — Secondaries get per-link DNS, scoped non-authoritative

For a secondary (non-primary) tunnel under the new path, vortix calls `resolvectl dns <iface> <ips>` but NOT `resolvectl domain <iface> '~.'`. Result: the secondary's DNS is reachable on that link (answers reverse lookups for AllowedIPs ranges; usable for direct queries targeted at the link) but does not compete with the primary's resolver for general hostname resolution. This is strictly better than today's "DNS stripped and discarded" behaviour for secondaries.

### R4 — Fall back to existing resolvconf path on non-resolved hosts

When `is_systemd_resolved()` is false, behaviour is unchanged: wg-quick handles DNS via resolvconf as before, and the existing missing-dep error fires when `resolvconf_works()` returns false. NetworkManager / openresolv / nscd / no-DNS-manager hosts see no change.

### R5 — Fail-open on resolvectl failure

If `wg-quick up` succeeds but the subsequent `resolvectl dns` or `resolvectl domain` call fails (resolved service crashed mid-connect, permission denied, etc.), the connect completes with a warn-level log entry and a toast describing the failure. The tunnel stays up. Justification: IP routing is the security boundary; DNS misregistration degrades resolution but does not leak traffic.

### R6 — Cleanup on disconnect is implicit

`wg-quick down <iface>` removes the kernel interface, at which point systemd-resolved auto-clears the link's DNS / domain registration (resolved's documented behaviour for link removal). Vortix does NOT need to issue an explicit `resolvectl revert <iface>` — but plan-time should add a one-line verification that this still holds on the supported distro matrix.

## Removed / changed behaviors

| Today | After this change |
|---|---|
| `vpn_runtime::check_dependencies` returns `"resolvconf (systemd)"` as a missing tool on resolved hosts whenever the `.conf` has `DNS =`. | The `is_systemd_resolved()` branch of the check returns "no missing dep" — vortix's own resolvectl path handles DNS, no shim required. The error message itself is not deleted (it still fires on non-resolved hosts without resolvconf), only its trigger condition narrows. |
| Secondary `WgTunnel::up()` strips `DNS = …` from the temp config and discards the value. The secondary tunnel runs with no per-link DNS. | Strip still happens (wg-quick must not try to set DNS itself on the new path, regardless of primary/secondary), but the captured DNS server list is passed to a new `LinuxDns::set_link_dns` step that runs after `wg-quick up`. On the resolvconf fallback path, behaviour is unchanged — the strip-and-discard remains the right move there. |
| `wg-quick`'s built-in `resolvconf -a tun.<iface> …` invocation is the sole DNS-registration mechanism on Linux. | On resolved hosts, wg-quick never sees the `DNS =` line (it's stripped before wg-quick runs) and so never invokes `resolvconf`. Vortix's post-up `resolvectl` calls are the DNS-registration mechanism. On non-resolved hosts, wg-quick + resolvconf remains the path. |

Nothing is fully *removed* by this change. The resolvconf shim's existing code path stays — it's the fallback for non-resolved Linux. The `is_systemd_resolved()`, `resolvconf_works()`, `wireguard_config_has_dns()`, and `strip_dns_directive()` helpers all stay (some get extended; none get deleted).

## Goals

1. **A clean systemd-resolved system imports and connects a WireGuard profile with `DNS = …` without installing `resolvconf` / `openresolv` / `systemd-resolvconf`.** Verified on Omarchy / Arch + resolved (the issue reporter's setup) plus default Fedora Workstation (resolved is the default since F33).
2. **Secondary-tunnel DNS goes from "stripped and discarded" to "registered on the link, non-authoritative" on resolved hosts.** Multi-tunnel users see strictly better DNS behaviour on Linux without configuration changes.
3. **Zero behaviour change on non-resolved Linux hosts.** Ubuntu-with-resolvconf, NetworkManager-managed Fedora variants, NixOS with `services.resolved.enable = false`, and Alpine see byte-identical behaviour to today.
4. **The new path is invisible when it works.** No new panels, no new sigils, no new keybindings. The Security Guard, Connection Details, and sidebar render identically; the only user-visible artefact is the *absence* of the old missing-dep error.

## Non-goals / Out of scope

- **Full systemd-networkd integration.** The issue title mentions networkd, but the reporter's actual block is the resolvconf gate. Managing tunnels as `.netdev` / `.network` unit files under `/etc/systemd/network/` and driving them with `networkctl` is a substantially larger architectural shift (persistent on-disk state, conflicts with vortix's ephemeral session model, different up/down semantics). Defer to a separate brainstorm if there's demand.
- **DNS-manager indicator on the Security Guard panel.** A "DNS via: resolvectl / resolvconf / none" line would make the new mechanism legible to a curious user, but it adds carry cost (a row every Linux user pays for) for value that mostly matters to one debugger of a rare failure mode. Density-via-signalling per CLAUDE.md says no. Re-evaluate if real users ask for it.
- **Per-tunnel domain-suffix split-DNS.** True split-DNS on resolved (`resolvectl domain <iface> '~corp.example.com'`) requires knowing the tunnel's domain suffix. WireGuard `.conf` has no standard field for this, and vortix exposes no UI / config knob for it. Out of scope; secondaries get the non-authoritative floor described in R3.
- **NetworkManager-specific DNS path.** NM ships its own resolvconf-compatible shim and its own wg-quick integration; the issue doesn't reproduce there. Not touched.
- **Direct `/etc/resolv.conf` writes.** Already a non-goal in `docs/brainstorms/2026-05-30-system-dependency-reduction-requirements.md` because of races with resolved. `resolvectl` avoids the file entirely by talking to resolved over DBus / Varlink under the hood.
- **macOS and Windows.** Issue is Linux-specific; this brainstorm covers Linux only.

## Key technical decisions

### Detection: symlink + binary + version probe, all three must pass

`is_systemd_resolved()` already checks `/etc/resolv.conf` for a symlink into `/run/systemd/resolve/`. That's necessary but not sufficient — the file could be a stale symlink or resolved could be installed but not running. The new path engages only when all three signals agree: (a) the symlink points at resolved, (b) `resolvectl` is on PATH, (c) a `resolvectl --version` probe succeeds within a 10s timeout (matching the existing `resolvconf_works` probe shape). Any failure routes back to the resolvconf fallback path.

### Strip-then-set on the primary, not "let wg-quick try resolvconf and recover"

Even on resolved hosts the primary's `DNS =` line is stripped from the wg-quick-fed config copy before `wg-quick up` runs. We do not want wg-quick to attempt resolvconf, fail, and have us paper over it after the fact — the failure window is messy (wg-quick's error formatting varies by distro, partial-success states are hard to detect, the interface might come up but `wg-quick up` returns non-zero). Strip-first is simpler and matches what already happens for secondaries.

### Fail-open on resolvectl errors, not fail-closed

If `wg-quick up` succeeded the kernel interface exists, routes are installed, and packets flow. A subsequent `resolvectl dns` failure means DNS resolution falls back to the system default — likely the user's primary resolver, which probably resolves the same hostnames. Tearing the tunnel down because of a DNS-management failure would be over-rotating on a non-security concern. The toast + warn log is enough for the user to diagnose.

### Secondaries get DNS-set-without-domain — strictly better than today

R3's "register DNS but don't claim `~.`" semantics on resolved means a secondary tunnel's DNS server can answer queries for hostnames in its AllowedIPs reverse-DNS zones, and the user can target the link explicitly via `resolvectl query -i <iface> <name>` when they need to. Today secondaries have no per-link DNS at all. Going further (auto-derived split-DNS by IP prefix, or per-tunnel domain suffixes) would require config-schema work that's out of scope.

### No cleanup call on disconnect

Per systemd-resolved's documented behaviour, link removal (which `wg-quick down` does via `ip link delete`) drops the link's DNS / domain registration automatically. Plan-time should verify this on the supported distro matrix and only add an explicit `resolvectl revert <iface>` call if a leak is observed.

## Success criteria

1. **Imported `.conf` with `DNS =` connects on Omarchy without `resolvconf` / `openresolv` / `systemd-resolvconf` installed.** Verified end-to-end on a fresh Omarchy VM or a Docker image matching its package set.
2. **Default Fedora Workstation (F39+) connects the same profile** without installing `openresolv`. The Fedora integration test in CI exercises this matrix.
3. **`resolvectl status` after connect shows the tunnel iface with the expected DNS server(s) registered.** Primary's iface also shows `Default Route: yes` (the `~.` domain).
4. **A second tunnel up while the primary is up has its DNS registered too**, visible in `resolvectl status` for the secondary iface but without `Default Route: yes`.
5. **`wg-quick down <iface>` (or vortix-driven disconnect) clears the resolvectl registration** with no manual revert step. Verified via `resolvectl status` post-disconnect.
6. **Existing Ubuntu / Debian path is byte-identical to today.** Existing CI lanes (Ubuntu Test, Ubuntu Integration) stay green with no test changes required.
7. **Fail-open toast fires** when a resolvectl call fails post-`wg-quick up` (simulate via `systemctl stop systemd-resolved` between `wg-quick up` and the resolvectl call). Tunnel stays connected.

## Dependencies / Assumptions

- **`resolvectl` is present on every host where `is_systemd_resolved()` returns true.** `resolvectl` is part of the `systemd` package itself (not a separate package on any major distro); resolved running implies resolvectl on PATH. Verified by inspection of Arch, Fedora, Debian, and Ubuntu package metadata.
- **`resolvectl dns <iface> <ip>` requires no extra privileges beyond what vortix already holds.** Vortix runs root / via sudo for tunnel ops; resolvectl writes to resolved via DBus / Varlink and is permitted for root.
- **systemd-resolved auto-drops link state on `ip link delete`.** Verified by reading `man systemd-resolved.service` ("interfaces … are automatically reset … when removed"). Plan-time will validate empirically.
- **The `is_systemd_resolved()` symlink check correctly distinguishes resolved-managed `/etc/resolv.conf` from a stub-mode `/etc/resolv.conf`.** A user can use resolved in "stub" or "uplink" mode where `/etc/resolv.conf` is a static file pointing at `127.0.0.53`. The symlink-into-`/run/systemd/resolve/` check captures the standard configurations; corner cases get the resolvconf fallback path, which still works.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| resolvectl path silently no-ops on a host where the symlink check passes but resolved isn't actually authoritative for `/etc/resolv.conf` (e.g. user has `/etc/resolv.conf` hand-edited to bypass resolved). | Low | Low | The `resolvectl dns` call still succeeds (resolved happily records per-link DNS); applications that bypass resolved continue bypassing. No regression vs today, since today's wg-quick+resolvconf path has the same end state. |
| `resolvectl --version` probe hangs (resolved deadlocked, DBus stuck). | Very low | Med | 10s timeout matches the existing `resolvconf_works` probe. On timeout the path falls back to the resolvconf branch; if that also fails the user gets the existing missing-dep error message — strictly no worse than today. |
| Plan-time discovers a distro where link removal does NOT auto-clear resolved state. | Low | Low | Add an explicit `resolvectl revert <iface>` call on disconnect for that distro (or unconditionally — the call is cheap and idempotent). Documented as a plan-time follow-up. |
| User has a third-party DNS manager on top of resolved (e.g. dnsmasq layered for caching). | Low | Low | Out of scope; the resolvconf fallback path still works for them if they have the appropriate shim installed. Document in the README's Linux DNS notes. |
| Behaviour delta on secondaries (DNS now registered where it wasn't before) breaks a user's split-DNS expectation. | Very low | Low | The new behaviour is non-authoritative — global hostname resolution still goes through the primary's resolver. A user who explicitly *wanted* the secondary's DNS to be invisible can't get there without us adding a config opt-out; defer until someone asks. |

## Outstanding questions

Resolvable at plan time:

1. **One PR or split into two (R1+R4 dep-check change first, R2+R3 resolvectl path second)?** Both shapes work; the dep-check tweak is mechanically tiny but doesn't deliver user value alone. Recommendation: single PR — the user-visible behaviour requires both halves.
2. **Where does the resolvectl logic live?** `vortix_platform_linux/dns.rs` already shells `resolvectl status` for *reading* DNS; extending it with `set_link_dns(iface, ips, authoritative: bool)` / `clear_link_dns(iface)` keeps the symmetry. Or introduce a new `LinuxDnsManager` port. Plan-time decision; either matches existing patterns.
3. **Wiring point for the post-`wg-quick up` resolvectl call.** Two candidates: (a) `WgTunnel::up()` (protocol layer — same place that strips DNS today), with a platform-layer DNS-manager dependency injected in. (b) `vpn_runtime` layer, after `Tunnel::up()` returns successfully. (a) keeps the protocol-layer atomic; (b) keeps protocol-layer pure of platform-specific calls. Plan-time decision — both require thought about boundary checks (`cargo xtask check-platform-leak` / `check-protocol-leak`).
4. **Manual-testing rows.** Plan needs to add rows under `docs/manual-testing/` for the new path (fresh Omarchy / Fedora-resolved / multi-tunnel-on-resolved scenarios) and update or remove any rows that reference the old "must install systemd-resolvconf" instruction.
5. **README / install-instructions update.** Drop the "install resolvconf" line for Arch / Fedora users; add a note that resolved-using distros are now first-class.

## References

- Origin issue: [#190 — Support for networkd / resolved](https://github.com/Harry-kp/vortix/issues/190)
- Companion prior brainstorm: [docs/brainstorms/2026-05-30-system-dependency-reduction-requirements.md](2026-05-30-system-dependency-reduction-requirements.md) — this work extends its "minimize what users must install" theme but exempts itself from the "no direct DNS writes" non-goal because resolvectl talks to resolved, not to `/etc/resolv.conf`.
- Current dep-check call site: [crates/vortix/src/vpn_runtime/mod.rs](../../crates/vortix/src/vpn_runtime/mod.rs) (the `Protocol::WireGuard` branch of `check_dependencies`).
- Current DNS-strip helper for secondaries: `strip_dns_directive` in [crates/vortix/src/vortix_protocol_wireguard/tunnel.rs](../../crates/vortix/src/vortix_protocol_wireguard/tunnel.rs).
- Resolved-detection + resolvconf probe helpers: `is_systemd_resolved` and `resolvconf_works` in [crates/vortix/src/utils.rs](../../crates/vortix/src/utils.rs).
- Existing resolvectl shell-out (read-only `status` parse): [crates/vortix/src/vortix_platform_linux/dns.rs](../../crates/vortix/src/vortix_platform_linux/dns.rs).
