---
id: 2026-05-28-multi-connection
title: "Simultaneous active VPN profiles — multi-tunnel state model, primary derivation, TUI focus model"
status: draft
type: requirements
created: 2026-05-28
related:
  - 2026-05-24-engine-fsm-event-journal-requirements.md
  - 2026-05-24-tunnel-trait-enum-dispatch-requirements.md
  - 2026-05-24-daemon-engine-handle-requirements.md
  - 2026-05-24-capability-ports-platform-requirements.md
discussion: https://github.com/Harry-kp/vortix/discussions/199
posture: feature-pull  # user-asked, validated via research and architectural scan
---

# Simultaneous active VPN profiles

## Summary

Vortix today binds the whole product — state, FSM, killswitch, UI panels, CLI — to the assumption of one active tunnel at a time. A user managing more than one VPN profile cannot have two profiles active simultaneously even when their routes are non-overlapping; they have to disconnect-then-connect to switch, which destroys the "Vortix as a frontend for all my profiles" use case. This requirements document captures the design for lifting that constraint: N concurrently-active tunnels, heterogeneous (WireGuard + OpenVPN mixable), with a derived "primary" concept anchored on whichever tunnel currently owns the kernel's default route. The TUI absorbs the change via sidebar badges and a focus-driven detail panel — no new panels, no per-tunnel detail duplication. The Security Guard becomes explicitly scoped to the primary, resolving the existing "Security Guard kind of breaks with multiple profiles" failure mode by construction. The killswitch becomes a union of active-tunnel interfaces refreshed atomically on every transition. The CLI gains additive per-profile semantics while preserving single-tunnel backwards compatibility.

The multi-tunnel feature itself ships in one cut — no phased rollout within it — but is **gated on completing the deferred v0.3.x daemon items** (engine wiring, SO_PEERCRED enforcement, read-only-ops bypass) as a separate prior release. Building the multi-tunnel registry on an unwired `EngineHandle` stub would compound the sudo-prompt UX regression and force a double IPC-schema break. Section 9 captures the prerequisite contract.

This is not a split-tunneling feature ([issue #15](https://github.com/Harry-kp/vortix/issues/15)) — split-tunneling is per-app routing rules; this is per-tunnel coexistence with the SOP-anchored routing contract that AllowedIPs already provides. The two features compose; split-tunnel can layer on top of multi-tunnel later.

---

## Problem frame

Today's connection state lives in two places:

- `crates/vortix/src/state/connection.rs:38` — the old single-`ConnectionState` enum (Disconnected / Connecting / Connected / Disconnecting), one variant occupied at any time.
- `crates/vortix/src/vortix_core/engine/state.rs:107` — the v0.3.0 FSM's `Connection` enum (six variants including `Reconnecting` and `AwaitingUserInput`), again one variant occupied at any time. `Engine<T: Tunnel>` (`crates/vortix/src/vortix_core/engine/fsm.rs:59`) owns one of these.

Both layers assume one profile. The downstream consequences cascade through the codebase:

- **Sidebar** (`crates/vortix/src/ui/dashboard/sidebar.rs:58`) decorates exactly one row as "active" via `app.engine.connection_state`.
- **Header** (`crates/vortix/src/ui/dashboard/header.rs:20`) renders either Real IP (Disconnected) or VPN IP (Connected) — no concept of "which of N tunnels is the user's public exit."
- **Connection Details** (`crates/vortix/src/ui/dashboard/connection_details.rs:34`) renders details only when `ConnectionState::Connected` matches — bound to "the" tunnel.
- **Security Guard** (`crates/vortix/src/ui/dashboard/security.rs:34`) infers leak posture from `app.engine.public_ip` vs `app.engine.real_ip` — single-tunnel model. The "kind of breaks" complaint in [discussion #199](https://github.com/Harry-kp/vortix/discussions/199) reflects this honestly: bringing up a second tunnel pollutes the IP/DNS measurements the panel assumes are scoped to one exit.
- **Killswitch** (`crates/vortix/src/core/killswitch.rs:34`) takes `vpn_interface: &str` and `vpn_server_ip: Option<&str>` — singular. A second tunnel's interface and server IP aren't in the firewall allow-list, so the second tunnel either fails to handshake or its traffic gets blocked.
- **CLI** (`crates/vortix/src/cli/commands.rs`) — `vortix up <profile>` implicitly replaces the active connection. `vortix down` disconnects the (one) active. No grammar for addressing one of N.
- **Toggle logic in the TUI** (`crates/vortix/src/app/connection.rs:15`) — `toggle_connection` enters `InputMode::ConfirmSwitch` when connecting a different profile while one is active, treating switch as the only valid coexistence outcome.

The discussion #199 author writes: *"I really enjoy Vortix, but I do not primarily use it for anonymization, I use it as a frontend for all my profiles and many times I need connectivity to more than one VPN-profile at the same time."* This isn't an edge case — it's a primary use case for power users that Vortix categorically excludes.

External research ([Casavant 2020](https://casavant.org/2020/10/10/wireguard-fwmark.html), [SparkLabs Viscosity KB](https://www.sparklabs.com/support/kb/article/using-multiple-vpn-connections-simultaneously/), [Tunnelblick discussion thread](https://groups.google.com/g/tunnelblick-discuss/c/ENEeJyBuFz4), [NetworkManager `ipv4.never-default` patterns](https://forum.level1techs.com/t/use-this-connection-only-for-resources-on-its-network/206908), [Mullvad multi-hop docs](https://mullvad.net/en/help/multihop-wireguard)) shows:

- The protocol layer (WG `AllowedIPs`, OVPN `route` + `redirect-gateway`) **already defines** how multiple tunnels should route. Vortix can lean on this contract — it is the de-facto SOP every power-user multi-VPN setup leans on today.
- **No GUI client has surfaced this contract well.** Tunnelblick allows it but requires manual DNS-disable per secondary. Viscosity treats all tunnels symmetrically with no "primary" surface. NetworkManager's `ipv4.never-default` is a Linux-only checkbox without a visible primary indicator. Mullvad/Proton/Nord/Express all refuse the use case at the client layer.
- The application-layer gotchas are documented but unfixed: the **fwmark hijack** (secondary tunnel's handshake gets routed through primary's table 51820, fails silently), DNS resolver conflicts, killswitch single-interface assumption.

This is the design opportunity: Vortix is positioned to be the first power-user VPN TUI that surfaces the primary/secondary contract explicitly, handles the per-protocol gotchas, and integrates the killswitch + leak detection coherently against the multi-tunnel reality.

---

## Actors

- **A1. Remote dev with corp + commercial setup** — runs a corporate WG tunnel (`10.0.0.0/8` AllowedIPs) for intranet access and Mullvad/Proton (`0.0.0.0/0` AllowedIPs) for public-internet privacy. Expects both up concurrently; expects intranet apps to reach corp and everything else to exit via Mullvad. Today's Vortix forces them to choose.
- **A2. Multi-region QA engineer** — three regional tunnels (US, EU, APAC) all active simultaneously to test geo-behavior. None claims `0/0`. Default route stays on the real network; specific destinations are reached via specific tunnels. Today this requires running three Vortix instances or falling back to raw `wg-quick`.
- **A3. Sysadmin / MSP** — N customer VPCs each with its own split-route VPN. Switches between SSH sessions to different customers without disconnect-reconnect cycles. Today the disconnect-reconnect cycle is the Vortix workflow, which is unusable at N>2.
- **A4. Self-hoster with Tailscale + commercial VPN** — Tailscale mesh covers home services; a commercial VPN covers public-internet exit. Tailscale already coexists fine because it's an overlay; Vortix must not fight Tailscale's `utun`/`tun0`. Today this works (Vortix doesn't touch non-Vortix interfaces), but Vortix's TUI shows only its own tunnels, so the user is blind to the Tailscale half.
- **A5. Site-to-site + road-warrior sysadmin** — permanent site link + ephemeral remote tunnel. Persistent across reboots, easy ephemeral connect. The persistent site link is exactly the "secondary that survives" pattern multi-tunnel enables.

Discussion #199 author maps most cleanly to A1.

The **chained multi-hop privacy actor** (Mullvad/Proton "Secure Core" style) is explicitly **not an actor for this feature** — multi-hop is intra-vendor server chaining, not user-controlled side-by-side tunnels. Out of scope.

---

## Goals and non-goals

### Goals

- **G1.** N concurrent active tunnels (no hard ceiling; soft ceiling determined by terminal width — see UX §6).
- **G2.** WG + OVPN mixable in the same active set (heterogeneous).
- **G3.** A single user-visible "primary tunnel" concept, derived from kernel routing (not stored), anchored on whichever tunnel currently owns `0.0.0.0/0`.
- **G4.** Honest UX in the "no primary" case — when all active tunnels are split-route, the header and Security Guard explicitly say the user is exposed to the public internet via their real network.
- **G5.** Killswitch posture remains correct under multi-tunnel — the firewall allow-list is the union of all active tunnel interfaces, refreshed atomically.
- **G6.** CLI backwards-compatible for users with one tunnel; additive grammar for users with N (`vortix up <p>` is additive; `vortix down` disconnects all; `vortix down <p>` for one).
- **G7.** TUI absorbs multi-tunnel with no new panels and ≤3 lines of additional vertical footprint in the worst case.
- **G8.** The default-route conflict (two tunnels both claiming `0/0`) is detected before invoking `Tunnel::up` and surfaced as a confirm dialog, never as a silent route hijack.
- **G9.** Single-cut ship of the multi-tunnel feature itself — no phased rollout within multi-tunnel, no behind-flag intermediate states. The v0.3.x prerequisite (D1-D3) is a separate prior release named in §9 — it is a gating predecessor, not a phase of the multi-tunnel rollout.

### Non-goals

- **NG1.** Split-tunnel-by-app routing rules ([issue #15](https://github.com/Harry-kp/vortix/issues/15)). Out of scope for this release; composable later.
- **NG2.** Multi-hop chaining within Vortix (traffic-through-A-then-B). Out of scope; commercial vendors handle this server-side and Vortix doesn't need to mimic.
- **NG3.** Teoder's "disable Security Guard" sibling ask. Tracked separately. Multi-tunnel's SG-scoping-to-primary already addresses the "kind of breaks" symptom; the visibility toggle is independent.
- **NG4.** Auto-injection of `FwMark` directives into user WG configs. v1 warns; user fixes their own config.
- **NG5.** OpenVPN management-socket integration for precise per-remote killswitch allow-list. v1 allows all `remote` directives' IPs as a conservative over-allow.
- **NG6.** Profile-import-time AllowedIPs overlap analysis across all profiles. Future enhancement.
- **NG7.** Per-namespace tunnel model (Linux netns, macOS utun pinning, `vortix run --through <p> -- <cmd>`). Different feature; explicitly discarded during brainstorming.
- **NG8.** Mac App Store distribution. Vortix uses `utun` directly, not `NEPacketTunnelProvider` — the App Store path is already closed and this feature doesn't change that.

---

## The SOP we're inheriting (routing contract)

The de-facto convention for multi-VPN setups, derivable from `wg-quick(8)`, OpenVPN's `--route`/`--redirect-gateway` directives, and NetworkManager's `ipv4.never-default` semantics:

1. **AllowedIPs (WG) / route directives (OVPN) are the routing contract.** Each tunnel's declared destinations are what it owns. Vortix does not invent routing semantics; it reads what the profile declares and surfaces the resulting kernel routing table.
2. **At most one tunnel claims `0.0.0.0/0`.** That tunnel is the "primary" — the one governing the user's public-internet identity. All other tunnels declare specific non-overlapping CIDRs.
3. **Only the primary manages DNS.** Secondary tunnels' DNS directives are suppressed at connect-time (per-protocol mechanism, see §7.4).
4. **The kernel routing table is ground truth.** "Primary" is a derived label, not stored state. The routing watcher re-evaluates after every up/down transition and on a tick.

This contract is **dictatable**. Vortix enforces it at connect-time via confirm-on-default-route-conflict (G8) and at runtime via DNS suppression for non-primary tunnels.

---

## UX design

### 6.1 Three governing principles

1. **One focus = one detail.** The sidebar's selected row drives Connection Details. Never duplicate per-tunnel.
2. **Multi-state lives in the sidebar via badges.** A single status character per row carries connection state; `*` suffix carries the derived primary marker.
3. **Header anchors on the one identity question.** "What does the public internet see me as?" — exactly one IP, always belonging to the primary (or the real network when no primary exists).

### 6.2 Sidebar (`crates/vortix/src/ui/dashboard/sidebar.rs`)

Each row's existing `status_char` slot expands its vocabulary:

| Char | Meaning | Color |
|------|---------|-------|
| `●` | Connected (any role; Degraded health is surfaced in Connection Details, not via badge) | `theme::SUCCESS` |
| `●` + name + ` *` | Connected, primary (owns default route) | `theme::SUCCESS` bold |
| `◐` | Connecting | `theme::WARNING` |
| `↻` | Reconnecting (lost link; retrying automatically) | `theme::WARNING` dim |
| `◑` | Disconnecting | `theme::WARNING` |
| `?` | AwaitingUserInput (waiting for 2FA / passphrase prompt) | `theme::WARNING` |
| `✗` | Connect-failed (with reason in details) | `theme::ERROR` |
| ` ` | Disconnected | dim |

The `*` is rendered **as a suffix after the profile name**, not as a new column.

**Char migration from current single-tunnel UI.** Today's `sidebar.rs:144-150` uses `✓` / `…` / `⏻` for Connected / Connecting / Disconnecting; multi-tunnel replaces them with `●` / `◐` / `◑` to unify the active-tunnel vocabulary and free `✓` for the Security Guard panel (which already uses it for leak-check pass marks). Old chars are deprecated, not preserved.

**Column-budget arithmetic.** `name_budget` in `sidebar.rs:66` is `inner.width − fixed_cols(2+4+10+3=19)`. At 80-col terminals with sidebar at ~25% width (inner ≈ 20), `name_budget ≈ 1`; adding `+2` for the primary `*` suffix makes the math negative and `saturating_sub` floors it. **Constraint:** minimum supported sidebar inner-width is 24 chars (yields `name_budget ≥ 5` with the `*` suffix); below this the sidebar collapses to status-char + truncated-name with no primary marker shown.

**Degraded health.** `ConnectionHealth::Degraded` (HandshakeStale / HighPacketLoss / HighLatency from `state.rs:61`) does NOT modify the sidebar badge — focused-row Connection Details surfaces a `Health:` line instead. A distinct badge variant for Degraded is deferred to a future enhancement; v1 prefers signal-density over byte-budget for the rare degraded case.

### 6.3 Header (`crates/vortix/src/ui/dashboard/header.rs`)

Single line, three states:

**Connected, with a primary:**
```
▲00:42 │ Exit: 5.6.7.8 via corp* │ Tunnels [●corp* ●pers ●lab] │ KS: ARMED
```

**Connected, no primary (all secondaries):**
```
⚠ Real: 12.34.56.78 │ Tunnels [●us-east ●eu-west ●ap-south] │ KS: OFF*
```
The leading `▲` becomes `⚠` to signal the unprotected public exit. `KS: OFF*` because killswitch with no default-route tunnel has nothing meaningful to enforce.

**Fully disconnected:** unchanged from today.

**Overflow handling:**
```
With-primary, narrow:    ▲00:42 │ Exit: 5.6.7 via corp* │ [●corp* ●p ●l +2] │ KS: ARMED
No-primary, narrow:      ⚠ Real: 12.34.5 │ [●us ●eu ●ap +1] │ KS: OFF*
Fully disconnected:      no tunnel strip; same as today's disconnected header
Very narrow (<60 col):   [●*●●●●●● 7]  — primary marker preserved; dot row + count

[●corp* ●pers ●lab ●us +2]      ← canonical narrow form: count overflow
[●*●●●●●● 7]                    ← very narrow fallback: primary's `*` at index 0; dot row + count
[⚠●●●●●●● 7]                    ← very narrow + non-Connected state: ⚠ prefix when any tunnel is in ↻/?/✗
```
Reuses existing `unicode-width` budgeting in `crates/vortix/src/ui/widgets/footer.rs`. All three header states degrade through the same overflow ladder. The very-narrow form **must** preserve the primary `*` marker (G3 / Principle 3: header anchors on identity); reserve one byte for it even at the narrowest width. When any tunnel is in `Reconnecting` (↻), `AwaitingUserInput` (?), or `Connect-failed` (✗) state and the dot-row form is active, prepend a `⚠` glyph so the user knows at least one tunnel needs attention — they then focus the sidebar for detail. The narrow form `[●corp* ●p ●l +2]` uses the actual per-tunnel status char (e.g., `[↻corp ●p ●l +2]`) when above the dot-row threshold.

### 6.4 Connection Details (`crates/vortix/src/ui/dashboard/connection_details.rs`)

Panel title gains the focused profile name: `Connection Details (corp)`.

Body lines stay the existing shape with one addition:

```
VPN IP  : 10.0.0.5 @ utun3
Server  : 1.2.3.4:51820
Role    : Primary (0.0.0.0/0)        ← NEW LINE
Cipher  : ChaCha20-Poly1305
↓ 12.4 KB/s   ↑ 3.1 KB/s
─ tab: cycle focus to next active     ← only when N>1
```

The `Role` line variants:
- `Primary (0.0.0.0/0)` — owns the kernel default route
- `Addressable (10.0.0.0/8)` — declared specific CIDR(s); not the default route
- `Addressable (multi)` — declared multiple disjoint CIDRs; comma-list shown when budget allows
- `Addressable (0.0.0.0/0, suppressed)` — declares `0/0` but another tunnel currently holds the kernel default route; appears when this tunnel was demoted after a role-inversion event (a different tunnel took over `0/0` while this one stayed Connected)
- `Reconnecting via <last role>` — kernel interface may still be up from before the link drop; carry the pre-drop role until the next route-table re-evaluation
- `n/a (awaiting input)` — tunnel is mid-connect, paused on a 2FA / passphrase prompt

When the focused row is `Disconnected` or `Connecting`, the panel shows the existing not-yet-connected state (no Role line yet, since the kernel hasn't seen the tunnel come up). For `AwaitingUserInput` rows, Connection Details shows the auth call-to-action *alongside* the tab-cycle hint when N>1 — both navigation paths must remain visible:

```
Press [Enter] to provide 2FA / passphrase
─ tab: cycle focus to other active tunnels    ← only when N>1
```

The Enter hint takes the top line (it's the primary action); the tab hint is conditional on N>1 (same rule as the standard Connection Details footer). For N=1 the tab hint is suppressed (nothing to cycle to).

### 6.5 Security Guard (`crates/vortix/src/ui/dashboard/security.rs`) — explicitly scoped to primary

Today's SG implicitly assumes one tunnel = one exit. The fix: make the scope visible.

**With a primary:**
```
   PROTECTED
 ✓ Exit owner : corp*
 ✓ IP Masked  : 5.6.7.8
   Real IP    : 12.34.56.78 (hidden)
 ✓ DNS Secure : 10.0.0.1 (Cloudflare)
 ⚠ IPv6       : Not enforced (v4-only killswitch)
 ✓ Killswitch : Armed (Auto)
```

The `Exit owner : corp*` line is the load-bearing addition. It tells the user *whose properties this panel is auditing*. The IP/DNS checks below are scoped to that tunnel.

**With no primary (all secondaries):**
```
   PARTIAL
 ⚠ No primary tunnel
   Default route via real network
 ✓ Tunnels reachable for split traffic
 ─ Killswitch : No default route to scope (see mode below)
   • Auto: standby — no default route to enforce on
   • AlwaysOn: armed (blocks all except active
     tunnel interfaces — secondaries still protected)

(Sigil legend: ✓ check passed · ⚠ check failed or at risk · ─ check
not applicable — no exit identity to scope checks to)
```

Honest about the partial-protection state. No other client does this; it's the strongest UX argument for the primary-derivation approach.

**IPv6 enforcement is a known gap.** The current killswitch (`IptablesFirewall::setup_iptables` and `PfFirewall::generate_pf_rules`) emits IPv4 rules only — `ip6tables` is never invoked on Linux; pf rules carry no `inet6` family qualifier on macOS. Multi-tunnel inherits this gap. The Security Guard panel surfaces `⚠ IPv6 : Not enforced (v4-only killswitch)` rather than pretending v6 is blocked. Closing the IPv6 plane (parallel `ip6tables-restore` + `inet6` pf rules) is **out of scope for this release** but tracked as an explicit follow-up; the SG line is honest about it instead of masking the regression.

**Disconnected entirely:** unchanged from today.

### 6.6 Connect flow

| Current state | User action | New behavior |
|--------------|-------------|--------------|
| Disconnected | `Enter` on profile A | Connect A (unchanged) |
| A connected (primary) | `Enter` on B with disjoint AllowedIPs | Add B as addressable secondary, **no prompt** |
| A connected (primary) | `Enter` on B with `0/0` AllowedIPs | Confirm overlay: *"Connecting 'B' takes the default route from 'A'. Apps will route through B. Continue?"* |
| A connected (primary), B's CIDR overlaps with A's | `Enter` on B | Confirm overlay: *"B claims 10.0.0.0/16 which overlaps with A's routes. Last-up wins (silent on macOS). Continue?"* |
| A connected (primary) | `Enter` on A | Disconnect A (unchanged toggle) |
| A `Disconnecting` | `Enter` on B | **Queue B's connect behind A's teardown.** Registry holds the connect request; sidebar shows inline hint *"Queued — connecting after A finishes disconnect"*. Fires `Tunnel::up(B)` when A's FSM reaches `Disconnected`. |
| A `Connecting` | `Enter` on A again | No-op (idempotent). Connection Details panel surfaces *"Already connecting — press [c] to cancel and retry"* hint. |
| A `Connecting` | `Enter` on B (different profile) | Run conflict detection against A's *declared* AllowedIPs (treat in-flight Connecting as a pending primary claimant — see §7.3 detect_conflict rule). If B claims 0/0 and A also claims 0/0, fire the takeover confirm overlay *before* B's `Tunnel::up`. Otherwise connect B in parallel. |
| A `AwaitingUserInput` (2FA / passphrase) | `Enter` on B (different profile) | Connect B in parallel. The auth overlay stays focused on A; B's FSM runs independently. If B claims 0/0 and A claims 0/0, fire the same takeover-conflict overlay (A is treated as a pending primary claimant). |
| A `AwaitingUserInput` | `Enter` on A | Open or re-focus the auth input overlay. Same key both surfaces the call-to-action in Connection Details and routes the next keystroke into the overlay. |
| A `✗ Connect-failed` | `Enter` on A | Retry: clear the failure record, re-enter `Connecting`. The `✗` badge persists in the sidebar until the user takes a sidebar action (retry, Disconnect-style clear, or focus-away) — the registry does not auto-reap `✗` rows on Tick, so Connection Details can show the failure reason indefinitely. |
| A `Reconnecting` | `Enter` on A | Cancel reconnect, return A to `Disconnected`. |

The existing `InputMode::ConfirmSwitch` (`crates/vortix/src/app/connection.rs:48`) is renamed to `InputMode::ConfirmDefaultRouteTakeover` and gets a sibling `InputMode::ConfirmRouteOverlap`. Same overlay framework, narrower trigger conditions.

**Backwards compatible:** users with 1 profile or non-overlapping profiles never see a confirm prompt under the new behavior.

### 6.7 Disconnect flow

| Action | Effect |
|--------|--------|
| `d` (sidebar row focused, that row is connected) | Disconnect that one tunnel; primary re-derives |
| `D` (Shift+d) when N>1 active | Confirm: *"Disconnect all N tunnels? [y/N]"* |
| `D` when N≤1 active | Same as `d` (no confirm) — backwards compatible |
| CLI `vortix down` | Disconnect ALL (preserves single-tunnel default) |
| CLI `vortix down <profile>` | Disconnect that profile (new) |
| CLI `vortix down --all` | Explicit form for scripts |

**Teardown UX visibility.** With N>1 tunnels and `vortix down --all` (or `D` shift-d), teardown is sequential (secondaries first, primary last, per §H6). Sidebar reflects this in real time — each row transitions `◑ → blank` individually as its FSM completes. The atomic-disappearance shape is intentionally avoided so the user sees teardown progress; if a single tunnel hangs in `Disconnecting`, the row stays `◑` and is debuggable. Killswitch refreshes are coalesced (§7.6) — one ruleset rewrite at the end of the teardown sequence, not N.

`vortix down` without args still does what existing scripts expect (one tunnel → disconnect it; N tunnels → clean everything).

### 6.8 Footprint analysis

Compared to today's dashboard, multi-tunnel adds:

- Header: ~1 inline segment (`Tunnels [...]`) — same line, scales by terminal width
- Sidebar: 0 new columns, 0 new rows; `*` is a 2-char suffix
- Connection Details: +1 line (`Role:`), +1 conditional hint line (only when N>1)
- Security Guard: +1 line (`Exit owner:` or `No primary tunnel`)

**Total worst-case additional vertical footprint: 3 lines.** No new panels.

---

## Technical design

### 7.1 Registry of FSMs (not one fat FSM)

```rust
// crates/vortix/src/vortix_core/engine/registry.rs (new module)
pub struct TunnelRegistry<T: Tunnel> {
    /// One Engine<T> per active ProfileId. An entry exists from the first
    /// Connect command for that profile until the FSM reaches Disconnected
    /// (then reaped on next Tick).
    fsms: HashMap<ProfileId, Engine<T>>,

    /// Derived: profile that currently owns 0.0.0.0/0 in the kernel routing
    /// table. Refreshed on every tunnel up/down and on Tick.
    primary: Option<ProfileId>,

    /// Global killswitch — applied as the union of active interfaces.
    killswitch_mode: KillSwitchMode,
    killswitch_state: KillSwitchState,
}
```

Each `Engine<T>` (`crates/vortix/src/vortix_core/engine/fsm.rs:59`) keeps its existing single-tunnel behavior unchanged. The registry is a wrapper that fans out commands and aggregates state. **Existing FSM tests remain valid.**

**Legacy `ConnectionState` retirement.** The single-tunnel `ConnectionState` enum at `crates/vortix/src/state/connection.rs:38` is removed as part of this work. UI panels that read `app.engine.connection_state` today (`sidebar.rs:58`, `header.rs:20`, `connection_details.rs:34`, `security.rs:34`, `chart.rs:67`) migrate to read from registry snapshot accessors:
- `registry.tunnel_count() -> usize`
- `registry.primary() -> Option<ProfileId>`
- `registry.snapshot(profile_id) -> Option<TunnelSnapshot>` — for the focused row's detail
- `registry.snapshot_all() -> Vec<TunnelSnapshot>` — for sidebar enumeration

The TUI's `App` holds a single `registry: TunnelRegistry<T>` (replacing the legacy `engine: VpnEngine`). Header + Security Guard read from `registry.primary()`; Connection Details reads from `registry.snapshot(focused_profile_id)`. This is the answer to "what becomes of the legacy enum" — it dies with the multi-tunnel work, and there is no compatibility shim.

**`TunnelSnapshot` sensitivity.** The snapshot returned by `registry.snapshot(profile_id)` contains interface name, server IP, connection state, transfer counters, last-handshake timestamp, and the (derived) `Role` line value. **It is UID-confidential** — access is gated on `SO_PEERCRED` UID match at the daemon boundary (D2). Single-user configurations require no further redaction. Multi-user daemon scenarios are out of scope for v1; if added later, snapshots will need per-caller field filtering.

**Pending-connect queue shape.** Each `Engine<T>` in the registry carries its own optional `pending_after_disconnect: Option<ProfileId>` slot. The registry itself does NOT hold a cross-FSM queue map — the §6.6 "A `Disconnecting` + Enter B → queue" row is implemented by stashing B's profile_id on A's FSM when A enters `Disconnecting`, then firing B's connect from A's FSM when it reaches `Disconnected`. This matches §7.1's "each `Engine<T>` keeps its existing single-tunnel behavior unchanged" and extends naturally from today's `pending_connect: Option<usize>` (`crates/vortix/src/engine/mod.rs:70`) without introducing a registry-level queue manager.

**Why registry-of-N over one fat multi-tunnel FSM:**

| Concern | Fat FSM | Registry of N |
|---|---|---|
| Per-tunnel retry budget | Shared, contention | Each FSM independent (existing) |
| Per-tunnel link-change reconnect | Serial | Parallel, isolated |
| Test reuse | Rewrite | Existing tests still apply |
| Plan #010 daemon `EngineHandle` actor pattern | Misfit | Natural — registry = N actors |
| Failure isolation | Risk of cross-tunnel corruption | Hard per-FSM boundary |
| Code-change cost | Large rewrite of `fsm.rs` | New wrapper (~150 lines), FSM unchanged |

### 7.2 Primary derivation — read the kernel, don't store

`crates/vortix/src/vortix_core/ports/route_table.rs` extends:

```rust
pub trait RouteTable {
    fn default_gateway() -> Option<String>;            // existing
    fn default_route_interface() -> Option<String>;    // NEW
}
```

Per-platform impls — **extend existing primitives, don't introduce parallel commands:**
- `crates/vortix/src/vortix_platform_macos/route_table.rs` already uses `route get default` which prints both `gateway:` and `interface:` lines. The new method extends the existing parser to extract `interface:` rather than introducing `netstat -nr` as a second command. Reuse halves the macOS routing surface area in tests.
- `crates/vortix/src/vortix_platform_linux/route_table.rs` already uses `ip route show default` and returns `parts[2]` (the via-IP). Extend the parser to also walk the line for `dev <name>` and return the interface name. Same single command, second extraction.

The registry maps `interface_name → ProfileId` via the current `TunnelHandle.interface_name` (`crates/vortix/src/vortix_core/ports/tunnel.rs:37`).

**Refresh triggers:**
- After every `Tunnel::up` Ok
- After every `Tunnel::down` Ok
- On every `Tick` (5s cadence — cheap, one syscall)
- On `NetworkLinkChanged` events

**Event emitted on change:**
```rust
EngineEvent::PrimaryTunnelChanged {
    from: Option<ProfileId>,
    to: Option<ProfileId>,
    via_interface: Option<String>,
}
```

UI subscribes; header + SG + sidebar `*` badge re-render. Journal records the transition.

### 7.3 Default-route conflict detection at connect-time

Before invoking `Tunnel::up`:

```rust
fn would_claim_default_route(profile: &Profile, parsed: &dyn ParsedProfile) -> bool {
    match profile.protocol {
        ProtocolKind::WireGuard => {
            parsed_wg(parsed).peers.iter().any(|p|
                p.allowed_ips.iter().any(is_default_route))
        }
        ProtocolKind::OpenVpn => parsed_ovpn(parsed).has_redirect_gateway(),
    }
}
```

`Tunnel::parse_profile` (`crates/vortix/src/vortix_core/ports/tunnel.rs:83`) already returns a `ParsedProfile` trait object. The per-protocol concrete impls in `crates/vortix/src/vortix_protocol_wireguard/` and `crates/vortix/src/vortix_protocol_openvpn/` need accessors `peers().allowed_ips()` and `has_redirect_gateway()`.

**Implementation precondition (load-bearing).** Today's `WgParsedProfile` (`crates/vortix/src/vortix_protocol_wireguard/parser.rs`) captures only the `[Interface]` section — `dns_servers`, `address`, `mtu`, `raw` — and explicitly skips `[Peer]` content. `OvpnParsedProfile` (`crates/vortix/src/vortix_protocol_openvpn/parser.rs`) captures only `interactive_auth` and `raw`. **The entire SOP-anchored conflict detection, DNS scoping decision, and fwmark warning rest on parser work that does not exist today.** This is a structural parser extension that must land alongside the registry, not "~30 lines of accessors" on existing types:
- Add `WgPeer { public_key: PublicKey, allowed_ips: Vec<CidrV4|CidrV6>, endpoint: Option<SocketAddr>, fwmark: Option<u32> }`
- Add `WgParsedProfile.peers: Vec<WgPeer>`
- Add `OvpnParsedProfile.remotes: Vec<RemoteSpec>`, `OvpnParsedProfile.redirect_gateway: bool`, `OvpnParsedProfile.routes: Vec<OvpnRoute>`

These shapes flow into the registry's conflict-detector, the killswitch allow-list synthesis, and the fwmark warning. Scope this parser work explicitly in the implementation plan.

**Split-CIDR bypass — CIDR-union default-route check.** The `is_default_route` predicate must reject any CIDR union that covers full IPv4 (or IPv6) space, not just the canonical `0.0.0.0/0`. Examples to reject: `0.0.0.0/1 + 128.0.0.0/1` (the wg-quick conventional encoding documented in `wg-quick(8)`), `0.0.0.0/2 + 64.0.0.0/2 + 128.0.0.0/2 + 192.0.0.0/2` (/2 quartet), and any deeper-prefix combination that aggregates to /0. Implementation:

```rust
fn claims_default_route_v4(allowed_ips: &[CidrV4]) -> bool {
    // direct 0/0 — fast path
    if allowed_ips.iter().any(|c| c.prefix_len == 0) {
        return true;
    }
    // True CIDR aggregation: sort by prefix, merge adjacent ranges,
    // test whether the merged set covers 0.0.0.0/0.
    // NOT a pattern-matcher on the canonical /1 pair —
    // that would miss /2 quartets and other split variants.
    cidr_union_covers_v4_space(allowed_ips)
}
```

`cidr_union_covers_v4_space` **must** be a genuine CIDR aggregation algorithm (e.g., sort prefixes, coalesce adjacent ranges, test full-space coverage), not a list of special-case patterns. Same contract for IPv6 (`cidr_union_covers_v6_space` against `::/0`, covering `::/1 + 8000::/1`, the `::/2` quartet, and deeper splits). SC10 tests the canonical /1 pair; **add SC11** for the /2 quartet to exercise the aggregation algorithm proper. Without true aggregation, an imported profile with deeper-split AllowedIPs silently hijacks the default route — the confirm overlay never fires.

Registry's conflict check — must treat both **Connected** and in-flight **Connecting** FSMs as primary claimants:

```rust
fn detect_conflict(&self, new_profile: &Profile) -> Option<Conflict> {
    if would_claim_default_route(new_profile, &parsed) {
        // Check Connected first (the canonical primary)
        if let Some(current) = &self.primary {
            return Some(Conflict::DefaultRouteTakeover {
                current: current.clone(),
                new: new_profile.id.clone(),
            });
        }
        // Then check in-flight Connecting FSMs that declare 0/0
        // (the Connecting+Enter B race case from §6.6)
        if let Some(pending) = self.pending_default_route_claimant() {
            return Some(Conflict::DefaultRouteTakeover {
                current: pending.clone(),
                new: new_profile.id.clone(),
            });
        }
    }
    // CIDR overlap detection for non-default routes
    if let Some(overlap) = self.detect_cidr_overlap(new_profile) {
        return Some(Conflict::RouteOverlap(overlap));
    }
    None
}

fn pending_default_route_claimant(&self) -> Option<ProfileId> {
    self.fsms.iter()
        .find(|(_, fsm)| matches!(fsm.state(), Connection::Connecting { .. })
              && self.profile_declares_default_route(fsm.profile_id()))
        .map(|(id, _)| id.clone())
}
```

Without the in-flight check, two FSMs simultaneously in `Connecting` with `0/0` both pass conflict-detection (each sees `self.primary == None`) and silently race to default route. This violates G8 ("never as a silent route hijack") and SC3 ("On cancel, no kernel state changes" is unreachable if both have already mutated kernel state).

When a conflict is detected, the registry refuses to start the FSM and emits `EngineEvent::ConnectAttemptBlockedByConflict`; the UI shows the confirm overlay; on confirm the registry retries with `force: true`.

### 7.4 DNS scoping — primary owns DNS, secondaries skip

The protocol-level mechanism differs by tunnel type:

**WireGuard secondary** — strip `DNS =` directive at connect-time:
1. Read user's original `.conf`
2. Write a temp config (in Vortix's config dir, deleted on disconnect) with `DNS =` line removed. **Basename MUST match the original** (wg-quick derives interface name from filename — mismatched basenames produce wrong `TunnelHandle.interface_name`, breaking primary derivation and killswitch keyed lookups).
3. Invoke `wg-quick up <temp-config>`
4. wg-quick still installs routes per `AllowedIPs`, but doesn't touch resolvconf

**Temp-file security (load-bearing).** The temp file contains the user's `[Interface] PrivateKey`. Create with `O_CREAT|O_EXCL` at mode `0600` **before** any content is written — not via `fs::write` followed by `chmod` (the existing `write_user_file` helper performs `chown` after `fs::write`, leaving a TOCTOU window where the file is world-readable under default umask 0022). Use a dedicated `write_secret_file(path, content) -> Result<()>` helper that:
1. **Verify parent directory is not a symlink.** Call `lstat(parent_dir)` and reject if `is_symlink()` — `canonicalize` resolves through symlinks, so an attacker who replaces `~/.config/vortix` (or any ancestor) with a symlink could redirect the file to an attacker-controlled location even at mode 0600. The directory-level check closes this TOCTOU.
2. `open(O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW, 0o600)` — fails if file already exists, avoids predictable-name attacks, refuses to follow a symlink at the leaf
3. Write content
4. fsync + close

**Temp-config subdirectory + per-session UUID basenames.** O_EXCL combined with "basename MUST match the original" deadlocks reconnect after crashed-disconnect (the stale temp file survives until the 1-hour sweep, blocking re-create). Resolution: temp configs land in a per-session subdirectory `${config_dir}/tmp/${session_uuid}/${basename}.conf` — basename matches original, sessions are isolated, the crash sweep walks subdirs and unlinks whole session-uuid trees older than 1 hour. The session UUID is the journal session ID already in `crates/vortix/src/vortix_core/journal/writer.rs`.

**Migrate `write_openvpn_auth_file` to use this helper.** `crates/vortix/src/utils.rs:232-247` today calls `write_user_file` followed by a separate `chmod 0600` — the same TOCTOU window the WG temp config closes. Ship the migration in the same PR that introduces `write_secret_file` to avoid the gap persisting through the release window.

**Linux stdin alternative — conditional.** `wg-quick up /dev/stdin` accepts a config piped via stdin, sidestepping the temp-file lifecycle entirely on Linux. **But** wg-quick derives `%i` (interface-name token in hook scripts) from the *filename*; stdin produces an empty/`stdin` substitution, breaking any user config that uses `PreUp`/`PostUp`/`PreDown`/`PostDown` directives referencing `%i` or `$0`. The fwmark workaround configs §7.5 documents are exactly this shape (`PostUp = iptables -t mangle ... %i ...`). Resolution: parser-level check at connect-time — if the profile contains any of those hook directives, **fall back to the temp-file path even on Linux**. Otherwise stdin is fine. Document this conditional in the connect-flow runbook so the silent-hook-failure mode is impossible.

**Crash-cleanup sweep.** On Vortix startup, walk `${config_dir}/tmp/` and unlink any session-uuid subdirectory older than 1 hour (covers SIGKILL / panic / power-loss where on-disconnect cleanup didn't run). The session UUID matches the active journal session, so live sessions are never reaped. **No separate journal manifest is required** — glob-by-age over the per-session subdir is simpler and equally safe. (Round-2 evaluated a TempConfigCreated/TempConfigCleaned journal-event-pair manifest; the per-session subdir naming makes the manifest redundant.)

**OpenVPN secondary** — pass `--pull-filter ignore "dhcp-option DNS"`:
1. Invoke openvpn with the existing config plus the pull-filter argument
2. Routes still get pushed; DNS option is dropped before client applies it
3. Requires OpenVPN 2.4+ — assert via dependency check at connect-time

**Heterogeneous case:** WG primary + OVPN secondary, or OVPN primary + WG secondary, each follows its protocol's mechanism. No cross-protocol coupling.

**Primary promotion / demotion:** when the primary is disconnected and another tunnel would naturally take the default route (i.e., another tunnel already has `0/0` AllowedIPs but was previously suppressed), Vortix does NOT auto-promote it. Promotion requires a user action (`vortix up <new_primary>` or sidebar `Enter`). Rationale: silent promotion is surprising; explicit is honest. The existing tunnel stays alive as a secondary; if no new connect happens, the user sees `⚠ No primary tunnel` in the header.

### 7.5 Fwmark hijack handling (warn-only for v1)

At connect-time, for each WG secondary:
- Parse the config for any `FwMark = <value>` directive
- If absent AND a primary tunnel currently has `AllowedIPs=0/0`:
  - Emit a toast: *"Secondary '{name}' may fail to handshake: WireGuard routes unmarked packets through the primary's table. Add 'FwMark = 51820' to {config_path}."*
  - Link to a docs page (new: `docs/multi-tunnel-fwmark.md`) with 2-paragraph explanation
- Connect anyway (warning, not block) — user might be on Linux with policy routing that handles it, or the handshake might succeed if there's enough idle time

**Auto-injection is explicitly deferred** (NG4). Editing user configs is fragile, hard to debug, and violates the principle that Vortix doesn't mutate user intent.

**Security implication — not just a connectivity failure.** When fwmark hijack fires, the secondary tunnel's WireGuard handshake packets (containing the secondary's ephemeral public key and initiator timestamp) are routed *through the primary's tunnel* to the primary's VPN operator. The primary operator — which may be a different entity than the secondary operator (e.g., Mullvad as primary + corporate WG as secondary) — receives the secondary's connection attempt in plaintext from the primary's server perspective. This is a metadata/credential exposure across trust boundaries, not just "the handshake doesn't complete." The warn-only posture (v1) accepts this risk for users who choose to ignore the warning; a future v2 may upgrade to a blocking confirm specifically because of the cross-operator visibility, not the connectivity symptom.

### 7.6 Killswitch refresh on every transition

Today's signature (`crates/vortix/src/core/killswitch.rs:34`):
```rust
pub fn enable_blocking(vpn_interface: &str, vpn_server_ip: Option<&str>) -> Result<()>
```

Becomes:
```rust
pub fn enable_blocking_multi(active: &[ActiveTunnelInfo]) -> Result<()>;

pub struct ActiveTunnelInfo {
    pub interface: String,
    pub server_ips: Vec<String>,  // OVPN: all `remote` entries; WG: single endpoint
}
```

**Rule synthesis — Linux iptables (atomic via `iptables-restore`):**
```
*filter
:OUTPUT DROP [0:0]
-A OUTPUT -o lo -j ACCEPT
# RFC1918 + DHCP allow paths — preserved from existing setup_iptables (firewall.rs:64-115)
-A OUTPUT -d 192.168.0.0/16 -j ACCEPT
-A OUTPUT -d 10.0.0.0/8 -j ACCEPT
-A OUTPUT -d 172.16.0.0/12 -j ACCEPT
-A OUTPUT -p udp --dport 67:68 -j ACCEPT
# Per-tunnel allow paths
{for each tunnel}
-A OUTPUT -o {interface} -j ACCEPT
{for each server_ip}
-A OUTPUT -d {server_ip} -j ACCEPT
COMMIT
```

**Functional-preservation requirement.** The current `IptablesFirewall::setup_iptables` (`crates/vortix/src/vortix_platform_linux/firewall.rs:64-115`) and corresponding pfctl ruleset (`crates/vortix/src/vortix_platform_macos/firewall.rs:38-72`) already allow RFC1918 destinations and DHCP (UDP 67/68). The multi-tunnel ruleset MUST preserve these — dropping them is a silent regression that breaks LAN traffic and DHCP renewal for users with `AlwaysOn` killswitch.

**Implementation reality — atomicity is not in place today.**
- Linux: `IptablesFirewall::setup_iptables` currently issues per-rule `iptables -N/-F/-A/-I` calls sequentially — exactly the "flush + add" pattern with a leak window. Migrating to `iptables-restore` single-transaction mode is a backend swap, not a wrapper added on top.
- macOS: `pfctl` killswitch performs `pfctl -F all` (flush) → `pfctl -d` (disable), then `pfctl -f path` + `pfctl -e` to bring it back. Refresh path goes flush→enable, which is **not** atomic. Multi-tunnel requires a single-pass `pfctl -f - <ruleset` load-with-replace pattern; this is a primitive that needs to be added to the macOS `Killswitch` trait impl, not a signature change.

**Rule synthesis — macOS pfctl:** single ruleset pre-built and loaded via `pfctl -f -` (atomic by pf semantics).

**Refresh trigger:** every `Connected → Disconnected` or `Disconnected → Connected` transition observed by the registry. The registry **coalesces refreshes** — multiple transitions within one Tick cycle produce one ruleset rewrite, not N.

**Atomicity matters:** the naive "flush + add" pattern has a leak window. iptables-restore in single-transaction mode and pfctl's load-with-replace are both atomic. Use them.

**No-primary edge case:** when the registry has no primary, killswitch in `AlwaysOn` mode keeps blocking everything except the active secondary interfaces. In `Auto` mode it stays armed but doesn't block (current semantics).

**Persistence schema migration — alternatives weighed.**

Today's `PersistedState` (`crates/vortix/src/core/killswitch.rs:59-65`) stores a single `vpn_interface: Option<String>` and `vpn_server_ip: Option<String>` — single-tunnel-shaped. `load_state()` (lines 69-90) swallows parse failure as `None` (silently dropping the persisted posture). Multi-tunnel must decide what happens on recovery.

**Option A — full V1→V2 schema migration (preferred).** Introduce `PersistedStateV2 { schema_version: u8, mode, state, active_tunnels: Vec<ActiveTunnelInfo> }` with serde shape that absorbs both versions in a single struct via `#[serde(default)]` on the new vec and `#[serde(default = "default_schema_version")]` (returning 1) on `schema_version`. On load:
- `schema_version == 1` (legacy) or missing: coerce single-tunnel fields (`vpn_interface` + `vpn_server_ip`) into a one-element `Vec<ActiveTunnelInfo>`, log a migration notice, write back as V2 immediately so the next load is direct
- `schema_version == 2`: load directly
- **Phantom-interface validation:** after coerce, cross-reference each `interface_name` against the live kernel interface list (`ip link show` / `ifconfig`). Drop entries whose interface no longer exists; log a warning. Prevents the V1→V2 path from re-arming the killswitch with stale `utunN` allow-rules that the OS may have reassigned to a non-Vortix tunnel (e.g., Tailscale grabbing the freed slot).

**Option B — Off-on-recovery + user re-arms (simpler).** On crash recovery, if the schema is V1 or coerce fails for any reason, disable the killswitch (`state = Disabled`), preserve `mode`, and surface a one-line recovery toast (`Killswitch recovered to Off — please re-arm if you need protection`). User re-arms via the existing `[s]` keystroke; `enable_blocking_multi` rebuilds rules with fresh registry state. Ten lines of code; failure mode is "user must explicitly re-arm" which is already documented in R3.

**Recommendation: Option A.** AlwaysOn users whose secondary traffic gets silently blocked on reboot (the Option-B failure mode) is a worse UX than the schema-migration carrying cost, *and* secondaries dropping out of the allow-list on every restart (Option B) defeats the multi-tunnel value proposition for power users. Option A is ~50 lines and lands once.

**Downgrade contract (V2 → V1, when user reverts to v0.3.x after a multi-tunnel regression).** V2 state on disk must be readable by V1 v0.3.x — otherwise rollback requires manual `rm $persisted_state_path`. Two paths: (1) make D1 land V1-tolerance for unknown `active_tunnels`/`schema_version` fields *before* multi-tunnel ships (preferred — pure backport), or (2) document explicitly that downgrade requires deleting the state file, and surface this in the §9 rollback procedure. Without one of these, the schema bump is a one-way upgrade.

### 7.7 CLI surface

`crates/vortix/src/cli/args.rs` and `crates/vortix/src/cli/commands.rs`:

| Command | Today | After |
|---------|-------|-------|
| `vortix up <p>` | Connect (replaces current) | Connect (additive; confirm only on default-route conflict via `--yes` to skip) |
| `vortix down` | Disconnect the one | Disconnect ALL |
| `vortix down <p>` | Not supported | Disconnect that one |
| `vortix down --all` | Not supported | Explicit all (for scripts that want clarity) |
| `vortix status` | One snapshot | `{ connections: [...], primary: <profile_id_or_null> }` |
| `vortix reconnect` | Reconnect last-used | Reconnect ALL active |
| `vortix reconnect <p>` | Not supported | Reconnect that one |

**JSON schema:** bump from `schema_version: 1` to `schema_version: 2` when this lands. v1 consumers reading `data.connection` see only the primary (singular, backwards-compatible for scripts that only cared about the primary). v2 consumers read `data.connections` (array) and `data.primary` (id-or-null).

### 7.8 Daemon impact

**Co-design note (not "extension").** The daemon `Command` enum does not exist today — the current daemon (`crates/vortix/src/daemon/server.rs:122`) uses `IpcOp::{Execute, Snapshot, Subscribe, Shutdown}` and returns `IpcError::Internal("engine wiring not yet connected in daemon — coming in v0.3.x")` for the substantive ops. Plan #010 introduces `Command` as part of D1's engine wiring. Multi-tunnel **co-designs** the initial shape of `Command` rather than "growing optional parameters" on an enum that's already shipped — this is what justifies bundling the schema decision with the wiring rather than evolving it twice. The shape multi-tunnel needs:

```rust
pub enum Command {
    Connect { profile_id: ProfileId, force: bool },   // force skips conflict confirm
    Disconnect { profile_id: Option<ProfileId> },     // None = all
    Reconnect { profile_id: Option<ProfileId> },
    Status,                                           // returns Vec<TunnelSnapshot>
    Snapshot { profile_id: Option<ProfileId> },
    Subscribe,                                        // events from any tunnel
}
```

D1 lands a single-tunnel `Connect { profile_id }` + `Disconnect` minimum to prove the wiring; multi-tunnel adds the optional `profile_id` on Disconnect/Reconnect/Snapshot and the `Vec<TunnelSnapshot>` return shape on Status. Plan-#010-and-multi-tunnel-together: one IPC schema bump (1→2). Single-tunnel D1 followed by multi-tunnel: 1→2 then 2→3, with downstream consumers paying the migration tax twice.

### 7.9 Session journal multi-tunnel changes

Per-tunnel events already carry `profile_id` (`crates/vortix/src/vortix_core/journal/writer.rs`). With N tunnels active, events interleave in the single session JSONL — consumers filter via `jq 'select(.profile_id == "corp")'`.

New event types:
- `PrimaryTunnelChanged` (§7.2)
- `ConnectAttemptBlockedByConflict { conflict: Conflict, user_decision: ... }`
- `KillswitchRefreshed { active_interfaces: Vec<String> }`

No schema break for the journal — these are additive event variants.

---

## Heterogeneous (WG + OVPN concurrent) edge cases

Mapping the §7 design to the protocol-level seams:

### H1. DNS suppression — per-protocol mechanism

| Tunnel role | WG (wg-quick) | OVPN (openvpn) |
|---|---|---|
| Primary | Keep `DNS=`; wg-quick calls resolvconf | Let openvpn pull `dhcp-option DNS`, run `update-resolv-conf` |
| Secondary | Strip `DNS=` from temp config | Pass `--pull-filter ignore "dhcp-option DNS"` |

Both protocols have a "skip DNS" knob. Vortix wires both.

### H2. Interface namespace on macOS

WG userspace (wireguard-go) and OVPN both allocate `utunN`. Kernel allocates next-available — no physical collision — but registry must track which `utunN` belongs to which `ProfileId`. `TunnelHandle.interface_name` already carries this; consistent keying in the HashMap handles it.

### H3. PID lifecycle differences

- Kernel WG (Linux): no PID, kernel owns lifecycle, `wg-quick down` removes interface
- Userspace WG (macOS wireguard-go) and OVPN: PID-owned, killable

`TunnelHandle.pid: Option<u32>` already handles both. No new logic.

### H4. Killswitch allow-list for OVPN servers

OVPN configs can have multiple `remote` directives for failover. Vortix doesn't know at parse-time which one openvpn picks. **v1 conservative:** allow all `remote` IPs in the killswitch ruleset. **v2:** integrate with OpenVPN's management socket to query the actually-connected remote (NG5 — deferred).

### H5. Reconnect storm asymmetry

OVPN has `connect-retry-max` (finite); WG retries indefinitely. The FSM's per-tunnel `DEFAULT_RETRY_BUDGET_SECS=300` (`crates/vortix/src/vortix_core/engine/state.rs:16`) bounds both uniformly — but when OVPN exhausts its internal retries while Vortix's budget hasn't, the registry kicks off a fresh `openvpn` invocation rather than letting openvpn decide to give up.

### H6. Teardown ordering on `vortix down --all`

Naive parallel teardown races killswitch refreshes and routing churn. **Resolution:** sequential teardown, secondaries first, primary last; coalesce killswitch refreshes — apply post-teardown ruleset once at the end.

### H7. Telemetry attribution

Today's telemetry probes via "the" VPN interface for latency/jitter/loss. With N tunnels:
- **Primary** tunnel: full telemetry (latency probe via primary's interface, public-internet meaningful)
- **Secondary** tunnels: reduced telemetry (transfer stats + handshake age only — public-internet latency via a secondary isn't a meaningful metric)

Connection Details for a focused secondary displays the reduced set explicitly: *"Latency: n/a (secondary tunnel)"*.

### H8. Fragmentation symptom in heterogeneous setups

WG primary with MTU 1280 + OVPN secondary with default MTU 1500 → OVPN handshake UDP fragments through primary's table 51820 → fragmentation kills handshake. **Same fix as fwmark hijack:** secondary's `FwMark` directive (WG) or equivalent escape route (OVPN — see plan §7.5 follow-up). The v1 warning surface (H1) covers both symptoms.

### H9. Capability mismatch detection

`TunnelCapabilities` (`crates/vortix/src/vortix_core/ports/tunnel.rs:69`) advertises `supports_split_tunnel`, `supports_ipv6`. Registry checks capability before allowing a combination:
- WG supports IPv6 in tunnel; OVPN's IPv6 depends on build flags and config
- If WG primary forces IPv6 globally and OVPN secondary doesn't tunnel IPv6, surface: *"IPv6 will leak from OVPN-secondary tunnel '{name}'"*

---

## Dependencies / Prerequisites — gating v0.3.x items

This feature **cannot start** until the following v0.3.x items land. Building the multi-tunnel registry on a stub `EngineHandle` would force a double IPC schema break and compound the sudo-prompt UX regression that multi-tunnel exposes most acutely.

### D1. Daemon engine wiring (plan #010, deferred to v0.3.x per ROADMAP.md)

**Hard prerequisite.**

Today `crates/vortix/src/daemon/` `dispatch()` returns `IpcError::Internal("engine wiring not yet connected")` for `Execute`/`Snapshot`/`Subscribe`. The TUI bypasses the handle entirely and mutates `self.engine` directly (`crates/vortix/src/app/mod.rs:58` comment chain explicitly notes the handle is "non-load-bearing today").

**Done definition for D1:**
- `vortix up <profile>` and `vortix down` route through the daemon when a daemon is present
- TUI's `App` accesses VPN state through `EngineHandle::Local`, not direct field mutation
- The single-tunnel happy path is exercised end-to-end through the daemon in tests

**Why this gates multi-tunnel:** the registry IS a set of `EngineHandle` actors. If `EngineHandle::Local` has never carried real traffic for one tunnel, designing the registry against it is speculative.

### D2. `SO_PEERCRED` / `getpeereid` enforcement (deferred alongside D1)

**Hard prerequisite.**

A multi-tunnel daemon controls N tunnels via IPC. Exposing that surface to arbitrary local clients without UID auth is irresponsible — a non-root attacker on the same host could disconnect a privileged user's corporate tunnel, etc.

**Today's blast radius (which multi-tunnel multiplies).** The shipped daemon (`crates/vortix/src/daemon/server.rs`) accepts any client on the socket and dispatches without a peer-credential check; the only gate is filesystem permissions (mode 0600 on the socket path). Any local process running as the daemon owner — including a non-root user account's web browser via a compromised extension — can connect and issue commands. At single-tunnel today this exposes one tunnel; at multi-tunnel it exposes N. The doc treats D2 as gating-multi-tunnel partly to close this gap before the attack surface scales. `SECURITY.md` documents this corner case (UID race during socket connect) as the explicitly-deferred item that D2 closes.

**Done definition for D2:**
- Linux: `SO_PEERCRED` socket option read; reject clients with UID ≠ daemon-owner UID
- macOS: `getpeereid(2)` equivalent
- `SECURITY.md` updated from "documented posture" to "shipped enforcement"

### D3. Read-only ops bypass-daemon

**Hard prerequisite.**

`vortix status`, `vortix list`, `vortix audit` continue to work without a daemon running. Multi-tunnel's `vortix status` returns `{ connections: [...], primary: ... }`; without the bypass, every status call requires a daemon connection — a regression for scripts.

**Done definition for D3:**
- `vortix status` / `list` / `audit` read from local files + scanner output when no daemon socket present
- They route through the daemon when present, for live data

### D4. `OvpnTunnel` happy-path integration test (deferred per ROADMAP.md)

**Soft prerequisite — nice to have, not gating.**

Heterogeneous WG+OVPN benefits from CI coverage on the OVPN side. WG already has the v0.3.0 integration test scaffolding (privileged Docker container per [plan #012](docs/plans/2026-05-24-012-feat-ci-integration-tests-plan.md)). OVPN test fixtures (cert generation + stub server) land in v0.3.x.

If D4 slips, multi-tunnel can ship with OVPN tested manually + a follow-up CI gap; if D4 lands first, heterogeneous CI is automatic from day 1.

### Sequencing recommendation

1. **v0.3.x point release** — D1 + D2 + D3 bundled, scope-bounded. ~3-5 weeks.
2. **Multi-tunnel release** — starts the day v0.3.x tags. ~6-10 weeks given surface area.
3. **D4 in parallel** — own CI track, lands when ready; doesn't gate multi-tunnel ship.

### Rollback procedure (G9 single-cut ship — no behind-flag fallback)

Multi-tunnel ships in one cut with no in-version feature flag. If a post-tag regression surfaces in production, the only fallback path is version-revert to the immediately-prior `v0.3.x` release. Document the procedure explicitly so users can self-recover:

1. **Revert binary.** `brew install Harry-kp/tap/vortix@v0.3.x` (or equivalent for cargo / pacman / nix).
2. **Killswitch state file may be incompatible.** `PersistedStateV2` is written by multi-tunnel; if D1 does not pre-land `serde(deny_unknown_fields = false)` tolerance for V2 fields (see §7.6 downgrade contract), V1 readers fail to load and silently disarm. Two paths: **(a)** ensure D1 ships V1 tolerance for `active_tunnels` / `schema_version` *before* multi-tunnel — preferred, makes rollback seamless; **(b)** the rollback procedure includes `rm ${XDG_CONFIG_HOME}/vortix/killswitch-state.json` and re-arming manually — documents the cost of the schema bump.
3. **Imported profiles continue to work.** Profile configs are not migrated by the schema bump; reverting does not orphan user-imported `.conf` / `.ovpn` files.
4. **No data loss on revert.** The session journal at `${XDG_DATA_HOME}/vortix/sessions/` is append-only JSONL and tolerated by both versions.

This procedure assumes the maintainer pre-lands the V1 read-tolerance work as part of D1. Path (b) is the fallback if (a) slips. Either choice should be made before multi-tunnel ships, not after rollback is needed.

---

## Success criteria

A user can:

- **SC1.** Connect to corp (`AllowedIPs=10.0.0.0/8`), then connect to Mullvad (`AllowedIPs=0.0.0.0/0`), and see both in the sidebar with corp marked `●` and Mullvad marked `● *`. Curl-ing an intranet IP routes through corp; curl-ing the public internet routes through Mullvad's exit IP.
- **SC2.** Connect to three regional tunnels with disjoint CIDRs (no `0/0`) and see the header show `⚠ Real: <ip>` with no `*`. Security Guard shows `PARTIAL`.
- **SC3.** With corp connected, attempt to connect Mullvad — see the default-route conflict confirm overlay before any `Tunnel::up` runs. On cancel, no kernel state changes.
- **SC4.** With corp + Mullvad active, `vortix status --json` returns both connections plus `primary: "mullvad"`. `vortix down corp` disconnects corp but leaves Mullvad intact (and Mullvad stays primary).
- **SC5.** With WG primary + OVPN secondary, DNS resolution uses the WG-pushed resolver only (verified via `dig` — same answer when only WG is up vs both up).
- **SC6.** With killswitch `Auto`, bringing up a new tunnel updates iptables/pfctl rules atomically — no observable leak window (verified via continuous traffic during transition).
- **SC7.** With WG primary (`0/0` AllowedIPs) and WG secondary without `FwMark`, see the toast warning at secondary connect-time. (Or, if the user adds `FwMark = 51820`, no warning.)
- **SC8.** Single-tunnel scripts (`vortix up foo && vortix down`) work unchanged.
- **SC9.** With an OVPN secondary configured with `connect-retry-max 3`, induce a handshake failure: openvpn exits after 3 internal retries; registry kicks off a fresh openvpn invocation within the per-tunnel 300s budget; observed total attempts before `RetryBudgetExhausted` ≈ N×3 where N is the number of registry-initiated invocations. Verifies §H5 retry normalization is wired and bounded. **Note:** automated verification of SC9 requires D4 (OVPN integration test fixtures); without D4, SC9 is verified manually on the maintainer's laptop and the gap is recorded in the release checklist.
- **SC10.** Create a malicious profile with `AllowedIPs = 0.0.0.0/1, 128.0.0.0/1` (split-CIDR /1-pair encoding of 0/0). With another tunnel currently primary, attempt to connect the malicious profile. The default-route confirm overlay fires before any `Tunnel::up` runs. Verifies §7.3 CIDR-union check covers the canonical split-CIDR bypass.
- **SC11.** Create a malicious profile with `AllowedIPs = 0.0.0.0/2, 64.0.0.0/2, 128.0.0.0/2, 192.0.0.0/2` (/2 quartet encoding of 0/0). With another tunnel currently primary, the confirm overlay must still fire. Verifies §7.3's CIDR-union check is a true aggregation algorithm, not a pattern-matcher on the /1 pair.
- **SC12.** Connect profile A claiming `0/0`, then immediately (before A reaches `Connected`) press Enter on profile B which also claims `0/0`. The default-route takeover confirm overlay fires for B *before* B's `Tunnel::up` runs — i.e., conflict detection treats A's in-flight `Connecting` state as a pending primary claimant per §7.3. Verifies G8 ("never as a silent route hijack") holds for the Connecting+Enter B race case in §6.6.

---

## Open questions / unverified assumptions

- **Q1.** macOS routing-table read format on macOS 14+ — assumed `netstat -nr -f inet | awk '/^default/{print $NF}'` returns the interface name. Needs a 15-min spike to verify under modern macOS where the routing daemon has changed in incremental ways.
- **Q2.** wg-quick: does stripping `DNS =` from the config also suppress search-domain configuration? If so, secondaries lose `Search =` semantics too — possibly fine, possibly surprising. Needs investigation.
- **Q3.** pfctl ruleset reload atomicity under load — Apple's docs claim atomic but no formal proof; should test under deliberate connection churn to confirm no leak window.
- **Q4.** OpenVPN `--pull-filter ignore` minimum version — added in OpenVPN 2.4 per release notes; need to assert OVPN 2.4+ in `check_dependencies` (`crates/vortix/src/app/connection.rs:67`).
- **Q5.** Should secondary tunnels with `AllowedIPs = 0.0.0.0/0` be **rejected** when connecting (since exactly one primary is allowed) or **demoted** (silently treated as "addressable on 0/0 minus the primary's routes")? Current design says reject + confirm-to-promote. Alternative: implicit-but-loud demotion. The reject-with-confirm path is cleaner; surfacing for review.
- **Q6.** Telemetry probing strategy for secondaries — does Vortix probe via the secondary's interface at all (transfer stats are passive; latency requires active probing)? Active probing through a non-default tunnel needs explicit `--interface` flag on the probe (`curl --interface utunN`), which may not work uniformly on macOS+Linux. Verify.

---

## Risks

- **R1.** **v0.3.x scope creep.** "Let's finish v0.3.x first" can become "let's perfect the daemon." Mitigation: explicit done-definitions for D1-D3 in §9; don't expand v0.3.x beyond them; refuse "while we're here" refactors.
- **R2.** **Per-protocol DNS suppression fragility.** wg-quick's `Table = off` mode disables more than just DNS (it skips automatic route setup entirely). Choosing strip-DNS-line over Table=off keeps the impact narrow but bets on wg-quick not introducing DNS side effects via other directives. Q2 explores this.
- **R3.** **macOS-specific killswitch atomicity.** pfctl atomicity claims have edge cases under high churn. If a multi-tunnel user disconnects-and-reconnects 5 times in 2 seconds, a leak window between rule replacements is plausible. Mitigation: registry coalescer (§7.6) collapses bursts into one refresh.
- **R4.** **Daemon dependency for power users.** Without the daemon running, multi-tunnel users see N sudo prompts (one per connect, one per killswitch refresh). With the daemon, one privileged process mediates everything. If users skip the daemon (legitimate use case for laptops where they don't want a long-running root process), the experience is worse than today. Mitigation: document the daemon-strongly-recommended posture in `docs/MIGRATION.md`-equivalent for this feature.
- **R5.** **Heterogeneous untested combinations in CI.** WG+WG and OVPN+OVPN are exercisable today via the WG integration scaffolding. WG+OVPN and OVPN+OVPN need OVPN CI fixtures (D4). If D4 slips, heterogeneous shipping rests on maintainer-laptop testing — degraded reliability story.
- **R6.** **The fwmark hijack warning becomes user training rather than a fix.** Warn-only means users with WG primary + WG secondary will get a toast they can dismiss; if they dismiss without reading, the secondary's handshake fails silently. Mitigation: link the toast to a clear 2-paragraph docs page explaining what to add to the config and why; consider blocking-confirm overlay instead of toast if user research shows toast is dismissed too easily.
- **R7.** **"Primary changes when you weren't looking."** Because primary is derived from the kernel routing table, a user editing `/etc/wireguard/*.conf` between connects or running raw `wg-quick` outside Vortix can change the primary without a Vortix UI action. The routing-watcher Tick catches this on next refresh and emits `PrimaryTunnelChanged` — correct behavior, but worth documenting as a property so power users don't think Vortix is being magical.

---

## References

### Internal

- `crates/vortix/src/vortix_core/engine/fsm.rs:59` — `Engine<T: Tunnel>` (the per-tunnel FSM that becomes the registry's actor)
- `crates/vortix/src/vortix_core/engine/state.rs:107` — `Connection` enum (six variants, single-profile today)
- `crates/vortix/src/vortix_core/ports/tunnel.rs:37` — `TunnelHandle` (carries interface name and PID per-tunnel)
- `crates/vortix/src/vortix_core/ports/route_table.rs` — `RouteTable` port (extends for `default_route_interface()`)
- `crates/vortix/src/core/killswitch.rs:34` — `enable_blocking` (becomes `enable_blocking_multi`)
- `crates/vortix/src/ui/dashboard/sidebar.rs:58` — sidebar active-row decoration (becomes per-row badge)
- `crates/vortix/src/ui/dashboard/header.rs:20` — header status logic (becomes primary-anchored)
- `crates/vortix/src/ui/dashboard/connection_details.rs:34` — Connection Details (becomes focus-driven)
- `crates/vortix/src/ui/dashboard/security.rs:34` — Security Guard (becomes primary-scoped)
- `crates/vortix/src/app/connection.rs:15` — `toggle_connection` (becomes additive)
- `crates/vortix/src/cli/args.rs:88` — CLI `Up` / `Down` (gains profile-name arg variants)
- `docs/brainstorms/2026-05-24-engine-fsm-event-journal-requirements.md` — the existing FSM design this builds on
- `docs/brainstorms/2026-05-24-daemon-engine-handle-requirements.md` — daemon design that needs D1-D3 to ship before this
- [GitHub Discussion #199](https://github.com/Harry-kp/vortix/discussions/199) — origin

### External (research-validated)

- [Jeff Casavant — WireGuard fwmark gotchas](https://casavant.org/2020/10/10/wireguard-fwmark.html) — primary source for the fwmark hijack failure mode (§7.5, H8)
- [SparkLabs Viscosity — Using Multiple VPN Connections Simultaneously](https://www.sparklabs.com/support/kb/article/using-multiple-vpn-connections-simultaneously/) — best-existing GUI client documentation of multi-tunnel UX
- [Tunnelblick discussion — two VPNs at once](https://groups.google.com/g/tunnelblick-discuss/c/ENEeJyBuFz4) — DNS suppression workaround pattern (§7.4)
- [Apple Developer Forums — multiple simultaneous VPN tunnels on macOS](https://developer.apple.com/forums/thread/687862) — `NEPacketTunnelProvider` single-VPN OS constraint (NG8)
- [Level1Techs Forum — NetworkManager never-default](https://forum.level1techs.com/t/use-this-connection-only-for-resources-on-its-network/206908) — `ipv4.never-default` as Linux NM analog
- [IVPN — WireGuard kill switch Linux](https://www.ivpn.net/knowledgebase/linux/linux-wireguard-kill-switch/) — single-interface kill switch pattern (the gap multi-tunnel closes)
- [Mullvad multi-hop docs](https://mullvad.net/en/help/multihop-wireguard) — confirms multi-hop = server-side chaining (out-of-scope for this feature)
- [wg-quick(8) man page](https://man7.org/linux/man-pages/man8/wg-quick.8.html) — `Table`, `FwMark`, `DNS` directive semantics

---

## Deferred / Open Questions

Items appended from the 2026-05-28 multi-persona review (`ce-doc-review`). Each is a maintainer-judgment decision that did not resolve during the review and needs explicit resolution before planning starts.

### From 2026-05-28 review

- **Q-DEF-1. Fwmark warning — UX surface (security framing first).** Per §7.5, the fwmark hijack is **credential/metadata exposure across trust boundaries** — the secondary's handshake material flows through the primary's operator. This is not a connectivity failure that the user can shrug off; it's a privacy event the user wouldn't catch without instrumentation. Pick one: **(a) blocking-confirm at connect site** — accepts the friction to prevent a non-recoverable cross-operator metadata leak; **(b) persistent panel line in Connection Details** — visible-but-not-blocking; fails readable rather than fails-dismissable (scope-guardian's option); **(c) toast with link to docs page** — v1 ergonomic minimum, accepts that dismissed warnings produce silent credential exposure for users who don't read. §7.5 body currently commits to (c); R6 says "consider blocking-confirm." Resolve in body (§7.5 + R6), don't ship the contradiction.

- **Q-DEF-2. OVPN `remote` IP allow-list — concrete killswitch-bypass exploit, not a posture nit.** §H4 picked "allow all `remote` IPs" as the v1 conservative posture. **Concrete threat:** in `AlwaysOn` killswitch mode, every IP in every imported OVPN profile's `remote` directives bypasses the firewall. An attacker who can cause a user to import a malicious `.ovpn` file (or a profile from a hostile provider) gets that profile's `remote` IPs *permanently allow-listed* through the killswitch — providing an egress path for any traffic the attacker can route to those IPs, even when no Vortix tunnel is up. Three resolution paths: **(i)** trust-source labeling at import (`profile.trust = trusted | untrusted`; only allow-all for trusted, prompt-per-IP for untrusted), **(ii)** OpenVPN management-socket integration in v1 (lift NG5 into scope; allow only the actually-connected `remote`), **(iii)** keep allow-all and document the import-trust assumption explicitly in `SECURITY.md` (cheapest; accepts the threat for users who import from untrusted sources). The killswitch's job is to be the last line of defense; option (iii) makes that defense conditional on profile-source trust, which the doc must state.

- **Q-DEF-3. v0.3.x prerequisite schedule justification.** The doc estimates 3-5 weeks for D1+D2+D3. D1 has been deferred since v0.3.0 ship with no historical date; adversarial review flagged that the estimate has no precedent. Resolution: write a one-pager retrospective on what blocked D1 the first time, and either (a) confirm the 3-5 week estimate is achievable now because that blocker is removed, or (b) revise the estimate honestly. The multi-tunnel start-date depends on this.

- **Q-DEF-4. No-auto-promotion when primary disconnects — direct conflict with actor A5.** Current decision: when the primary tunnel disconnects, Vortix does NOT auto-promote a secondary with `0/0` AllowedIPs; user must explicitly `vortix up <new_primary>`. **A5 contradiction (load-bearing):** A5's stated motivation in §3 — "permanent site link + ephemeral remote tunnel… The persistent site link is exactly the 'secondary that survives' pattern multi-tunnel enables" — is degraded by the no-promotion default. If primary disconnects and the persistent secondary doesn't auto-take the default route, A5's workflow is: "site link survives but I have no public-internet exit until I notice and manually promote." Either A5's actor narrative needs revision (clarify the persistent secondary is split-route only, never default-route failover) or the default needs to invert with an opt-out (auto-promote + visible banner: `Promoted 'corp' to primary because 'mullvad' disconnected — [u] to revert`). Adversarial framing: this contradicts user expectation from browsers, cellular handoff, every redundancy system. Resolve with A5 in scope, not as a generic UX preference.

- **Q-DEF-5. Primary derivation — strategic-identity bet, not just a technical-architecture choice.** §7.2 derives primary from the kernel routing table on every Tick. The two options encode different product philosophies, **not just different code paths**:
  - **(a) Kernel-truth-only:** Vortix is "a faithful viewer of system state." Primary is whatever the kernel says; surprises are documented as a property (R7). Compounds toward: transparent observability tool, low maintenance, fits scripting workflows. The kernel-truth path is also the cleanest fit with §7.4's no-auto-promotion decision — silent kernel changes are the documented behavior, not an alarm condition.
  - **(b) Vortix-owned + kernel-divergence detection:** Vortix is "the authoritative manager of your VPN state." Vortix knows what should be true; the kernel disagreeing is an alert condition (toast: `Primary in Vortix is 'corp' but kernel default is via utun5 — external change detected`). Compounds toward: opinionated VPN manager, higher feature surface, more for end-users. Natural extensions: sticky-primary across reboots, restore-primary-on-reconnect, primary-preferences-per-profile.
  - **Pick consciously, not for short-term implementation convenience.** The decision shapes whether future features (sticky-primary, per-profile defaults, multi-session primary memory) are natural extensions or fights against the model. It also affects all four UI surfaces (header, sidebar `*`, Security Guard, Connection Details Role line) and the persistence schema (whether `primary: ProfileId` is stored in `PersistedStateV2` or derived per-load).

- **Q-DEF-6. `TunnelRegistry` struct vs `Vec<(ProfileId, EngineHandle)>` with free fan-out functions.** Scope-guardian and adversarial both flagged that the named `TunnelRegistry` type introduces ~150 lines of wrapper, HashMap management, coalescer, refresh triggers — when a plain collection of `EngineHandle` actors with three helper functions (`fan_out`, `find_primary`, `reap_disconnected`) might serve the same need. Resolution: prototype both shapes at the implementation start (one day each), pick based on which is clearer when read alongside the existing single-tunnel `EngineHandle::Local` impl, and document the decision in the plan doc.

- **Q-DEF-7. Killswitch coalescer — v1 inclusion vs v2 deferral.** §7.6 commits to a coalescer that batches multiple transitions within one Tick into a single ruleset rewrite. Scope-guardian challenged this as preemptive optimization — realistic user flows are sequential connects separated by seconds, not sub-Tick bursts. Adversarial flagged that coalescing introduces a Tick-cycle (5s) leak window when batching, which is itself a tradeoff not a pure win. Resolution: either (a) keep coalescer as v1 with a Tick-cadence justification grounded in measured `vortix up A; vortix up B; vortix up C` latency or scripted-test scenarios, or (b) defer coalescer to v2 and ship the simpler "one transition = one rewrite" path for v1. The H6 teardown sequence's killswitch-once-at-end behavior can be a separate one-shot batching site without a general coalescer.

- **Q-DEF-8. Release-comms sequencing for the v0.3.x → multi-tunnel two-release plan.** The G9 reword names v0.3.x as "a separate prior gating release." Users who upgrade to v0.3.x see release notes about *infrastructure only* (daemon engine wiring, peer-credential enforcement, read-only-ops bypass) — no user-visible feature payoff. Two risks: (1) v0.3.x looks like a regression-risk update with no upside, suppressing adoption and starving multi-tunnel of users on the gating prerequisite; (2) users who do upgrade and notice the daemon items expect multi-tunnel imminently — when 6-10 more weeks elapse, trust erodes. Pick a release-comms posture: **(a)** v0.3.x ships with explicit "foundation release" framing naming multi-tunnel as next planned milestone (accepts soft-deadline pressure); **(b)** v0.3.x ships with no multi-tunnel preview, treating the gap as opaque infrastructure; **(c)** hold v0.3.x announcement until multi-tunnel's planning has a concrete ship window. Resolution depends on Q-DEF-3's schedule outcome.

- **Q-DEF-9. RFC1918 allow-list overlap with tunnel CIDRs.** §7.6 preserves the existing RFC1918 + DHCP allow-list to avoid breaking LAN/DHCP. With multi-tunnel, a tunnel that declares `AllowedIPs = 10.0.0.0/8` overlaps with the flat `-A OUTPUT -d 10.0.0.0/8 -j ACCEPT` rule — destinations in that CIDR can reach via *any* interface, bypassing the tunnel's interface restriction. Single-tunnel today accepts this implicitly. Multi-tunnel surfaces it because a corp tunnel claiming a subset of RFC1918 becomes a bypass surface. Pick: **(a)** keep flat allow (accept the tradeoff; document explicitly as a known limitation in `SECURITY.md`); **(b)** interface-scope the RFC1918 allow to non-tunnel interfaces only (`! -o utun*` qualifier on the LAN rule); **(c)** subtract per-tunnel declared CIDRs from the flat allow at rule-synthesis time (corp tunnel removes its `10.0.0.0/8` from the LAN allow when active). This is G5 ("killswitch posture remains correct") in tension with the regression-fix that re-added RFC1918.

