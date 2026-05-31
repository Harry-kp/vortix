---
date: 2026-06-01
topic: multi-tunnel-state-authority
---

# Multi-tunnel state authority architecture

## Summary

Establish a single source of truth for each Connected tunnel's kernel interface — the protocol layer's `Tunnel::up()` result — and remove every other write path to that field. All 12 multi-tunnel UX scenarios (sidebar asterisk, header CONNECTED-name, Connection Details Role, Security Guard IP row, overlay routing) then derive from one invariant: every Connected tunnel's stored interface matches kernel reality, set once at connect-time and never overwritten until disconnect.

---

## Problem Frame

Today, two independent subsystems claim authority over the same field — `details.interface` for each Connected tunnel. The protocol layer (`Tunnel::up()`) sets it once at connect-time from authoritative sources (OpenVPN log scrape, wg-quick output). The scanner, running every ~1 second, also sets it from per-PID heuristics that collide in multi-tunnel topologies: on macOS, `check_openvpn_by_pid` falls back to "first utun device with an `inet` line that isn't WireGuard" because modern openvpn opens utun via a kernel control socket rather than `/dev/utun*`. With two openvpn PIDs active, both calls return the same utun — typically the older tunnel's device. The scanner's `refresh_registry_from_session` then overwrites the authoritative value, and the primary-election logic in `recompute_primary` matches arbitrary tunnels against the kernel's egress interface depending on `HashMap` iteration order.

The user-observable failures cluster in two scenarios:

- **Adding a split tunnel on top of a primary** (matrix scenario #3): the asterisk and header switch to the new tunnel even though the kernel still routes egress through the original. The UI lies about which tunnel owns the route.
- **Adding a primary on top of a split tunnel** (matrix scenario #12): the existing split's iface gets clobbered into the new primary's slot, and neither registry entry matches the kernel's egress, so both render as `Addressable` (split tunnel) when one of them genuinely owns the default route.

A secondary defect compounds these: `scanner_promote_to_connected` can transition an in-flight `Connecting` tunnel to `Connected` using scanner data **before** the protocol layer's authoritative result returns. The promotion uses the (already wrong) scanner-reported interface, and the later authoritative result has no clean path to correct it because the entry is already `Connected`.

Both defects stem from the same architectural shape: **dual authority over a field that has, by construction, one true value at any moment.**

---

## Actors

- **A1. End-user running multiple VPN tunnels.** Mixes profiles (full-tunnel primaries, split tunnels, mixed-protocol WireGuard + OpenVPN) and switches between configurations during a session. Expects every surface (sidebar, header, Role, SG IP) to agree with each other and with the kernel's actual routing decision.

---

## Key Flows

- **F1. Single tunnel — full lifecycle.**
  - **Trigger:** User selects a profile in the sidebar and presses Enter; later presses Enter again or `d` to disconnect.
  - **Actors:** A1
  - **Steps:** Protocol layer's `Tunnel::up()` runs, returns authoritative interface; registry transitions Connecting → Connected with that interface; recompute_primary runs and elects the tunnel if it owns kernel egress; user disconnects; recompute_primary runs again; entry transitions to Disconnected.
  - **Outcome:** Single-tunnel state is correctly reflected on every surface during all transitions.
  - **Covered by:** R1, R2, R6, R7, R9, R10

- **F2. Add secondary tunnel beside primary.**
  - **Trigger:** With one tunnel already up, user presses Enter on another profile.
  - **Actors:** A1
  - **Steps:** Conflict detector classifies the new profile (claims default route? overlaps CIDR? disjoint?). Disjoint → connects directly. Overlap → ConfirmRouteOverlap overlay; user accepts. Default-route claim → ConfirmDefaultRouteTakeover overlay; user chooses Switch or Both.
  - **Outcome:** Both tunnels' interfaces correctly recorded; primary correctly reflects whichever owns kernel egress; every surface agrees.
  - **Covered by:** R1, R2, R3, R7, R9, R10

- **F3. Primary disconnect with eligible auto-promote candidate.**
  - **Trigger:** Active primary disconnects (user action or external).
  - **Actors:** A1
  - **Steps:** Primary's routes leave the kernel routing table. Kernel re-elects whichever remaining tunnel's routes win for the egress probe. `recompute_primary` runs and observes the new primary. UI surfaces 10-second auto-promote banner.
  - **Outcome:** Banner announces the promotion; new primary surfaces on every panel.
  - **Covered by:** R7, R8, R9

- **F4. External-tunnel adoption (best-effort).**
  - **Trigger:** Scanner detects a connected tunnel not in the registry whose name matches a catalog profile.
  - **Actors:** A1 (passive — they ran `wg-quick up corp` from another terminal)
  - **Steps:** Scanner constructs `ActiveSession` with whatever it can determine, including a best-effort interface. If the host platform's per-PID iface detection is reliable, register the entry as Connected with that interface; otherwise register without an interface and refuse to elect as primary.
  - **Outcome:** Externally-started tunnels appear in the TUI; if iface is uncertain, the UI signals "external (iface unknown)" and won't claim primary status.
  - **Covered by:** R4, R7

---

## Requirements

**Interface authority contract**

- R1. The interface name stored at `details.interface` for any Connected tunnel is set exactly once at the moment the protocol layer's `Tunnel::up()` returns successfully. It is never overwritten while the tunnel remains in any non-Disconnected state.
- R2. Scanner-driven refresh paths update mutable session metadata (transfer counters, MTU, internal IP, latest-handshake age, endpoint when not previously known) but never the interface field of an existing Connected entry.
- R3. The Connecting → Connected state transition can be driven ONLY by the protocol layer's success result. The scanner cannot promote a Connecting entry to Connected based on its own observation, regardless of whether the scanner sees a matching kernel-level tunnel.

**External adoption**

- R4. When the scanner detects a connected tunnel that matches a catalog profile but has no registry entry, the adopted entry is registered with the scanner's best-effort interface only if the host platform supports reliable per-PID iface detection. If per-PID detection is not reliable on the platform (current state: macOS multi-openvpn), the entry is registered without an interface and is excluded from primary-election candidacy until a reliable interface is determined. The UI signals the unmapped state clearly.

**Mixed-protocol consistency**

- R5. The protocol layer for WireGuard returns the kernel-visible interface name in `Tunnel::up()`'s result, identical to what `route -n get <internet IP>` or `ip route get <internet IP>` would report when this tunnel owns the egress. On platforms where wg-quick creates an aliased device (e.g., macOS, where wg-quick maps a config-named tunnel onto an underlying `utunN`), the protocol layer returns the underlying utun name, not the config basename.

**Connect lifecycle**

- R6. A Connecting tunnel that does not reach Connected via the protocol layer within the configured connect timeout transitions to Disconnected with a `last_failure` record. Stuck-in-Connecting must not be a possible terminal state. The timeout fires regardless of what the scanner observes about the underlying daemon during the wait.

**Primary derivation**

- R7. The registry's `primary` field is derived from kernel routing alone: probe the kernel for the egress interface of an internet-bound IP, match that interface byte-for-byte against the `details.interface` of every Connected tunnel, and elect the unique matching tunnel as primary. When no tunnel matches, `primary` is `None`. No vortix-side tiebreaker, prioritization, or stored override exists.
- R8. When the active primary's entry transitions to Disconnected, the registry re-derives primary per R7 in the same operation. If a different Connected tunnel now matches the kernel's egress interface, primary changes to that tunnel and a 10-second auto-promote banner surfaces in the TUI showing `Promoted '<new>' because '<old>' disconnected — [u] to revert`. When no remaining tunnel matches kernel egress, primary becomes `None` with no banner.

**Per-surface display invariant**

- R9. The sidebar asterisk, the header `CONNECTED (<name>/<protocol>)` segment, the Connection Details `Role:` line, and the Security Guard `Identity` IP row all derive their value from a single source: the registry's `primary` field and the per-profile `snapshot.role`. No surface independently classifies which tunnel is primary. Every surface must agree, in every state, on every render.
- R10. The `Role` derivation has the following precedence and meaning:
  - `Primary` — this profile is the registry's `primary`.
  - `AddressableSuppressed` — this profile's static AllowedIPs claim the default route, AND a different profile is the registry's `primary`.
  - `Addressable` — this profile's static AllowedIPs do NOT claim the default route, AND another profile is `primary` or `primary` is `None`.
  - The first check (`self.primary == Some(profile_id)`) takes precedence over any AllowedIPs-based logic. This means a tunnel without `0/0` AllowedIPs in its config CAN render as `Primary` if the kernel routes egress through it (e.g., OpenVPN with server-pushed `redirect-gateway`), and a tunnel WITH `0/0` AllowedIPs that lost the kernel-route race renders as `AddressableSuppressed`.

---

## Acceptance Examples

Format: `Scenario N — <setup>. Expected per surface.` Every AE below derives from the requirements above; none introduce new behavior. Test profiles: `F1`, `F2`, `F1'` claim default route (e.g., OpenVPN with `redirect-gateway` in client config, or WG with `AllowedIPs = 0.0.0.0/0`); `S` does not.

- **AE1. Scenario 1 — Connect F1 alone.** Covers R1, R7, R9, R10. Header: `CONNECTED (F1/<proto>)`. Sidebar `*`: F1. F1 Role: `Primary`. SG IP row: F1's exit IP with ✓ sigil. No overlay.

- **AE2. Scenario 2 — Connect S alone.** Covers R7, R9, R10. Header: no exit indicator (primary is `None`). Sidebar `*`: none (S shows the connected dot but not the primary marker). S Role: `Addressable`. SG IP row: "split-route — no exit". No overlay.

- **AE3. Scenario 3 — F1 up, then connect S (disjoint CIDR).** Covers R1, R2, R3, R7, R9, R10. No overlay (conflict detector reports disjoint). Header: F1. Sidebar `*`: F1. F1 Role: `Primary`. S Role: `Addressable`. SG IP row: F1's exit IP, ✓. The scanner running during/after S's connect must not change any of the above.

- **AE4. Scenario 4 — F1 up, then connect S with overlapping CIDR.** Covers R7, R9, R10, plus the existing ConfirmRouteOverlap requirement from the original brainstorm. ConfirmRouteOverlap overlay fires; user presses Y. Post-connect surface state identical to AE3.

- **AE5. Scenario 5 — F1 up, then connect F2; user presses Y on takeover overlay (Switch).** Covers R1, R7, R8, R9. ConfirmDefaultRouteTakeover overlay fires; user presses Y. F1 is disconnected sequentially; F2 connects after F1's teardown completes. Header: F2. Sidebar `*`: F2. F1 row: no row state (disconnected). F2 Role: `Primary`. SG IP row: F2's exit IP, ✓.

- **AE6. Scenario 6 — F1 up, then connect F2; user presses B on takeover overlay (Both).** Covers R1, R7, R9, R10. ConfirmDefaultRouteTakeover overlay fires; user presses B. Both tunnels remain up. The kernel's longest-prefix match for the egress probe resolves to whichever tunnel's routes were inserted last (typically F2). Header: F2. Sidebar `*`: F2. F1 Role: `AddressableSuppressed`. F2 Role: `Primary`. SG IP row: F2's exit IP, ✓.

- **AE7. Scenario 7 — From AE6 state, disconnect F2.** Covers R7, R8, R9, R10. F2's routes leave the kernel. Kernel egress now resolves to F1's still-present routes. Auto-promote banner surfaces (10s, `[u]` to revert). Header: F1. Sidebar `*`: F1. F1 Role: `Primary`. F2 row: no row state (disconnected).

- **AE8. Scenario 8 — From AE6 state, disconnect F1.** Covers R7, R9. F1 was suppressed, not the kernel's egress owner. F1's routes leave; F2's routes (which were winning) remain. No primary change. No banner. Header: F2. Sidebar `*`: F2. F2 Role: `Primary`. F1 row: no row state.

- **AE9. Scenario 9 — From AE3 state, disconnect S.** Covers R7, R9. S's routes are specific (non-default). Their removal does not affect kernel egress. Header: F1. Sidebar `*`: F1. F1 Role: `Primary`. S row: no row state. No banner.

- **AE10. Scenario 10 — From AE3 state, disconnect F1.** Covers R7, R8, R9, R10. F1's default-covering routes leave the kernel; egress reverts to the LAN gateway. S has no default-claiming routes, so no auto-promote candidate. Primary becomes `None`. Header: no exit. Sidebar `*`: none. S Role: `Addressable`. SG IP row: "split-route — no exit". No banner.

- **AE11. Scenario 11 — From AE6 state, connect F1' (third default-route-claiming profile).** Covers R1, R7, R9, R10. ConfirmDefaultRouteTakeover overlay fires citing F2 as the current primary; user presses B. F1' connects. Kernel egress resolves to F1''s routes (last-inserted). Header: F1'. Sidebar `*`: F1'. F1' Role: `Primary`. F1 Role: `AddressableSuppressed`. F2 Role: `AddressableSuppressed`. SG IP row: F1''s exit IP, ✓.

- **AE12. Scenario 12 — Connect S, then connect F1.** Covers R1, R3, R7, R9, R10. No overlay when connecting S (it doesn't claim default; no primary exists yet). When F1 connects, conflict detector reports no conflict (no current primary, no in-flight 0/0 claimant); no overlay; connect proceeds. F1's routes win kernel egress. Header: F1. Sidebar `*`: F1. F1 Role: `Primary`. S Role: `Addressable`. SG IP row: F1's exit IP, ✓.

---

## Success Criteria

- All 12 scenarios in the matrix pass manual verification — each surface (header, sidebar asterisk, Role, SG IP row, overlay) matches its AE row exactly, including during the transition windows where the scanner is running concurrently with a connect or disconnect.
- The state-authority invariant holds: at no point during any of the 12 scenarios does any code outside the protocol layer's `Tunnel::up()` result write to `details.interface` of an existing Connected entry.
- Mixed-protocol topologies (WG primary + OpenVPN secondary, OpenVPN primary + WG secondary) behave identically to single-protocol topologies, scenario-for-scenario.
- A regression test exists for the iface-clobber path (preserving authoritative iface across a scanner refresh that reports a different iface).
- A regression test exists for the scanner-promote race (Connecting + scanner-reported active session must NOT result in Connected with scanner-derived iface).

---

## Scope Boundaries

- Improving the macOS scanner's per-PID heuristic detection — deprioritized. After this work, correctness no longer depends on it. The scanner's per-PID iface detection remains as best-effort metadata for external adoption only (R4), where unreliable detection now degrades to "no primary election" rather than to a wrong primary.
- IPv6 default-route handling — deferred. The egress probe target stays IPv4 (e.g., 8.8.8.8); IPv6 multi-tunnel topologies follow when v6 support lands more broadly per the original brainstorm's H1.
- Killswitch ruleset rewrite ordering during primary changes — already covered by §7.6 of the original multi-connection requirements doc; no new requirements added here.
- Windows multi-tunnel — out of scope until `vortix_platform_windows` exits stub status (see CHANGELOG v0.3.0 deferred list).
- The `[B]` takeover overlay's semantics — out of scope as a UX question. This doc inherits the current "new becomes active exit" wording. If a future brainstorm wants to flip those semantics (e.g., "old stays primary, new added as suppressed"), it can — but it does not change the iface-authority contract above.

---

## Key Decisions

- **D1. Protocol layer is sole authority for `details.interface`.** Chosen over (a) live kernel queries per render (high syscall cost; wide refactor across killswitch/NetworkStats/scanner consumers) and (b) making the scanner's per-PID heuristic correct (fragile per-platform; doesn't address the scanner-promote race). The chosen approach is the smallest delta with the largest correctness gain — and it captures what the existing plan's D-4 already intended.
- **D2. No vortix-side auto-promote tiebreaker.** When multiple eligible secondaries could promote, the kernel's deterministic route-resolution decides. Vortix's `recompute_primary` faithfully renders whichever tunnel the kernel chose. This avoids layering a policy on top of the kernel and matches D-4's kernel-truth stance literally.
- **D3. WireGuard on macOS returns the underlying utun device from `Tunnel::up()`.** The config basename is a human-facing label; the kernel only knows the utun. Returning the utun keeps the registry's iface field byte-comparable with `route get`'s output. Discovery method (parse `wg-quick` output, scan `ifconfig` for the alias, etc.) is a planning concern.
- **D4. Scanner adoption can register a tunnel without an interface.** When per-PID detection isn't reliable on the host, an externally-adopted entry has `details.interface = None` and is ineligible for primary election. The TUI surfaces this state ("external — iface unmapped") rather than fabricating an iface from "first available utun" heuristics.

---

## Dependencies / Assumptions

- The kernel-routing probe (`route -n get 8.8.8.8` on macOS, `ip route get 8.8.8.8` on Linux) returns the actual egress interface under all relevant VPN topologies, including OpenVPN's `redirect-gateway def1` (which inserts `0.0.0.0/1 + 128.0.0.0/1` over the original default rather than replacing the default-route entry). This assumption was validated in the prior session's route-probe fix.
- The existing connect-timeout in the OpenVPN protocol layer (`OVPN_PID_FILE_TIMEOUT_SECS` and the connect-timeout-secs parameter) transitions a stuck Connecting state to Disconnected with `last_failure`. Verification pending — see Outstanding Questions.
- The WireGuard protocol layer has equivalent connect-timeout semantics. Verification pending.
- The TUI auto-promote banner machinery (10s display, `[u]` revert keybinding) is wired through `EngineEvent::PrimaryTunnelChanged` to the UI layer per the original brainstorm's §6 and plan U18. Existence in current code is assumed; this doc does not introduce the banner concept.
- `EngineEvent::PrimaryTunnelChanged` includes a `reason` discriminant the UI uses to decide whether to show the banner (banner only when reason is `PriorPrimaryDisconnected`, not on user-driven takeover).

---

## Outstanding Questions

### Resolve Before Planning

None — the brainstorm's three call-outs (auto-promote selection rule, WG-on-macOS iface, connect-timeout safety net) were resolved during dialogue and captured in D2, D3, and Dependencies/Assumptions respectively.

### Deferred to Planning

- [Affects R5][Technical] On macOS, what is the most stable method for `wg-quick`'s connect path to discover the underlying `utunN` device for a given config name? Options to evaluate: parse `wg-quick up` stdout/stderr for the interface-creation line, run `ifconfig <config-name>` and parse the underlying device reference in the output, use `wg show <name>` and cross-reference, or query the `networksetup` interface list. Pick the method least likely to break on macOS version drift.
- [Affects R4][Technical] When scanner adoption registers a tunnel without an interface, what does the TUI render in the Connection Details `Interface:` line? Options: "external (unmapped)", "—", or omit the row entirely with a sibling badge.
- [Affects R6][Needs verification] Verify the OpenVPN connect-timeout actually transitions Connecting → Disconnected with a `last_failure` record in current code, and that the failure record is consumed by the FSM to allow user retry. Verify the equivalent path on WireGuard.
- [Affects R3][Technical] Removing `scanner_promote_to_connected` requires a clean alternative for the case where the protocol layer's success message is delayed or dropped (e.g., IPC bug, message channel saturation). Decide: hard-rely on the protocol layer's result, or add a watchdog timeout in the App layer that surfaces "connect appears successful but no result received — retry?" to the user.
- [Affects R8][Technical] The 10-second auto-promote banner needs a clean unique-identifier per primary transition to avoid stacking multiple banners on rapid promote/demote cycles. Decide the dedupe mechanism during planning.
