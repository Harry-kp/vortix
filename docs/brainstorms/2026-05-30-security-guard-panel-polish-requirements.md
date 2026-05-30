---
date: 2026-05-30
topic: security-guard-panel-polish
---

# Security Guard panel polish

## Summary

A visual polish pass on the dashboard's Security Guard panel so a normal tech user can answer "how safe am I, what's exposed?" within ~2 seconds of glancing, with no overflowing text, no ill-fitted padding or headings, and a calm reading rhythm. Content (IP, DNS, IPv6, killswitch, encryption) stays as-is; layout, sigil placement, and visual weighting change. No new theme colours — the panel reuses the existing palette so it stays coherent with the Sidebar, Connection Details, Chart, and Logs panels.

---

## Problem Frame

The Security Guard panel sits in the dashboard's bottom-left at roughly 32×10 cells when the terminal is 80×24 (the project's minimum baseline per `CLAUDE.md`'s "fits cleanly at 80×24" note) and ~48×18 at 120×40. The current `crates/vortix/src/ui/dashboard/security.rs` `PROTECTED` branch renders ~17 lines of content — bold `PROTECTED` headline, per-check rows with `✓/✗/⚠` sigils on the left, optional sub-rows (`Real IP: ... (hidden)`, `Provider: (Cloudflare)`, `Pre-VPN: ...`), an always-warning IPv6 row, a long killswitch line ending in a multi-clause status phrase, the encryption row, "Last checked" timestamp, and a sigil legend.

That set hits the panel's height limit on most terminals. A compaction loop drops blank lines until it fits, leaving a cramped wall of left-aligned sigils + colons + truncated values. The PROTECTED headline is always loud regardless of whether the killswitch is engaged, the IPv6 row warns about a problem the user cannot fix on any supported platform, and the legend (the sigils' meaning) is the first line dropped during compaction. Net effect: a user looking for "am I safe right now?" reads seven mismatched rows and infers from sigil colour, which is not the experience a security panel should deliver.

The fix is purely visual — no checks are added or removed, no data sources change, no new colour constants ship.

---

## Requirements

**Layout**

- R1. The three render branches (`PROTECTED`, `PARTIAL`, `EXPOSED`) follow one shared visual language — sigil-on-right column, dim section words, muted-by-default sigils, no perpetual sub-bullets — so the panel feels consistent regardless of posture.
- R2. Each row has the shape `<leading space> <label> <value> <padding> <sigil>`. The sigil column is right-aligned and a fixed width (3 cells: `✓ ` / `✗ ` / `⚠ ` / `─ `) so labels + values get every other cell in the panel for content.
- R3. Sections are introduced by a single short word in dim accent (`Identity`, `Defense`), not by a bold headline. The bold `PROTECTED` / `PARTIAL` / ` EXPOSED ` banner is removed from the default render.
- R4. Section grouping is: `Identity` (IP + Location) and `Defense` (Killswitch + Encryption + IPv6). DNS belongs under `Identity` (it's the user's identity on the network, same group as IP) — confirmed in dialogue alongside the section-word picks.
- R5. Each section is separated from the next by exactly one blank line. No double blanks. The footer line (`Updated Ns ago`) is separated from the last section by one blank line.

**Visual weighting**

- R6. Sigils use the existing theme constants only — `theme::SUCCESS` for `✓`, `theme::ERROR` for `✗`, `theme::WARNING` for `⚠`, `theme::INACTIVE` for `─`. No new colour constants ship.
- R7. In the all-OK state every sigil renders muted (the existing dim variant of its colour, achieved via `Style::default().fg(…)` without `Modifier::BOLD`). A sigil only renders **bright** (with `Modifier::BOLD`) when its row is in an alarm state — `✗` on a real leak, `⚠` on an acute issue (e.g. KS dropped, real IP visible during connect handshake).
- R8. The panel's overall colour palette and border styling stay coherent with the other dashboard panels — same `theme::BORDER_DEFAULT` / `theme::BORDER_FOCUSED` choice, same horizontal padding of 1, same `Block::default().borders(Borders::ALL)` shape.

**Content trimming (always-on render)**

- R9. The long killswitch status phrase (`firewall engaged — only VPN traffic permitted`, `watching — will engage if the VPN drops`, etc.) is removed from the default-rendered KS row. The row reads `Killswitch <mode-label> <sigil>`. The phrase remains available via focus / flip behaviour (R14) and via `vortix killswitch` on the CLI.
- R10. The IPv6 row uses `─` (not applicable) instead of `⚠` (warning) and the value text is `v4-only`. The previous explainer string (`Not enforced (v4-only killswitch)`) is removed from the default render.
- R11. The `Real IP: <ip> (hidden)` sub-bullet is removed from the default render. Reason: the value is visible whether the masking sigil is `✓` or not, and showing it leaks the user's real IP in screenshots of an otherwise-clean panel.
- R12. The DNS provider name (`(Cloudflare)`, `(Google)`, `(Quad9)`) collapses inline with the DNS value (`1.1.1.1 · Cloudflare`) instead of rendering as a sub-row.
- R13. The sigil legend row (`Legend: ✓ pass · ⚠ at risk · ─ not applicable`) is removed from the panel. The same legend ships in the `?` help overlay so meaning stays discoverable for first-time users.

**Detail surface (preserves removed content elsewhere)**

- R14. The current `f`-flip "Active Connections Audit" view stays as the existing placeholder. The KS status phrase and IPv6 explainer that were removed in R9 / R10 remain available via the CLI (`vortix killswitch`, `vortix status`) and via inline status copy when their row is in an alarm state (see R15 and Acceptance Examples).
- R15. When a row is in an alarm state (sigil bright `✗` or bright `⚠`) it MAY render one extra sub-line below it with a short human-readable reason (e.g. `leaking — see status`, `VPN dropped — press r to reconnect`). The sub-line uses `theme::TEXT_SECONDARY`. This sub-line is the only sub-row allowed in the default render and only when the parent row is alarming.

**Responsive width handling**

- R16. At panel widths < 28 cells, the section words (`Identity`, `Defense`) drop and the panel renders as a flat 5-row list (the rows themselves never overflow because the sigil column is right-aligned and labels are short).
- R17. Values that would still overflow (rare — only the public IP can ever exceed ~16 chars after R12 inlines the provider) get truncated with `…` rather than mid-character cut, using the existing `utils::truncate` helper.

**Footer**

- R18. Replace `Last checked: 3s ago` with `Updated 3s ago` (fewer leading words, less prefix weight). Same source of truth (`app.runtime.last_security_check`).

---

## Acceptance Examples

- AE1. **Covers R1, R3, R5, R6, R7.** Given the primary tunnel is connected with masked IP, non-leaking DNS, `vpn-only` killswitch in `Blocking` state, when the panel renders at 32×10, it shows the headline-free `Identity` + `Defense` layout. Every sigil is muted green/grey, no row contains a bold modifier, and the panel fits with no compaction-driven blank-line drop.

```
┌── Security Guard ─────────────┐
│  Identity                     │
│   IP   1.2.3.4 · US-East  ✓   │
│   DNS  1.1.1.1 · Cloud.   ✓   │
│                               │
│  Defense                      │
│   Killswitch   VPN-only   ✓   │
│   Encryption   ChaCha20   ✓   │
│   IPv6         v4-only    ─   │
│                               │
│  Updated 3s ago               │
└───────────────────────────────┘
```

- AE2. **Covers R7, R15.** Given the primary tunnel is connected and `app.runtime.real_dns == app.runtime.dns_server` (DNS-leak condition), when the panel renders, the DNS row's sigil is bright `✗` (with `Modifier::BOLD`), the value shows the leaking DNS IP, and exactly one sub-line in `theme::TEXT_SECONDARY` reads `leaking — see status`. All other sigils stay muted. No other row gains a sub-line.

- AE3. **Covers R1, R9, R15.** Given killswitch mode is `Auto` and state is `Blocking` (VPN dropped after being up), when the panel renders, the `Killswitch` row sigil is bright `⚠`, the row reads `Killswitch   VPN dropped   ⚠`, and one sub-line reads `firewall engaged — press r to reconnect`. The killswitch long phrase is NOT shown in the all-OK state (AE1) but IS surfaced as this alarm sub-line.

- AE4. **Covers R1, R10.** Given the panel is in the `PARTIAL` branch (active tunnels exist but no primary owns the default route), when it renders, it follows the same `Identity` + `Defense` layout as AE1 — not a different visual language. The IP row's sigil is `─` (no primary exit to evaluate), the `Killswitch` row reads its current mode + sigil, and the IPv6 row reads `v4-only ─` as in AE1.

- AE5. **Covers R1, R3.** Given there are zero active tunnels (`EXPOSED` branch), when the panel renders, it still uses the section-word + sigil-right layout. The `Identity` IP row sigil is bright `⚠`, value reads the user's real public IP (`utils::truncate`-bounded), and a single sub-line in `theme::TEXT_SECONDARY` reads `no VPN — your real IP is visible`. The bold `EXPOSED` banner is removed.

- AE6. **Covers R16.** Given the panel renders at width 26 cells (below the 28-cell threshold), when it renders, the `Identity` and `Defense` section words drop. The five content rows render flat (IP, DNS, Killswitch, Encryption, IPv6), each still terminated by the right-aligned sigil. The footer row (`Updated …`) is preserved.

- AE7. **Covers R13.** Given the panel is rendering and the user has not opened `?` once, when they want to know what `─` means, they press `?` and find the sigil legend among the keybindings. The legend never renders inside the Security Guard panel itself.

---

## Success Criteria

- A user opening the dashboard for the first time can verbalize their safety posture ("I'm protected, IP is hidden, killswitch is on") within ~2 seconds of glancing at the panel, without scanning seven sigil colours sequentially.
- The panel at 80×24 fits its rendered content with **zero** compaction-driven blank-line drops — the layout is sized to fit, not relying on the runtime to trim.
- Every sigil colour and every text colour on screen resolves to an existing `crate::theme` constant — no new colour constants land in `crates/vortix/src/theme.rs`.
- A regression test covers each of AE1–AE6 so the polish doesn't drift back to the current shape; the test asserts on the rendered `Vec<Line>` (line count + per-row sigil placement + presence/absence of sub-lines) rather than pixel output.
- The manual-testing backlog gains one row that names the panel and the cell-budget assertion (80×24 with no compaction drops) so future contributors verify the panel hasn't regrown.

---

## Scope Boundaries

- The flip-side `f` "Active Connections Audit" view stays as the current placeholder. Per-socket VPN routing verification is tracked separately (GitHub issue #168 referenced in `render_back`).
- Other dashboard panels (Sidebar, Connection Details, Chart, Logs) and the dashboard header bar are not re-skinned. Coherence is achieved by the Security Guard panel reusing their theme constants, not by touching them.
- No new colour constants in `crate::theme`. If a colour is missing, the polish accommodates by using an existing constant or by switching to bold/dim modifiers on an existing colour.
- No new checks added (no split-tunnel verification, no encryption-strength scoring, no per-server geo-IP validation). The set of facts the panel reports is the current set.
- No behavioural change to killswitch logic, leak-detection logic, or scanner cadence. The polish reads from existing runtime state.
- No change to the CLI (`vortix status`, `vortix killswitch`) human or JSON output — the long killswitch status phrase the panel drops (R9) is still emitted by the CLI's `vortix killswitch` human path.

---

## Key Decisions

- **Sigil on the right, not the left.** Pulls the status off the eye-grabbing leftmost column, frees label + value to expand into the panel's width, and lets the panel read like a form ("here's what you have, here's its status") rather than a checklist ("here are seven verdicts, one per row"). Trade: loses the leftmost-status pattern users may know from other CLI tools.
- **Muted by default, bright only on alarm.** The all-OK state has no bolded sigils anywhere — the panel is calm and recedes when nothing needs attention. An alarming row is the only bold element on screen, which makes attention-pulling work without screen-wide colour churn.
- **Drop the long KS status phrase from the always-on render.** The phrase ("firewall engaged — only VPN traffic permitted" etc.) is helpful when something IS the killswitch's job to explain, but in the all-OK state it's the longest line in the panel and routinely truncates. Remove from default; resurface as the alarm sub-line (R15) and via `vortix killswitch` on the CLI.
- **IPv6 sigil becomes `─` (not applicable), not `⚠`.** The killswitch is v4-only on every supported platform and the user has no fix path. A persistent `⚠` trains the user to ignore warnings; `─` honestly says "this dimension isn't being enforced and there's nothing you can do." The dimension is still reported, just not flagged as a fixable problem.
- **Remove `Real IP: <ip> (hidden)` from the default render.** Showing the real IP in dim grey under a "✓ masked" sigil leaks it in screenshots of an otherwise-clean panel. The `✓` already attests that masking is working; the actual value is not required at the safety-readout layer.
- **Move the sigil legend into the help overlay.** Legend was the first line dropped during compaction, so it was unreliable as the discovery surface anyway. The `?` overlay is the canonical place for "what does this symbol mean" and already lists every keybinding.

---

## Dependencies / Assumptions

- Existing `crate::theme` constants are sufficient — specifically `SUCCESS`, `ERROR`, `WARNING`, `INACTIVE`, `TEXT_SECONDARY`, `ACCENT_PRIMARY`, `BORDER_DEFAULT`, `BORDER_FOCUSED`. Verified against `crates/vortix/src/theme.rs` should be done during planning if any of these are absent.
- The `?` help overlay (`crates/vortix/src/ui/overlays/help.rs`) can absorb the three-symbol sigil legend without exceeding `state::HELP_OVERLAY_MAX_HEIGHT` — verified during planning.
- `app.runtime.real_dns` / `real_ip` / `public_ip` / `dns_server` / `killswitch_mode` / `killswitch_state` / `last_security_check` / `registry.primary()` continue to be the source-of-truth fields the panel reads from. The polish is rendering-only; no new runtime state.
- Existing `utils::truncate` helper handles the rare overflow case for very long public IPs (R17). No new helper introduced.
- The panel's animated panel wrapper (`render_animated_panel` in `dashboard/mod.rs`) is unaffected — polish is inside the `render` callback only.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R4][Technical] Where exactly does the existing `theme::ACCENT_PRIMARY` resolve under the current Nord palette, and is it visually distinct enough from `theme::TEXT_SECONDARY` to read as a section-word accent (planning should view side-by-side in the actual TUI before locking the colour pick for the section words).
- [Affects R7][Technical] Confirm whether `Modifier::BOLD` on an existing theme colour creates the "bright vs muted" distinction the design needs, or whether the design needs a second tone (in which case fall back to using `theme::TEXT_SECONDARY` for the muted state — never adding a new colour constant).
- [Affects R15][Technical] Whether the alarm sub-line can be cleanly rendered within the existing `Paragraph::new(audit)` shape, or whether it needs a per-row wrap helper. Planning to decide.
