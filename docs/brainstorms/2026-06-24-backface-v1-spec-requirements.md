---
date: 2026-06-24
slug: backface-v1-spec
status: ready-for-plan
origin: docs/ideation/2026-06-24-flip-panel-back-faces-ideation.md (survivors #2 + #4)
parent_issue: https://github.com/Harry-kp/vortix/issues/235
sub_issue: https://github.com/Harry-kp/vortix/issues/168
---

# BackFace v1 spec + Security Guard EICAS migration — requirements

## Problem frame

The `ratatui-flip-panel` widget ships and three dashboard panels (Chart, Connection Details, Security Guard) have back-face placeholders that point at issues #166/#167/#168. The placeholders themselves promise content "in a future release" — there is no shared contract, no shared vocabulary, no consistent scope rendering, no degradation pattern. Building each back face independently will produce three diverging UI surfaces with three sets of conventions.

This is the foundation pass: establish the BackFace v1 contract and validate it by migrating the Security Guard back face to EICAS-style content (per ideation survivor #4). The other two panels (#166, #167) keep their existing placeholders until follow-up PRs.

## Scope

**In scope:**
- A new module `crates/vortix/src/ui/dashboard/backface.rs` exposing the BackFace v1 contract:
  - `VerdictMode` enum + helpers (4-state, modeled on `KillSwitchMode`)
  - `Severity` enum + helpers (4-level, EICAS-derived)
  - `Scope` enum + helpers (5 cases: primary / focused-secondary / external-adopted / unsupported / partial)
  - `render_verdict_band(...)`, `render_scope_footer(...)`, `render_nav_hint_band(...)` helpers
- Migrate `crates/vortix/src/ui/dashboard/security.rs::render_back` to the spec with EICAS-style content
  - Reads `SocketAudit` port to classify sockets as Pass/Watch/Fail/Unknown
  - Renders verdict band → alert ribbon (priority-ordered, exceptions-only) → scope footer + nav-hint
- Unit tests covering each helper + `Severity`/`VerdictMode`/`Scope` enum methods
- Snapshot tests for `security.rs::render_back` with three scenarios (clean, one-leak, no-VPN)
- CHANGELOG entry under `### Added` and `### Changed`
- Manual-testing backlog row (`docs/manual-testing/backlog.md`)

**Out of scope (deferred to follow-up PRs):**
- Connection Details back face migration (#167) — keeps current placeholder
- Chart back face migration (#166) — keeps current placeholder
- `vortix back <panel> --json` CLI sibling
- BackFaceProvider trait formalization (the helpers stand alone first; trait emerges in PR2)
- Cross-panel jump keys / entity pinning
- Auto-flip on anomaly

## Requirements

**R1.** A new `VerdictMode` type with four variants — `Pass`, `Watch`, `Fail`, `Unknown` — and helpers mirroring `KillSwitchMode`:
- `display_name() -> &'static str` returns `"Pass"`, `"Watch"`, `"Fail"`, `"Unknown"`.
- `short_label() -> &'static str` returns `"PASS"`, `"WATCH"`, `"FAIL"`, `"???"` for header-row use.
- `color(&theme) -> Color` returns the theme color for the verdict.
- `serde::Serialize` / `serde::Deserialize` use the lowercase slug form (`"pass"`, `"watch"`, `"fail"`, `"unknown"`).
- Module docs mirror the `KillSwitchMode` module-doc table — one vocabulary, used identically on every surface.

**R2.** A new `Severity` type with four variants — `Warning`, `Caution`, `Advisory`, `Status` — and helpers:
- `display_name()` returns the long form.
- `glyph() -> char` returns `'●'` (Warning), `'◐'` (Caution), `'◯'` (Advisory), `'·'` (Status).
- `color(&theme) -> Color` — red/amber/cyan/white per the theme module.
- Priority ordering enforced by the enum's `Ord` impl (`Warning < Caution < Advisory < Status` for sort-ascending = most-severe-first).

**R3.** A new `Scope` type with five variants:
- `Primary { interface: String }` → renders as `scope: primary utun3`
- `FocusedSecondary { interface: String }` → renders as `scope: utun5 — focused secondary, reduced telemetry`
- `ExternalAdopted { interface: Option<String> }` → renders as `scope: external-adopted, unauthoritative`
- `Unsupported { platform: &'static str }` → renders as `scope: unsupported on Windows`
- `Partial { reason: &'static str }` → renders as `scope: partial — non-root` (or other reason)

**R4.** `render_verdict_band(frame, area, verdict: VerdictMode, headline: &str)` — renders a single-row banner:
- Format: `<short_label>  <headline>` (e.g., `PASS  47/47 sockets via primary utun3`)
- Color applies to both label and headline based on `verdict.color()`.
- Falls back to a single empty row if `area.height == 0`.

**R5.** `render_scope_footer(frame, area, scope: &Scope)` — renders the scope row, right-aligned, dim color.

**R6.** `render_nav_hint_band(frame, area, hints: &[(&str, &str)])` — renders e.g. `/ filter   s sort   ? help   Esc back`, right-aligned, dim. Hints are passed in as `(key, label)` pairs; only the hints provided render.

**R7.** Security Guard `render_back` migrates to the new helpers:
- Reads `app.registry.primary()` to determine scope.
- Reads socket audit data (synchronously from a cached snapshot — polling cadence stays as-is for v1; if no snapshot is available yet, render `Unknown` verdict + "Loading socket inventory…" headline).
- Classifies sockets:
  - VPN-routed = `local_addr` matches primary tunnel's `internal_ip`
  - LAN-local = `remote_addr` in `127.0.0.0/8`, `::1`, or RFC1918
  - Leak = otherwise (non-VPN, non-LAN)
- Builds verdict:
  - `Pass` when all sockets are VPN or LAN
  - `Fail` when ≥1 leak exists
  - `Watch` is unused in v1 (reserved for future "approaching threshold" use cases)
  - `Unknown` when the socket-audit data is unavailable (Windows / no-root macOS / first-render race)
- Builds alert ribbon entries (only rendered when verdict is `Fail`):
  - One `Severity::Warning` line per leak: `LEAK pid <pid> <command> → <remote_addr> (<age>s ago)`
- Renders: verdict band → blank row → alert ribbon (or empty if verdict is `Pass`) → blank row → scope footer + nav-hint
- Honors the existing `app.registry.primary().is_some()` check for the disconnected case — verdict becomes `Unknown` with headline "Not connected".

**R8.** Unit tests for:
- `VerdictMode::display_name`, `short_label`, slug round-trip via serde
- `Severity::glyph`, priority ordering
- `Scope` Display impl for each variant
- Socket classification function (4 input cases: VPN, LAN-loopback, LAN-private, leak)

**R9.** Snapshot tests for `security.rs::render_back` using ratatui's `TestBackend`:
- Clean scenario: primary up, 5 VPN sockets, 2 LAN sockets → expect `PASS  7/7 sockets via primary utun3`
- Leak scenario: primary up, 5 VPN + 1 leak → expect `FAIL  6 sockets · 1 leak` + warning line for the leak
- Disconnected scenario: no primary → expect `???  Not connected`

**R10.** CHANGELOG entry under `[Unreleased]`:
- `### Added`: BackFace v1 spec (verdict band + alert ribbon + scope footer + nav-hint helpers).
- `### Changed`: Security Guard back face now renders EICAS-style content (verdict + exception ribbon) using the BackFace v1 helpers. Closes #168.

**R11.** Manual-testing backlog row (one row, asserts 80×24 fit):
- Title: "Security Guard back face (EICAS) — clean, leak, disconnected"
- Setup: standard demo profiles
- Pass signal: `f` from Security Guard front renders the new verdict-first content; all-OK case shows ONE line of content; leak case adds alert ribbon; 80×24 has no truncation.

## Decisions

**D1.** Vocabulary is **`Pass` / `Watch` / `Fail` / `Unknown`** — 4 states, not 5. "Watch" is reserved for future approaching-threshold logic (e.g., "5% packet loss is rising — Watch"); leaving it in the enum from day one avoids a breaking change later. The previous brainstorm survivor mentioned `Excellent / Watching / Degraded / Failed / Unknown` (5); collapsed to 4 because:
- `Excellent` vs `Pass` is just a label difference; `Pass` is shorter for header-row rendering and matches CI-test vocabulary.
- `Degraded` vs `Fail` collapses into one "something is wrong" category — finer-grain severity belongs to the per-alert `Severity` enum, not the overall verdict.

**D2.** Severity vocabulary is **`Warning` / `Caution` / `Advisory` / `Status`** — direct EICAS borrow (Boeing 757+, ARP 4102/4). Borrowing the established standard avoids re-inventing the wheel and signals provenance.

**D3.** EICAS rendering is **exceptions-only** — the ribbon shows ONE row per active alert; when no alerts exist, only the verdict band renders. This honors the density principle's "earn the row from the exception" — a 47-row inventory pays its carry cost only when something is wrong.

**D4.** **No socket-table affordance in v1.** Users who want to see the full inventory during the all-OK case can use the existing `vortix audit` CLI. The TUI back face is the alarm surface; the CLI is the inventory surface. If demand surfaces, a `s` keystroke could later cycle to a "show all sockets" mode.

**D5.** **Scope footer is mandatory** on every back face that uses the spec. Even when scope is "primary" (the common case), rendering it makes the multi-tunnel and degradation cases visually consistent — users know to look in the same place.

**D6.** **The `BackFaceProvider` trait is NOT formalized in v1.** Helpers stand alone first; the trait can be extracted in PR2 when Connection Details migrates. Premature trait extraction risks shape-mismatch when the second use case lands.

**D7.** **CLI sibling (`vortix back security --json`) is deferred to PR3.** The JSON envelope shape will be settled when at least two back faces use the spec — single use case is not enough material to commit to a public JSON contract.

**D8.** Tests use **ratatui's `TestBackend`** for snapshot tests rather than golden-file diffs — keeps tests self-contained, avoids file-path issues across platforms.

## Scope boundaries

**Deferred for later** (named explicitly so they don't sneak in during plan/work):
- Connection Details quality timeline (#167)
- Chart per-process content (#166)
- JSON envelope + CLI sibling
- BackFaceProvider trait extraction
- Cross-panel jump keys
- Auto-flip on anomaly
- Front-face summary band previewing back content

**Outside this product's identity:**
- A full-screen Inspector overlay (ideation survivor #6) — that's a different architectural direction that would replace the flip pattern; deliberately not picked here.

## Acceptance examples

**AE1.** Clean session: connect to primary, no other tunnels. Press `f` on Security Guard. Expected: `PASS  N/N sockets via primary utunX` headline (where N is current socket count), scope footer reads `scope: primary utunX`, no ribbon body. Visually identical at 80×24 to a single-line + footer.

**AE2.** Leak session: connect to primary, manually open a socket bypassing the VPN (e.g., `curl --interface en0`). Within polling cadence (~3s), press `f` on Security Guard. Expected: `FAIL  N sockets · 1 leak` headline, ribbon row `● LEAK pid <pid> curl → <remote> (Xs ago)`, scope footer reads `scope: primary utunX`. 80×24 fits.

**AE3.** Disconnected: no VPN active. Press `f` on Security Guard. Expected: `???  Not connected` headline, no ribbon, scope footer reads `scope: not connected`.

**AE4.** External-adopted secondary on macOS where `interface_authoritative=false` (e.g., manually run `wg-quick up profile-x` from another terminal). Press `f` on Security Guard. Expected: scope footer reads `scope: external-adopted, unauthoritative`; verdict is `Unknown` with headline "Socket attribution unavailable for adopted tunnels".

**AE5.** Windows: press `f` on Security Guard. Expected: `???  Socket audit unsupported on Windows` + scope footer `scope: unsupported on Windows`.

## Open questions / explicit assumptions

- **A1 (assumption):** the `SocketAudit` port's `snapshot()` method is already wired and reachable from `App`. If not — that's the first blocker; verify in plan stage. If unwired, a small adapter is acceptable scope creep; a complete port re-implementation is not (re-scope to follow-up).
- **A2 (assumption):** ratatui's `TestBackend` is already a transitive dep — vortix uses ratatui, and `TestBackend` is a feature flag on the same crate. If a separate dep needs adding, do so in this PR.
- **A3 (decision pending plan):** how often the security back face re-polls socket audit. v1 reuses whatever cadence already drives `app.runtime.dns_leak` etc.; if no such cadence exists for sockets, plan stage proposes adding a 3s tick.

## Success criteria (one-line)

`f` on Security Guard reveals a back face whose first line is the verdict, whose middle rows are exceptions-only (zero rows when clean), and whose footer makes scope unambiguous — at 80×24, with no truncation, on macOS Linux Windows, with snapshot tests covering all three render scenarios.
