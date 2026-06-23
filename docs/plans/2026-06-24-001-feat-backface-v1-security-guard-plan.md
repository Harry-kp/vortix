---
date: 2026-06-24
seq: 001
type: feat
slug: backface-v1-security-guard
status: active
depth: standard
origin: docs/brainstorms/2026-06-24-backface-v1-spec-requirements.md
parent_issue: https://github.com/Harry-kp/vortix/issues/235
sub_issue: https://github.com/Harry-kp/vortix/issues/168
branch: feat/backface-v1-security-guard
---

# Plan: BackFace v1 spec foundation + Security Guard EICAS migration

## Problem Frame

The `ratatui-flip-panel` widget shipped earlier this year, but the back faces of the three dashboard panels (Chart / Connection Details / Security Guard) are static placeholders that point at future issues. There is no shared layout contract, no shared vocabulary, no scope-rendering convention, and no degradation pattern. Building each back face independently would produce three diverging surfaces with three keymaps and three flavours of "we don't have data for this case."

This plan ships the BackFace v1 contract (verdict band + scope footer + nav-hint helpers + the small enum set) and validates it by migrating Security Guard's back face to EICAS-style content. Connection Details (#167) and Throughput (#166) stay on their current placeholders for follow-up PRs.

Origin doc: `docs/brainstorms/2026-06-24-backface-v1-spec-requirements.md` (R1–R11, D1–D8, AE1–AE5).

---

## Scope

**In scope:**
- New module `crates/vortix/src/ui/dashboard/backface.rs` carrying `VerdictMode`, `Severity`, `Scope` enums + their helpers, plus the three render helpers (`render_verdict_band`, `render_scope_footer`, `render_nav_hint_band`).
- Wiring `SocketAudit::snapshot()` into App state via a 3 s polling task so the Security Guard back face has live data to render.
- Migration of `crates/vortix/src/ui/dashboard/security.rs::render_back` to use the new helpers with EICAS-style content (verdict band → alert ribbon (only when failing) → scope footer + nav-hint).
- Unit tests for every enum + helper.
- Snapshot tests for `render_back` covering clean / leak / disconnected scenarios via `ratatui::backend::TestBackend`.
- CHANGELOG entry under `[Unreleased]`.
- Manual-testing backlog row.

**Out of scope (deferred to follow-up PRs):**
- Connection Details back face migration (#167) — keeps current placeholder.
- Chart back face migration (#166) — keeps current placeholder.
- `vortix back <panel> --json` CLI sibling.
- `BackFaceProvider<T>` trait extraction — helpers stand alone first; the trait can be extracted in PR2 once a second consumer arrives. (Origin D6.)
- Cross-panel jump keys / entity pinning / auto-flip on anomaly.
- Front-face summary band previewing back content.

### Deferred to Follow-Up Work

- Replicating the contract on Chart (#166) and Connection Details (#167) back faces.
- JSON envelope for `vortix back <panel> --json`.
- BackFaceProvider trait extraction once a second panel adopts the spec.

### Outside this product's identity

- Replacing the bounded-panel flip pattern with a full-screen Inspector overlay (ideation survivor #6). That is a different architectural direction deliberately not picked here.

---

## Key Technical Decisions

- **Vocabulary: `Pass` / `Watch` / `Fail` / `Unknown`** (4 states, not 5). `Watch` is reserved for future approaching-threshold logic — leaving it in the enum from day one avoids a breaking change later. Origin D1.
- **Severity vocabulary: `Warning` / `Caution` / `Advisory` / `Status`** — direct EICAS borrow (Boeing 757+, ARP 4102/4). Origin D2.
- **EICAS rendering is exceptions-only.** The ribbon shows one row per active alert; when no alerts exist, only the verdict band renders. Honors the density principle's "earn the row from the exception" — the 47-row inventory pays its carry cost only when something is wrong. Origin D3.
- **No socket-table affordance in v1.** Users wanting the full inventory during the all-OK case use the existing `vortix audit` CLI. The TUI back face is the alarm surface; the CLI is the inventory surface. Origin D4.
- **Mandatory scope footer on every back face that uses the spec.** Visually consistent across multi-tunnel and degradation cases. Origin D5.
- **No `BackFaceProvider` trait in v1.** Helpers stand alone first; trait extracted in PR2 when Connection Details migrates. Origin D6.
- **CLI sibling (`vortix back security --json`) deferred to PR3.** JSON envelope shape settled once two back faces use the spec. Origin D7.
- **Tests use `ratatui::backend::TestBackend`** for snapshot tests rather than golden-file diffs. Origin D8.
- **3 s polling cadence for SocketAudit** — matches the rough cadence of existing telemetry ticks (DNS leak probe etc.); v1 reuses the existing message-loop tick rather than adding a separate timer. If wiring proves more invasive than expected, fallback at execution time is documented in U2.

---

## High-Level Technical Design

*This illustrates the intended approach and is directional guidance for review, not implementation specification.*

```
┌─────────────────────────────────────────────────────────────────────┐
│ backface.rs (new module)                                            │
│                                                                      │
│  enum VerdictMode { Pass, Watch, Fail, Unknown }                    │
│    - display_name() -> &'static str  (Pass / Watch / Fail / Unknown)│
│    - short_label() -> &'static str   (PASS / WATCH / FAIL / ???)    │
│    - color(&Theme) -> Color                                          │
│    - Serialize/Deserialize as lowercase slugs                        │
│                                                                      │
│  enum Severity { Warning, Caution, Advisory, Status }               │
│    - glyph() -> char  (● / ◐ / ◯ / · )                              │
│    - color(&Theme) -> Color  (red / amber / cyan / white)            │
│    - Ord impl: Warning < Caution < Advisory < Status                 │
│                                                                      │
│  enum Scope {                                                        │
│    Primary { interface: String },                                    │
│    FocusedSecondary { interface: String },                           │
│    ExternalAdopted { interface: Option<String> },                    │
│    Unsupported { platform: &'static str },                           │
│    Partial { reason: &'static str },                                 │
│  }                                                                   │
│    - Display impl renders the `scope: ...` footer string             │
│                                                                      │
│  fn render_verdict_band(frame, area, verdict, headline)             │
│  fn render_scope_footer(frame, area, scope)                         │
│  fn render_nav_hint_band(frame, area, hints: &[(&str, &str)])       │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  │ consumed by
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ security.rs::render_back  (rewritten)                               │
│                                                                      │
│  1. Determine scope from app.registry.primary() + platform          │
│  2. Read app.runtime.socket_audit_snapshot (Option<Vec<...>>)       │
│  3. Classify each socket: VPN | LAN | Leak                          │
│  4. Build verdict: Pass / Fail / Unknown (+ headline string)        │
│  5. Build alert ribbon entries (one per leak)                       │
│  6. Layout:                                                          │
│     row 0:    verdict_band                                           │
│     row 1:    blank                                                  │
│     rows 2-N: alert ribbon (only when verdict == Fail)               │
│     last-1:   scope_footer                                           │
│     last:     nav_hint_band                                          │
└─────────────────────────────────────────────────────────────────────┘
                                  ▲
                                  │ feeds
                                  │
┌─────────────────────────────────────────────────────────────────────┐
│ App + message loop  (new poll task)                                 │
│                                                                      │
│  Every 3 s tick: call SocketAudit::snapshot() via the platform impl │
│  Result lands in app.runtime.socket_audit_snapshot                  │
│  First-render race: snapshot may be None → verdict = Unknown        │
└─────────────────────────────────────────────────────────────────────┘
```

The shape is intentionally small. Each unit is one atomic concern, dependency-ordered.

---

## Implementation Units

### U1. BackFace v1 module — enums + helpers + unit tests

**Goal:** Land the `backface` module (enums + render helpers + their unit tests) as a standalone, unconsumed module. Subsequent units exercise it.

**Requirements:** R1, R2, R3, R4, R5, R6, R8 (the enum-method unit tests).

**Dependencies:** none.

**Files:**
- `crates/vortix/src/ui/dashboard/backface.rs` (new)
- `crates/vortix/src/ui/dashboard/mod.rs` (modify — `pub mod backface;`)

**Approach:**
- Define `VerdictMode`, `Severity`, `Scope` enums per the High-Level Technical Design.
- Each enum gets `#[derive(Debug, Clone, Copy, PartialEq, Eq)]` plus `Serialize`/`Deserialize` where origin R1 calls for it (`VerdictMode`).
- `Severity` derives `Ord` + `PartialOrd` with the variant order Warning → Caution → Advisory → Status (smallest = most-severe so ascending sort surfaces alarms first).
- Module-level docs mirror the `KillSwitchMode` template: header comment with the slug table and a paragraph on "one vocabulary, used everywhere."
- Render helpers use ratatui `Paragraph` / `Line` / `Span` building blocks. Color lookups use the existing `crate::theme` module.
- The `render_nav_hint_band` helper formats `(key, label)` pairs as `<key> <label>` separated by three spaces, right-aligned.

**Patterns to follow:**
- `crates/vortix/src/vortix_core/state/killswitch.rs` — module-doc style, helper layout, slug constants.
- `crates/vortix/src/ui/dashboard/security.rs::render` — existing back-face block construction (Block + Padding + title_bottom hint) — keep the outer chrome consistent.
- `crates/vortix/src/theme.rs` — color names.

**Test scenarios** (in `crates/vortix/src/ui/dashboard/backface.rs` `#[cfg(test)] mod tests`):
- `verdict_mode_display_name_returns_canonical_label` — each variant returns the expected long-form string.
- `verdict_mode_short_label_returns_three_or_four_chars` — `PASS` / `WATCH` / `FAIL` / `???`.
- `verdict_mode_serde_round_trip_via_lowercase_slug` — JSON `"pass"` ↔ `VerdictMode::Pass`, and likewise for other variants.
- `severity_glyph_matches_eicas_table` — each variant returns the expected unicode glyph.
- `severity_ordering_surfaces_most_severe_first` — vector of `[Status, Warning, Advisory, Caution]` sorted ascending yields `[Warning, Caution, Advisory, Status]`.
- `scope_display_primary_renders_with_interface` — `Scope::Primary { interface: "utun3" }.to_string()` == `"scope: primary utun3"`.
- `scope_display_focused_secondary_renders_with_reduced_telemetry_label` — covers AE4 prefix.
- `scope_display_external_adopted_renders_unauthoritative_label`.
- `scope_display_unsupported_renders_platform_label` — covers AE5 prefix.
- `scope_display_partial_renders_reason`.
- `render_verdict_band_uses_verdict_color` — renders into a `TestBackend`, asserts the `PASS` label cell color matches `VerdictMode::Pass.color(&theme)`.
- `render_scope_footer_right_aligns_text` — renders into a `TestBackend` 40 cols wide, asserts the scope string ends at the right margin.
- `render_nav_hint_band_omits_keys_not_passed` — `render_nav_hint_band(frame, area, &[("Esc", "back")])` renders only the Esc hint, not a full keymap.

**Verification:** `cargo test -p vortix backface::tests` passes. `cargo clippy -p vortix --all-targets -- -D warnings` is clean.

---

### U2. SocketAudit polling integration into App state

**Goal:** Make the latest `Vec<SocketSnapshot>` reachable from the renderer. Add a polling task that calls `SocketAudit::snapshot()` on a 3 s cadence (or the closest existing tick) and writes the result to `App` state.

**Requirements:** R7 (this is the data-availability prerequisite for the Security Guard migration).

**Dependencies:** none (independent from U1).

**Files:**
- `crates/vortix/src/app/mod.rs` (modify — add `socket_audit_snapshot: Option<Vec<SocketSnapshot>>` or similar to the `VpnRuntime` struct, gated behind the same fields that already hold `dns_leak` etc.)
- `crates/vortix/src/app/update.rs` (modify — handle a new `Message::SocketAuditUpdate(...)` variant)
- `crates/vortix/src/message.rs` (modify — add the message variant)
- `crates/vortix/src/main.rs` or the existing telemetry tick spawn site (modify — spawn the polling task; identify the exact site during execution by grepping for the existing DNS-leak / latency tick spawner)

**Approach:**
- The `SocketAudit` trait lives in `crates/vortix/src/vortix_core/ports/socket_audit.rs`. Platform impls already exist (`vortix_platform_linux`, `vortix_platform_macos`, `vortix_platform_windows` returns `Unsupported`).
- Find the existing async task/timer that drives DNS-leak / latency telemetry; piggyback on the same cadence (or a 3 s sibling) to call `platform::SocketAudit::snapshot()`.
- The polling task sends a `Message::SocketAuditUpdate(result: Result<Vec<SocketSnapshot>, SocketAuditError>)` to the app message loop.
- `update.rs` matches the new message and writes the result to `app.runtime`. On `Err(SocketAuditError::Unsupported)`, store `None`; on `Err(SocketAuditError::Permission)`, store `None` and (optionally) set a flag for `Scope::Partial`.
- Field name suggestion: `socket_audit_snapshot: Option<Vec<SocketSnapshot>>` with a sibling `socket_audit_status: SocketAuditStatus { Ok, Unsupported, Partial }` — final names settled during implementation per planning rule §3.6.

**Patterns to follow:**
- The existing DNS leak / latency telemetry flow — same message-bus pattern; mimic the pollers near it.
- `crates/vortix/src/vortix_core/ports/socket_audit.rs` for the trait + error variants.

**Test scenarios:**
- Existing tests should not regress (`cargo test --workspace`).
- A focused unit test on the message handler: `socket_audit_update_with_ok_writes_snapshot_to_app` — construct an `App`, dispatch `Message::SocketAuditUpdate(Ok(vec![sample_socket]))`, assert `app.runtime.socket_audit_snapshot == Some(vec![sample_socket])`.
- `socket_audit_update_with_unsupported_sets_snapshot_to_none` — same shape with `Err(Unsupported)`; asserts snapshot stays `None`.

**Verification:** `cargo test --workspace` passes. Running `cargo run -- ` on Linux/macOS produces a snapshot within 3 s of startup (manual signal during execution).

---

### U3. Security Guard `render_back` migration to EICAS-style content

**Goal:** Rewrite `crates/vortix/src/ui/dashboard/security.rs::render_back` to render via the BackFace v1 helpers with EICAS-style content, consuming the snapshot from U2.

**Requirements:** R7. Covers AE1, AE2, AE3, AE4, AE5.

**Dependencies:** U1 (helpers + enums), U2 (snapshot reachable from App).

**Files:**
- `crates/vortix/src/ui/dashboard/security.rs` (modify — replace the body of `render_back`)
- `crates/vortix/src/ui/dashboard/constants.rs` if it exists, or wherever `TITLE_FLIP_CONNECTIONS_AUDIT` / `FLIP_BACK_HINT` live (modify the back-face title and hint copy if needed)

**Approach:**
- Determine scope:
  - No primary → `Scope::Primary { interface: "—".into() }` with a verdict headline of `Not connected`, OR a dedicated `Scope::Partial { reason: "not connected" }`. Implementation decides which reads better at 80×24; either lands within the spec.
  - Windows → `Scope::Unsupported { platform: "Windows" }`, verdict `Unknown`, headline `Socket audit unsupported on Windows`. Covers AE5.
  - Primary + `interface_authoritative=false` → `Scope::ExternalAdopted { interface: ... }`, verdict `Unknown`, headline `Socket attribution unavailable for adopted tunnels`. Covers AE4.
  - Primary + authoritative + snapshot `None` → verdict `Unknown`, headline `Loading socket inventory…`.
  - Primary + authoritative + snapshot `Some(sockets)` → classify each socket and build the verdict.
- Socket classification (per R7):
  - VPN = `local_addr` matches the primary's `internal_ip`
  - LAN-loopback = `remote_addr` in `127.0.0.0/8` or `::1`
  - LAN-private = `remote_addr` in RFC1918 / RFC4193 ranges
  - Leak = otherwise
- Verdict:
  - All VPN or LAN → `Pass`, headline `N/N sockets via primary <iface>`
  - Any Leak → `Fail`, headline `N sockets · K leak` (K = leak count)
  - `Watch` not used in v1.
- Alert ribbon:
  - Only built when verdict == `Fail`.
  - One row per leak, severity `Warning`, format `LEAK pid <pid> <command> → <remote_addr> (<age>s ago)`.
  - Sorted by age ascending (most-recent first) for the EICAS "oldest-first within tier" preserve when multiple severities are present. (At v1 there's only one severity — `Warning` for leaks — so ordering is by age only.)
- Layout in `render_back`:
  - `area` is split into [verdict_row=1, blank=1, ribbon_rows=variable, blank=1, footer_row=1] (use `Layout::vertical`). The ribbon is rendered only when verdict == `Fail`; when `Pass` / `Unknown`, the verdict row stands alone above the footer.
  - The outer block (border, padding, title) stays as-is so the flip animation continues to work with the existing chrome.
- Nav-hint band shows `Esc back` only in v1 (no sort/filter affordances yet).

**Patterns to follow:**
- The current `security.rs::render` (front face) for block construction.
- `crates/vortix/src/vortix_core/state/killswitch.rs::KillSwitchMode::display_name` etc. — helper dispatch style mirrored by the new `VerdictMode` helpers.

**Test scenarios** (snapshot tests in `crates/vortix/src/ui/dashboard/security.rs` `#[cfg(test)] mod tests` or a sibling `security_tests.rs`):
- `render_back_clean_session_shows_pass_verdict_only` — Covers AE1. Construct an `App` with primary tunnel up + 7 VPN/LAN sockets; render via `TestBackend`; assert the first row contains `PASS  7/7 sockets via primary utun3` and no ribbon rows render between verdict and footer.
- `render_back_leak_session_shows_fail_and_warning_ribbon` — Covers AE2. Construct an `App` with primary up + 5 VPN + 1 leak; render; assert verdict row contains `FAIL  6 sockets · 1 leak` and the row beneath contains a Warning glyph + `LEAK pid` substring.
- `render_back_disconnected_shows_unknown_verdict` — Covers AE3. Construct an `App` with no primary; render; assert first row contains `???  Not connected` and the footer reads `scope: not connected` (or the equivalent Partial label landed on during implementation).
- `render_back_external_adopted_shows_unknown_with_unauthoritative_scope` — Covers AE4. Construct an `App` with primary + `interface_authoritative=false`; render; assert verdict is `Unknown` and footer reads `scope: external-adopted, unauthoritative`.
- `render_back_windows_shows_unsupported_scope` — Covers AE5. Behavior gated by Linux/macOS-only data; the cleanest implementation is a test-only helper that injects `Scope::Unsupported { platform: "Windows" }` directly. Assert footer matches.

**Verification:** Snapshot tests pass. Manual: with `wg-quick up <profile>` running and `f` pressed on Security Guard panel in the running binary, the back face shows a green PASS row when no leaks exist; opening `curl --interface en0 https://example.com` and waiting ~3 s makes the back face transition to FAIL with a Warning row identifying the leak.

---

### U4. Snapshot tests for `render_back`

**Goal:** Stand up the snapshot-test scaffolding for `render_back` if it doesn't already exist, and ship the five scenarios above with full `TestBackend` rendering.

**Requirements:** R9. Covers AE1–AE5.

**Dependencies:** U1, U2, U3.

**Files:**
- `crates/vortix/src/ui/dashboard/security.rs` (modify — `#[cfg(test)] mod tests` block, or `security_tests.rs` sibling if the file is already very long)
- `crates/vortix/Cargo.toml` (modify only if `ratatui::backend::TestBackend` is not already accessible — it should be; the dependency is the same `ratatui` crate the renderer uses)

**Approach:**
- Use `ratatui::Terminal::new(TestBackend::new(width, height))` with `width=80, height=24` (the documented density budget).
- After `terminal.draw(|f| render_back(f, &app, area, default_style))`, inspect `terminal.backend().buffer()` to assert row contents.
- Cell-content assertions use small helpers like `assert_row_contains(buffer, row_idx, "PASS")` so tests stay readable. Define such helpers at the top of the test module.
- Construct realistic `App` fixtures with helper functions: `fn app_with_primary(sockets: Vec<SocketSnapshot>) -> App`, `fn app_disconnected() -> App`. These mirror the existing fixture patterns in the codebase where they exist.

**Patterns to follow:**
- Search the repo for existing `TestBackend` usage; if any panel already has snapshot tests, mirror their helper shape exactly. If none exists, the helpers in this unit set the precedent.

**Test scenarios:** see U3 — this unit is the home for all five snapshot tests; U3's "test scenarios" list IS the U4 deliverable.

**Verification:** `cargo test -p vortix --lib dashboard::security` passes. All five snapshots run and pass.

---

### U5. Documentation — CHANGELOG entry + manual-testing backlog row

**Goal:** Record the user-facing change and add a manual-testing scenario per repo convention.

**Requirements:** R10, R11.

**Dependencies:** U1, U2, U3, U4.

**Files:**
- `crates/vortix/CHANGELOG.md` (modify — add under `[Unreleased]`)
- `docs/manual-testing/backlog.md` (modify — append a new row to the table)
- `docs/ideation/2026-06-24-flip-panel-back-faces-ideation.md` (modify — mark survivors #2 and #4 as "Built in #<PR>" once the PR opens; deferred to commit-time)

**Approach:**

- **CHANGELOG entry shape** (under `[Unreleased]`):

  ```markdown
  ### Added
  - **BackFace v1 spec** — shared verdict band + scope footer + nav-hint band helpers that future back faces consume. New `VerdictMode` / `Severity` / `Scope` types live in `ui::dashboard::backface`.
  - **`vortix_core::ports::socket_audit` polling** — the TUI now refreshes the socket inventory every 3 s for live consumption by the Security Guard back face.

  ### Changed
  - **Security Guard back face** now renders EICAS-style content (verdict line + exception ribbon) using the BackFace v1 helpers, replacing the placeholder that pointed at #168. Closes #168.
  ```

- **Manual-testing row shape** (in `docs/manual-testing/backlog.md`):

  | Scenario | Setup | Pass signal |
  |---|---|---|
  | Security Guard EICAS back face — clean/leak/disconnected | Connect to a WG profile with all traffic routed; press `f` on Security Guard. Force a leak via `curl --interface en0 https://example.com` and wait ~3 s. Disconnect entirely and press `f` again. | Clean: single `PASS` verdict line + `scope: primary utunX` footer, no ribbon, fits 80×24. Leak: `FAIL` verdict + one Warning row identifying the leak. Disconnected: `???  Not connected` + `scope: not connected`. |

**Patterns to follow:**
- `crates/vortix/CHANGELOG.md` existing `[Unreleased]` shape (keep-a-changelog format).
- `docs/manual-testing/backlog.md` existing table — one row per scenario, three columns.

**Test scenarios:** none — pure documentation change. `Test expectation: none — documentation update.`

**Verification:** `git diff CHANGELOG.md docs/manual-testing/backlog.md` shows the additions and nothing else.

---

## System-Wide Impact

- **Renderer ↔ data flow:** new `socket_audit_snapshot` field on `App` is the first piece of "polled platform-side data feeding the TUI" for sockets. Other back faces (#166 per-process bandwidth, #168 already shares this snapshot) will consume the same field. No other panels read it today.
- **Public API surface:** the new `VerdictMode` / `Severity` / `Scope` types are `pub` within the binary crate but not exposed externally — vortix doesn't ship a library API. No external compatibility considerations.
- **JSON envelope:** no schema changes in this PR. The `vortix_core::ports::socket_audit::SocketSnapshot` shape is already stable from plan 013.
- **CI:** no new workflows. Existing test/lint/clippy/docs jobs cover the new module.
- **Cross-platform:** Windows already returns `SocketAuditError::Unsupported` from the port; U3 explicitly handles that path by rendering `Scope::Unsupported`. Linux non-root and macOS non-root produce partial inventories per the port's existing semantics.

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| `SocketAudit` polling task wiring is more invasive than estimated (separate runtime, message-bus shape mismatch). | U2 is the discovery work; if it grows beyond a half-day, drop U2 and have U3 render `Unknown` permanently until the wiring lands in a follow-up. The spec foundation (U1) ships either way. |
| Snapshot tests prove brittle when the theme color or spacing changes. | Assertions live at the substring level (`row_contains("PASS")`) not the cell-color level for content checks; one separate test asserts the color binding explicitly for `VerdictMode::Pass`. |
| ratatui version drift since `TestBackend` was last exercised. | `ratatui::backend::TestBackend` is part of the main ratatui crate behind the default features — verify in U4 by running the first snapshot test. |
| Density-principle creep — alert ribbon body grows past 6 rows when many leaks present. | Truncate at 5 ribbon rows + a `+N more` summary row when N > 5. Documented in U3 implementation notes; same pattern as the multi-tunnel overflow ladder. |

---

## Verification Plan (post-implementation)

Run the full CI parity command set from `docs/ci-parity.md` — partial verification has bitten this repo four times. Then validate manually:

1. `cargo test --workspace` — all tests green.
2. `cargo clippy --workspace --all-targets -- -D warnings` — clean.
3. `cargo fmt --all -- --check` — clean.
4. `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` — clean.
5. `cargo xtask check-platform-leak`, `check-protocol-leak`, `check-core-leak` — all clean (no new boundary violations).
6. Manual: run vortix on macOS or Linux, connect to a WG profile, press `f` on Security Guard — verify the three scenarios from the manual-testing backlog row.

---

## Sequencing Summary

```
U1 (backface module + tests) ──┐
                                ├──> U3 (Security Guard render_back) ──> U4 (snapshot tests) ──> U5 (docs)
U2 (SocketAudit polling) ──────┘
```

U1 and U2 are independent and can be done in either order or in parallel. U3 fans in both. U4 and U5 close out.
