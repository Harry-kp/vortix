---
plan_id: 2026-05-24-018
title: "fix: hook editor form UX — bounded command box, compact event picker, fielded inputs"
type: fix
status: active
created: 2026-05-24
target_branch: refactor/architectural-migration-v1
target_pr: 201
target_version: 0.3.0
parent_plan: 2026-05-24-017-feat-tui-hook-management-plan.md
---

# Hook editor form UX polish

> Follow-up to plan 017 U5. The form ships functional but visually
> off — the maintainer flagged it after first hands-on use. This is
> a focused redesign of the overlay, not a feature addition.

---

## Observed issues (from screenshot)

| # | Problem | Visible effect |
|---|---|---|
| O1 | Event picker overflows modal width. | Last 2 events ("connect_failed", "reconnecting") truncated at the right edge. |
| O2 | Command textarea has no visible boundary. | ~8 rows of empty space with no indication where the editable area is. User can't see "type here". |
| O3 | Single-line inputs (Name, Timeout) have no field boundary. | Text just floats below the label — looks like static text, not a form field. |
| O4 | Save/Cancel only show brackets when focused. | At rest they read as plain text, not buttons. |
| O5 | Field spacing is loose and uneven. | Gaps between Command/Timeout/Env vary; form looks unstructured. |
| O6 | Modal too narrow on wider terminals. | Wastes horizontal real estate. |

---

## Redesign decisions

### D1 — Event picker becomes a one-line arrow-cycle widget

Replace the inline-all-events row with `◀  post_connect  ▶` — one
event visible, arrows cycle. Saves an entire row's worth of
horizontal space, never truncates, makes the focus indicator
unambiguous.

Left/Right keys (already handled in U5) cycle. The selected event
kind is centered between the arrows. When the field is focused the
arrows render in accent color; when unfocused they're dim.

### D2 — Command textarea wrapped in a bordered box

`Block::default().borders(Borders::ALL)` around the textarea with a
fixed inner height (5–7 rows depending on available modal space).
The border color reflects focus state (accent when focused, default
otherwise). When the textarea is empty, the empty box still
communicates "type here" because it has a visible boundary.

### D3 — Single-line inputs get a thin underline

Name and Timeout fields render the input value followed by a
single-character-high underline (`─` × width) so the field
boundary is visible at rest. When focused, the underline picks up
accent color. This is the ratatui equivalent of an HTML
`<input>`'s baseline.

### D4 — Save/Cancel always render with brackets

`[ Save ]` and `[ Cancel ]` at rest, with focus indicated by color
+ bold rather than by brackets-vs-no-brackets. Buttons look like
buttons even when nothing is focused. Add a small space gutter
between them so they're visually separated.

### D5 — Compact, consistent spacing

Replace the mix of `Length(2)` and `Min(N)` with explicit per-field
`Length(1)` for labels + `Length(1)` for single-line values + a
single `Length(1)` separator between sections. Command gets
`Length(7)` (1 label + 6 textarea body inside its border). Env rows
flow in a `Min(N)` slot at the bottom.

### D6 — Wider modal

Cap at `min(area.width - 4, 96)` instead of 78. The form benefits
materially from horizontal space — long shell commands fit on one
line, env rows show full key + value, event picker has breathing
room.

---

## Implementation units

### U1. Rewrite `hook_edit.rs` overlay render

**Goal:** Apply D1–D6 in `crates/vortix/src/ui/overlays/hook_edit.rs`.

**Files:**
- modify: `crates/vortix/src/ui/overlays/hook_edit.rs` (entire render path)

**Approach:**
- Top constants: `OVERLAY_WIDTH = 96`, `OVERLAY_MAX_HEIGHT = 30`,
  `COMMAND_INNER_ROWS = 6`.
- Outer `Block` unchanged (border + title + title_bottom).
- Vertical layout: event-picker(1) · separator(1) · name-label(1) ·
  name-value(1) · name-underline(1) · separator(1) · command-label(1)
  · command-box(Min, ≥ COMMAND_INNER_ROWS+2) · separator(1) ·
  timeout-label(1) · timeout-value(1) · timeout-underline(1) ·
  separator(1) · env-header(1) · env-rows(Min(2)) · separator(1) ·
  enabled(1) · validation(1) · buttons(1).
- Event picker as one line `◀  {event}  ▶` (or `< / >` ASCII
  fallback). Compact, centered within the label slot.
- Command textarea wrapped in `Block::default().borders(Borders::ALL)`.
  Border color = accent when focused, default otherwise.
- Underline helpers: a `render_input_with_underline(frame, area,
  text, cursor, focused)` that paints the value on row 0 and a
  `─` row of `area.width` characters on row 1, accent-colored when
  focused.
- Buttons always render `[ Save ]` / `[ Cancel ]`. Style ([accent
  + bold] when focused, default-secondary otherwise).
- Env rows render with explicit `KEY` / `VALUE` column headers and
  align values vertically.

**Test scenarios:**
- Visual smoke (manual): open form on a fresh hook, verify all 6
  events visible via left/right cycling, command box has visible
  border at all states, single-line inputs have underline,
  Save/Cancel always show brackets.
- The 23 existing U5 tests in `crates/vortix/src/state/hook_edit.rs`
  must keep passing — this plan touches presentation only, not
  state-machine semantics.

**Verification:** `cargo test --workspace` stays green; `cargo
clippy --workspace --all-targets -- -D warnings` clean; manual
visual check matches the design above.

### U2. Adjust focus styling helper coverage

**Goal:** Ensure `label_span` and `focused_inline` cover the new
layout — labels above bounded inputs vs labels above
underlined inputs may want different intensities so the
field-vs-label visual hierarchy stays clear.

**Files:**
- modify: `crates/vortix/src/ui/overlays/hook_edit.rs` (helpers)

**Test scenarios:**
- Test expectation: none beyond U1's visual smoke. This is a
  rendering polish unit; behavior unchanged.

**Verification:** workspace tests stay green; clippy clean.

---

## Scope boundaries

### In scope
- Visual redesign of the Add/Edit form overlay.
- Underline rendering for single-line inputs.
- Bordered box for the command textarea.
- Button bracket consistency.
- Modal width bump.

### Out of scope
- Form state machine changes (already shipped in plan 017 U5).
- Adding new fields.
- New keybinds (Tab navigation already works).
- Argv-mode toggle (deferred per plan 017).

---

## Risk

| Risk | Severity | Mitigation |
|---|---|---|
| Resizing the command textarea breaks the cursor-positioning math. | Low | The TextArea widget's internal scroll handles cursor visibility (U4); only the `Rect` it renders into changes. |
| The bordered box clips a multi-line command edit. | Low | `COMMAND_INNER_ROWS = 6` gives 6 visible lines; TextArea scrolls past that. |
| Wider modal looks oversized on narrow terminals. | Low | `min(area.width - 4, 96)` clamps to terminal width. |
