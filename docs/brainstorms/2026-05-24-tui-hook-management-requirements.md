---
id: 2026-05-24-tui-hook-management
title: "TUI hook management — add/edit/delete/toggle from inside the Lifecycle Hooks overlay"
status: ready-for-planning
type: requirements
created: 2026-05-24
related:
  - 2026-05-24-architectural-completion-requirements.md
target_pr: 201
target_version: 0.3.0
posture: feature-extension
---

# TUI hook management

## Problem frame

vortix v0.3.0 ships lifecycle hooks (plan 015 phase A) plus a TUI
observability layer (plan 016) — a Lifecycle Hooks overlay (`Shift-H`)
shows recent fires, a failure toast surfaces errors with a 30-second
per-hook rate limit, and a startup toast flags malformed `[[hooks]]`
entries. What it does *not* do is let the user **manage** those
hooks. To add, edit, toggle, or delete a hook today the user must:

1. Find `~/.config/vortix/config.toml` on disk.
2. Open it in `$EDITOR`.
3. Edit the `[[hooks]]` section by hand (TOML structure, quoting,
   inline tables, multi-line strings).
4. Save and exit.
5. Restart vortix.
6. Watch the startup toast for parse errors.

That violates the TUI's reason for existing. The whole point of
shipping a TUI on top of `wg-quick`/`openvpn` was to let users stop
editing files. Hooks are currently the one capability that breaks
that contract.

## Single-user model

This brainstorm explicitly assumes a **single-user mental model**:
the maintainer. They can write shell commands; they aren't asking
for a preset gallery or an automation builder. The friction isn't
"can't write shell" — it's the file-dance. Persona claims about
"non-tech-savvy users who need presets" are deferred to a future
brainstorm if and when those users actually appear.

## Actors

- **A1 — Maintainer**: power user, comfortable with shell, lives in
  the TUI. Wants every existing `settings.toml` `[[hooks]]` field
  editable from inside the running TUI session. The single user this
  brainstorm designs for.

## Key flows

- **F1 — Discover**: from the TUI, see every hook currently
  registered (not just recent fires), with its event, name, command
  excerpt, timeout, and enabled state.
- **F2 — Inspect**: drill into one hook to see its full config plus
  its recent fire history (last 20 fires, outcomes, exit codes,
  stderr excerpts).
- **F3 — Add**: from the Lifecycle Hooks overlay, open an Add form;
  fill event / name / command / timeout / env vars / enabled; save;
  see a toast confirming "Saved. Restart vortix to apply."
- **F4 — Edit**: from the registered-hooks list, open an Edit form
  pre-filled with the hook's current config; modify any field;
  save; same restart-apply toast.
- **F5 — Toggle**: flip a hook's `enabled` field from the list
  without opening the full form (single keystroke).
- **F6 — Delete**: from the list, delete a hook with a confirm
  dialog; the `[[hooks]]` block is removed from `settings.toml`;
  every unrelated section and comment in the file survives untouched.

## Acceptance examples

- **AE1 — Add a desktop-notify hook end-to-end without leaving the
  TUI.** From a cold TUI start, the maintainer opens the hooks
  overlay, presses `a`, picks `post_connect`, fills name +
  `notify-send "VPN $VORTIX_PROFILE connected"` + timeout `5s`,
  saves. The form closes; a toast says "Saved. Restart vortix to
  apply." `settings.toml` now contains a valid `[[hooks]]` block;
  every byte outside that block is unchanged.
- **AE2 — Hand-edited comments survive a TUI save.** Before TUI
  management, the user has hand-edited `settings.toml` with header
  comments and inline `# explain this` comments scattered through
  it. After any add/edit/delete/toggle operation, those comments
  are byte-for-byte preserved in the regions outside the `[[hooks]]`
  table the TUI is modifying.
- **AE3 — Multi-line command editing.** The form's command field
  accepts newlines. The user can paste a 6-line shell snippet,
  edit it, save it, and on reopen see the same 6 lines.
- **AE4 — Validation before write.** Save with empty command, empty
  name, or an event kind the FSM doesn't emit shows an inline
  validation error and leaves `settings.toml` unchanged on disk.
  The user is not forced to leave the form.
- **AE5 — External-edit detection.** If `settings.toml` has been
  modified on disk since the TUI opened the form (mtime mismatch),
  Save prompts via toast: "settings.toml changed externally —
  overwrite? [y/N]". No silent overwrite, no merge UI.
- **AE6 — Toggle keystroke.** From the registered-hooks list, the
  highlighted hook can be enabled/disabled with one key (proposed:
  `t`). The change writes through to `settings.toml`; toast confirms
  "Saved. Restart vortix to apply."
- **AE7 — Delete confirmation.** From the list, `d` (or Del) opens
  a confirm dialog ("Delete hook 'slack-notify'? [y/N]"). On
  confirm, the entry is removed and other entries are untouched.
- **AE8 — Disabled hooks render distinctly.** In the list, disabled
  entries are dimmed with a `[off]` prefix so the user can tell
  at a glance which are live.
- **AE9 — Restart-apply discipline.** After any successful save,
  the toast clearly says the change does not take effect until
  vortix restarts. The currently-running registry is not touched —
  the in-flight session continues firing the hooks that were
  registered at startup.
- **AE10 — Smoke parity.** The v0.3.0 smoke test (12 checks) still
  passes after this work lands.

## Scope boundaries

### In scope (PR #201)

- Registered-hooks list view inside the existing `Shift-H` overlay
  (extends, doesn't replace, the recent-fires view).
- Detail view: full config + recent fires for one hook.
- Add / Edit / Delete / Toggle flows with form widget.
- Multi-line command editing.
- `enabled: bool` schema field, defaults `true`; toggle keystroke.
- Pre-save validation (TOML well-formed, registry rebuilds clean,
  required fields present).
- Comment-preserving, atomic write to `settings.toml`.
- Mtime-check on save with overwrite confirm via toast.
- "Saved. Restart vortix to apply." toast wording on every
  successful write.
- Action menu entries for Add/Edit/Delete/Toggle alongside the
  existing "Lifecycle Hooks" overlay entry.
- Docs sweep (README highlight, v0.3.0 release notes, help overlay
  keybind entries, MIGRATION) and smoke updates.

### Deferred for later (post-v0.3.0)

- **Hot-reload of the running registry.** Restart-apply is the v0.3.0
  posture; hot-reload via ArcSwap or a reload signal stays as a
  v0.3.x follow-up if real friction shows up.
- **Per-profile hook attachment.** A separate brainstorm; current
  schema is global `[[hooks]]` only.
- **Preset / template library.** No "Notify on connect" gallery in
  v0.3.0 — the single-user model in this brainstorm doesn't need
  one. Revisit if/when a non-shell-comfortable user persona
  materializes.
- **Daemon-RPC management.** The daemon (plan 010/015 phase D) is
  skeleton-only in v0.3.0. When engine routing through the daemon
  ships, hook management may move to an RPC call instead of a
  direct file write — but that's not this work.
- **Concurrent-edit merge UI.** Mtime-check + overwrite prompt is
  the entire conflict story. No three-way merge.

### Outside this product's identity

- **Visual rule builder / IFTTT-style action chains.** vortix is a
  VPN manager; the "hook" mechanism stays a low-level shell-out, not
  a no-code automation framework.
- **Hook composition / pipelines.** One event fires N independent
  hooks (what we have today). No chaining, no fan-in, no shared state
  between hook fires.
- **GUI alternatives.** No native window, no web UI, no system tray
  icon. The TUI is the UI.

## Decisions and rationale

### D1 — Save + restart-apply (no hot-reload)

After save, the in-process registry is not touched. A toast tells the
user the change applies on next vortix start. Hot-reload (ArcSwap
on the registry, file-watcher) is deferred.

**Why:** the registry lives in a tokio task spawned at TUI startup
(plan 015 phase A wiring). Hot-reload would need either an
atomic-swap container around the registry or a teardown/respawn
of the subscriber task. Both are real chunks of code with race
windows (envelope arrives during swap → goes to old registry → noise
in journal). The user explicitly chose simpler. Restart-apply is
honest, predictable, and ships clean.

### D2 — `enabled: bool` field (ship the toggle)

Schema gains an `enabled: bool` defaulting to `true`. Disabled hooks
remain in `settings.toml` but the registry skips them at startup.

**Why:** "pause this hook for a meeting / a debugging session" is
real behavior that's neither edit nor delete. Adding the field is
one line of `HookConfig` + one filter in `build_registry_from_config`.
The toggle keystroke (`t`) is one keybind. Cost is trivial, value
is real, and skipping it now means we'd add it in v0.3.1 anyway.

### D3 — Multi-line command via textarea widget

The command field is a true multi-line editor, not a single-line input.

**Why:** ratatui ships single-line input only; real hooks (especially
`post_connect` with multi-step setup) are multi-line shell. Forcing
single-line means users would either flatten with `&&` chains
(hostile) or shell out to a script file (defeats the TUI-no-files
principle). Either vendor `tui-textarea` (well-maintained, MIT
licensed, ~2k LOC) or build a minimal one. Planning resolves which.

### D4 — Comment-preserving TOML round-trip (non-negotiable)

`settings.toml` writes go through `toml_edit` (or equivalent),
preserving every comment, blank line, key ordering, and unrelated
section.

**Why:** `settings.toml` is the maintainer's hand-curated config —
log levels, retention windows, kill-switch policy, comments
explaining "why we chose this." A TUI save that silently destroys
that content is a trust-killing bug we ship exactly once before
the maintainer never opens the hooks overlay again. `toml_edit` is
designed for this; it's the standard answer in the Rust ecosystem.

### D5 — Global `[[hooks]]` only; per-profile deferred

Per-profile hook attachment (e.g., `[[profiles.corp.hooks]]`) is
explicitly out of scope. The schema this brainstorm manages is the
current global `[[hooks]]` array.

**Why:** per-profile is a separate product question — different
schema, different UI ("which profile am I editing for?"), different
flows. Trying to land both in one brainstorm muddies both. v0.3.x
ships global-only; per-profile gets its own brainstorm if it earns
one.

### D6 — Bundled in PR #201 (no defer)

This work lands in the same PR as plan 015 + plan 016, alongside
the v0.3.0 architectural migration.

**Why:** the maintainer has been explicit across this project that
PR #201 is the single ship. Splitting hook management into v0.3.1
is technically cleaner but ships v0.3.0 with a half-managed
feature (you can *see* hooks fire but can't *change* them). The
maintainer chose "do it right, in this PR" over "ship clean,
follow up." Honored.

### D7 — Mtime-check + overwrite toast on conflict

When the form opens, it captures `settings.toml`'s mtime. On save,
if mtime has advanced (external editor wrote it), Save prompts
the user via toast: "settings.toml changed externally — overwrite?
[y/N]". No merge UI.

**Why:** real conflict resolution is a different product. The
expected normal case is the TUI is the only writer. The mtime
check exists so the maintainer doesn't lose hand-typed edits made
in `$EDITOR` while a stale form was open.

## Dependencies and assumptions

- **`toml_edit` crate** (new dependency). Comment-preserving TOML
  edit/serialize. ~1k LOC + tree, well-maintained, MIT/Apache. The
  only mature option in the Rust ecosystem for this.
- **Multi-line textarea**: `tui-textarea` crate (vendor) or build a
  minimal one. Planning decides.
- **`HookConfig` schema**: gains an `enabled: Option<bool>` field
  (defaulting to `true` when missing — backward compatible with
  existing TOML).
- **Atomic write**: write to `settings.toml.tmp`, fsync, rename
  over `settings.toml`. Standard pattern; no new deps.
- **No daemon dependency**: the daemon is skeleton-only in v0.3.0
  (engine routing returns `IpcError::Internal`). The TUI writes
  `settings.toml` directly; daemon RPC stays a v0.3.x topic.
- **The TUI is the only intended writer**, but the mtime check
  prevents silent overwrite when that assumption is violated.

## Open questions (resolved during planning)

- **OQ1 — Textarea widget choice.** Vendor `tui-textarea` (faster
  to land, external dependency surface) or build a minimal multi-
  line input inside `crates/vortix`? Planning decides based on the
  crate's footprint and our edit-feature needs.
- **OQ2 — Toggle keybind placement.** `t` on the list view is the
  proposed binding (it's unused there). Validate during planning
  against existing key allocations.
- **OQ3 — Form layout.** Fields stack vertically (event picker →
  name → command textarea → timeout → env vars → enabled checkbox
  → Save/Cancel) — but exact widget sizing, scroll-on-overflow
  behavior, and tab-order resolve at implementation time.
- **OQ4 — Env-var editor shape.** Hooks support arbitrary env vars
  as a string-string map. The UI for editing a map is non-trivial.
  Options: a single multi-line key=value text field, a repeating
  pair input, or a "raw TOML inline-table" escape hatch. Planning
  picks.
- **OQ5 — Reload-on-next-event as a stretch.** If hot-reload looks
  cheap during planning (e.g., the journal-subscriber can simply
  re-build the registry from `Settings::load()` before each
  lifecycle dispatch), we may land it for free. Not required to
  meet D1.

## Success criteria

- **SC1 — End-to-end add flow under 60 seconds from cold start.**
  From `cargo run -- vortix`, the maintainer can land a working
  `notify-send` hook in under a minute, no external editor.
- **SC2 — Comment-preservation invariant.** A `settings.toml` with
  comments above and below the `[[hooks]]` array survives any
  TUI save with the non-hook regions byte-for-byte identical
  (verifiable via checksum on the non-`[[hooks]]` slice).
- **SC3 — Validation captures 95% of misconfigurations before
  write.** Empty command, empty name, invalid event kind, malformed
  timeout — all caught at form save, not at next startup.
- **SC4 — Smoke parity.** `scripts/smoke-v0.3.0.sh` still passes
  12/12 after this work lands.
- **SC5 — No regressions to plan 015 / 016.** All existing hook
  fires, toasts, overlay rendering, and config-error toasts
  continue to work; the registered-hooks list grows alongside,
  not in place of, the recent-fires view.
- **SC6 — Test coverage.** Unit tests for the TOML round-trip
  (comments preserved, ordering preserved, unrelated sections
  preserved), form-state machine (validation rejects bad input,
  unsaved-changes flag drives Cancel-confirm), mtime conflict
  path, and `enabled = false` registry-skip behavior. End-to-end
  workspace `cargo test` stays green.

## Risks

- **R1 — `toml_edit` round-trip edge cases.** Exotic TOML shapes
  (deeply nested tables, multi-line strings with embedded quotes)
  may round-trip imperfectly. Mitigation: snapshot tests for the
  fixtures we ship, plus the mtime-overwrite safety net.
- **R2 — Form widget complexity.** Multi-line editing + tab order
  + Esc-cancel-with-unsaved-changes is real UI work and we have no
  precedent in `crates/vortix/src/ui/overlays/`. Vendor `tui-textarea`
  is the smaller risk if its API fits.
- **R3 — PR #201 scope creep.** PR #201 already absorbed plans
  005/006/007/015/016. Adding this is another 7–8 units. Mitigated
  by the maintainer's explicit "do it right, in this PR" decision —
  this is a known cost, not an accidental one.
- **R4 — Restart-apply UX confusion.** Users may expect "save
  apply" instinct and be confused when the next connect doesn't
  fire the new hook. Mitigated by: toast wording, optional
  banner on the hooks overlay until restart, and possibly a
  stretch goal of reload-on-next-event (OQ5).

## Related work

- `docs/plans/2026-05-24-009-feat-lifecycle-hooks-plan.md` —
  schema + dispatcher.
- `docs/plans/2026-05-24-015-feat-deferred-subsystems-bundle-plan.md`
  — wiring of the hook subscriber into the TUI.
- `docs/plans/2026-05-24-016-feat-tui-hook-surface-plan.md` —
  observability layer (toasts + overlay) that this work extends.
- `docs/architecture-migration-v1.md` — phase A row should add a
  follow-up reference once this lands (see plan 016 precedent).

## Handoff

Ready for `/ce-plan`. Planning needs to resolve OQ1–OQ5 and
sequence the 7–8 implementation units (registered-hooks list view,
detail drill-in, multi-line form widget, add/edit/delete/toggle
flows, comment-preserving TOML writer + atomic write, mtime
conflict pipeline, action-menu/keybind wiring, docs + smoke).
