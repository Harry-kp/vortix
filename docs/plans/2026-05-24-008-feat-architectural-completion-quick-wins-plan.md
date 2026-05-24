---
plan_id: 2026-05-24-008
title: "feat: Architectural completion — quick wins (Track A)"
type: feat
status: completed
created: 2026-05-24
target_branch: refactor/architectural-migration-v1
target_pr: 201
target_version: 0.3.0
origin: docs/brainstorms/2026-05-24-architectural-completion-requirements.md
---

# feat: Architectural completion — quick wins (Track A)

## Problem Frame

The architectural migration v1 bundle (plans 001–006) and the rollout
playbook (plan 007) ship as v0.3.0 in PR #201. Before the rollout, a
preemptive audit identified six small architectural seams worth adding
*now* because they're cheap today and painful to retrofit once features
start landing on top.

Plan 008 lands those six seams as the final commits on PR #201,
inside the v0.3.0 cutover. None of them ship new user-facing features;
all six are forward-compatibility reservations or correctness bumpers
that the next 1–2 years of feature work will land against.

## Summary

Six implementation units, all cheap, all additive, all land in PR #201:

- **U1.** `--json` envelope gains a `schema_version: 1` field, with a
  documented bump policy.
- **U2.** Engine FSM gains an `AwaitingUserInput` variant + matching
  `EngineInput::UserAnswered` + `EngineEvent::UserPromptRequested`.
  Slot reservation only; no consumer wired.
- **U3.** `Settings` gains a `schema_version: u32` field with a
  migration placeholder fn.
- **U4.** New `crates/vortix-platform-windows/` stub crate that
  compiles on Windows but returns `PlatformUnsupported` for every port
  method. Proves the Platform aggregate admits a third OS.
- **U5.** Startup orphan-daemon scan — warns when `wg-quick` or
  `openvpn` processes look like leftovers from a previous vortix
  crash. Warn-only; no auto-adopt.
- **U6.** CI cold-start performance test asserting `vortix --version`
  runs in under 200 ms. Locks in the README's "<100 ms" claim with
  comfortable margin.

---

## Scope Boundaries

**In scope:**
- The six units above, each landing as one commit on
  `refactor/architectural-migration-v1`.
- Tests for each unit where behavioral.
- Documentation updates in `docs/MIGRATION.md` where the seam is
  user-visible (U1, U3).

**Deferred to follow-up work:**
- Wiring `AwaitingUserInput` to a real 2FA prompt UI (plan 009+ or
  feature-specific PR).
- Implementing the Windows port impls — the stub returns
  `PlatformUnsupported` everywhere.
- Auto-adopt of orphan daemons (depends on plan 010 IPC layer).
- Schema-migration logic for old `Settings` files (no v0.2.x file to
  migrate yet; placeholder fn covers future renames).

**Outside this product's identity:**
- Adding new Platform impls beyond macOS/Linux/Windows-stub.
- Replacing the structured-output envelope format wholesale (the
  envelope shape is locked at v0.3.0).

---

## Requirements

| ID | Requirement | Source |
|----|-------------|--------|
| R1 | The structured JSON envelope returned by every `--json` command carries `"schema_version": 1` at the top level | Origin: prevents silent contract drift |
| R2 | The Engine `Connection` enum has an `AwaitingUserInput` variant ready for 2FA flows; matching Input/Event types exist | Origin: #191 will need this; cheap now, retrofit forces special cases |
| R3 | `Settings::schema_version` is serialized with `default = 1`; a `migrate_settings(value: toml::Value) -> Result<Settings>` placeholder fn exists | Origin: future field renames need a detection path |
| R4 | `vortix-platform-windows` crate exists, compiles via `cfg(target_os = "windows")`, and implements every port trait with `Err(PlatformUnsupported)` returns | Origin: #17 (Windows); proves three-OS architecture without shipping a half-baked impl |
| R5 | At startup, vortix scans for orphan `wg-quick`/`openvpn` processes from a previous crash and warns on stderr; no automatic adoption | Origin: silent gap; current behavior is to ignore them |
| R6 | A test asserts `vortix --version` completes in under 200 ms on the workspace test runners | Origin: README claims "<100 ms"; no enforcement today |

---

## Implementation Units

### U1. JSON envelope `schema_version`

- **Goal:** Every `--json` output gets a top-level `"schema_version": 1`. Establishes the contract for v0.3.0; future field changes bump the version.
- **Requirements:** R1
- **Dependencies:** none
- **Files:**
  - `crates/vortix/src/cli/output.rs` (or whichever module emits the structured envelope — confirm at execution time)
  - `docs/MIGRATION.md` (add a short "JSON output contract" subsection)
- **Approach:**
  - Find the central envelope-emit point. The `print_success` / `print_error` helpers already exist (seen in `crates/vortix/src/cli/commands.rs`).
  - Add a `schema_version` field to the envelope struct, default `1`.
  - Document the bump policy: bump on any field rename, type change, or removal. Field additions don't require a bump (consumers should tolerate unknown fields).
- **Patterns to follow:** existing `MigrateData`, `SettingsData` envelope structs in `crates/vortix/src/cli/commands.rs`.
- **Test scenarios:**
  - `vortix migrate --json` output parses as JSON and contains `"schema_version": 1`
  - `vortix settings --json` output contains `"schema_version": 1`
  - `vortix engine status --json` output contains `"schema_version": 1`
  - The constant is defined once and reused (grep verifies)
- **Verification:** smoke script (`scripts/smoke-v0.3.0.sh`) is updated to assert the field's presence in at least one JSON output.

### U2. FSM `AwaitingUserInput` variant

- **Goal:** Reserve the FSM slot for mid-flow user prompts (2FA challenge, certificate password) without wiring a real consumer.
- **Requirements:** R2
- **Dependencies:** none
- **Files:**
  - `crates/vortix-core/src/engine/state.rs` (add variant to `Connection`)
  - `crates/vortix-core/src/engine/input.rs` (add `UserAnswered { prompt_id, answer }`)
  - `crates/vortix-core/src/engine/event.rs` (add `UserPromptRequested { prompt_id, prompt_kind, prompt_text }`)
  - `crates/vortix-core/src/engine/fsm.rs` (handle the new states in match arms; default transitions for now)
- **Approach:**
  - `Connection::AwaitingUserInput { prompt_id: String, prompt_kind: PromptKind, since: Instant }` — top-level variant, not nested in Connecting.
  - `PromptKind` enum: `TwoFactorCode`, `Passphrase`, `Generic { label: String }`. `#[non_exhaustive]` so future kinds don't break consumers.
  - Default FSM transitions: `Connecting → AwaitingUserInput` on `UserPromptRequested`; `AwaitingUserInput → Connecting` on `UserAnswered`; `AwaitingUserInput → Disconnected` on timeout or `Cancel`.
  - Bump `EventEnvelope::SCHEMA_VERSION` if the event schema changes — confirm at execution time whether adding a variant requires a bump (additive enum variants typically don't if downstream uses `#[non_exhaustive]` matching).
- **Patterns to follow:** existing `Connection::Connecting`, `Connection::Connected` and their corresponding inputs/events.
- **Test scenarios:**
  - `Engine::handle(UserPromptRequested {...})` from `Connecting` transitions to `AwaitingUserInput`
  - `Engine::handle(UserAnswered {...})` from `AwaitingUserInput` transitions back to `Connecting`
  - `Engine::handle(UserAnswered {...})` from `Connected` is a no-op (or returns an error event) — define which
  - `AwaitingUserInput { since }` timeout transitions to `Disconnected{last_failure: Some("user-prompt-timeout")}`
  - Serialization round-trip: an `EventEnvelope` containing `UserPromptRequested` survives JSON encode + decode
- **Verification:** `cargo test -p vortix-core engine` passes; the new variant appears in the snapshot serialization tests.

### U3. `Settings::schema_version` + migration placeholder

- **Goal:** Reserve the forward-migration path for `settings.toml`. When v0.4 renames a field, the migration function is the documented seam.
- **Requirements:** R3
- **Dependencies:** none
- **Files:**
  - `crates/vortix-config/src/settings.rs` (add field + placeholder fn)
- **Approach:**
  - Add `pub schema_version: u32` to `Settings`, default `1` via `#[serde(default = "default_schema_version")]`.
  - Add `pub fn migrate_settings(raw: toml::Value) -> Result<Settings, SettingsError>` — for v1, just deserialize as-is. For unknown versions, return `Err(SettingsError::UnsupportedSchema)`.
  - Add `SettingsError::UnsupportedSchema { found: u32, supported_max: u32 }` variant.
  - Update the `Settings::load()` figment pipeline to call `migrate_settings` after merging layers.
- **Patterns to follow:** existing `Sidecar::SCHEMA_VERSION` constant in `crates/vortix-config/src/profile_store.rs`.
- **Test scenarios:**
  - Empty settings file loads with `schema_version = 1`
  - Settings file with explicit `schema_version = 1` loads cleanly
  - Settings file with `schema_version = 999` returns `Err(UnsupportedSchema)` rather than silently parsing
  - `migrate_settings` on a v1 raw `toml::Value` returns the expected `Settings`
- **Verification:** `cargo test -p vortix-config settings` passes; loading a v0.3.0 settings file is unchanged in behavior.

### U4. `vortix-platform-windows` stub crate

- **Goal:** Prove the Platform aggregate admits a third OS by adding a Windows crate that compiles on `cfg(target_os = "windows")` and returns `PlatformUnsupported` for every operation. No actual Windows functionality.
- **Requirements:** R4
- **Dependencies:** none
- **Files:**
  - `crates/vortix-platform-windows/Cargo.toml` (new)
  - `crates/vortix-platform-windows/src/lib.rs` (new)
  - `crates/vortix-platform-windows/src/{killswitch,dns,interface,network_stats,route_table}.rs` (new — one stub impl per port)
  - `Cargo.toml` (root) — add to workspace `members`
  - `crates/vortix/Cargo.toml` — add `cfg(target_os = "windows")` dependency target
  - `crates/vortix/src/platform/aggregate.rs` — add the Windows arm to whatever match drives platform selection
- **Approach:**
  - Mirror the structure of `crates/vortix-platform-macos/` exactly. Same file names, same trait impls.
  - Every impl method returns `Err(SomeError::PlatformUnsupported)` — use the existing error types from each port.
  - The crate is `publish = false`, `version = "0.0.0"` — same convention as the other platform crates.
  - The binary's `cfg(target_os = "windows")` dependency block adds this crate the same way it adds macos/linux.
  - `cargo build --workspace --target x86_64-pc-windows-gnu` is the verification (if the toolchain is installed) — but the unit's primary verification is that the crate compiles into the binary on a normal `cargo check` from macOS/Linux, because nothing depends on it from those targets.
- **Patterns to follow:** `crates/vortix-platform-macos/src/lib.rs`, structure of every port impl in that crate.
- **Test scenarios:**
  - `cargo check -p vortix-platform-windows --target x86_64-pc-windows-gnu` (if toolchain present) compiles
  - Every port trait impl returns `Err(PlatformUnsupported)` on first call
  - `crates/vortix/src/platform/aggregate.rs` builds on macOS/Linux with the new Windows arm in place (it's gated by `cfg`, so it's compiled away on non-Windows)
- **Verification:** `cargo build --workspace --all-targets` still passes; `cargo run -p xtask -- check-platform-leak` still passes (the new crate is in the allowlist by virtue of being at `crates/vortix-platform-*`).

### U5. Startup orphan-daemon scan

- **Goal:** When vortix starts, if there are `wg-quick`/`openvpn` processes from a previous crashed vortix run, warn the user. No auto-adopt.
- **Requirements:** R5
- **Dependencies:** none
- **Files:**
  - `crates/vortix/src/main.rs` (add scan call after platform install, before any user-facing logic)
  - `crates/vortix-process/src/orphan_scan.rs` (new module — process-list scan with WG/OVPN filter)
- **Approach:**
  - Use the existing `CommandRunner` to invoke `ps -eo pid,comm,args` (Unix) — Windows path is no-op since this is for a leftover-Unix-VPN scenario.
  - Filter for command names matching `wg-quick`, `openvpn`, or `wireguard-go`.
  - Emit a stderr warning if any are found, listing PIDs and the matching command.
  - Do NOT attempt to kill or adopt. The user runs `sudo kill <pid>` or `sudo vortix down --force` themselves.
- **Patterns to follow:** existing `crates/vortix-process/` modules.
- **Test scenarios:**
  - `orphan_scan` with no VPN processes returns an empty list
  - `orphan_scan` with a fake `ps` output (via `MockRunner`) listing one `wg-quick` returns it
  - The startup log message includes the PID and command name when found
  - The scan never panics on platforms where `ps` is missing — returns empty
- **Verification:** `cargo test -p vortix-process orphan_scan` passes; manually triggered orphan scenario logs as expected.

### U6. Cold-start performance test

- **Goal:** Lock in the README's "<100 ms startup" claim with a CI test that runs `vortix --version` in a subprocess and asserts wall-time < 200 ms (margin for CI variability).
- **Requirements:** R6
- **Dependencies:** the binary must build (every other unit's prereq)
- **Files:**
  - `crates/vortix/tests/cold_start.rs` (new integration test)
- **Approach:**
  - `std::process::Command::new(env!("CARGO_BIN_EXE_vortix")).arg("--version")` — runs the actual binary.
  - Measure wall-time around `.output()`.
  - Assert `< Duration::from_millis(200)`. CI is slower than dev; 200 ms is the comfortable ceiling for the README's <100 ms claim.
  - Skip the test under `cfg(debug_assertions)` if it consistently flakes on slower CI runners; document the threshold for release builds.
- **Patterns to follow:** existing integration tests under `crates/vortix/tests/`.
- **Test scenarios:**
  - The integration test runs the binary and measures wall-clock
  - Assertion fails (loud) if the binary takes >200 ms
  - Test runs in CI's matrix (Ubuntu, macOS) — both should pass with margin
- **Verification:** `cargo test -p vortix --test cold_start --release` passes locally and in CI.

---

## System-Wide Impact

| Surface | Impact | Mitigation |
|---|---|---|
| `--json` consumers | New `schema_version` field appears in every envelope | Additive; ignorable by consumers; documented in MIGRATION.md U1 |
| `Connection` enum match sites | New `AwaitingUserInput` variant | Add `#[non_exhaustive]` on `Connection` if not already; existing match sites get a default arm that treats `AwaitingUserInput` like `Connecting` for v0.3.0 |
| Settings consumers | New `schema_version` field deserialized | Default value 1 means existing files load unchanged |
| Cargo workspace | One new member (`vortix-platform-windows`) | `cargo build --workspace` rebuilds slightly slower; `cargo doc` covers it |
| Startup time | Orphan scan runs a `ps` subprocess on Unix | Should be <10ms; verified by U6's perf test |

---

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `Connection` enum becomes non-exhaustive and breaks downstream pattern matches | Low — already `#[non_exhaustive]` per plan 005 design | Low | Confirm at execution; add `#[non_exhaustive]` if missing |
| Orphan scan picks up *legitimate* VPN processes from a different vortix instance | Low | Medium — false-positive warning | Match on parent-PID being non-vortix to filter out same-session processes; document the limitation |
| `vortix --version` cold-start test flakes on slow CI runners | Medium | Low — false test failure | 200ms ceiling is 2x the README claim; if flake persists, gate behind `cfg(not(debug_assertions))` |
| Windows stub crate hides `cfg(unix)` leaks that only surface on actual Windows build | Medium | Low for v0.3.0 (no Windows users) | The whole point of the stub is to surface them — `cargo check --target x86_64-pc-windows-gnu` runs in CI optionally |
| Settings v1 → v2 migration logic never gets exercised | Low | Low | Acceptable; the seam exists; first real migration will populate it |

---

## Implementation Unit Ordering

U1 → U3 → U2 → U6 → U5 → U4

- U1 first: smallest, additive, no dependencies; sets the documentation pattern.
- U3 second: similar shape to U1 (additive field + version handling).
- U2 third: touches `vortix-core` types; rebuilds the workspace.
- U6 fourth: integration test; needs binary to build (so after U2 settles).
- U5 fifth: real subprocess work; cleanest to do after the FSM/types churn.
- U4 last: new crate, biggest scaffolding lift; isolated so we don't churn it during earlier units.

---

## Verification Strategy

| Layer | Check | When |
|---|---|---|
| Per-unit | `cargo test -p <crate>` | After each unit's commit |
| Workspace | `cargo test --workspace` | After U4 (every unit landed) |
| Clippy | `cargo clippy --all-targets -- -D warnings` | Pre-commit on each unit |
| Format | `cargo fmt --all -- --check` | Pre-commit |
| xtask lints | `check-subprocess`, `check-platform-leak`, `check-protocol-leak` | After U4 (new crate is the most likely lint trigger) |
| Smoke | `scripts/smoke-v0.3.0.sh dev` | After U1 (schema_version assertion added to smoke) |
| Cross-target | `cargo check --target x86_64-pc-windows-gnu --workspace` | After U4 — optional, requires the toolchain |

All gates must be green before plan 008 closes.

---

## Out of Scope (cross-reference)

This plan does NOT implement:

- A real 2FA prompt UI (deferred — will use U2's FSM slot when a feature plan lands)
- Real Windows port impls (deferred — U4 is a stub; full Windows is a multi-month effort, not scoped)
- Auto-adopt of orphan daemons (deferred — depends on plan 010 IPC)
- Real schema-migration logic for Settings (deferred — placeholder is sufficient until first rename)
- A second `ProfileStore` impl (deferred — premature)
- Telemetry export to Prometheus/OpenTelemetry (deferred — no demand signal)
