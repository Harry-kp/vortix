---
title: "refactor: retire legacy ConnectionState (P5 of multi-connection plan #001 U7)"
type: refactor
status: pending
date: 2026-05-30
origin: docs/plans/2026-05-28-001-feat-multi-connection-plan.md (U7 + U6 Stage B follow-through)
---

# refactor: retire legacy `ConnectionState` (P5)

## Summary

The multi-connection feature (plan 001 U6 Stage B) migrated every panel renderer to read from `app.registry.snapshot(profile_id)`. But the legacy `ConnectionState` enum at `crates/vortix/src/vpn_runtime/connection_state.rs` is still alive — every connect/disconnect/scanner/retry path writes to and reads from `runtime.connection_state` as the single-tunnel state machine. Plan 001 U7 specified this enum's retirement; the prior session (commits `e96a48a` → `90b62e8`) built a bookkeeping mirror approach (`mirror_*_into_registry` family) that keeps both representations in lock-step but did not retire the legacy enum.

P5 is the final step: delete `connection_state` from `VpnRuntime`, drive all behavior through `TunnelRegistry`, retire the file `vpn_runtime/connection_state.rs`.

The work splits into four stages of escalating semantic depth:

- **P5a — renderer / helper cleanup** (low risk, ~15 sites): finish migrating the few remaining direct reads in `ui/widgets/footer.rs`, drop the legacy-fallback branches in `app/helpers.rs` now that the registry holds all transitional states (Path A landed in commit `39473eb`).
- **P5b — scanner + retry refactor** (high semantic depth, ~40 sites): rewrite `handle_sync_system_state` to track per-profile state machines via the registry. Refactor retry / auto-reconnect / pending_connect to be per-profile or document the policy choice (global vs per-tunnel) explicitly.
- **P5c — CLI migration** (parallel concern, ~10 sites): the CLI's blocking helpers in `crates/vortix/src/vpn_runtime/connection.rs` have their own `ConnectionState` usage on the `VpnRuntime` struct. Migrate them off the enum or add a registry to `VpnRuntime`.
- **P5d — delete the field + the file** (trivial after a/b/c, ~5 sites): drop `pub connection_state: ConnectionState` from `VpnRuntime`, delete `vpn_runtime/connection_state.rs`, remove the re-export in `vpn_runtime/mod.rs`.

---

## Problem Frame

See the plan 001 origin §6 and U6 Stage B / U7. The short version:

1. Plan 001's design declares the `TunnelRegistry<TunnelKind>` as the source of truth for active VPN state. It's an N-tunnel registry; the FSM `Connection` enum it stores has Connecting / Connected / Disconnecting / Reconnecting / Disconnected / AwaitingUserInput variants.
2. The legacy single-tunnel `ConnectionState` enum was supposed to retire in U6 Stage B but only got **relocated** from `state/connection.rs` to `vpn_runtime/connection_state.rs`. The file's own header comment acknowledges this: "Plan U7 will retire this in favour of the per-tunnel `Connection` FSM owned by `TunnelRegistry`."
3. The mirror approach the prior session built (commits `e96a48a`, `90a6c7c`, `e3fd9c2`, `462636e`, `903662e`, `39473eb`) keeps both representations consistent. Renderers read registry only; legacy state-write sites mirror into the registry. This works for visible state today but leaves dual sources of truth.
4. P5 removes the legacy mirror. Single source of truth. Smaller code, fewer bugs from the two getting out of sync (which has been the source of every TUI bug in this session — connect mirror missing, disconnect mirror missing on pending-switch path, wrong interface in handle, etc.).

---

## What's already shipped (foundation P5 builds on)

Before starting P5, the next session should verify these are in place on `feat/multi-connection`:

### Engine seed-state API (`crates/vortix/src/vortix_core/engine/fsm.rs`)

Public methods that mutate `Engine.state` directly without driving `Tunnel::up`/`down`. Used by the registry's bookkeeping `set_*` methods.

- `Engine::seed_connected_state(profile_id, details, since)` — commit `462636e`
- `Engine::seed_disconnected_state()` — commit `462636e`
- `Engine::seed_connecting_state(profile_id, started_at, attempt, retry_budget_remaining)` — commit `39473eb`
- `Engine::seed_disconnecting_state(profile_id, started_at)` — commit `39473eb`
- `Engine::seed_failed_state(failure_reason)` — commit `39473eb`

**Not yet present** — add in P5b if needed:
- `Engine::seed_reconnecting_state(profile_id, started_at, attempt, retry_budget_remaining, last_error)`
- `Engine::seed_awaiting_input_state(profile_id, prompt_id, prompt_kind, since)`

### Registry bookkeeping API (`crates/vortix/src/vortix_core/engine/registry.rs`)

- `TunnelRegistry::set_connected(profile_id, allowed_ips, details, since, engine_factory)`
- `TunnelRegistry::set_disconnected(profile_id)`
- `TunnelRegistry::set_connecting(profile_id, allowed_ips, started_at, attempt, retry_budget, engine_factory)`
- `TunnelRegistry::set_disconnecting(profile_id, started_at)`
- `TunnelRegistry::set_failed(profile_id, allowed_ips, failure, engine_factory)`

All call `recompute_primary` internally where appropriate.

### App mirror helpers (`crates/vortix/src/app/connection.rs`)

These bridge legacy state-write sites into the registry. **P5d deletes these** once the legacy field is gone:

- `App::mirror_connect_into_registry(profile_name)`
- `App::mirror_disconnect_into_registry(profile_name)`
- `App::mirror_connecting_into_registry(profile_name)`
- `App::mirror_disconnecting_into_registry(profile_name)`
- `App::mirror_failed_into_registry(profile_name, error_msg)`

### Existing test coverage (~10 mirror tests in `app/tests.rs`)

- `connect_result_success_mirrors_into_registry`
- `disconnect_result_success_removes_from_registry`
- `scanner_promotion_from_connecting_to_connected_mirrors_into_registry`
- `scanner_drop_from_connected_clears_registry`
- `mirrored_registry_entry_uses_real_interface_not_mock0`
- `mirror_refresh_updates_registry_when_details_change`
- `mirrored_registry_entry_carries_full_rich_details_not_just_interface_and_pid`
- `mirror_connecting_makes_registry_hold_connecting_state`
- `mirror_disconnecting_transitions_existing_connected_entry`
- `mirror_disconnecting_no_op_when_registry_has_no_entry`
- `mirror_failed_makes_registry_hold_disconnected_with_failure`
- `switch_path_disconnect_completion_removes_old_profile_from_registry`

These tests assert the **mirror semantics** — that after a legacy state transition, the registry is in the right state. P5 must keep them green (they should still pass with the legacy enum gone, since the registry will be the only state and the assertions are registry-shaped).

---

## Inventory (where the work lives)

Last counted on `feat/multi-connection` at commit `90b62e8`:

| File | `connection_state` refs (production) | Notes |
|---|---:|---|
| `crates/vortix/src/app/update.rs` | 30 | Heaviest. Scanner, retry, message handlers. P5b core. |
| `crates/vortix/src/app/connection.rs` | 23 | Connect/disconnect orchestration. P5a + P5b. |
| `crates/vortix/src/cli/commands.rs` | 11 | CLI surfaces. P5c. |
| `crates/vortix/src/vpn_runtime/connection.rs` | 10 | CLI blocking helpers. P5c. |
| `crates/vortix/src/app/helpers.rs` | 7 | Dual-source helpers. P5a (drop fallback). |
| `crates/vortix/src/app/profile.rs` | 3 | Profile management. Mostly P5a. |
| `crates/vortix/src/app/telemetry_poll.rs` | 1 | Scoping read. P5a. |
| `crates/vortix/src/ui/widgets/footer.rs` | 1 | Status line. P5a. |
| `crates/vortix/src/vpn_runtime/mod.rs` | varies | Re-exports. P5d. |
| `crates/vortix/src/vpn_runtime/connection_state.rs` | (definitions) | Delete in P5d. |

Plus ~82 references in test files — those update mechanically with the production sites.

Total writes (excluding tests): **21** (all `connection_state = ConnectionState::...` assignments).

---

## Requirements

R1-R13 from plan 001 already cover the behavioral contract. P5 adds these refactor-specific requirements:

| ID | Requirement |
|---|---|
| P5-R1 | Single source of truth for active VPN state: `TunnelRegistry`. The legacy `ConnectionState` field disappears from `VpnRuntime`. |
| P5-R2 | Every read of "is profile X in state Y?" goes through `app.registry.snapshot(&ProfileId::new(name))` or a new helper that wraps it. |
| P5-R3 | Every write to active state goes through `app.registry.set_*` (connected/disconnected/connecting/disconnecting/failed) — no legacy mirror needed. |
| P5-R4 | Multi-tunnel retry semantics decided + documented: per-profile retry, or global (single concurrent retry)? Plan-time decision below. |
| P5-R5 | Multi-tunnel auto-reconnect semantics decided + documented: when a Connected tunnel drops, does the auto-reconnect kick in for it specifically, or only when no tunnels are active? |
| P5-R6 | CLI's `vortix up` / `vortix down` / `vortix status` route through the registry too, or have their own equivalent. Behavior parity with TUI. |
| P5-R7 | Net binary size growth must remain ≤ 2MB per plan 001 R4 (the per-profile state likely adds a small Vec<Retry> on App). |
| P5-R8 | All existing mirror tests stay green. The behavioral contract they encode is the registry's contract; the implementation moves around them. |
| P5-R9 | New tests cover the per-profile retry / auto-reconnect semantics (whatever policy is chosen). |

---

## Key Technical Decisions

### D-1. Per-profile retry vs single global retry

**Today (legacy):** `runtime.retry_count: u32` + `runtime.retry_profile_idx: Option<usize>` + `runtime.auto_reconnect_profile: Option<String>` are single slots. Only ONE connect can be retrying at a time.

**Multi-tunnel options:**

- **Option A (per-profile retry state):** Move retry state into the registry's per-tunnel `RegistryEntry` or a parallel `HashMap<ProfileId, RetryState>`. Each profile retries independently. More state, more correct.
- **Option B (single global retry):** Keep the single-slot semantics — at most one profile retries at a time. Simpler but if the user connects A, A fails and starts retrying, then user manually connects B which fails, B's retry overwrites A's. Lossy.
- **Option C (no retry across profile switches):** When the user initiates a new connect, cancel any in-flight retry. Per-profile retry only within "current attempt" boundaries. Middle ground.

**Recommendation: Option A** — per-profile retry state. The multi-tunnel feature inherently expects independent tunnels; retry should follow. Add `retry_state: HashMap<ProfileId, RetryState>` to App (not the registry — retry is App orchestration concern, not FSM-intrinsic). Memory cost is tiny (~32 bytes per entry, only present for profiles with active retries).

**Open question at implementation time:** Should the retry policy be configurable (settings already has `connect_max_retries` and `connect_retry_base_delay_secs`) or hardcoded per-profile-attempt? Defer to per-profile-with-existing-settings.

### D-2. Auto-reconnect on drop: per-profile vs primary-only

**Today (legacy):** `auto_reconnect_profile: Option<String>` — single slot. When the active VPN drops, vortix reconnects it. With multi-tunnel, multiple Connected tunnels exist; any of them could drop independently.

**Options:**
- **Per-profile auto-reconnect:** Each Connected profile sets its own auto-reconnect target. When any one drops, just that one reconnects.
- **Primary-only auto-reconnect:** Only the primary tunnel auto-reconnects. Secondaries don't. (Defensible: secondaries are "addressable" by design — they're routes-only, the user implicitly accepted them as ancillary.)
- **None:** Drop the auto-reconnect feature entirely. Surface "VPN dropped" toast and require manual re-connect. (Most explicit; user controls.)

**Recommendation: per-profile auto-reconnect** for parity with Option A above. Symmetric reasoning.

### D-3. CLI migration approach

**Today:** `vpn_runtime/connection.rs` provides blocking `connect()` / `disconnect()` / `status()` helpers on `VpnRuntime`. They write directly to `VpnRuntime.connection_state`. No registry exists in `VpnRuntime`.

**Options:**
- **Add a `TunnelRegistry` field to `VpnRuntime`:** the same struct used by App. CLI drives the registry directly. Most consistent, biggest delta.
- **Keep the CLI's single-tunnel semantics:** the CLI is a single-tunnel surface by design (one `vortix up X`; multi-tunnel happens in TUI). Leave it alone, retire only the App-side. The legacy enum lingers as a CLI-only type.
- **Build a thin facade:** CLI calls into an App-like layer that uses the registry. Most architectural; biggest refactor.

**Recommendation: Option 2** — keep CLI single-tunnel, document why. The CLI's `vortix up X` always means "connect THIS one VPN". Multi-tunnel adds complexity the CLI doesn't need. Move the legacy enum into a CLI-only module (`crates/vortix/src/cli/state.rs`), retire it from `vpn_runtime`. P5c becomes scope reduction (move the enum to a CLI-private location, not delete it).

**Decision deferred to implementation:** the recommendation is concrete enough to move forward. Plan-time owner can override if they prefer Option 1.

### D-4. Scanner refactor shape

**Today:** `handle_sync_system_state` in `update.rs:776+` has three branches keyed off `connection_state`:
1. Connecting → Connected promotion (matches the ONE in-flight profile against scanner sessions)
2. Connected adoption (no prior Connecting; e.g. vortix restart with VPN already up)
3. Drop detection (Connected/Connecting/Disconnecting → Disconnected when no active session)

**Multi-tunnel shape:** scanner iterates the registry's snapshots. For each entry:
- Find matching active session by interface name
- If found and state is Connecting: promote to Connected
- If found and state is Connected: refresh details
- If not found and state is Connected/Connecting/Disconnecting: drop detected

The control flow is a `for entry in registry.snapshot_all()` loop over the registry, not a single `match` on the legacy field. Each profile is independent.

**Patterns to follow:** the existing scanner logic at update.rs:801-1108. Most of the per-branch work (location lookup, killswitch sync, telemetry refresh) stays the same — just moves inside a per-profile loop.

### D-5. Refactor order: P5a → P5c → P5b → P5d (not a→b→c→d)

P5b (scanner + retry) is the deepest. Doing P5c (CLI migration) first removes the CLI from the scope of P5b, simplifying the scanner refactor (which currently has to support both surfaces). So order is:

1. **P5a** — renderer cleanup, no behavior change, build confidence
2. **P5c** — CLI scope-narrows (move legacy enum to a CLI-private module)
3. **P5b** — scanner + retry refactor (the hard one)
4. **P5d** — delete the App-side field

---

## Implementation Units

### Phase P5a — Renderer / helper cleanup

#### U-P5a-1. Migrate `ui/widgets/footer.rs` to registry-only reads

**Goal:** Remove the last direct `connection_state` read in the footer status line.

**Files:**
- Modify: `crates/vortix/src/ui/widgets/footer.rs`

**Approach:** the footer renders a single-line "connected to X" / "disconnected" / "connecting to X" summary. With multi-tunnel, summarize against `app.registry.primary()` + `app.registry.tunnel_count()`. When primary is `Some(profile_id)`, show "connected to <name>"; when tunnels exist but no primary, show "N tunnels active, no primary"; when zero tunnels, show "disconnected". The legacy read becomes a registry read.

**Test scenarios:**
- Empty registry → footer shows "disconnected"
- 1 tunnel primary → footer shows "connected to <name>"
- 2 tunnels, none primary → footer shows "2 tunnels active, no primary"
- 1 tunnel in Connecting state → footer shows "connecting to <name>"

**Verification:** existing footer tests should rewire; new tests for the multi-tunnel cases.

---

#### U-P5a-2. Drop legacy-fallback branches in `app/helpers.rs`

**Goal:** The helpers (`active_tunnel_count`, `active_tunnel_ids`, `is_profile_connected`, `is_profile_connecting`) all have dual-source code: "check registry first, fall back to `runtime.connection_state` if registry is empty". Post-Path-A (commit `39473eb`), the registry holds all transitional states. The fallback is dead code; remove it.

**Files:**
- Modify: `crates/vortix/src/app/helpers.rs`

**Approach:** delete the `match self.runtime.connection_state { ... }` fallback branches. Return values come solely from registry reads. The `connection_state_for_focused_profile(...)` accessor (if any) becomes a simple registry lookup.

**Test scenarios:** existing tests should pass unchanged because Path A made the registry the truthful source. If any test relied on the fallback (e.g., asserts behavior when only legacy state was set), update the test to populate the registry instead.

**Verification:** `cargo test --workspace` green; the `mirror_*_into_registry` tests cover the assertions.

---

#### U-P5a-3. Migrate `app/profile.rs` + `app/telemetry_poll.rs` reads

**Goal:** The 3 reads in `profile.rs` and the 1 in `telemetry_poll.rs` are status checks ("is this profile currently active?"). Replace with `app.registry.snapshot(profile_id).is_some_and(|s| s.state.is_connected())` or `app.is_profile_connected(idx)` from helpers.

**Files:**
- Modify: `crates/vortix/src/app/profile.rs`
- Modify: `crates/vortix/src/app/telemetry_poll.rs`

**Test scenarios:** profile-list iteration tests pass; telemetry polling continues to scope to the primary tunnel.

---

### Phase P5c — CLI scope narrowing

#### U-P5c-1. Move legacy `ConnectionState` to a CLI-private location

**Goal:** Stop the legacy enum leaking out of `vpn_runtime` (which the TUI uses). Relocate it to a CLI-only module so the App-side migration in P5b/P5d doesn't have to coordinate with the CLI's separate use of the enum.

**Files:**
- Move: `crates/vortix/src/vpn_runtime/connection_state.rs` → `crates/vortix/src/cli/state.rs` (or `crates/vortix/src/cli/blocking_state.rs`)
- Modify: `crates/vortix/src/vpn_runtime/mod.rs` — remove the `mod connection_state` + `pub use ConnectionState, DetailedConnectionInfo`
- Modify: `crates/vortix/src/vpn_runtime/connection.rs` (the CLI's blocking helpers) — import from `crate::cli::state` instead
- Modify: `crates/vortix/src/cli/commands.rs` — adjust imports

**Approach:** mechanical move. The CLI's `vortix_core::engine::DetailedConnectionInfo` import (the registry's shape) stays; the **legacy** `DetailedConnectionInfo` (in the moved file) is the CLI's own. Two structs with the same name in different modules; CLI imports one, App imports the other. After P5d the App side has only the engine one — no name clash.

**Test scenarios:** CLI integration tests (`tests/integration/`) continue to pass. The CLI build path doesn't reach into App; the move is invisible at the CLI surface.

**Verification:** `cargo test --workspace` + `cargo xtask check-platform-leak` (none of the boundary checks fire).

---

### Phase P5b — Scanner + retry refactor (the heavy one)

#### U-P5b-1. Per-profile retry state

**Goal:** Replace App-level retry singletons (`retry_count`, `retry_profile_idx`, `auto_reconnect_profile`) with a per-profile `HashMap<ProfileId, RetryState>`. Each tunnel's retry is independent.

**Files:**
- Modify: `crates/vortix/src/vpn_runtime/mod.rs` — drop the three singletons; add `pub retry_state: HashMap<ProfileId, RetryState>` (or store on App directly)
- New type: `RetryState { attempt: u32, profile_idx: usize, auto_reconnect: bool, scheduled_at: Option<Instant>, delay_secs: u64 }` in `crates/vortix/src/state/retry.rs` (new file)
- Modify: `crates/vortix/src/app/update.rs` — handle_connect_result failure branch + Tick loop both read/write the per-profile entry instead of the singletons
- Modify: `crates/vortix/src/app/connection.rs` — `cancel_connect`, `toggle_connection`, etc. read per-profile

**Approach:**
- On a connect failure: `app.retry_state.insert(profile_id, RetryState { attempt: prev+1, ... })`
- On Tick: iterate `app.retry_state.iter()`, fire the connect-retry for any entry whose `scheduled_at` is past
- On manual user disconnect/cancel: remove that profile's entry

**Test scenarios:**
- Connect A fails → A enters retry state. Connect B → B's retry state is independent of A. Both retry independently.
- Connect A fails, A retries 3 times, user manually disconnects A → A's retry state cleared.
- Two profiles in retry → both fire on their schedule; no global retry slot collision.

**Open question at implementation time:** The legacy code has a guard against double-firing retries when `pending_connect.is_some()`. Document the per-profile equivalent: "a profile in retry state has its own queue; doesn't block other profiles".

---

#### U-P5b-2. Per-profile scanner loop

**Goal:** Rewrite `handle_sync_system_state` (currently `update.rs:776+`) to loop over registry snapshots and reconcile each profile against the scanner's `Vec<ActiveSession>`. Today's logic operates on the single in-flight profile from `connection_state`; new shape operates on every registry entry.

**Files:**
- Modify: `crates/vortix/src/app/update.rs:776+` — rewrite `handle_sync_system_state`

**Approach (per-profile loop):**

```rust
fn handle_sync_system_state(&mut self, active: Vec<ActiveSession>) {
    for snap in self.registry.snapshot_all() {
        let match_session = active.iter().find(|s| s.name == snap.profile_id.as_str());

        match (&snap.state, match_session) {
            // Connecting → Connected promotion
            (Connection::Connecting { .. }, Some(session)) => {
                // build DetailedConnectionInfo from session, registry.set_connected(...)
            }
            // Connected refresh (details update)
            (Connection::Connected { details: existing, .. }, Some(session)) => {
                // refresh fields if changed, set_connected with new details
            }
            // Drop detection
            (Connection::Connected { .. } | Connection::Connecting { .. } | Connection::Disconnecting { .. }, None) => {
                // tunnel went away — kill it, mark Failed, maybe enter retry
            }
            // (Other states: leave alone)
            _ => {}
        }
    }

    // After the loop: handle the "no in-flight profile but scanner sees an active session"
    // case — the legacy adoption branch. For each unmatched session, decide whether to
    // adopt it into the registry (typically yes — external `wg-quick up` ran).
    for session in active.iter() {
        let id = ProfileId::new(&session.name);
        if self.registry.snapshot(&id).is_none() && self.runtime.profiles.iter().any(|p| p.name == session.name) {
            // Adopt: set_connected with the session's details.
        }
    }
}
```

**Test scenarios:**
- Single Connected tunnel, scanner reports its session → details refresh, no state change
- Connecting tunnel + scanner reports its session → promote to Connected
- Connected tunnel, scanner reports no session → drop detected, set_failed, enter retry
- Externally-started VPN → adopted on next scanner tick
- Multiple Connected tunnels, scanner reports two of three → the third drops; others unaffected
- Two Connecting tunnels race → both promote independently

**Verification:** existing scanner tests pass; new tests for the multi-Connected and adoption cases.

---

#### U-P5b-3. Migrate write sites in `connection.rs` + `update.rs`

**Goal:** Replace every `runtime.connection_state = ConnectionState::...` with a `registry.set_*` call. The mirror helpers become the direct write path (rename or inline).

**Files:**
- Modify: `crates/vortix/src/app/connection.rs` — `toggle_connection`, `connect_profile_inner`, `disconnect`, etc.
- Modify: `crates/vortix/src/app/update.rs` — Message handlers (ConnectResult, DisconnectResult, etc.)

**Approach:** for each `runtime.connection_state = X` assignment, find the equivalent `registry.set_*` and call it. Drop the assignment. The state machine semantics move from runtime-level to registry-level.

**Special cases:**
- `pending_connect: Option<usize>` is App-level orchestration (queue a connect after disconnect completes). This is NOT registry state; it stays on App.
- `retry_state` is per-profile (per U-P5b-1); registry doesn't own it.

**Test scenarios:** existing connect/disconnect tests pass; the mirror tests can be simplified (no need to assert the mirror — registry IS the source of truth).

---

### Phase P5d — Final cleanup

#### U-P5d-1. Delete `connection_state` field + the file

**Goal:** With all reads and writes migrated, remove the field and the file.

**Files:**
- Modify: `crates/vortix/src/vpn_runtime/mod.rs` — drop `pub connection_state: ConnectionState` from `VpnRuntime`
- Modify: `crates/vortix/src/app/connection.rs` — delete the `mirror_*_into_registry` helpers (no longer called)
- Modify: `crates/vortix/src/app/helpers.rs` — remove imports of `ConnectionState`
- Delete: `crates/vortix/src/vpn_runtime/connection_state.rs` (after P5c moved the CLI's copy)

**Test scenarios:** every existing test still passes (the mirror tests now assert the registry directly).

**Verification:** `grep -rn 'connection_state' crates/vortix/src/` returns only CLI / vpn_runtime/connection.rs uses (CLI-private after P5c). Run the full CI parity set.

---

## Scope Boundaries

### Deferred to follow-up work

- **Auto-reconnect policy edge cases.** What happens when a profile auto-reconnects and its connect fails? Today the legacy logic would retry. Document the per-profile retry interaction. Defer the full state machine of "retry-of-auto-reconnect-of-retry" to a separate consideration.
- **CLI multi-tunnel support.** P5c keeps CLI single-tunnel by design (D-3). If the user later wants `vortix up A B` to bring up two tunnels simultaneously, that's a separate feature.
- **Daemon engine wiring (D1 from plan 001).** P5 doesn't depend on D1. The registry stays in-process. When D1 lands, the registry will move into the daemon process; that's orthogonal to P5.

### Outside this plan

- Anything requiring `EngineHandle::Local` actor wiring (plan 001 §9 D1).
- Renaming the public surface of the registry. Keep `TunnelRegistry`, `RegistryEntry`, etc. names stable.

---

## Verification Strategy

**Per-unit verification** is in each unit's "Verification" field.

**Cross-cutting verification:**

1. **Mirror-test invariant (P5-R8):** Every test in `crates/vortix/src/app/tests.rs` that asserts mirror semantics must keep passing through P5a → P5d. If a test asserts both the legacy state and the registry, drop the legacy assertion.

2. **Binary-size budget (P5-R7):** Measure `du -h target/release/vortix` before P5a starts and after P5d lands. Delta must be ≤ 2MB (overall plan 001 budget; P5 specifically should NEGATIVE delta because we're deleting code).

3. **CI parity (every commit):** Per `docs/ci-parity.md`, run the full set before every push. P5 will burn cycles if half-migrations land.

4. **Manual smoke (after P5b):** The scanner refactor changes behavior. Manual checklist:
   - Connect one WG profile, disconnect; observe sidebar/header transitions
   - Connect WG-A, connect OVPN-B with disjoint AllowedIPs; both up
   - Externally `wg-quick down wg-A`; observe drop detection + auto-reconnect
   - `pkill -9 openvpn` on B; observe drop detection
   - Connect A, A fails handshake (use a profile with a bad endpoint); observe retry behavior
   - Simultaneously: A retrying, B successfully connecting; A's retry doesn't interfere with B

5. **Boundary checks (every commit):** `cargo xtask check-platform-leak` / `check-protocol-leak` / `check-subprocess` / `check-no-shell-regressions` must all pass.

---

## System-Wide Impact

- **`VpnRuntime` shape change:** drops `connection_state`, adds `retry_state: HashMap<ProfileId, RetryState>` (or move retry to App).
- **API surface:** the `mirror_*_into_registry` helpers go away. Callers route through `registry.set_*` directly.
- **Test count:** ~12 mirror tests stay green (they assert registry semantics, which is what stays). Possibly fewer total — some can collapse.
- **Lines of code:** P5 is net DELETION. The legacy file goes away, the mirror helpers go away, the dual-source helpers in `app/helpers.rs` simplify. Rough estimate: -300 net lines.
- **Renderer call sites:** unchanged. Renderers already read from registry; this plan finishes the writers.

---

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scanner refactor (P5b) introduces a drop-detection regression | Med | High | Comprehensive scanner test coverage before the refactor; manual smoke per Verification §4 |
| Per-profile retry policy disagrees with user expectation | Low | Med | Document the policy choice in the unit; if a user complaint arrives, surface as a setting |
| CLI module reorg (P5c) breaks an integration test | Low | Low | `tests/integration/*.sh` test the CLI surface, not internal module paths |
| Mid-migration commit leaves the branch in a half-state | Med | Med | Land each phase as its own commit; each commit must keep all tests green and the full CI parity passing |
| Auto-reconnect on a dropped secondary surprises the user | Med | Med | D-2 default is per-profile auto-reconnect; if surprising, surface the auto-promote banner pattern for drop events |

**Dependencies between units:**

```
P5a (renderer cleanup) ──┐
                         ├──> P5b (scanner + retry refactor) ──> P5d (delete field)
P5c (CLI move out)    ──┘
```

P5a and P5c are independent and can land in either order. P5b depends on both (it's easier to refactor the scanner when the CLI scope is already narrowed and the renderers are clean). P5d is trivial after P5a + P5b + P5c.

---

## Alternative Approaches Considered

- **Keep the mirror approach forever.** Rejected — dual sources of truth keep producing bugs (the session caught 5 separate mirror-omission bugs across `e96a48a` → `903662e`). Single source of truth pays for itself.
- **Convert the registry to async actors (full D1).** Rejected as part of P5 — that's its own plan (#001 §9 D1). The registry stays sync; P5 doesn't depend on the actor model.
- **Make `ConnectionState` a deprecated alias** that internally consults the registry. Rejected — adds indirection without removing the surface; future readers still see "is there a connection_state?" and wonder why.

---

## Documentation Plan

- **`docs/manual-testing/multi-connection.md`** (referenced by `CLAUDE.md`): add post-P5b manual checks for scanner / retry / auto-reconnect per-profile behavior.
- **`vpn_runtime/connection_state.rs` deletion** is logged in the P5d commit message + this plan's reference.
- **`CLAUDE.md`** — drop the historical reference to `state/connection.rs` if any; the legacy enum is gone after P5d.

---

## Open Questions

Resolve at execution time:

1. **D-1 retry settings:** should per-profile retry use the existing `connect_max_retries` / `connect_retry_base_delay_secs` globally, or grow per-profile overrides? Default: keep the globals as-is, apply per-profile.
2. **D-2 auto-reconnect:** is the per-profile default correct, or should it be primary-only? Verify with user before P5b ships.
3. **D-4 scanner adoption policy:** when scanner sees a profile in the catalog but not in the registry, do we auto-adopt? Default: yes (mirrors current legacy behavior). Off if it causes test churn.
4. **Removed-profile-while-active edge case:** what if a profile is deleted from disk while its registry entry is Connected? Today the FSM stays Connected. Post-P5, should the scanner's profile-resolver returning `None` trigger Disconnecting? Defer to a follow-up bug if/when reproduced.

---

## References

- Plan 001: `docs/plans/2026-05-28-001-feat-multi-connection-plan.md` (U6 Stage B + U7 + R-IDs)
- Path A landing: commit `39473eb` (multi-state mirror foundation)
- Auto-promote banner: commit `90b62e8` (the render path that was missing)
- Mirror-state legacy bookkeeping shape: commits `e96a48a` / `90a6c7c` / `e3fd9c2` / `462636e` / `903662e`
- Branch state at P5 start: `feat/multi-connection` HEAD = `90b62e8`
