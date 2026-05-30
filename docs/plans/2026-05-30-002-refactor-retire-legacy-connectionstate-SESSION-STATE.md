---
plan: docs/plans/2026-05-30-002-refactor-retire-legacy-connectionstate-plan.md
status: completed
created: 2026-05-30
last_updated: 2026-05-30
branch: feat/multi-connection
branch_head_at_plan_time: 90b62e8
branch_head_at_completion: 09040ca
---

## Progress (last checkpoint: 2026-05-30, commit `b321abe`)

| Stage | Status | Commit |
|---|---|---|
| P5a — renderer/helper cleanup | DONE | `6b6ec76` — `refactor(app): drop legacy ConnectionState fallback reads (P5a)` |
| P5b U-P5b-1 — per-profile retry/auto-reconnect | DONE | `b321abe` — `refactor(retry): per-profile retry/auto-reconnect state` |
| P5b U-P5b-2 — per-profile scanner loop + auto-adopt | DONE | `a12256c` — `refactor(scanner): per-profile registry loop with auto-adopt` |
| P5b U-P5b-3 + P5d — delete legacy field + CLI refactor | DONE | `09040ca` — `refactor: retire legacy connection_state field` |
| P5c — CLI scope narrowing | FOLDED into P5d | `09040ca` (CLI helpers take profile/details params; no field to relocate around) |

Also landed in-session (not P5):
- `6392a9d` — `ux(dashboard): pad panel borders for breathing room` (uncommitted at session start)

### P5c divergence (worth re-reading before resuming)

The plan's D-5 order (P5a → P5c → P5b → P5d) was changed mid-session.
Doing P5c before P5b would have required `vpn_runtime` to depend on
`cli` because the CLI's blocking helpers in `vpn_runtime/connection.rs`
write to the same `VpnRuntime.connection_state` field App uses. Per
D-5's stated rationale ("narrowing scope for P5b"), this turned out
not to apply — the TUI scanner (P5b U-P5b-2) and the CLI blocking
path are separate execution paths, so P5b doesn't need P5c to be done
first. P5c is now folded into P5d: after P5b removes App-side reads
and writes, the legacy enum has only one user (the CLI's blocking
helpers in `vpn_runtime/connection.rs` and `cli/commands.rs`). At that
point P5d relocates it to `cli/state.rs` as a CLI-private type as it
deletes the App-side field.

### Decisions confirmed with the user (2026-05-30)

- **D-2 auto-reconnect default:** per-profile (each Connected profile
  registers its own auto-reconnect; only the dropped one reconnects).
  Implemented in `b321abe`.
- **D-4 scanner adoption policy:** auto-adopt (mirrors current legacy
  behavior). To be applied in U-P5b-2.

### Status: P5 complete (2026-05-30, `09040ca`)

All P5 stages are landed. The legacy `connection_state` field on
`VpnRuntime` has been deleted. The App layer's single source of
truth for active VPN state is now `TunnelRegistry`. The CLI's
blocking helpers carry their own local `ConnectionState` view (one
process, one tunnel) without sharing state.

### U-P5b-3 + P5d work (entangled, ~50 sites)

**Reads to migrate (~30 sites):** every `&self.runtime.connection_state`
read in `crates/vortix/src/app/{update.rs,connection.rs}` becomes a
registry query. Common patterns:
- `matches!(connection_state, Disconnected)` → `self.active_tunnel_count() == 0`
- `if let Connecting { profile, .. } = ...` → iterate
  `registry.snapshot_all()` for the profile in Connecting state
- `&self.runtime.connection_state` passed to
  `build_active_tunnels_from_state` → rewrite the builder to read
  from `registry.snapshot_all()` directly

**Writes to delete (~10 sites):** every `runtime.connection_state = X`
in App code. The `mirror_*_into_registry` helpers already do the
registry side; the legacy assignments are redundant once reads no
longer consult them.

**Mirror helpers to delete:** `App::mirror_{connect,disconnect,
connecting,disconnecting,failed}_into_registry`. After write-site
migration these have no callers from production code; test helpers
need to update too (call `registry.set_*` directly or use a thin
test-only adapter).

**CLI refactor (vpn_runtime/connection.rs):** the CLI's blocking
helpers (`connect_and_wait`, `disconnect_and_wait`, `scan_status`)
read `self.connection_state`. Two clean options:
1. Make them local-state-based: each invocation builds + returns a
   `ConnectResult`/`DownData` from local variables; no shared field
   on `VpnRuntime`. `disconnect_and_wait` needs a profile-name arg
   so it doesn't need to discover the "current" profile.
2. Add a `TunnelRegistry` field to `VpnRuntime` and drive the CLI
   through it. Bigger refactor but symmetric with the TUI.

Either path lets `VpnRuntime` shed its `connection_state` field.

**Type relocation (D-3 + folded P5c):** after the App side stops
using `ConnectionState`/`DetailedConnectionInfo`, the only remaining
users are the CLI's blocking helpers (vpn_runtime/connection.rs,
cli/commands.rs). Move the type to `crates/vortix/src/cli/state.rs`
and have the CLI helpers import from there. Delete
`crates/vortix/src/vpn_runtime/connection_state.rs`.

**Test plumbing:** the test helpers in `app/tests.rs` and
`tests/integration.rs` (`set_connected`, `set_connecting`,
`set_disconnecting`) call the `mirror_*_into_registry` family. After
P5d deletes those, the helpers call `registry.set_*` directly with
the same engine-factory pattern used in the existing mirror
implementations (see `placeholder_engine_for_profile` and
`extract_allowed_ips` in `app/connection.rs`).

### Primitives ready for resume

These exist on the branch and don't need to be rebuilt:

- `Engine::seed_{connected, disconnected, connecting, disconnecting, failed}_state`
  (crates/vortix/src/vortix_core/engine/fsm.rs)
- `TunnelRegistry::set_{connected, disconnected, connecting, disconnecting, failed}`
  (crates/vortix/src/vortix_core/engine/registry.rs)
- `App::mirror_*_into_registry` (still callable from tests; to be
  deleted in P5d)
- `App::refresh_registry_from_session` (new in U-P5b-2 — pushes
  session details to registry without consulting legacy state)
- `App::primary_state()` (not yet — add as part of U-P5b-3 reads
  migration)
- `App::is_profile_active`, `is_profile_connected`, `is_profile_connecting`,
  `active_tunnel_count`, `active_tunnel_ids` (registry-only after P5a)
- `runtime.retry_state: HashMap<ProfileId, RetryState>` (per-profile
  retry from U-P5b-1)
- `Message::RetryConnect { idx, attempt }` (unchanged signature)


# Session state — P5: retire legacy `ConnectionState`

## Start here next session

1. Read [`2026-05-30-002-refactor-retire-legacy-connectionstate-plan.md`](./2026-05-30-002-refactor-retire-legacy-connectionstate-plan.md) — the implementation units, key technical decisions, and order are all there.
2. Verify the branch is at `feat/multi-connection` HEAD (use `git log -1 --oneline`; commit `90b62e8` is the auto-promote-banner-render commit, the last of the foundation work).
3. Stay on `feat/multi-connection`. Do not branch off main. This work is bundled into PR #1 (multi-tunnel + CI restructure + test automation + system-dep reduction + multi-state mirror + P5).
4. Pre-push command set (mandatory, per `docs/ci-parity.md`):
   ```
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
   cargo xtask check-subprocess
   cargo xtask check-platform-leak
   cargo xtask check-protocol-leak
   cargo xtask check-no-shell-regressions
   cargo-deny check
   ```
   "Passes locally" is a claim that requires the full command output, not a verbal assertion. CI burned 4 cycles in earlier sessions skipping subsets.

## Recommended execution order

Per the plan's §"Implementation Units" the units land in this order — P5a → P5c → P5b → P5d (NOT a→b→c→d). The reason is in plan §"D-5": doing C before B narrows the scope B has to refactor.

| Stage | Units | Approx size | Risk |
|---|---|---|---|
| P5a | U-P5a-1 (footer), U-P5a-2 (helpers drop fallback), U-P5a-3 (profile + telemetry_poll reads) | ~15 sites | Low — no behavior change |
| P5c | U-P5c-1 (move legacy enum to `cli/state.rs`) | ~12 sites | Low — mechanical move |
| P5b | U-P5b-1 (per-profile retry), U-P5b-2 (scanner per-profile loop), U-P5b-3 (write-site migration) | ~40 sites | **High** — real behavioral change |
| P5d | U-P5d-1 (delete field + file + mirror helpers) | ~5 sites | Trivial after P5b |

Commit per unit. Keep tests green at every commit boundary. Don't push half-migrated work.

## Hard constraints (do not violate)

- **Branch:** stay on `feat/multi-connection`. Bundled into PR #1.
- **Dependency pins:** `rand = "0.8"` and `sha2 = "0.10"` in `crates/vortix/Cargo.toml` are PINNED (per `CLAUDE.md`).
- **Mirror tests stay green:** the 12 tests under "What's already shipped" in the plan encode the registry's behavioral contract. The plan's P5-R8 requires they keep passing through every commit.
- **No new shell-outs:** `cargo xtask check-no-shell-regressions` blocks accidentally calling `curl`/`ping`/`which`/etc.

## What's already plumbed (don't rebuild)

The prior session built the mirror foundation P5 dismantles. Don't reinvent these primitives:

- `Engine::seed_{connected, disconnected, connecting, disconnecting, failed}_state` — `crates/vortix/src/vortix_core/engine/fsm.rs`
- `TunnelRegistry::set_{connected, disconnected, connecting, disconnecting, failed}` — `crates/vortix/src/vortix_core/engine/registry.rs`
- `App::mirror_{connect, disconnect, connecting, disconnecting, failed}_into_registry` — `crates/vortix/src/app/connection.rs`

P5b's write-site migration replaces the mirror calls with direct `registry.set_*` calls (same primitives, called directly instead of via mirror). P5d then deletes the mirror helpers.

## Key technical decisions (defaults to follow)

From plan §"Key Technical Decisions":
- **D-1:** per-profile retry state (`HashMap<ProfileId, RetryState>` on App)
- **D-2:** per-profile auto-reconnect (symmetric with D-1)
- **D-3:** CLI stays single-tunnel — move the legacy enum to a CLI-private module rather than migrate the CLI
- **D-4:** scanner becomes a per-profile loop over registry snapshots
- **D-5:** execution order P5a → P5c → P5b → P5d

If any of these prove wrong at implementation time, document the divergence in the commit message.

## Open questions (resolve at execution time, not blocking)

Per plan §"Open Questions":

1. Per-profile retry config (settings vs hardcoded) — keep settings-driven by default
2. Auto-reconnect default (per-profile vs primary-only) — confirm with user before P5b ships
3. Scanner adoption policy (auto-adopt externally-started VPNs vs require explicit catalog entry) — default yes
4. Deleted-profile-while-Connected edge — defer to a follow-up bug if it surfaces

## After P5 lands

Resume the parent task list:
- **#30 (pending):** Help overlay missing multi-tunnel keybindings — small. Land right after P5.
- **#26 (pending):** Plain-English audit across logs/toasts/CLI — separate, focused pass.
