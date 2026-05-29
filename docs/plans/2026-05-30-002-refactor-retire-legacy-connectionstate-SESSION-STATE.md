---
plan: docs/plans/2026-05-30-002-refactor-retire-legacy-connectionstate-plan.md
status: not_started
created: 2026-05-30
branch: feat/multi-connection
branch_head_at_plan_time: 90b62e8
---

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
