---
date: 2026-05-24
title: "refactor!: Split vortix into a Cargo workspace"
status: active
type: refactor
origin: docs/brainstorms/2026-05-24-cargo-workspace-split-requirements.md
related_brainstorms:
  - docs/brainstorms/2026-05-24-commandrunner-port-requirements.md
  - docs/brainstorms/2026-05-24-engine-fsm-event-journal-requirements.md
  - docs/brainstorms/2026-05-24-tunnel-trait-enum-dispatch-requirements.md
  - docs/brainstorms/2026-05-24-capability-ports-platform-requirements.md
  - docs/brainstorms/2026-05-24-config-profile-secret-stack-requirements.md
ideation: docs/ideation/2026-05-24-vortix-architecture-ideation.md
---

# refactor!: Split vortix into a Cargo workspace

## Summary

Migrate vortix from a single crate at the repository root to a flat matklad-style Cargo workspace with eight day-one members under `crates/`. The user-facing binary stays named `vortix` and continues to be the sole crates.io artifact; the seven internal crates are unpublished (`publish = false`, `version = "0.0.0"`). This is a pure structural refactor — no behavior changes — adopting a **minimal-relocation strategy**: only the platform layer and `src/config.rs` actually move out of the main binary crate today, with the other four internal crates (`vortix-core`, `vortix-process`, `vortix-protocol-wireguard`) shipping as empty stub crates that subsequent PRs (ideas 1, 3, 5, 6, 7) populate. release-plz and cargo-dist configurations learn the workspace topology while preserving every external-facing distribution path. The commit is `refactor!: split into Cargo workspace` to signal a source-layout breaking change (minor bump pre-1.0).

---

## Problem Frame

Vortix today lives as a single crate `vortix` at `Cargo.toml` (repo root) with 72 Rust files under `src/` covering engine logic, TUI rendering, CLI dispatch, platform-specific code, configuration, and shared utilities. Every architectural decision — "the TUI must not reach into platform internals," "the engine must not assume tokio," "the config module must not import ratatui" — exists only as good intention because nothing enforces the boundary. Crate boundaries are the only architectural fence Rust enforces automatically; without them, every subsequent refactor in the 6-PR migration would have to invent its own discipline.

The v0.3.0 and v1.0 roadmap commitments (daemon mode, lifecycle hooks, profile groups, Windows, multi-protocol, split tunneling, audit logging, config encryption, team management) each multiply the platform/protocol matrix and the engine/UI separation requirements. Without a workspace, each one adds files under `src/` that further fuse the layers; with one, each becomes a focused PR that lands code into the right crate.

This refactor delivers no user-visible feature. It delivers the *boundary system* that the next five architectural PRs occupy. `cargo install vortix`, `brew upgrade vortix`, `npm update -g @harry-kp/vortix`, `yay -Syu vortix-bin`, and `nix flake update` continue to install the same binary at the same name from the same crate.

---

## System-Wide Impact

- **End users:** Zero observable change. The binary name, version semantics, install command, and runtime behavior are all preserved.
- **Distribution pipeline:** release-plz, cargo-dist 0.30.3, Homebrew tap `Harry-kp/homebrew-tap`, npm scope `@harry-kp`, AUR (externally maintained), Nix flake (externally maintained) all keep working. release-plz config gains no new packages; cargo-dist's `members` updates to point at the new binary crate location.
- **Contributors:** "Where does this code live?" gains a mechanical answer once the migration completes. Today, contributors merging in this PR will see most code still under `crates/vortix/src/`; subsequent PRs (ideas 1, 3, 5, 6, 7) progressively relocate code into the proper crates as their refactors land.
- **Downstream library consumers:** Today there are none. After this PR, `crates/vortix-core/` exists as an empty stub ready to be the embedding API surface; first real consumers arrive with idea 3 (FSM types + EngineHandle).
- **CI:** Builds switch from `cargo build` (single crate) to `cargo build --workspace`. Per-crate test binaries shrink CI time. The CI subprocess-lint runner from idea 1's R12 ships in idea 1's PR, not this one — `xtask` is scaffolded here.
- **Idea 1's brainstorm doc:** Receives a small addendum stating that after this PR lands first, idea 1's destination paths are `crates/vortix-core/src/ports/process.rs` (trait) and `crates/vortix-process/src/` (impls). No other revision to idea 1's substance.

---

## Output Structure

```
Cargo.toml                    (virtual workspace manifest — no [package])
rust-toolchain.toml
release-plz.toml              (updated: package path)
dist-workspace.toml           (updated: members = ["cargo:crates/vortix"])
cliff.toml                    (unchanged)
deny.toml                     (unchanged)
rustfmt.toml                  (unchanged)
flake.nix                     (unchanged — externally referenced)
README.md                     (small update: workspace layout note)
ROADMAP.md / RELEASING.md     (small update: workspace context)
CHANGELOG.md                  (release-plz updates on merge)

crates/
├── vortix-core/              # empty stub — populated by ideas 3, 5, 6, 7
│   ├── Cargo.toml            # publish = false, version = "0.0.0"
│   └── src/lib.rs            # //! Placeholder; see docs/ideation/...
├── vortix-process/           # empty stub — populated by idea 1
│   ├── Cargo.toml            # publish = false, version = "0.0.0"
│   └── src/lib.rs
├── vortix-platform-macos/    # populated NOW from src/platform/macos/
│   ├── Cargo.toml            # publish = false, version = "0.0.0"
│   └── src/
│       ├── lib.rs
│       ├── dns.rs            (from src/platform/macos/dns.rs)
│       ├── firewall.rs       (from src/platform/macos/firewall.rs)
│       ├── interface.rs      (from src/platform/macos/interface.rs)
│       └── network.rs        (from src/platform/macos/network.rs)
├── vortix-platform-linux/    # populated NOW from src/platform/linux/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── dns.rs            (from src/platform/linux/dns.rs)
│       ├── firewall.rs       (from src/platform/linux/firewall.rs)
│       ├── interface.rs      (from src/platform/linux/interface.rs)
│       └── network.rs        (from src/platform/linux/network.rs)
├── vortix-protocol-wireguard/ # empty stub — populated by idea 5
│   ├── Cargo.toml
│   └── src/lib.rs
├── vortix-config/             # populated NOW from src/config.rs
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs             (from src/config.rs verbatim)
│       └── (idea 7 later splits this further)
├── vortix/                    # the user-facing binary crate
│   ├── Cargo.toml             # [package] name = "vortix", publish = true
│   └── src/
│       ├── main.rs            (from src/main.rs)
│       ├── lib.rs             (from src/lib.rs — re-exports for tests)
│       ├── app/               (from src/app/)
│       ├── cli/               (from src/cli/)
│       ├── core/              (from src/core/ — moves to other crates in later PRs)
│       ├── engine/            (from src/engine/ — moves to vortix-core in idea 3)
│       ├── state/             (from src/state/ minus ui.rs)
│       ├── tui/               (renamed from src/ui/ — TUI-specific naming)
│       │   ├── mod.rs
│       │   ├── state.rs       (from src/state/ui.rs)
│       │   ├── theme.rs       (from src/theme.rs)
│       │   ├── dashboard/
│       │   ├── overlays/
│       │   ├── widgets/
│       │   └── helpers.rs
│       ├── platform.rs        (thin re-export over the platform crates)
│       ├── vpn/               (from src/vpn/ — moves to vortix-config in idea 7)
│       ├── event.rs           (TUI event loop — stays in binary)
│       ├── message.rs         (TEA-style messages — stays in binary)
│       ├── constants.rs       (mixed; split deferred to later PRs)
│       ├── logger.rs          (stays in binary)
│       └── utils.rs           (god-file; splitting deferred)
└── xtask/                     # build chores
    ├── Cargo.toml             # publish = false
    └── src/main.rs            # subcommand dispatch; minimal --help today
tests/
├── cli_integration.rs        (relocated relative paths inside binary crate context)
└── integration.rs

(unchanged elsewhere)
.github/workflows/
.gitignore
assets/
demo.tape
flake.lock
LICENSE
scripts/
SECURITY.md
CODE_OF_CONDUCT.md
CONTRIBUTING.md
```

This structure is a scope declaration showing the day-one shape. The per-unit `**Files:**` sections below are authoritative for each file move.

---

## Key Technical Decisions

- **Minimal-relocation strategy.** Of 72 source files, only the ~10 platform files and `src/config.rs` actually leave the main binary crate today. The other four internal crates (`vortix-core`, `vortix-process`, `vortix-protocol-wireguard`, plus the `xtask` build crate) ship as empty stubs. Subsequent PRs (ideas 1, 3, 5, 6, 7) move code into them. **Rationale:** keeps this PR's diff dramatically more reviewable (most file moves are `git mv` into `crates/vortix/src/`), preserves the working tree's compilability, and lets each later refactor land into a clean target without colliding with this structural move.
- **Binary crate named `vortix` exactly.** Non-negotiable for distribution compatibility — `cargo install vortix`, the Homebrew formula, the npm package, the AUR package all reference this name. (Origin: brainstorm R3.)
- **Only `vortix` published to crates.io.** Internal crates carry `version = "0.0.0"` and `publish = false` per matklad's discipline trick. release-plz config keeps its single `[[package]] name = "vortix"` entry. (Origin: brainstorm R4, R8.)
- **`src/ui/` becomes `crates/vortix/src/tui/`.** The current `ui` name is ambiguous (could mean GUI, web UI, etc.); `tui` is precise. This rename happens IN this PR because it travels naturally with the relocation. **Risk:** a small additional diff vs. pure-move. **Mitigation:** rename is purely cosmetic; CI catches any missed reference at compile time.
- **`src/state/ui.rs` → `crates/vortix/src/tui/state.rs`.** TUI-specific state belongs with the TUI module. Other `src/state/*.rs` files (connection, killswitch, profile) stay at `crates/vortix/src/state/` for this PR; they relocate to `vortix-core` in ideas 3/6/7.
- **`src/theme.rs` → `crates/vortix/src/tui/theme.rs`.** Same TUI-specific rationale.
- **`src/vpn/mod.rs` stays in `crates/vortix/src/vpn/`.** Currently contains profile import code that belongs in `vortix-config` per idea 7; relocating it here as a sub-decision is out of scope. Idea 7's PR moves it.
- **Workspace `[workspace.dependencies]` for shared deps and `[workspace.lints]` for shared lints.** Each crate's `Cargo.toml` uses `{ workspace = true }`. (Origin: brainstorm R6, R7.)
- **Workspace MSRV `rust-version = "1.75"` declared once at the root.** Unified across all crates. (Origin: brainstorm Dependencies section.)
- **release-plz keeps single `[[package]]` entry; internal crates are filtered out by their `publish = false` flag.** No multi-package release machinery introduced. (Origin: brainstorm R8.)
- **cargo-dist 0.30.3 stays at the same version.** Only `dist-workspace.toml`'s `members` field updates to `["cargo:crates/vortix"]`. All other settings (six target triples, three installers, tap, npm-scope, publish-jobs, install-path) unchanged. (Origin: brainstorm R9.)
- **Conventional-commit form `refactor!: split into Cargo workspace`.** Pre-1.0, `refactor!:` triggers a minor bump per `release-plz.toml` semver rules in `RELEASING.md`, signaling a source-layout breaking change without bumping past 1.0. (Origin: brainstorm R15.)
- **`xtask` ships with a minimal subcommand-dispatch scaffold.** Today: `cargo xtask --help` lists future subcommands; `cargo xtask check-subprocess` is a TODO stub returning OK so idea 1's PR can drop its real implementation in. The subprocess-lint runner is **not** functional in this PR. (Origin: this plan's decision; idea 1's brainstorm R12.)
- **Tests dir (`tests/`) stays at the repo root,** moving its references to point at the new binary crate location. cargo's integration-test discovery for a binary crate works from the crate root, so `tests/` lives at `crates/vortix/tests/`. (Origin: this plan's decision; cargo convention.)
- **Existing `[lints.rust]` `unsafe_code = "warn"` and `[lints.clippy]` `all = warn pedantic = warn` preserved verbatim** in `[workspace.lints]`. No tightening of lints in this PR. (Origin: brainstorm Cargo.toml grounding.)
- **`README.md`, `ROADMAP.md`, `RELEASING.md` updated** with a brief workspace-layout note in this PR. CHANGELOG.md update is handled automatically by release-plz on merge.
- **Tree must be compilable at every commit.** This PR may land as a single atomic commit; ce-work decides commit boundaries. The intermediate-step compilability is verified by the final `cargo build --workspace` + `cargo test --workspace` passing in CI; intermediate working-tree states are not required to compile so long as the final state does.

---

## Implementation Units

### U1. Create the workspace skeleton (empty crates + root manifest)

**Goal:** Stand up the directory structure and virtual root manifest before any code moves. The workspace builds (with empty crates) before files relocate.

**Requirements:** R1, R2, R6, R7, R8, R10

**Dependencies:** None — this is the foundation.

**Files:**
- Create `Cargo.toml` (virtual workspace manifest at repo root — overwrites current single-package `Cargo.toml`)
- Create `crates/vortix-core/{Cargo.toml, src/lib.rs}`
- Create `crates/vortix-process/{Cargo.toml, src/lib.rs}`
- Create `crates/vortix-platform-macos/{Cargo.toml, src/lib.rs}`
- Create `crates/vortix-platform-linux/{Cargo.toml, src/lib.rs}`
- Create `crates/vortix-protocol-wireguard/{Cargo.toml, src/lib.rs}`
- Create `crates/vortix-config/{Cargo.toml, src/lib.rs}`
- Create `crates/vortix/Cargo.toml` (the binary crate manifest — fields migrated from current root `Cargo.toml`)
- Create `crates/xtask/{Cargo.toml, src/main.rs}`
- Stash today's `Cargo.toml` content so its `[package]` block, `[dependencies]`, `[lints.*]`, `[profile.*]` move into the new `crates/vortix/Cargo.toml`

**Approach:**
- Root `Cargo.toml` becomes virtual: `[workspace] members = ["crates/*"]`, `[workspace.package] rust-version = "1.75"`, `[workspace.dependencies]` with the existing ratatui, crossterm, time, color-eyre, clap, clap_complete, serde, serde_json, toml, dirs, unicode-width, open, urlencoding entries; `[workspace.lints.rust] unsafe_code = "warn"`, `[workspace.lints.clippy]` with the existing pedantic/all entries; `[profile.release]` and `[profile.dist]` blocks moved verbatim.
- Each internal crate's `Cargo.toml`: `[package] name = "<crate>", version = "0.0.0", edition = "2021", rust-version.workspace = true, publish = false`. `[lints] workspace = true`. Empty `[dependencies]` for stub crates.
- `crates/vortix/Cargo.toml`: full `[package]` block migrated from today's root manifest (name, version, description, license, keywords, categories, repository, homepage, documentation, authors, readme, exclude). `publish = true`. `[[bin]] name = "vortix" path = "src/main.rs"`. `[dependencies]` references workspace deps via `{ workspace = true }`. `[target.'cfg(unix)'.dependencies] libc = "0.2"` preserved.
- Each `lib.rs` stub for empty internal crates: a single `//!` doc comment naming the crate's future home, pointing at the ideation doc for context. `vortix-platform-{macos,linux}` get `//! macOS/Linux platform adapters.` `vortix-config` gets `//! Vortix configuration management.` The two non-empty platform crates ship with their relocated files in U3.
- `crates/xtask/src/main.rs`: a minimal `clap`-based CLI accepting subcommands (`check-subprocess` as a stub returning OK, plus `--help`).
- The `exclude` field on `crates/vortix/Cargo.toml` adjusts paths: today's `target/*`, `scripts/*` paths are repo-root-relative; per-crate `exclude` is relative to that crate, so adjust to `../../target/*`, `../../scripts/*` or drop entries that aren't relevant to the binary crate's package.

**Patterns to follow:**
- `release-plz.toml` `[workspace]` block stays; just confirms the workspace exists.
- matklad "Large Rust Workspaces" pattern: flat `crates/`, virtual root, version `0.0.0` on internal crates, folder-name-equals-crate-name.
- Existing `[profile.dist] inherits = "release" lto = "thin"` stays.

**Test scenarios:**
- *Test expectation: none — pure scaffolding; behavioral tests come with later units.* `cargo metadata` is the only verification.
- Verification: after U1 lands, `cargo metadata --no-deps --format-version 1 | jq '.workspace_members | length'` returns 8.
- Verification: `cargo build --workspace` succeeds (all crates empty so this is fast). The `vortix` binary builds with no source files yet — expected `[[bin]] path` error is suppressed because U2 lands main.rs.

**Verification:** `ls crates/` lists exactly 8 directories. The virtual root `Cargo.toml` contains no `[package]` block.

---

### U2. Move the binary crate's source tree (most of `src/`)

**Goal:** Relocate the bulk of the existing `src/` tree into `crates/vortix/src/` so the binary crate has its code. This is the largest file-move step.

**Requirements:** R1, R10, R11, R12, R13

**Dependencies:** U1

**Files (moves; use `git mv` to preserve history):**
- `src/main.rs` → `crates/vortix/src/main.rs`
- `src/lib.rs` → `crates/vortix/src/lib.rs`
- `src/app/` (8 files) → `crates/vortix/src/app/`
- `src/cli/` (5 files) → `crates/vortix/src/cli/`
- `src/core/` (7 files) → `crates/vortix/src/core/` (these later relocate to `vortix-core`, `vortix-protocol-wireguard`, or `vortix-platform-*` per ideas 3, 5, 6 — staying put for now)
- `src/engine/` (2 files) → `crates/vortix/src/engine/` (relocates to `vortix-core` in idea 3)
- `src/state/connection.rs`, `src/state/killswitch.rs`, `src/state/profile.rs`, `src/state/mod.rs` → `crates/vortix/src/state/`
- `src/event.rs` → `crates/vortix/src/event.rs` (TUI event loop — stays in binary)
- `src/message.rs` → `crates/vortix/src/message.rs` (TEA-style messages — stays in binary)
- `src/constants.rs` → `crates/vortix/src/constants.rs`
- `src/logger.rs` → `crates/vortix/src/logger.rs`
- `src/utils.rs` → `crates/vortix/src/utils.rs` (god-file relocated as-is; splitting deferred)
- `src/vpn/mod.rs` → `crates/vortix/src/vpn/mod.rs` (relocates to `vortix-config` in idea 7)

**Files (renames + moves):**
- `src/ui/` (24 files) → `crates/vortix/src/tui/` (rename `ui` → `tui` during move)
- `src/state/ui.rs` → `crates/vortix/src/tui/state.rs` (rename + move)
- `src/theme.rs` → `crates/vortix/src/tui/theme.rs` (move into the renamed `tui/`)

**Files (modifications inside moved files):**
- Update `crates/vortix/src/lib.rs`'s `pub mod ui;` → `pub mod tui;`.
- Update all `use crate::ui::*` and `use crate::theme::*` and `use crate::state::ui::*` references to `use crate::tui::*` / `use crate::tui::theme::*` / `use crate::tui::state::*`. Affects modules across `app/`, `cli/`, `tui/`, `state/`, and possibly `main.rs`.
- Update `mod ui;` declarations in any `mod.rs` files to `mod tui;` where present.

**Approach:**
- Use `git mv` for every file/directory move so blame history follows.
- After moves, run `cargo build -p vortix` to surface every broken `use` path. Most failures are the `ui` → `tui` rename and the `state::ui` → `tui::state` rename.
- The `src/platform/` directory stays untouched at this step; U3 handles it. Vortix's `src/lib.rs` keeps `pub mod platform;` for now.

**Patterns to follow:**
- Today's `src/lib.rs` re-exports: `pub mod app; pub mod cli; pub mod config; pub mod constants; pub mod core; pub mod engine; pub mod event; pub mod logger; pub mod message; pub mod platform; pub mod state; pub mod theme; pub mod ui; pub mod utils; pub mod vpn;`. After U2: drop `pub mod config;` (moved to its own crate in U4) and `pub mod theme;` (now `tui::theme`), rename `pub mod ui;` to `pub mod tui;`. Other entries stay.
- The binary's `crates/vortix/src/main.rs` keeps its `use vortix::...` imports (the binary depends on its own library crate via the `vortix` crate name; this works in a workspace as it does today).

**Test scenarios:**
- *Test expectation: none — pure relocation; behavioral tests are in `tests/` and run via cargo unchanged.*
- Verification: `cargo build -p vortix` succeeds.
- Verification: `cargo test -p vortix --lib` succeeds (today's `src/app/tests.rs` runs with no behavior change).
- Verification: `grep -r '\bcrate::ui::' crates/vortix/src/` returns zero results (rename complete).
- Verification: `grep -r '\bcrate::theme::' crates/vortix/src/` returns zero results.

**Verification:** Build succeeds; unit tests pass; no stale references to the old module names.

---

### U3. Relocate platform code into `vortix-platform-{macos,linux}`

**Goal:** Move OS-specific code out of the binary crate into its proper platform crates. This is the first concrete payoff of the workspace shape.

**Requirements:** R2, R10

**Dependencies:** U1, U2

**Files (moves):**
- `src/platform/macos/mod.rs` → `crates/vortix-platform-macos/src/lib.rs` (rename: `mod.rs` becomes `lib.rs` of the new crate)
- `src/platform/macos/dns.rs` → `crates/vortix-platform-macos/src/dns.rs`
- `src/platform/macos/firewall.rs` → `crates/vortix-platform-macos/src/firewall.rs`
- `src/platform/macos/interface.rs` → `crates/vortix-platform-macos/src/interface.rs`
- `src/platform/macos/network.rs` → `crates/vortix-platform-macos/src/network.rs`
- Equivalent for Linux: `src/platform/linux/*` → `crates/vortix-platform-linux/src/*`
- `src/platform/mod.rs` (8 lines) → split per its content: trait definitions (`Firewall`, `NetworkStatsProvider` per the idea-6 grounding) stay in `crates/vortix/src/platform.rs` for now, since `vortix-core` is still empty; the OS-dispatch logic (the `cfg(target_os = "...")` blocks selecting macOS vs Linux) lives in `crates/vortix/src/platform.rs`. The platform traits move to `vortix-core` in idea 6's PR.

**Files (modifications):**
- `crates/vortix-platform-macos/Cargo.toml`: add `[dependencies]` for crates the moved code already uses (look at `use crate::utils::*`, `use crate::constants::*`, `use crate::core::killswitch::*`, `use crate::platform::Firewall`, etc., in the original files — these become workspace-internal deps on `vortix` or `vortix-core` from the current crate, OR temporary path-dep duplicates). Critical: the existing `src/platform/linux/firewall.rs` imports `use crate::core::killswitch::{KillSwitchError, Result}`, `use crate::logger::{self, LogLevel}`, `use crate::platform::Firewall`, `use crate::constants`. The crate-relative imports must be retargeted to `use vortix::core::killswitch::...`, `use vortix::logger::...`, etc. **This creates a circular dependency** if `crates/vortix-platform-{linux,macos}` depend on `crates/vortix` and vice versa.
- **Resolution:** Make `vortix-platform-{linux,macos}` depend on `vortix-core` (currently empty) and add the few types the platform code references (`KillSwitchError`, `Firewall` trait, `LogLevel`, `Result` alias, constants) as temporary moves into `crates/vortix-core/src/lib.rs` as `pub` re-exports or thin shims that the binary crate also reads. **Actually simpler:** keep `Firewall` trait and `KillSwitchError` and `Result` in `crates/vortix/src/platform.rs` and `crates/vortix/src/core/killswitch.rs`; have the platform crates depend on `vortix` (the binary crate's library half) for these. This creates a small library-binary dependency, which Rust allows.
- **Even simpler (recommended):** In this PR, the platform crates depend on the binary crate's library half via `vortix = { path = "../vortix" }`. The binary `crates/vortix/Cargo.toml` adds `vortix-platform-macos = { path = "../vortix-platform-macos" }` (target-gated to `cfg(target_os = "macos")`) and `vortix-platform-linux = { path = "../vortix-platform-linux" }` (`cfg(target_os = "linux")`). The two-way path-dep is acceptable as a transitional shape; idea 6's PR cleans it up by moving the Firewall trait, KillSwitchError, etc., into `vortix-core` and removing the platform→vortix dep.
- Update `crates/vortix/src/platform.rs` (new file, holds the old `src/platform/mod.rs` content): the `mod macos; mod linux;` declarations become `pub use vortix_platform_macos as macos;` and `pub use vortix_platform_linux as linux;` under their respective `cfg(target_os)`.
- Update every `use crate::platform::macos::...` and `use crate::platform::linux::...` in the binary crate to keep working through the re-export.

**Approach:**
- Acknowledge the transitional two-way path dep is ugly but bounded. Document it in `crates/vortix-platform-{macos,linux}/Cargo.toml` with a comment naming idea 6's PR as the cleanup.
- Resist the urge to clean up the cross-crate types in this PR; that's idea 6's work. Doing it here expands scope and risks idea 6 having no cleanup to do.

**Patterns to follow:**
- `cfg(target_os = "macos")`-gated workspace deps in the binary's `Cargo.toml`.
- matklad workspace pattern: per-OS path deps + target-gated activation.

**Test scenarios:**
- *Test expectation: none — pure relocation.*
- Verification: `cargo build --workspace` succeeds on the current developer machine (whichever OS they're on). On macOS: `vortix-platform-macos` is included in `vortix`'s dep tree; `vortix-platform-linux` is target-gated out (not built). Mirrored for Linux.
- Verification: `cargo build -p vortix-platform-macos --target x86_64-apple-darwin` succeeds (verifies the macOS-only crate builds in isolation).
- Verification: cross-compilation sanity (`cargo build -p vortix-platform-linux --target x86_64-unknown-linux-gnu` from macOS) — may fail due to missing toolchain; not a blocker but documents intended behavior.
- Verification: `grep -rn 'mod macos\|mod linux' crates/vortix/src/` returns no matches (the per-OS modules are now external crates).

**Verification:** `crates/vortix-platform-macos/` and `crates/vortix-platform-linux/` each contain 5 files (`lib.rs` + 4 OS-specific files). Binary builds on current developer's OS.

---

### U4. Relocate `src/config.rs` into `vortix-config`

**Goal:** Move the configuration module into its own crate to populate `vortix-config` (which idea 7 will further restructure).

**Requirements:** R2, R10

**Dependencies:** U1, U2

**Files (moves):**
- `src/config.rs` (751 lines) → `crates/vortix-config/src/lib.rs` (the entire file becomes the new crate's library entry point; idea 7's PR splits it further)

**Files (modifications):**
- `crates/vortix-config/Cargo.toml`: add `[dependencies]` for `serde = { workspace = true, features = ["derive"] }`, `toml = { workspace = true }`, `dirs = { workspace = true }`. The existing `src/config.rs` uses these.
- Update `use crate::*` references inside `src/config.rs` (now `crates/vortix-config/src/lib.rs`). Specifically, the file imports from `serde`, `std`, and uses `OnceLock` — no cross-crate types from the original `vortix` lib appear in a quick grep. Verify in U4 implementation: if any `use crate::logger` or `use crate::constants` is present, they need retargeting (likely via `vortix = { path = "../vortix" }` transitional dep).
- Update `crates/vortix/src/lib.rs`: remove `pub mod config;` line.
- Update `crates/vortix/src/main.rs` and other binary callers: `use vortix::config::*` → `use vortix_config::*`.
- Add `vortix-config = { path = "../vortix-config" }` to `crates/vortix/Cargo.toml` `[dependencies]`.

**Approach:**
- If `src/config.rs` references types from elsewhere in the binary, accept the transitional two-way path dep as documented in U3.
- Public re-export pattern: if many call sites use `vortix::config::*`, add `pub use vortix_config as config;` in `crates/vortix/src/lib.rs` to keep paths stable during this PR. Removed in idea 7's PR.

**Patterns to follow:**
- Same workspace dep pattern as platform crates.

**Test scenarios:**
- *Test expectation: none — pure relocation.*
- Verification: `cargo build --workspace` succeeds.
- Verification: `cargo test --workspace` passes (no behavior change).
- Verification: `vortix_config` is in the binary's dep tree (`cargo tree -p vortix | grep vortix-config`).

**Verification:** `crates/vortix-config/src/lib.rs` is the relocated `src/config.rs`. Binary builds and existing config-loading behavior is unchanged.

---

### U5. Update release-plz, cargo-dist, and CI configuration

**Goal:** Teach the existing release pipeline about the workspace topology while keeping the user-facing artifact `vortix` identical.

**Requirements:** R8, R9, R10

**Dependencies:** U1, U2, U3, U4 (the workspace shape must be final before pipeline configs reference it)

**Files (modifications):**
- `release-plz.toml`:
  - The `[workspace]` block stays (release-plz already understood we had a workspace context; it now becomes the actual workspace root).
  - `[[package]]` block updates: `name = "vortix"` unchanged; path is implicit (release-plz finds the crate by name in the workspace). The `semver_check = false` flag stays.
  - Verify release-plz config respects per-crate `publish = false` so internal crates aren't accidentally targeted. (Default behavior; verify with `release-plz --dry-run`.)
- `dist-workspace.toml`:
  - `[workspace] members = ["cargo:."]` → `[workspace] members = ["cargo:crates/vortix"]`. This is the load-bearing change for cargo-dist.
  - All other settings unchanged: `cargo-dist-version = "0.30.3"`, `ci = "github"`, installers (shell/homebrew/npm), `tap = "Harry-kp/homebrew-tap"`, `npm-scope = "@harry-kp"`, six target triples, `install-path = "CARGO_HOME"`.
- `.github/workflows/release-plz.yml` (existing): verify the workflow uses `actions/checkout` + `release-plz/action`. The action infers the workspace from `release-plz.toml`. No changes anticipated; verify against current YAML during implementation.
- `.github/workflows/release.yml` (existing — likely the cargo-dist generated workflow): regenerate via `cargo dist init --hosting github --check` if cargo-dist requires it, or hand-edit if minimal. The expected change is the build matrix referring to `--package vortix` or the workspace-aware build command.
- `.github/workflows/ci.yml`: change `cargo build` / `cargo test` to `cargo build --workspace --all-targets` / `cargo test --workspace --all-targets`. Add a matrix entry for `cargo build -p vortix-platform-linux --target x86_64-unknown-linux-gnu` and the macOS equivalent to verify platform crates build standalone.
- `.github/workflows/install-sanity.yml`: update any hardcoded paths that referenced the single-crate `Cargo.toml`. Verify `cargo install --path crates/vortix --locked` is the command shape.
- `.github/workflows/dependabot-auto-merge.yml`: no expected changes (operates on PR labels).
- `flake.nix`: review and update if it references `./Cargo.toml`'s `[package]` block directly. If `nix flake` builds via cargo, no change; if it parses the manifest, point at `crates/vortix/Cargo.toml`. Externally maintained nix flake (per brainstorm Dependencies/Assumptions) — coordinate with maintainer or leave for follow-up if it breaks.
- `.gitignore`: add `crates/*/target/` defensively (cargo respects the workspace `target/` at the root, but per-crate `target/` could appear if a contributor builds inside a crate dir).

**Approach:**
- Run `cargo dist plan` locally before merging to verify the workspace change is recognized. Run `release-plz update --dry-run` to verify the package detection.
- Coordinate with the AUR and Nix maintainers (off-platform) — if those packages reference the source-tree layout, they need a heads-up before the merge.
- The cargo-dist `0.30.3` version stays unless a workspace-layout bug forces an upgrade. If an upgrade is needed, document it as a separate concern.

**Test scenarios:**
- *Test expectation: pipeline verification, no unit tests for config files.*
- Verification: `cargo dist plan` runs cleanly and reports `vortix` as the dist target for all six target triples.
- Verification: `release-plz update --dry-run` reports exactly one package being considered (`vortix`); proposes a `0.3.0` (minor bump) version.
- Verification: `cargo install --path crates/vortix --locked` produces a runnable `vortix` binary at `~/.cargo/bin/vortix`; `vortix --version` reports the version from `crates/vortix/Cargo.toml`.
- Verification: CI passes on all platforms in the build matrix on the open PR.

**Verification:** Pipeline configs reflect the new workspace; dry-runs succeed; no internal crates appear in publish considerations.

---

### U6. Scaffold `xtask` with subcommand-dispatch skeleton

**Goal:** Establish the `xtask` crate as the home for future build chores (subprocess lint runner, packaging helpers, release-plz support) without populating its substance.

**Requirements:** R2 (workspace member), idea 1's brainstorm R12 (subprocess lint comes later)

**Dependencies:** U1

**Files (new):**
- `crates/xtask/Cargo.toml`:
  - `[package] name = "xtask", version = "0.0.0", edition = "2021", publish = false`
  - `[[bin]] name = "xtask" path = "src/main.rs"`
  - `[dependencies] clap = { workspace = true, features = ["derive"] }`
  - `[lints] workspace = true`
- `crates/xtask/src/main.rs`:
  - Minimal `clap` derive struct with a `Command` enum carrying a `CheckSubprocess` variant (today a stub returning OK and a TODO comment) and any other subcommands deemed worth scaffolding (`Help` is auto-generated by clap).
  - Stub body for `CheckSubprocess`: prints `xtask check-subprocess: not implemented; populated by idea 1's PR` and returns `Ok(())`.
  - `main()` parses args, dispatches.

**Files (new alias):**
- `.cargo/config.toml` (create if absent):
  - Add `[alias] xtask = "run --package xtask --quiet --"` so `cargo xtask <subcommand>` works without a long path.

**Approach:**
- The `xtask` crate is intentionally thin; this PR creates the harness. Idea 1's PR replaces the `CheckSubprocess` stub with a real `rg`-driven implementation per idea 1's R12.
- Document the xtask convention in `CONTRIBUTING.md` (one-line note: "Build chores run via `cargo xtask <task>`; subcommands are added under `crates/xtask/`").

**Patterns to follow:**
- matklad `xtask` convention.
- Existing `clap` usage in `src/cli/args.rs` for derive-style arg parsing.

**Test scenarios:**
- *Test expectation: none — placeholder scaffold.*
- Verification: `cargo xtask --help` lists subcommands.
- Verification: `cargo xtask check-subprocess` exits 0 with the stub message.

**Verification:** `crates/xtask/` exists with a working `--help`; the cargo alias resolves.

---

### U7. Update docs (README, ROADMAP, RELEASING, addendum to idea 1's brainstorm)

**Goal:** Reflect the workspace shape in user-facing docs and add the addendum to idea 1's brainstorm document so its destination paths are explicit.

**Requirements:** R10, R15; brainstorm's "land order with idea 1" section (R18, R19)

**Dependencies:** U1, U2, U3, U4 (the workspace shape is final)

**Files (modifications):**
- `README.md`:
  - Add a one-paragraph "Workspace layout" subsection in an appropriate location (probably under "Contributing" or near "Installation from source"). Brief description of the eight crates and where to find what.
  - Example: "vortix is organized as a Cargo workspace. The user-facing binary lives in `crates/vortix/`; internal infrastructure crates (`vortix-core`, `vortix-process`, `vortix-platform-{macos,linux}`, `vortix-protocol-wireguard`, `vortix-config`, `xtask`) compose into it. Only `vortix` is published to crates.io."
- `ROADMAP.md`:
  - Add a brief note that the v0.3.0 architectural migration is in progress and link to `docs/ideation/2026-05-24-vortix-architecture-ideation.md` and the brainstorm docs.
- `RELEASING.md`:
  - Update the diagram if needed: the release pipeline diagram already shows release-plz → crates.io → cargo-dist; only the package context changes. Add a line noting that internal crates are `publish = false`.
- `docs/brainstorms/2026-05-24-commandrunner-port-requirements.md`:
  - Add a short "Addendum: Post-workspace-split path migration" subsection at the end (or under Dependencies / Assumptions). Note that since the workspace split lands first, the CommandRunner trait's destination is `crates/vortix-core/src/ports/process.rs` and impls live in `crates/vortix-process/src/`. No other substance change to idea 1's brainstorm.
- `.github/PULL_REQUEST_TEMPLATE.md` (if present): add a note about the workspace layout to the contributor checklist.

**Approach:**
- Keep doc updates concise; major user-facing reorganization can wait until the full architecture migration is done.
- The addendum to idea 1's brainstorm is small but load-bearing — it's part of the PR's deliverables per the brainstorm's R18-R19.

**Test scenarios:**
- *Test expectation: none — documentation.*
- Verification: rendered README on GitHub shows the new workspace layout note.
- Verification: idea 1's brainstorm doc contains the addendum.

**Verification:** Docs reflect the workspace shape; idea 1's brainstorm carries the destination-path addendum.

---

## Verification Strategy

Beyond per-unit verification, the final PR state must satisfy these end-to-end checks:

- `cargo build --workspace --all-targets --locked` succeeds on macOS (developer machine) and on the CI Linux runner.
- `cargo test --workspace --all-targets` passes — no behavior change, so existing tests must all pass.
- `cargo metadata --no-deps --format-version 1 | jq '.workspace_members | length'` returns 8.
- `cargo install --path crates/vortix --locked` produces a `vortix` binary at the same version as the pre-PR HEAD (or whatever release-plz computes for the next bump).
- `cargo dist plan` exits 0 and reports `vortix` as the dist target across the six target triples (shell/homebrew/npm installers; macOS Intel + Apple Silicon, Linux glibc + musl, both x64 + arm64).
- `release-plz update --dry-run` reports exactly one package being considered (`vortix`) and proposes a minor version bump (e.g., `0.2.2 → 0.3.0` for the `refactor!:` semver signal).
- `rg 'Command::new' crates/vortix-core/ crates/vortix-process/ crates/vortix-protocol-wireguard/ crates/vortix-config/` returns zero matches (the stub crates have no subprocess code) — sanity check that we didn't accidentally drop code into the wrong crate.
- Binary `vortix --version` and `vortix --help` work identically to the pre-PR binary. Manual smoke test: connect to an existing profile, observe same telemetry, same kill switch behavior.

---

## Risks & Mitigations

- **Cross-crate dep cycle between `vortix-platform-{macos,linux}` and `vortix`.** Accepted as transitional. Documented in the platform crates' Cargo.toml. Cleaned up in idea 6's PR (which moves the `Firewall` trait, `KillSwitchError`, etc., into `vortix-core`). Mitigation: explicit comment, scope-locked to one PR's worth of life.
- **`cargo dist` failure on first tag post-merge.** Mitigation: dry-run via `cargo dist plan` before merge; if a real release fires and breaks, the existing fix-forward pattern (per `cf76218 fix: use RELEASE_PLZ_TOKEN…`) applies. Suggest cutting a dry-run release branch first.
- **AUR / Nix flake package maintainers might not know about the layout change.** Mitigation: open an issue in each external package's repo before merging (AUR via aur.archlinux.org/packages/vortix-bin, Nix via the flake source).
- **release-plz computing a major bump (`1.0.0`) instead of minor (`0.3.0`) for `refactor!:`.** Pre-1.0 semver in `RELEASING.md` documents `feat!:` triggering a minor bump pre-1.0; verify `refactor!:` follows the same rule. If not, the conventional-commit body can be tweaked.
- **The `ui` → `tui` rename touches many files; one missed reference causes a compile error.** Mitigation: rely on `cargo build` to surface every miss; resolve before commit. Standard refactor risk.
- **`src/config.rs`'s `OnceLock<PathBuf>` for the process-wide config dir is preserved by the move into `vortix-config`.** It's a process-global, so callers in the binary still observe the same lifetime semantics. Verify that the binary's `main()` calls `vortix_config::set_config_dir(...)` (was `vortix::config::set_config_dir(...)`) at the right point.
- **Test discovery for `tests/cli_integration.rs` and `tests/integration.rs`.** Integration tests for a binary crate live in `<crate>/tests/`. Relocate `tests/` to `crates/vortix/tests/`. Cargo discovers them automatically once relocated; verify with `cargo test --test cli_integration`.

---

## Scope Boundaries

This plan deliberately excludes scope that would expand the PR beyond reviewable size:

- Populating any of the four empty stub crates (`vortix-core`, `vortix-process`, `vortix-protocol-wireguard`) — that work lives in ideas 1, 3, 5, 6, 7's PRs.
- Splitting `crates/vortix/src/utils.rs` or `crates/vortix/src/constants.rs` — both are god-files but splitting them is its own work (idea 7 will absorb much of the config-related content from constants).
- Moving `src/engine/`, `src/core/`, `src/state/{connection,killswitch,profile}.rs` into `vortix-core` — that's idea 3's PR.
- Cleaning up `cfg(target_os)` blocks outside the platform crates — that's idea 6's PR's R12.
- Replacing `dirs` v6 with `directories` — that's idea 7's PR.
- Renaming or restructuring any of the existing modules beyond `src/ui/` → `crates/vortix/src/tui/` and the related `src/state/ui.rs` → `crates/vortix/src/tui/state.rs` move.
- Tightening lints (`unsafe_code = "forbid"`, additional clippy categories).
- Bumping the cargo-dist version, MSRV, or any other tool version.
- New tests beyond build-passes-everywhere and existing tests still passing.

### Deferred to Follow-Up Work

- Documentation expansion: when the full migration completes (after idea 7), revise `README.md` and `ROADMAP.md` to reflect the final architecture with diagrams.
- AUR maintainer outreach: open the issue ahead of merge to give them lead time on packaging adjustments.
- Pre-release dry-run on a release branch: before merging this PR, cut a `release-plz-dry-run-workspace` branch and verify cargo-dist + release-plz behave end-to-end against the new layout. Don't tag publicly; verify the workflow logs.

---

## Outstanding Questions

### Resolve Before Planning

(None — all material decisions resolved in the brainstorm and this plan.)

### Deferred to Implementation

- Whether `cargo-dist 0.30.3` requires a regen of `.github/workflows/release.yml` after the `dist-workspace.toml` change. `cargo dist init` may produce a slightly different workflow; if so, regenerate; if not, leave as-is. Verified during U5.
- Exact set of `[workspace.dependencies]` to factor out vs. keep per-crate. Recommend factoring `serde`, `serde_json`, `toml`, `clap`, and any other dep used by ≥2 crates; per-crate deps stay local. Mechanical; ce-work picks.
- Whether to add a `[workspace.metadata]` block for tools that read workspace metadata (e.g., `cargo-deny`, `cargo-machete`). Likely yes; planner notes the addition.
- Exact text of the README's "Workspace layout" note. Mechanical wording choice.
- Whether `flake.nix` needs an update or stays unchanged. Inspect during U5; if changes are needed, coordinate with the flake maintainer (externally maintained per brainstorm).
- Whether `src/lib.rs`'s `pub mod` set should expose any new types from the relocated crates (probably not; the binary uses them via `vortix_config::*`, `vortix_platform_*::*` directly).
