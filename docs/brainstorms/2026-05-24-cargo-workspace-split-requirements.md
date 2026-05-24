---
date: 2026-05-24
topic: cargo-workspace-split
---

# Cargo Workspace Split

## Summary

Migrate vortix from a single crate to a flat matklad-style Cargo workspace with eight day-one crates — `vortix-core`, `vortix-process`, `vortix-platform-macos`, `vortix-platform-linux`, `vortix-protocol-wireguard`, `vortix-config`, the user-facing `vortix` binary crate (CLI + TUI shell code together), and `xtask` for build chores. Only `vortix` is published to crates.io; internal crates stay unpublished. This is a pure structural move with no behavior changes — `cargo install vortix`, the Homebrew formula, the npm package, AUR, and Nix paths are unchanged. The new layout is the foundation that every later survivor (CommandRunner, FSM, daemon, Tunnel trait, capability ports, config stack) lands into.

---

## Problem Frame

vortix is a single crate today (`Cargo.toml` at the repo root, source under `src/`). The single-crate shape worked through v0.2.x but is now the load-bearing reason multiple architectural pains compound on each other.

Crate boundaries are the only architectural fence Rust enforces automatically. Without them, the project's structural decisions — "TUI must not reach into platform internals," "config code must not import ratatui," "engine code must not assume tokio" — exist only as good intentions until a contributor or a refactor breaks them. The result is observable in the current code: `utils.rs` (35 KB) and `config.rs` (26 KB) accumulated their size partly because no other module's *boundary* was strict enough to refuse the next helper. Platform-specific code is sprinkled with `#[cfg(target_os = "…")]` blocks across `core/`, `engine/`, and `cli/` because there is no `vortix-platform-*` crate to absorb them. The `App ⇆ VpnEngine` Deref boundary leaks because there is no `vortix-core` to define what an engine even is from the outside.

The downstream consequences are concrete. Windows support (v1.0 roadmap) currently means hunting `cfg` blocks across the entire source tree; with a `vortix-platform-windows` crate, it would mean implementing one crate. Multi-protocol support (v1.0 — OpenVPN, IKEv2) currently means adding match arms to the connection path; with `vortix-protocol-*` crates, each protocol's dependency footprint is isolated. Daemon mode (v0.3.0) currently has no obvious home for the long-lived engine and the IPC surface; with `vortix-core` separating the engine from the binary, the daemon is just another consumer of the same library.

This refactor does not, by itself, deliver any of those downstream features. It delivers the *boundary system* those features then occupy. Without it, every later refactor has to relitigate "where does this code live" inside a single crate that gives no help with the answer.

The migration risk is real and named. release-plz, cargo-dist 0.30.3, Homebrew tap, npm scope, AUR package, Nix flake all reference the artifact named `vortix` produced from the crate named `vortix` at this repo. The recent commit `cf76218 fix: use RELEASE_PLZ_TOKEN in release workflow for tag checkout auth` shows the release path has been fragile in the last cycle. This PR's job is to deliver the workspace shape *without destabilizing distribution*.

---

## Actors

- A1. **Contributor adding a new feature** — wants a clear home for the code they're writing without having to negotiate with an unrelated file.
- A2. **Contributor porting vortix to Windows (future)** — wants one crate to implement, not a `cfg` audit across the whole repo.
- A3. **Future library consumer** — a Tauri wrapper, an MCP server, a system tray, a tested fake — wants to depend on `vortix-core` without pulling in `ratatui` or `clap`.
- A4. **End user installing vortix** — runs `cargo install vortix` / `brew install harry-kp/tap/vortix` / `npm i -g @harry-kp/vortix` / `yay -S vortix-bin` / `nix run github:Harry-kp/vortix`. **Must observe no change.**
- A5. **release-plz workflow** — opens release PRs, publishes to crates.io, tags. Must keep working with one published package.
- A6. **cargo-dist 0.30.3** — runs on tags, builds the binary for six targets, ships installers. Must find the binary crate in its new location.
- A7. **CI** — runs `cargo build` / `cargo test` / lint / dist sanity. Must succeed across the workspace.

---

## Key Flows

- F1. **End user installs vortix after the migration**
  - **Trigger:** User runs `cargo install vortix` (or `brew install …`, `npm i -g …`, etc.).
  - **Actors:** A4
  - **Steps:**
    1. Package manager fetches the `vortix` crate / formula / package by its existing name.
    2. crates.io / cargo-dist artifacts resolve to the same `vortix` binary at the same version line as before.
    3. The binary lands on the user's PATH and runs identically.
  - **Outcome:** User observes zero change in install command, binary name, version semantics, or behavior.
  - **Covered by:** R1, R2, R8, R9

- F2. **Contributor adds a new module after the migration**
  - **Trigger:** Contributor implements a new helper related to network monitoring.
  - **Actors:** A1
  - **Steps:**
    1. Contributor identifies which crate the helper belongs to (port → `vortix-core`; platform-specific impl → `vortix-platform-*`; protocol-specific → `vortix-protocol-*`; shell code → `vortix`).
    2. Compiler enforces that the new code can only import from declared workspace dependencies.
    3. PR shows a focused diff inside one or two crates.
  - **Outcome:** "Where does this go?" has a near-mechanical answer. PRs stay focused.
  - **Covered by:** R3, R4, R5

- F3. **release-plz cuts a release after the migration**
  - **Trigger:** A PR with conventional-commit messages lands on `main`.
  - **Actors:** A5, A6
  - **Steps:**
    1. release-plz sees one `[[package]]` entry in `release-plz.toml` (`vortix`) and computes a version bump.
    2. release-plz opens a Release PR updating `crates/vortix/Cargo.toml` and `CHANGELOG.md`.
    3. Maintainer merges. release-plz publishes `vortix` to crates.io and tags `vX.Y.Z`.
    4. cargo-dist fires on the tag, reads `dist-workspace.toml` pointing at `crates/vortix`, builds six-target binaries, ships installers.
  - **Outcome:** Release flow is structurally identical to today; only the path inside the repo changed.
  - **Covered by:** R8, R9, R10

---

## Requirements

**Workspace structure**

- R1. The repository root contains a virtual workspace manifest (`Cargo.toml` with `[workspace]` and no `[package]`). Crates live under `crates/`. Folder name equals crate name, with no exceptions.
- R2. Day-one workspace members are:
  - `crates/vortix-core/` — port traits, FSM types, event schema, shared error types, profile types. Zero TUI / process-runtime / clock / OS deps. May depend on serde, thiserror, and similar pure-data crates.
  - `crates/vortix-process/` — `RealRunner` and `MockRunner` impls of `vortix-core::ports::process::CommandRunner`. Tokio + tracing live here.
  - `crates/vortix-platform-macos/` — macOS impls of `vortix-core` capability port traits.
  - `crates/vortix-platform-linux/` — Linux impls of `vortix-core` capability port traits.
  - `crates/vortix-protocol-wireguard/` — WireGuard `Tunnel` impl, profile parser, `wg-quick`/`wg` adapters.
  - `crates/vortix-config/` — figment + directories + keyring binding (the substance of idea 7).
  - `crates/vortix/` — the user-facing binary crate. Holds `main.rs`, CLI arg parsing (clap), JSON envelope, TUI bootstrap (ratatui), and the CLI / TUI shell code. Depends on all the libraries above.
  - `crates/xtask/` — Rust binary (invoked via `cargo xtask <task>`) for the CI subprocess-lint runner (idea 1's R12), packaging chores, and release-plz support helpers.

**Crate naming and identity**

- R3. The user-facing binary crate is named `vortix` exactly. Its `Cargo.toml` declares `[package] name = "vortix"`. The compiled binary is also named `vortix`. **This is the only requirement that is non-negotiable for distribution compatibility.**
- R4. Internal crates (`vortix-core`, `vortix-process`, `vortix-platform-*`, `vortix-protocol-*`, `vortix-config`) carry `version = "0.0.0"` and `publish = false` in their per-crate `Cargo.toml`. release-plz will not version them; crates.io will not receive them.
- R5. `xtask` is not a regular crate from the publish standpoint — `publish = false`. Its `version` may stay `0.0.0` or `0.1.0` (mechanical, planner picks).

**Workspace configuration**

- R6. The virtual root `Cargo.toml` declares `rust-version = "1.75"` and a `[workspace.lints]` table mirroring the current `[lints.rust]` and `[lints.clippy]` from the existing root `Cargo.toml` (`unsafe_code = "warn"`, `clippy::all`, `clippy::pedantic`). Each crate inherits via `[lints] workspace = true`.
- R7. The virtual root `Cargo.toml` declares `[workspace.dependencies]` with shared external deps (ratatui, crossterm, clap, serde, etc.) so each crate references them as `{ workspace = true }`. Internal cross-crate deps use path references inside `crates/`.

**Distribution and release pipeline**

- R8. `release-plz.toml` continues to have exactly one `[[package]] name = "vortix"` entry, unchanged in semantics. Internal crates do not appear because they carry `publish = false`.
- R9. `dist-workspace.toml` updates its `members` from `["cargo:."]` to `["cargo:crates/vortix"]`. All other cargo-dist settings (targets, installers, tap, npm-scope, publish-jobs, install-path) remain unchanged. cargo-dist version stays at 0.30.3 unless a workspace-layout bug forces an upgrade.
- R10. The published `vortix` crate's `[package]` metadata preserves the existing user-visible fields: `name = "vortix"`, `description`, `license`, `keywords`, `categories`, `repository`, `homepage`, `documentation`, `authors`, `readme`, and the existing `exclude` list (adjusted for the new path — `target/*`, `scripts/*`, etc., relative to the crate, not the workspace).
- R11. The `vortix` crate's `Cargo.toml` declares the binary explicitly with `[[bin]] name = "vortix" path = "src/main.rs"`. There is no ambiguity about the binary's name relative to the crate's name.

**Migration discipline**

- R12. The migration lands as a single big-bang PR. All eight crates are created at the same time; all code moves to its destination crate in the same diff; the old root `src/` directory is deleted in the same diff.
- R13. The PR is pure structural reorganization. No behavior is changed. No new tests are added beyond build-passes-everywhere and `cargo install --path crates/vortix` produces a working binary on the maintainer's machine. Refactors, simplifications, and tempting cleanups discovered during the move are deferred to follow-up PRs.
- R14. The PR explicitly verifies the distribution path by running locally, before merging: `cargo install --path crates/vortix --locked` produces a runnable `vortix` binary, and `cargo dist plan` (or equivalent dry-run) succeeds against the new layout.
- R15. The PR's commit message uses the conventional-commit form `refactor!: split into Cargo workspace` so release-plz computes the correct semver action (a minor bump pre-1.0 per RELEASING.md). The user-visible binary behavior is unchanged, but the workspace shape is a breaking change to the *crate's source layout*, which is worth signaling.

**Public API surface**

- R16. `vortix-core` follows a **minimum-public-surface** principle on day one. The initial `pub` surface includes only: port trait names (`CommandRunner`, `Tunnel`, `Killswitch`, `DnsResolver`, `RouteTable`, `NetworkMonitor`, `SplitTunnel`, `TunDevice`, `SecretStore` as they get added by later survivors), their associated `Spec`/`Outcome`/`Error` types, the `EngineHandle` API (added by idea 4), the event schema (added by idea 3), the shared error types, and the profile types. Everything else is `pub(crate)` until a concrete consumer asks for it.
- R17. Adding a `pub` item to `vortix-core` requires a justification in the PR description (the consumer that needs it, or the documented intent to be part of the embedding surface). This rule is enforced by review discipline, not tooling.

**Land order with idea 1 (CommandRunner)**

- R18. This PR lands **before** idea 1's CommandRunner refactor. Idea 1's brainstorm doc assumes a single-crate codebase; after this workspace split lands, idea 1's PR will land into the new layout and the `CommandRunner` trait will go directly into `vortix-core::ports::process` (trait) and `vortix-process` (impls), rather than into the old `src/process/` module path.
- R19. Idea 1's brainstorm doc will be updated (one short addendum) noting that the destination paths are now `crates/vortix-core/src/ports/process.rs` (trait) and `crates/vortix-process/src/` (impls). No other revision to idea 1's substance is required.

---

## Acceptance Examples

- AE1. **Covers R1, R2.** When the migration PR lands, then `cargo metadata --no-deps | jq '.workspace_members | length'` returns 8, and `ls crates/` lists exactly the eight day-one crate directories.

- AE2. **Covers R3, R8.** When release-plz runs after the migration, then `release-plz update --dry-run` reports exactly one package (`vortix`) being considered, and the simulated version bump targets `crates/vortix/Cargo.toml`, not the root.

- AE3. **Covers R4.** When a contributor accidentally runs `cargo publish -p vortix-core`, then publish fails with the expected "package has `publish = false`" error from cargo.

- AE4. **Covers R3, R9.** When cargo-dist runs against the new `dist-workspace.toml`, then it builds a binary named `vortix` for all six target triples, produces shell + homebrew + npm installers, and the homebrew formula in `Harry-kp/homebrew-tap` resolves to `harry-kp/tap/vortix` without rename.

- AE5. **Covers R6, R7.** When a contributor adds a dep to a single crate by hand-editing its `Cargo.toml` instead of going through `[workspace.dependencies]`, then a future `cargo deny` or `cargo machete` check (or review discipline) flags the divergence. (Tooling exact form is a planner decision.)

- AE6. **Covers R12, R13.** When the migration PR is open for review, then the diff shows ~zero edits to the actual logic in moved files — only path and `use` updates plus crate scaffolding. A reviewer running `git diff --stat origin/main` sees mostly renames.

- AE7. **Covers R13, R14.** When a maintainer runs `cargo install --path crates/vortix --locked` on the migration branch, then a `vortix` binary lands at `~/.cargo/bin/vortix` and `vortix --version` reports the same version line as before the migration.

- AE8. **Covers R16.** When a downstream consumer tries to import `vortix_core::internal::engine::StateMutator`, then the compile fails because `internal` is `pub(crate)`. When they import `vortix_core::ports::Tunnel`, it compiles.

---

## Success Criteria

- A user running `cargo install vortix`, `brew upgrade vortix`, `npm update -g @harry-kp/vortix`, `yay -Syu vortix-bin`, or `nix flake update` after the migration ships observes no change in install behavior, binary name, or version semantics.
- release-plz cuts the next release after the migration without manual intervention beyond the standard merge of its Release PR.
- cargo-dist builds the binary for all six target triples on the next tag, identically to before the migration.
- A contributor opening the repository for the first time can answer "where does X live?" by reading the crate set without grepping. The mapping from concern to crate is mechanical.
- Idea 1's CommandRunner PR lands cleanly into `crates/vortix-process/` with no scaffolding work — the layout was already waiting for it.

---

## Scope Boundaries

- **Stub crates for `vortix-platform-windows`, `vortix-daemon`, `vortix-protocol-openvpn`, `vortix-protocol-ikev2`** are out of scope. They are created when ideas 4, 5, 6 begin. Adding empty placeholders now is roadmap performance, not commitment, and creates 4 empty crates to maintain.
- **Splitting CLI and TUI into separate library crates** (`vortix-cli`, `vortix-tui` as libraries the binary composes) is out of scope. Defer until a concrete second consumer — Tauri wrapper, MCP server, system tray, headless variant — makes the case. At that point the split will be informed by the consumer's actual API needs.
- **Renaming the user-facing artifact** is out of scope. The binary stays `vortix`, the published crate stays `vortix`, the Homebrew formula stays `vortix`, the npm package stays `@harry-kp/vortix`.
- **Publishing internal crates to crates.io** is out of scope. They stay `version = "0.0.0"` + `publish = false`. The publish story remains: one user-facing crate.
- **Bumping cargo-dist** is out of scope. 0.30.3 stays unless it actively rejects the workspace layout.
- **Behavior changes, refactors, or simplifications discovered during the move** are out of scope. Big-bang refactors that mix structural moves with cleanups become unreviewable; defer cleanups to follow-up PRs.
- **Adding new distribution channels** (`cargo binstall`, Snap, Flatpak, Scoop, winget) is out of scope. The six cargo-dist targets and four publish channels (crates.io, homebrew tap, npm scope, plus AUR/Nix externally maintained) remain.
- **MSRV bump** is out of scope. Workspace `rust-version = "1.75"` matches the current single-crate setting.

---

## Key Decisions

- **Workspace layout: flat under `crates/`, virtual root manifest, folder-name-equals-crate-name.** Matches matklad's pattern. Single-level nesting prevents tooling surprises and keeps paths short.
- **8 day-one crates, no stubs.** Each day-one crate has a real owner of code right now (after the move). Adding stub crates for future work would create dead crates with no `lib.rs` content — review confusion outweighs roadmap signaling.
- **Single binary crate `vortix` containing CLI + TUI shell code.** YAGNI on speculative library splits. A consumer-driven split later is informed by the consumer's API needs; a speculative split now would invent the wrong API.
- **Binary crate named `vortix` (not `vortix-cli` or `vortix-bin`).** Preserves `cargo install vortix`, the Homebrew formula, the npm package, the AUR package. Non-negotiable for distribution compatibility.
- **Only `vortix` published to crates.io.** Internal crates carry `publish = false`. release-plz config stays single-package. crates.io surface area is unchanged.
- **CommandRunner trait in `vortix-core`, impls in `vortix-process`.** Hexagonal discipline. Keeps `vortix-core` free of tokio/tracing deps — a future consumer that only wants port types (e.g., a schema-generation tool) doesn't pay the cost.
- **Land order: workspace split first, then idea 1 (CommandRunner).** Structural-then-behavioral. Reviewers see the layout move, then the behavior change in isolated PRs. Idea 1's brainstorm doc gets a short addendum about the destination paths after this lands.
- **Big-bang migration PR.** Carries forward the user's idea-1 preference. Mixed-structural-and-behavioral migrations are unreviewable; this PR is *only* structural, so the big-bang surface area is mostly renames.
- **Conventional-commit signal: `refactor!: split into Cargo workspace`.** Pre-1.0 (`fix:` → patch, `feat:` → minor, `feat!:` → minor per RELEASING.md), so `refactor!:` triggers a minor bump signaling a source-layout breaking change without bumping past 1.0.
- **Workspace inheritance for deps and lints.** `[workspace.dependencies]` for external deps; `[workspace.lints]` for the existing pedantic+all+`unsafe_code = warn` configuration. Per-crate `Cargo.toml` references `{ workspace = true }`.

---

## Dependencies / Assumptions

- **release-plz respects `publish = false` on internal workspace members.** Verified semantically by release-plz docs; the per-crate flag is the standard way to keep workspace members internal.
- **cargo-dist 0.30.3 supports `members = ["cargo:crates/<name>"]` in `dist-workspace.toml`** to target a workspace-internal crate. The dist-workspace docs describe this pattern; the planner should verify with `cargo dist plan` before merging.
- **The Homebrew tap, npm scope, AUR package, and Nix flake all reference the crate by name `vortix` and the binary by name `vortix`.** Confirmed by reading `dist-workspace.toml` (tap, npm-scope) and the existing release pipeline. AUR and Nix are externally maintained but follow the same name; if they reference the source layout, they will be updated by their maintainers.
- **`cargo install vortix` semantics:** crates.io installs the published `vortix` crate's binary. The internal source layout is irrelevant to the install path. Confirmed by Cargo book.
- **MSRV 1.75 is sufficient for all eight day-one crates.** No crate requires a higher version. AFIT (1.75) is the highest feature in use across the architecture; native AFIT is the dependency of idea 1's CommandRunner, which lands after this.
- **`cargo dist plan` (dry-run)** validates the cargo-dist configuration locally without firing a release. The planner should rely on it.
- **The recent release-plz fragility (`cf76218`) is unrelated to workspace topology.** The token-handling fix was about GitHub Actions auth, not about Cargo workspace structure. Workspace migration should not interact with that fix.

---

## Outstanding Questions

### Resolve Before Planning

(None — all material decisions resolved in the synthesis.)

### Deferred to Planning

- [Affects R10][Technical] Exact `exclude` list for the new `crates/vortix/Cargo.toml` — the current root `Cargo.toml` excludes `target/*`, `scripts/*`, `assets/*`, `.github/*`, and a list of TOML files. Some of those (`release-plz.toml`, `dist-workspace.toml`, `cliff.toml`, `deny.toml`, `rustfmt.toml`) stay at the workspace root and no longer need to be excluded from `crates/vortix/`. Mechanical; planner picks.
- [Affects R2][Technical] Specific destination crate for each existing source file. Rough mapping is clear (`src/engine/` → `vortix-core` types + `crates/vortix/` wiring; `src/cli/` → `crates/vortix/src/cli/`; `src/app/` → `crates/vortix/src/tui/`; `src/ui/` → `crates/vortix/src/tui/widgets/`; `src/core/{killswitch,scanner,…}` → split between `vortix-core` ports and `vortix-platform-*`/`vortix-protocol-wireguard` impls; `src/platform/{macos,linux}/` → `crates/vortix-platform-{macos,linux}/`; `src/state/` → `crates/vortix-core/src/state/`; `src/config.rs` → `crates/vortix-config/`; `src/utils.rs` → split per concern across `vortix-core` time helpers, `crates/vortix/src/cli/envelope.rs`, etc.). Ce-plan owns the final mapping.
- [Affects R12, R15][Technical] Whether the conventional-commit form should be `refactor!:` (recommended) or `chore!:` for the migration PR. Mechanical; release-plz semver behavior should be sanity-checked against `cliff.toml` filters.
- [Affects R6][Technical] Whether `unsafe_code = "warn"` should escalate to `"forbid"` in the workspace lints during the migration. Not in scope per R13 but worth a follow-up if no `unsafe` is in the tree.
- [Affects R2, R5][Technical] `xtask` initial contents — placeholder `cargo xtask check-subprocess` referenced by idea 1's R12, plus stub help text. Mechanical scaffolding.
