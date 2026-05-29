# CI parity — local verification commands

Single source of truth for "what CI runs". Run this exact set before pushing to avoid the *"green locally, red in CI"* trap. Authoritative reference is the workflow files under `.github/workflows/`; update both together.

## Doc-only PR convention

PRs that only touch `**/*.md`, `LICENSE`, or `CHANGELOG.md` skip every heavy CI workflow (`test.yml`, `lint.yml`, `boundary.yml`, `security.yml`, `integration-tests.yml`). The result: a doc-only PR shows no green check rows except `Release / plan` (cargo-dist-owned, fires on every PR). This is intentional — the saving is real CI minutes; the cost is that a reviewer sees an "empty" check list and has to trust the rule.

If your PR mixes a doc change with anything else (any `.rs`, `Cargo.toml`, `Cargo.lock`, or workflow YAML touch), CI fires normally. The skip only triggers when EVERY changed file matches the doc patterns.

## The full set

```bash
# 1. Format
cargo fmt --all -- --check

# 2. Build (fail-fast on compile errors before lint pass)
cargo check --workspace --all-targets

# 3. Clippy — note --all-targets includes tests + examples + benches
cargo clippy --workspace --all-targets -- -D warnings

# 4. Tests
cargo test --workspace

# 5. Docs — rustdoc lints only fire here, NOT in clippy
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps

# 6. Boundary checks (project-specific xtask)
cargo xtask check-subprocess
cargo xtask check-platform-leak
cargo xtask check-protocol-leak
cargo xtask check-no-shell-regressions
```

## Common traps

These have each cost ≥1 CI cycle on this repo. The fix is below each.

### Trap 1 — `-p vortix --lib` skips test code

`clippy::pedantic` is enabled workspace-wide, so test code gets pedantic lints too. `-p vortix --lib` skips test targets, hiding lints there.

```bash
# WRONG (hides lints in test code)
cargo clippy -p vortix --lib -- -D warnings

# RIGHT
cargo clippy --workspace --all-targets -- -D warnings
```

### Trap 2 — `#[cfg(target_os = "...")]` blocks are skipped on the wrong host

Code gated to Linux (`vortix_platform_linux/*`, `daemon/server.rs` SO_PEERCRED block) never compiles on macOS, and vice versa. Local clippy on a macOS host **cannot** catch a Linux-only lint. CI runs the matrix; humans usually don't.

**Mitigations:**
- Where feasible, cross-compile-check before pushing: `cargo check --workspace --all-targets --target x86_64-unknown-linux-gnu` (or `aarch64-apple-darwin` from a Linux box). Linker errors are expected for non-host targets; the lint pass still runs.
- Otherwise: push to a feature branch, watch CI, fix from the failure log. Don't merge until all matrix legs are green.

### Trap 3 — `cargo clippy` does NOT run rustdoc lints

`rustdoc::broken_intra_doc_links`, `rustdoc::missing_crate_level_docs`, etc. only fire under `cargo doc`. A clippy-clean tree can still fail the Docs check.

```bash
# WRONG (rustdoc lints not exercised)
cargo clippy --workspace --all-targets -- -D warnings

# RIGHT (matches the CI Docs job)
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
```

### Trap 4 — `cargo fmt` (without `--all`) skips workspace members

```bash
# WRONG on a workspace
cargo fmt -- --check

# RIGHT
cargo fmt --all -- --check
```

### Trap 5 — Forgetting the boundary checks

`cargo xtask check-{subprocess,platform,protocol}-leak` enforce architectural boundaries (no platform imports from `vortix_core`, no protocol imports from `vortix_platform_*`, etc.). They are NOT part of `cargo test`. CI runs them as separate jobs (plans 002 / 003 / 004).

## When to run what

| Situation | Minimum set |
|---|---|
| Tight edit loop on a single function | `cargo check -p vortix --lib` |
| Before opening a PR | Full set above |
| Before declaring a unit done (per-unit verification in plan docs) | Full set above |
| After dependency bumps (rand, sha2, libc, tokio) | Full set above + manual smoke per `docs/manual-testing/<feature>.md` |
| After cross-platform code touches | Full set, plus cross-compile-check (`--target`) where possible |

## Updating CI

When you change `.github/workflows/ci.yml`, update this file in the **same commit**. Reviewers should reject CI changes that don't update the local-parity guide.
