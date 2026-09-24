# CI parity — local verification commands

Single source of truth for "what CI runs". Run this exact set before pushing to avoid the *"green locally, red in CI"* trap. Authoritative reference is the workflow files under `.github/workflows/`; update both together.

Pull-request workflows intentionally do not filter on a base branch. This gives stacked PRs targeting their immediate parent the same checks as PRs targeting `main`; only `push` workflows remain restricted to `main`.

## Doc-only PR convention

PRs that only touch `**/*.md`, `LICENSE`, or `CHANGELOG.md` skip every heavy CI workflow (`test.yml`, `lint.yml`, `boundary.yml`, `security.yml`, `integration-tests.yml`). The result: a doc-only PR shows no green check rows except `Release / plan` (cargo-dist-owned, fires on every PR). This is intentional — the saving is real CI minutes; the cost is that a reviewer sees an "empty" check list and has to trust the rule.

If your PR mixes a doc change with anything else (any `.rs`, `Cargo.toml`, `Cargo.lock`, or workflow YAML touch), CI fires normally. The skip only triggers when EVERY changed file matches the doc patterns.

## One command

```bash
scripts/ci-local.sh           # full set, including the Linux cross-clippy on macOS
scripts/ci-local.sh --quick   # skips the release build
```

The script runs steps 1 and 3–6 below, the Linux cross-clippy (Trap 2) and the release build from step 7; run `release_smoke.sh` by hand when step 7 applies. Steps are listed so a failure can be re-run on its own.

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

# 7. Release-profile smoke — the ONLY step that builds `release`; steps 1-6 all
#    build dev, so a profile-only breakage is invisible to them. Mirrors the
#    `Integration / macos-release` job. On a macOS host this is exact parity.
cargo build --release -p vortix --locked
VORTIX_SIZE_BUDGET_BYTES=7000000 bash tests/integration/release_smoke.sh
```

Step 7 costs a fat-LTO link — about 2 minutes cold, and it is the only step here that
notices a `[profile.release]` or `[profile.dist]` edit. Skip it for a pure logic change;
never skip it when you touched a profile, `Cargo.toml`, a dependency feature, CLI output,
or anything cargo-dist owns. The budget figure lives in
[`docs/performance.md`](performance.md) — raise it deliberately, not reflexively.

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

Code gated to Linux (`linux/*`) never compiles on macOS, and vice versa, so a plain local clippy misses the other OS's lints.

**Fix:** on macOS, `scripts/ci-local.sh` also runs clippy for `x86_64-unknown-linux-gnu` once the target is installed (`rustup target add x86_64-unknown-linux-gnu`). `ring`'s build script uses macOS clang pointed at the SDK's libc headers; clippy never links:
```bash
SDK=$(xcrun --show-sdk-path) \
CC_x86_64_unknown_linux_gnu=clang AR_x86_64_unknown_linux_gnu=ar \
CFLAGS_x86_64_unknown_linux_gnu="--target=x86_64-unknown-linux-gnu -isystem $SDK/usr/include" \
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
```
Linux-only runtime behaviour (tests under `cfg(target_os = "linux")`) still runs only in CI; don't merge until every matrix leg is green.

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

`cargo xtask check-{subprocess,platform,protocol}-leak` and `check-no-shell-regressions` enforce architectural boundaries (OS `cfg` only in `macos/`/`linux/`/`platform.rs`, subprocesses only through `process/`, protocol binaries only in their protocol module, no new shell-outs to replaced system binaries). They are NOT part of `cargo test`. CI runs them as separate jobs.

## When to run what

| Situation | Minimum set |
|---|---|
| Tight edit loop on a single function | `cargo check -p vortix --lib` |
| Before opening a PR or pushing | `scripts/ci-local.sh` |
| After dependency bumps (rand, sha2, libc, tokio) | Full set above + manual smoke per `docs/manual-testing/<feature>.md` |
| After cross-platform code touches | `scripts/ci-local.sh` (includes the Linux cross-clippy on macOS) |
| Checking a build-time or binary-size regression | `scripts/bench-build.sh` — see [`docs/performance.md`](performance.md) |
| After touching a cargo profile, a dependency feature, or CLI output | Full set **including step 7** |

## Caching

Every workflow except `Format` restores a cargo cache through `.github/actions/rust-setup`
(`Swatinem/rust-cache`). `Format` passes `cache: 'false'` — `cargo fmt` compiles nothing, so the
restore/save round trip bought nothing.

The netns jobs in `Integration Tests` cannot use that action: the build runs inside a privileged
container that cannot see the runner's cargo home. (Its `release-smoke` job is an ordinary macOS
runner and does use `rust-setup` normally.) They instead layer-cache the harness image
(buildx + `type=gha`)
and caches `.ci-cargo-home` + `target` with `actions/cache`, keyed on `Cargo.lock`. The container
gets `CARGO_HOME=/workspace/.ci-cargo-home`; `CARGO_TARGET_DIR` is deliberately left alone because
`tests/integration/*.sh` invoke `target/release/vortix` by path. A step after the run chowns both
directories back to the runner user so `actions/cache` can save them.

## Updating CI

When you change anything under `.github/workflows/` or `.github/actions/`, update this file in the
**same commit**. Reviewers should reject CI changes that don't update the local-parity guide.
