# Build and binary size

The release `vortix` is about 4.2 MB (4,158,272 B, `aarch64-apple-darwin`, September 2026).
Measure build time and size with `scripts/bench-build.sh` on an idle machine; a parallel
build invalidates every timing.

## Profiles

`[profile.release]` uses `opt-level = "z"`, `codegen-units = 1` and fat LTO. Which build a
user gets:

| Channel | Profile |
|---|---|
| Shell installer, Homebrew, npm, static musl (cargo-dist) | `dist`, which inherits `release` |
| `cargo build --release` in a checkout | `release` |
| `cargo install vortix`, docs.rs | `crates/vortix/Cargo.toml`'s own `[profile.release]` |

Cargo ignores profiles in a workspace member, so `crates/vortix/Cargo.toml` repeats
`[profile.release]` for the crates.io build (and every build prints `profiles for the non root
package will be ignored`). **Keep the two blocks identical by hand.**

- **Building from source needs about 4 GB of memory** (or swap). The one-codegen-unit LTO
  build is OOM-killed in 2 GB with a bare `SIGKILL`.
- **Never set `panic = "abort"`.** Panics in tunnel operations and hooks are caught with
  `catch_unwind` so a process holding kill-switch state does not die.
- **Reject `lto = "thin"` in `[profile.dist]`.** `dist init` writes it back if cargo-dist is
  re-initialised; `dist` must inherit `release`.
- **`tracing-subscriber` uses `Targets`, not `EnvFilter`**, to avoid a regex engine.
  `Targets` treats an empty directive as a global `ERROR` level, so `main.rs::log_filter`
  strips empty segments; its tests hold that.

Considered and rejected: replacing `figment` (60 KB, and `VORTIX_*` override parsing would have
to be re-implemented exactly), `native-tls` instead of `rustls` (breaks the static musl
builds), and splitting the crate (the boundaries are enforced by `cargo xtask` instead).

## Size budget

`Integration / macos-release` builds `--release` on `macos-latest` and runs
`tests/integration/release_smoke.sh` with `VORTIX_SIZE_BUDGET_BYTES=7000000`; `ci-local.sh`
runs the same. No other test notices a profile regression. It also checks the version, that
`--json` keeps stdout clean, kill-switch verb parsing, and that an unprivileged launch exits 2.

When the budget trips, find out why before raising it: a reverted profile setting costs
megabytes and fails nothing else. Move the ceiling only in the commit that justifies it.
