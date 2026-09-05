# Build and binary-size budget

What the release binary costs, what the build costs, and which knobs are load-bearing.
Re-measure with `scripts/bench-build.sh` on an **idle** machine — every timing below is
wall-clock sensitive, and a parallel build invalidates the whole table.

## Which artifacts actually get the size win

Profiles only apply at the workspace root, and the workspace root `Cargo.toml` is not part of
the published `vortix` crate. So the numbers here describe the binaries built **from this
repo**, which is what every distribution channel except one uses:

| How a user gets vortix | Profile | Gets `opt-level = "z"` |
|---|---|---|
| shell installer / Homebrew / npm / static musl (cargo-dist) | `dist` (inherits `release`) | yes |
| `cargo build --release` in a checkout | `release` | yes |
| `cargo install vortix` from crates.io | `crates/vortix/Cargo.toml`'s own `[profile.release]` | yes |
| docs.rs | same | yes |

The last two rows only work because `crates/vortix/Cargo.toml` duplicates `[profile.release]`.
Cargo ignores a profile in a non-root workspace member, so every workspace command prints
`profiles for the non root package will be ignored` — that noise is the price of the crates.io
install path getting the same binary as every other channel. **The two blocks must be kept in
sync by hand;** changing one without the other silently splits the install paths again.

## Where the binary goes

Attribution from an unstripped `--release` build of `crates/vortix` on `aarch64-apple-darwin`,
symbols mapped to crates by mangled prefix. Measured before the changes below:

| Section | Bytes | Share |
|---|---:|---:|
| `__TEXT.__text` | 8,100,552 | 78% |
| `__TEXT.__eh_frame` | 718,656 | 7% |
| `__TEXT.__const` | 616,776 | 6% |
| `__TEXT.__gcc_except_tab` | 361,516 | 3% |
| `__DATA_CONST.__const` | 287,520 | 3% |
| `__TEXT.__unwind_info` | 118,888 | 1% |

Top `__text` contributors:

| Origin | Bytes | Note |
|---|---:|---|
| `vortix` | 2,174,616 | our own non-test code |
| `core` + `alloc` + `std` | 1,885,192 | generics we instantiate, not dead weight |
| serde derive machinery | ~800,000 | ~280 `Deserialize` + ~300 `Serialize` derives, 23 internally-tagged enums |
| `clap_builder` + `clap_complete` | 221,664 | |
| `rustls` + `ring` + `webpki` | 214,376 | required — every telemetry endpoint is `https://` |
| `tokio` | 207,424 | |
| `regex-automata` + `regex-syntax` | 174,692 | **removed**, see below |
| backtrace stack (`gimli`/`addr2line`/`backtrace`/`rustc-demangle`) | 131,404 | color-eyre's error reports |

The serde share is inherent to a JSON control protocol with ~280 typed messages, and the TLS
share is required by the endpoints in `constants.rs`. Neither is a lever.

## Levers pulled

### `opt-level = "z"` (was `3`)

| opt-level | `vortix` | all three binaries |
|---|---:|---:|
| `3` | 9,947,104 | 11,415,392 |
| `2` | 9,633,344 | 11,085,120 |
| `s` | 8,017,312 | 9,287,024 |
| `z` | **6,039,184** | **7,178,832** |

Runtime-neutral, measured as an interleaved A/B against `main` on an idle machine (3 reps,
40/25 invocations each). Vortix has no sustained compute: a 1-second TUI tick, 25 ms flip
animation frames, and a VPN data plane that lives in `wg-quick`/`openvpn` subprocesses.

| Invocation | main (`opt-level = 3`) | branch (`opt-level = "z"`) |
|---|---:|---:|
| `vortix --version` | 4.59 ms | 4.53 ms |
| `vortix --help` | 4.67 ms | 4.61 ms |
| `vortix completions bash` | 40.11 ms | 40.75 ms |
| `vortix list` | 38.90 ms | 39.28 ms |

Differences are inside run-to-run spread. Do not repeat this measurement on a loaded machine —
a first attempt at load average 57 produced a spurious 3x "improvement" in both directions.
`tests/cold_start.rs` holds a 500 ms release ceiling independently.

### `panic = "abort"` — deliberately NOT set

It would drop most of the 1.2 MB of unwind tables, and it is off the table: `catch_unwind` is
load-bearing. A panic inside a tunnel operation (`tunnel.rs`,
`vortix_protocol_wireguard/tunnel.rs`), a control-worker job (`vortix_core/control/worker.rs`),
a lifecycle hook (`hooks/runner.rs`) or a background task (`background.rs`) is caught and turned
into an error rather than killing a process that holds kill-switch state. Aborting there trades
a firewall-safety guarantee for binary size.

### `[profile.dist]` no longer overrides `lto = "thin"`

It now inherits `lto = true` from `release`, so shipped artifacts get fat LTO. The cost is a
slower release build across the six target triples in `dist-workspace.toml`; the Release
workflow has no `timeout-minutes`, so there is headroom, but a tag build will take noticeably
longer than it used to. `[profile.dist]` is written by `dist init` — if cargo-dist is ever
re-initialised it will try to put `lto = "thin"` back, and that must be rejected in review.

### Dependency features that were never used

| Change | Left the graph |
|---|---|
| `tracing-subscriber` without `env-filter` | `matchers`, `regex-automata`, `regex-syntax` |
| `color-eyre` without `capture-spantrace` | `color-spantrace`, `tracing-error` |
| `ratatui` with `default-features = false` | `ratatui-macros`, the unused Calendar widget |
| `time` without `macros` | `time-macros` |
| `xtask` without `clap` and `ignore` | `ignore`, `globset`, `walkdir`, `bstr`, `same-file`, `winapi-util`, `crossbeam-{deque,epoch,utils}` |

`env-filter` is the notable one: it pulls a regex engine so `RUST_LOG` can carry span and field
directives. Vortix documents and uses only `RUST_LOG=<target>=<level>`, which
`tracing_subscriber::filter::Targets` parses identically without a regex engine. What is lost is
the `[span]` and `{field=value}` directive syntax, which nothing in the repo uses.

`Targets` does differ from `EnvFilter` in one place that bit us: it parses an empty directive as
a global `ERROR` level, where `EnvFilter` dropped empty segments. `main.rs::log_filter` strips
them before parsing, and five tests in `main.rs` hold that line — without them `RUST_LOG=` or a
trailing comma paints error output over the alternate screen.

## Levers considered and rejected

- **Dropping `figment`** for hand-rolled layering. Worth ~60 KB at `opt-level = "z"`, and
  re-implementing `Env::prefixed("VORTIX_").split("__")` coercion exactly is the kind of change
  that silently breaks a user's `VORTIX_*` override.
- **`native-tls` instead of `rustls`.** Drops `ring` + `webpki-roots`, breaks the static musl
  artifacts `dist-workspace.toml` ships.
- **Splitting `crates/vortix` into several crates** to parallelise `cargo check`. Reverses a
  deliberate decision — those boundaries are enforced by `cargo xtask check-*-leak` now.

## Test-target layout

`crates/vortix/tests/` held 22 top-level `*.rs` files, so cargo built and linked 22 test binaries
against the whole `vortix` rlib. Seventeen are now modules of one `tests/suite/main.rs`.

Five stay as their own targets:

| Suite | Why |
|---|---|
| `cli_integration.rs` | mutates `VORTIX_CONFIG_DIR` process-wide |
| `tunnel_custodian.rs` | mutates `VORTIX_CUSTODIAN_*` process-wide |
| `integration.rs` | installs a process-global config dir; its profile store has a 500 ms lock budget |
| `control_diagnostics.rs` | flaked when merged |
| `cold_start.rs` | asserts a wall-clock startup ceiling |

That list is empirical, not theoretical. The first version of the merge put `integration.rs` and
`control_diagnostics.rs` in the shared binary and both flaked within three runs — the profile
store's 500 ms lock times out when the holding thread is descheduled under ~245-way concurrency.

Modules that remain **do** use second-scale `tokio::time::timeout` hang-guards, and
`control_reconcile.rs` has two `elapsed() < 250ms` assertions. Those held over 10 consecutive
runs under 8x CPU oversubscription. If one starts flaking on CI, move that module back to a
top-level `tests/*.rs` rather than raising its budget.

**Adding a test file:** if it touches `std::env::set_var`, `config::set_config_dir`, a fixed port
or path, or asserts wall-clock duration, leave it at the top level of `tests/`. Otherwise put it
in `tests/suite/` and add a `mod` line to `tests/suite/main.rs` — a file in that directory with
no `mod` line compiles into nothing and its tests silently stop running.

## Numbers

Cold-target, interleaved A/B against `main` so background load hits both variants equally.
CPU time is the load-robust figure; wall time is what you feel.

| Step | main (wall) | branch (wall) | main (CPU) | branch (CPU) |
|---|---:|---:|---:|---:|
| `cargo check --workspace --all-targets` | 113.9 s | 109.1 s | 211.5 s | 198.4 s |
| `cargo clippy --workspace --all-targets` | 105.1 s | 101.1 s | 229.4 s | 208.3 s |
| `cargo test --workspace --no-run` | 175.4 s | 116.6 s | 560.1 s | 369.3 s |

Both sides built with `cargo build --release --locked` on `aarch64-apple-darwin`,
branch against `main` at `268b821`.

| Binary | main | branch | Delta |
|---|---:|---:|---:|
| `vortix` | 10,443,856 B | 6,039,184 B | **-42.2%** |
| `vortix-helper` | 1,015,440 B | 769,904 B | -24.2% |
| `vortix-bootstrap` | 452,848 B | 369,744 B | -18.4% |
| shipped total | 11,912,144 B | 7,178,832 B | **-39.7%** |

## Keeping the win

Every number above comes from profile settings, which is what makes them fragile: restoring
`opt-level = 3`, or letting `dist init` put `lto = "thin"` back into `[profile.dist]`, costs
megabytes and fails no test. Nothing in the suite reads a file size.

`Integration / macos-release` closes that. It builds `--release` on `macos-latest` and runs
`tests/integration/release_smoke.sh`, which enforces a **7,000,000 B ceiling on `vortix`** —
about 16% of headroom over the 6,039,184 B measured above. A profile regression blows through
it immediately; ordinary feature growth has room.

The job runs on macOS because that was the gap. `cargo test` builds dev, and every netns suite
is Linux-only, so before this job no CI anywhere executed a macOS release binary: a profile
that miscompiled or failed to link there would have surfaced first at tag time, mid-release.
The budget is calibrated for `aarch64-apple-darwin`, which is what `macos-latest` runs — a
different target has a different figure, which is why the check is opt-in via
`VORTIX_SIZE_BUDGET_BYTES` rather than hardcoded.

The script also pins the contracts that a size-driven profile change could plausibly break
without failing a unit test: all three binaries reporting the same version, `--json` keeping
stdout free of diagnostics, kill-switch verb parsing rejecting aliases, and an unprivileged
launch exiting 2 with an actionable message instead of hanging.

When the budget trips, decide — don't reflexively raise the number. Confirm the growth is
real work rather than a reverted profile knob, then move the ceiling in the same commit that
justifies it.

```sh
cargo build --release -p vortix --locked
VORTIX_SIZE_BUDGET_BYTES=7000000 bash tests/integration/release_smoke.sh
```
