# Running what CI runs

```bash
scripts/ci-local.sh            # before every push
scripts/ci-local.sh --quick    # same without the release build, while iterating
```

It must end with `All checks passed.` What each CI job needs locally:

| CI job (workflow) | Local equivalent |
|---|---|
| Format (`lint.yml`) | `cargo fmt --all -- --check` |
| Clippy macOS / ubuntu (`lint.yml`) | `cargo clippy --workspace --all-targets -- -D warnings`, plus the Linux-target clippy below |
| Docs (`lint.yml`) | `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` |
| Test macOS / ubuntu / fedora-41 (`test.yml`) | `cargo test --workspace` on the Mac; Linux-only code runs on the lab (`cargo test -p vortix`) |
| Boundary (`boundary.yml`) | `cargo xtask` `check-subprocess`, `check-platform-leak`, `check-protocol-leak`, `check-no-shell-regressions`, `check-docs` |
| Integration / macos-release (`integration-tests.yml`) | the release build and `tests/integration/release_smoke.sh` (size budget 7,000,000 B) |
| Integration / ubuntu-22.04, fedora-41 (`integration-tests.yml`) | Docker only; see [tests/integration](../tests/integration/README.md) |
| Security Audit (`security.yml`) | `cargo deny check`, not in `ci-local.sh` |
| Nix flake check (`nix.yml`) | `nix flake check`, not in `ci-local.sh` |

`ci-local.sh` runs everything above it in the table except the Linux runs of the tests.

## Traps

- **`--all-targets` and `--workspace` matter.** `cargo clippy -p vortix --lib` skips test code
  and the `xtask` crate, which CI lints.
- **Linux-only code is invisible to a macOS build.** `ci-local.sh` also runs clippy and rustdoc
  for `x86_64-unknown-linux-gnu` when that target is installed
  (`rustup target add x86_64-unknown-linux-gnu`; it cross-compiles with the macOS SDK's
  clang). Without it, a `cfg(target_os = "linux")` mistake shows up only in CI.
- **`cargo clippy` does not run rustdoc lints.** A broken intra-doc link fails only in
  `cargo doc` with `-D warnings`.
- **`cargo fmt` without `--all`** checks one package, not the workspace.

## Docs-only PRs

Changes that touch only Markdown, `LICENSE` or the changelog skip Test, Lint, Security and
Integration through `paths-ignore`; Nix runs only when the flake, the Cargo files or `crates/` change.
Boundary always runs, because `check-docs` covers Markdown: every link and heading anchor
resolves, every CLI subcommand and flag is in `docs/usage.md`, and every `config.toml` and
`settings.toml` key is in `docs/configuration.md`.
