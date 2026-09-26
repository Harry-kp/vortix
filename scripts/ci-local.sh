#!/usr/bin/env bash
# Run what CI runs, in the order CI fails fastest. See docs/ci-parity.md.
#   scripts/ci-local.sh            full set (macOS + Linux cross-clippy)
#   scripts/ci-local.sh --quick    skip the release build
set -euo pipefail
cd "$(dirname "$0")/.."

quick=false
[[ "${1:-}" == "--quick" ]] && quick=true

step() { printf '\n==> %s\n' "$*"; }

step "fmt";       cargo fmt --all -- --check
step "clippy";    cargo clippy --workspace --all-targets -- -D warnings
step "test";      cargo test --workspace
step "doc";       RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
step "xtask";     for check in check-subprocess check-platform-leak check-protocol-leak check-no-shell-regressions check-docs; do
                    cargo xtask "$check"
                  done

if [[ "$(uname)" == "Darwin" ]] && rustup target list --installed | grep -q x86_64-unknown-linux-gnu; then
  sdk=$(xcrun --show-sdk-path)
  export CC_x86_64_unknown_linux_gnu=clang AR_x86_64_unknown_linux_gnu=ar
  export CFLAGS_x86_64_unknown_linux_gnu="--target=x86_64-unknown-linux-gnu -isystem $sdk/usr/include"
  step "clippy (linux target)"
  cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
  step "doc (linux target)"
  RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --target x86_64-unknown-linux-gnu
else
  step "clippy (linux target) skipped: run 'rustup target add x86_64-unknown-linux-gnu' on macOS"
fi

if ! $quick; then
  step "release build"; cargo build --release -p vortix --locked
  # Same budget CI enforces on aarch64-apple-darwin (integration-tests.yml).
  step "release smoke"; VORTIX_SIZE_BUDGET_BYTES=7000000 bash tests/integration/release_smoke.sh
fi

printf '\nAll checks passed.\n'
