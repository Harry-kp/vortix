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
step "xtask";     for check in check-subprocess check-platform-leak check-protocol-leak check-no-shell-regressions; do
                    cargo xtask "$check"
                  done

if [[ "$(uname)" == "Darwin" ]] && rustup target list --installed | grep -q x86_64-unknown-linux-gnu; then
  step "clippy (linux target)"
  sdk=$(xcrun --show-sdk-path)
  CC_x86_64_unknown_linux_gnu=clang AR_x86_64_unknown_linux_gnu=ar \
  CFLAGS_x86_64_unknown_linux_gnu="--target=x86_64-unknown-linux-gnu -isystem $sdk/usr/include" \
    cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
else
  step "clippy (linux target) skipped: run 'rustup target add x86_64-unknown-linux-gnu' on macOS"
fi

if ! $quick; then
  step "release build"; cargo build --release -p vortix --locked
fi

printf '\nAll checks passed.\n'
