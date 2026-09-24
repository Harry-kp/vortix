#!/bin/bash

# Vortix Git Pre-commit Hook
# Mirrors CI checks to ensure only clean code is committed.

set -e

echo "🔍 Running pre-commit checks..."

# 1. Check Formatting
echo "🎨 Checking formatting (cargo fmt)..."
cargo fmt --all -- --check

# 2. Run Clippy
# --workspace --all-targets, not bare `cargo clippy`: clippy::pedantic is
# enabled workspace-wide, so test code gets pedantic lints too and a bare run
# never sees them. See Trap 1 in docs/ci-parity.md.
echo "📎 Running linter (cargo clippy)..."
cargo clippy --workspace --all-targets -- -D warnings

# 3. Secrets: profiles carry private keys; never let one into history.
if command -v gitleaks >/dev/null 2>&1; then
    echo "🔐 Scanning staged changes for secrets (gitleaks)..."
    gitleaks protect --staged --redact
fi

# 4. Run Tests
echo "🧪 Running tests (cargo test)..."
cargo test --workspace

echo "✅ All checks passed! Proceeding with commit."
exit 0
