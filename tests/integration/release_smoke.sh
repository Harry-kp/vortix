#!/usr/bin/env bash
# Release-profile smoke test.
#
# Everything else in CI builds dev. The netns suites are Linux-only and
# Test (macos-latest) is a `cargo test`, so before this script no job anywhere
# ran a macOS release binary — a profile that miscompiled or failed to link
# would have surfaced first at tag time.
#
# Unprivileged and dependency-free by necessity: no jq, no python, no GNU
# `timeout`. It runs on a bare macOS runner.
#
#   VORTIX_BIN_DIR            binary directory (default target/release)
#   VORTIX_SIZE_BUDGET_BYTES  when set, ceiling for the vortix binary. Opt-in
#                             because the figure is per-target; see
#                             docs/performance.md.

set -euo pipefail

BIN_DIR="${VORTIX_BIN_DIR:-target/release}"
VORTIX="$BIN_DIR/vortix"
HELPER="$BIN_DIR/vortix-helper"
BOOTSTRAP="$BIN_DIR/vortix-bootstrap"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export VORTIX_CONFIG_DIR="$WORK/config"
mkdir -p "$VORTIX_CONFIG_DIR"

for bin in "$VORTIX" "$HELPER" "$BOOTSTRAP"; do
    [ -x "$bin" ] || fail "missing or non-executable release binary: $bin"
done

# --- version agreement -------------------------------------------------------
#
# A stale artifact left in target/ from an earlier build is invisible until
# something reads the version back, and all three ship together.

workspace_version="$(
    sed -n '/^\[workspace\.package\]/,/^\[/p' Cargo.toml |
        sed -n 's/^version = "\([^"]*\)".*/\1/p' | head -1
)"
[ -n "$workspace_version" ] || fail "could not read version from [workspace.package] in Cargo.toml"

for bin in "$VORTIX" "$HELPER" "$BOOTSTRAP"; do
    out="$("$bin" --version 2>/dev/null)" || fail "$bin --version exited non-zero"
    case "$out" in
    *"$workspace_version"*) ;;
    *) fail "$bin reported '$out', expected version $workspace_version" ;;
    esac
done

"$VORTIX" --help >/dev/null 2>&1 || fail "vortix --help exited non-zero"
"$VORTIX" killswitch --help >/dev/null 2>&1 || fail "vortix killswitch --help exited non-zero"

# --- `--json` stdout contract ------------------------------------------------
#
# Machine consumers pipe stdout straight into a parser. Diagnostics such as the
# orphan-process warning must stay on stderr; one stray println here silently
# breaks every scripted caller. Checking the first byte is `{` catches that
# without needing a JSON parser in the container images.

for cmd in list status; do
    out="$("$VORTIX" "$cmd" --json 2>/dev/null)" || fail "vortix $cmd --json exited non-zero"
    case "$out" in
    "{"*) ;;
    *) fail "vortix $cmd --json stdout does not begin with '{' — diagnostics leaked to stdout" ;;
    esac
    case "$out" in
    *'"schema_version": 2'*) ;;
    *) fail "vortix $cmd --json is missing schema_version 2" ;;
    esac
    case "$out" in
    *'"ok": true'*) ;;
    *) fail "vortix $cmd --json did not report ok" ;;
    esac
done

# --- kill-switch vocabulary --------------------------------------------------
#
# One vocabulary on every surface, no aliases (CLAUDE.md). Verb parsing happens
# before the privilege check, so a rejected alias is assertable unprivileged.

if rejection="$("$VORTIX" killswitch auto 2>&1)"; then
    fail "vortix killswitch auto was accepted; 'auto' is not a valid verb"
fi
case "$rejection" in
*"off, block-on-drop, vpn-only"*) ;;
*) fail "rejection did not offer the canonical verbs, got: $rejection" ;;
esac

"$VORTIX" killswitch >/dev/null 2>&1 || fail "read-only 'vortix killswitch' exited non-zero"

completions="$("$VORTIX" completions bash 2>/dev/null)" || fail "vortix completions bash exited non-zero"
case "$completions" in
*"_vortix()"*) ;;
*) fail "bash completions do not define _vortix()" ;;
esac

# --- unprivileged launch -----------------------------------------------------
#
# Without root the TUI must refuse with a short actionable message and exit 2,
# not a privilege-chain backtrace and not a hang. Skipped as root, where this
# call legitimately launches the dashboard and would block forever — the Linux
# harness containers run as root.

if [ "$(id -u)" -ne 0 ]; then
    "$VORTIX" </dev/null >"$WORK/tui.out" 2>"$WORK/tui.err" &
    tui_pid=$!

    waited=0
    while kill -0 "$tui_pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    if kill -0 "$tui_pid" 2>/dev/null; then
        kill -9 "$tui_pid" 2>/dev/null
        wait "$tui_pid" 2>/dev/null || true
        fail "unprivileged launch hung for ${waited}s instead of refusing"
    fi

    tui_rc=0
    wait "$tui_pid" || tui_rc=$?
    [ "$tui_rc" -eq 2 ] || fail "unprivileged launch exited $tui_rc, expected 2 (permission denied)"

    grep -q "sudo vortix" "$WORK/tui.err" ||
        fail "unprivileged launch did not tell the user to retry with sudo"
    if grep -qiE "invalid invoking owner|backtrace|panicked" "$WORK/tui.err"; then
        fail "unprivileged launch leaked an internal error chain"
    fi
fi

# --- binary size budget ------------------------------------------------------
#
# The size win is a profile setting, so it regresses silently: restoring
# opt-level = 3, or letting `dist init` put back lto = "thin", costs megabytes
# and breaks nothing a test would notice.

if [ -n "${VORTIX_SIZE_BUDGET_BYTES:-}" ]; then
    size="$(wc -c <"$VORTIX" | tr -d ' ')"
    if [ "$size" -gt "$VORTIX_SIZE_BUDGET_BYTES" ]; then
        fail "vortix is ${size} B, over the ${VORTIX_SIZE_BUDGET_BYTES} B budget — see docs/performance.md"
    fi
    echo "  size: ${size} B (budget ${VORTIX_SIZE_BUDGET_BYTES} B)"
fi

echo "OK: release binaries link, run, and hold their CLI contracts"
