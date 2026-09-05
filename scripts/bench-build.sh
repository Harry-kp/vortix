#!/usr/bin/env bash
# scripts/bench-build.sh
#
# Re-measures the build-time and binary-size budget recorded in
# docs/performance.md. Every step starts from an empty target/ so the numbers
# describe a cold CI runner, not a warm laptop.
#
# Usage: scripts/bench-build.sh [output-file]
#
# Takes ~30 minutes and rebuilds from an empty target/ eight times. Run it on an
# idle machine — a parallel build skews every timing in the table.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
OUT="${1:-/dev/stdout}"

# Each cold build peaks around 5 GB. Filling the disk mid-run leaves a half-built
# target/ and an unusable shell, so refuse up front rather than halfway through.
REQUIRED_GB=12
available_gb=$(df -Pk . | awk 'NR==2 {print int($4 / 1048576)}')
if [ "${available_gb:-0}" -lt "$REQUIRED_GB" ]; then
    echo "bench-build: need ~${REQUIRED_GB}G free, have ${available_gb}G. Free space first." >&2
    exit 1
fi

: > "$OUT"

now() { python3 -c 'import time; print(time.time())'; }

step() { # step <label> <command...>
    local label="$1"
    shift
    local start end rc
    start=$(now)
    "$@" > /tmp/vortix-bench-step.log 2>&1
    rc=$?
    end=$(now)
    printf '%-42s %8.2fs  rc=%d\n' "$label" "$(python3 -c "print($end - $start)")" "$rc" >> "$OUT"
    if [ "$rc" -ne 0 ]; then
        {
            echo "---- failing output: $label ----"
            tail -40 /tmp/vortix-bench-step.log
            echo "---- end ----"
        } >> "$OUT"
    fi
}

{
    echo "host:     $(uname -sm), $(sysctl -n hw.ncpu 2>/dev/null || nproc) cores"
    echo "toolchain: $(rustc --version)"
    echo "commit:   $(git rev-parse --short HEAD)"
    echo "date:     $(date -u +%FT%TZ)"
    echo
} >> "$OUT"

rm -rf target
step "release build (cold)" cargo build --release
{
    echo "-- release binary sizes --"
    total=0
    for binary in vortix vortix-helper vortix-bootstrap; do
        path="target/release/$binary"
        [ -f "$path" ] || continue
        bytes=$(wc -c < "$path" | tr -d ' ')
        total=$((total + bytes))
        printf '  %-20s %10d bytes\n' "$binary" "$bytes"
    done
    printf '  %-20s %10d bytes\n' "TOTAL" "$total"
} >> "$OUT"

rm -rf target
step "dist build (cold, fat LTO, shipped)" cargo build --profile dist
if [ -f target/dist/vortix ]; then
    printf '  %-20s %10d bytes\n' "vortix (dist)" "$(wc -c < target/dist/vortix | tr -d ' ')" >> "$OUT"
fi

rm -rf target
step "check --workspace --all-targets (cold)" cargo check --workspace --all-targets
rm -rf target
step "clippy --workspace --all-targets (cold)" cargo clippy --workspace --all-targets -- -D warnings
rm -rf target
step "test --workspace (cold, build + run)" cargo test --workspace
step "test --workspace (warm, run only)" cargo test --workspace
step "fmt --all --check" cargo fmt --all -- --check
rm -rf target
step "doc --workspace --no-deps (cold)" env RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps
rm -rf target
for task in check-subprocess check-platform-leak check-protocol-leak \
            check-no-shell-regressions check-control-boundaries; do
    step "xtask $task" cargo xtask "$task"
done
