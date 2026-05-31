#!/usr/bin/env bash
# scripts/investigate-tui-hang.sh
#
# One-shot investigation harness for TUI-stutter / hang reports.
#
# What it does:
#   1. Kills any leftover vortix / openvpn from a previous run.
#   2. Clears the trace file at a known path.
#   3. Rebuilds vortix so the binary matches the code being investigated.
#   4. Launches vortix as root with RUST_LOG=vortix=warn — the production
#      observability hook fires `ui-handler slow: <variant> elapsed_ms=<N>`
#      for any Message handler that blocks the UI thread >50ms.
#   5. After you quit (Ctrl+C in the vortix terminal), automatically
#      summarises the findings: top slow handlers by count + by longest
#      single elapsed, plus a sanity-check of any still-running VPN
#      processes.
#
# Usage:
#   bash scripts/investigate-tui-hang.sh
#
# Then inside the TUI:
#   - Reproduce the stutter / hang.
#   - Press `q` (or Ctrl+C the cargo terminal) when done.
#   - The summary prints to your terminal and the raw trace stays at
#     /tmp/vortix-investigation.log for Claude to read.

set -u
TRACE=/tmp/vortix-investigation.log
SLOW_THRESHOLD_MS=50

# ── Colours (no-op if stdout isn't a tty) ─────────────────────────────────
if [ -t 1 ]; then
    CYAN=$'\033[36m'; GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    CYAN=''; GREEN=''; RED=''; YELLOW=''; DIM=''; BOLD=''; RESET=''
fi
step() { printf '%s==>%s %s\n' "$CYAN" "$RESET" "$*"; }
ok()   { printf '%s ✓%s  %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s ⚠%s  %s\n' "$YELLOW" "$RESET" "$*"; }
fail() { printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2; }

# ── Prereqs ───────────────────────────────────────────────────────────────
if [ ! -f Cargo.toml ] || ! grep -q '"crates/vortix"' Cargo.toml 2>/dev/null; then
    fail "Run this from the repo root (where Cargo.toml lives)."
    exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
    fail "sudo not available — vortix needs root to spawn openvpn / wg-quick."
    exit 1
fi

step "Step 1 / 5 — killing any leftover vortix + openvpn processes"
sudo pkill -9 vortix    2>/dev/null || true
sudo pkill    openvpn   2>/dev/null || true
sudo pkill    wg-quick  2>/dev/null || true
sleep 1
LEFTOVER=$(ps -axo pid,command | grep -E 'vortix|openvpn|wg-quick' | grep -v grep | grep -v investigate-tui-hang || true)
if [ -n "$LEFTOVER" ]; then
    warn "Some processes survived pkill (may need manual cleanup):"
    printf '%s\n' "$LEFTOVER" | sed 's/^/    /'
else
    ok "no orphan processes"
fi

step "Step 2 / 5 — clearing trace file at $TRACE"
: > "$TRACE"
chmod 666 "$TRACE"
ok "$TRACE ready"

step "Step 3 / 5 — building vortix (this output stays on terminal)"
if ! cargo build --quiet 2>&1; then
    fail "build failed; aborting before launch"
    exit 1
fi
ok "build complete"

# Snapshot pre-launch system state so the summary can compare.
ps -axo pid,command 2>/dev/null | grep -E 'vortix|openvpn|wg-quick' | grep -v grep > /tmp/vortix-investigation-pre.txt || true

step "Step 4 / 5 — launching vortix with RUST_LOG=vortix=warn"
cat <<'BANNER'

  Now drive the TUI to reproduce the stutter / hang:
    - Connect to the profile that triggers the issue (ovpn-cert).
    - Tab around, observe lag.
    - Press `q` (or Ctrl+C in this terminal) when you're done.

  Tracing is capturing every Message handler that holds the UI thread
  longer than 50ms — that's the signal we need to find what's still
  blocking. Don't worry about timing; just reproduce the bug naturally.

BANNER

# Run vortix in the foreground; stderr → trace file, stdout (TUI) stays
# on the terminal. `set +e` so we control the post-mortem regardless of
# how vortix exits (clean quit, panic, Ctrl+C).
set +e
sudo env RUST_LOG='vortix=warn' ./target/debug/vortix 2>>"$TRACE"
EXIT_CODE=$?
set -e

step "Step 5 / 5 — analysing trace"
printf '\n'

# ── Trace size ────────────────────────────────────────────────────────────
LINE_COUNT=$(wc -l < "$TRACE" | tr -d ' ')
printf '%sTrace file%s: %s (%s lines, exit code %s)\n' "$BOLD" "$RESET" "$TRACE" "$LINE_COUNT" "$EXIT_CODE"

# ── SLOW-handler summary ──────────────────────────────────────────────────
SLOW_LINES=$(grep -E 'ui-handler slow' "$TRACE" 2>/dev/null || true)
SLOW_COUNT=$(printf '%s' "$SLOW_LINES" | grep -c . || true)
SLOW_COUNT=${SLOW_COUNT:-0}

printf '\n%s── UI-handler slow events (threshold %sms) ──%s\n' "$BOLD" "$SLOW_THRESHOLD_MS" "$RESET"
if [ "$SLOW_COUNT" -eq 0 ]; then
    ok "no slow handlers fired — the UI thread was healthy throughout"
else
    warn "$SLOW_COUNT slow-handler events detected"
    printf '\n%sBy variant (frequency)%s:\n' "$BOLD" "$RESET"
    printf '%s' "$SLOW_LINES" \
        | grep -oE 'variant="[A-Za-z]+"' \
        | sort | uniq -c | sort -rn \
        | sed 's/^/    /'
    printf '\n%sLongest single elapsed times%s:\n' "$BOLD" "$RESET"
    printf '%s' "$SLOW_LINES" \
        | grep -oE 'variant="[A-Za-z]+" elapsed_ms=[0-9]+' \
        | sort -t= -k3 -rn \
        | head -10 \
        | sed 's/^/    /'
fi

# ── Stale-route-cache warnings ────────────────────────────────────────────
STALE_COUNT=$(grep -cE 'default-route cache is stale' "$TRACE" 2>/dev/null || echo 0)
STALE_COUNT=${STALE_COUNT:-0}
printf '\n%s── Default-route cache freshness ──%s\n' "$BOLD" "$RESET"
if [ "$STALE_COUNT" -eq 0 ]; then
    ok "scanner thread kept the cache fresh"
else
    warn "$STALE_COUNT stale-cache warnings (scanner thread falling behind)"
fi

# ── Post-mortem process state ─────────────────────────────────────────────
printf '\n%s── Surviving VPN processes after vortix exit ──%s\n' "$BOLD" "$RESET"
POST=$(ps -axo pid,ppid,stat,command 2>/dev/null | grep -E 'vortix|openvpn|wg-quick' | grep -v grep | grep -v investigate-tui-hang || true)
if [ -z "$POST" ]; then
    ok "no surviving processes"
else
    printf '%s\n' "$POST" | sed 's/^/    /'
fi

# ── Hand-off ──────────────────────────────────────────────────────────────
printf '\n%s── Hand-off ──%s\n' "$BOLD" "$RESET"
printf '  Raw trace:    %s\n' "$TRACE"
printf '  Pre-launch:   %s\n' "/tmp/vortix-investigation-pre.txt"
printf '  Lines:        %s\n' "$LINE_COUNT"
printf '  Slow events:  %s\n' "$SLOW_COUNT"
printf '  Stale events: %s\n' "$STALE_COUNT"
printf '\n%sTell Claude "done" — the raw trace at %s has everything Claude needs.%s\n\n' "$DIM" "$TRACE" "$RESET"
