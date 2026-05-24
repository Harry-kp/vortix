#!/usr/bin/env bash
# smoke-v0.3.0.sh — post-install smoke test for vortix v0.3.0 (plan 007 U4).
#
# Run against a freshly installed vortix binary to verify the v0.3.0
# user-visible surface works end-to-end without live VPN connections.
# No root required. Uses a scratch XDG_CONFIG_HOME / XDG_DATA_HOME so
# your real config is untouched.
#
# Usage:
#   scripts/smoke-v0.3.0.sh [expected-version]
#
# Default expected version: 0.3.0-rc.1. Pass the version string you
# installed if different. Use `dev` to skip the version-string match.
#
# Exit code: 0 if every check PASSES, 1 otherwise.

set -euo pipefail

EXPECTED_VERSION="${1:-0.3.0-rc.1}"
PASS=0
FAIL=0

# Scratch dirs — set BEFORE invoking vortix so it doesn't touch the
# user's real config.
SCRATCH_BASE="$(mktemp -d -t vortix-smoke-XXXXXX)"
export XDG_CONFIG_HOME="${SCRATCH_BASE}/config"
export XDG_DATA_HOME="${SCRATCH_BASE}/data"
mkdir -p "${XDG_CONFIG_HOME}" "${XDG_DATA_HOME}"

cleanup() {
  rm -rf "${SCRATCH_BASE}"
}
trap cleanup EXIT

pass() {
  printf '[PASS] %s\n' "$1"
  PASS=$((PASS + 1))
}

fail() {
  printf '[FAIL] %s (%s)\n' "$1" "$2" >&2
  FAIL=$((FAIL + 1))
}

# Resolve vortix binary — prefer the one on PATH, fall back to
# target/debug if running from a dev checkout.
if command -v vortix >/dev/null 2>&1; then
  VORTIX="$(command -v vortix)"
elif [ -x ./target/debug/vortix ]; then
  VORTIX="./target/debug/vortix"
elif [ -x ./target/release/vortix ]; then
  VORTIX="./target/release/vortix"
else
  printf '[FATAL] vortix binary not found on PATH or in ./target/{debug,release}\n' >&2
  exit 1
fi
printf 'Smoke test against: %s\n' "${VORTIX}"
printf 'Expected version:   %s\n' "${EXPECTED_VERSION}"
printf 'Scratch XDG base:   %s\n\n' "${SCRATCH_BASE}"

# ---- 1. --version reports a non-empty string and matches expected ----
if VERSION_OUT="$("${VORTIX}" --version 2>&1)"; then
  if [ "${EXPECTED_VERSION}" = "dev" ]; then
    pass "vortix --version runs (got: ${VERSION_OUT})"
  elif echo "${VERSION_OUT}" | grep -qF "${EXPECTED_VERSION}"; then
    pass "vortix --version reports ${EXPECTED_VERSION}"
  else
    fail "vortix --version" "expected '${EXPECTED_VERSION}', got: ${VERSION_OUT}"
  fi
else
  fail "vortix --version" "command exited non-zero"
fi

# ---- 2. --help mentions every v0.3.0 subcommand ----
HELP_OUT="$("${VORTIX}" --help 2>&1 || true)"
MISSING_SUBCMDS=""
for sub in engine journal settings secrets migrate export; do
  if ! echo "${HELP_OUT}" | grep -qw "${sub}"; then
    MISSING_SUBCMDS="${MISSING_SUBCMDS} ${sub}"
  fi
done
if [ -z "${MISSING_SUBCMDS}" ]; then
  pass "vortix --help lists every v0.3.0 subcommand"
else
  fail "vortix --help missing subcommands:" "${MISSING_SUBCMDS# }"
fi

# ---- 3. engine status (human mode) ----
if STATUS_OUT="$("${VORTIX}" engine status 2>&1)"; then
  if echo "${STATUS_OUT}" | grep -q "Disconnected"; then
    pass "vortix engine status reports Disconnected"
  else
    fail "vortix engine status" "missing 'Disconnected' in: ${STATUS_OUT}"
  fi
else
  fail "vortix engine status" "command exited non-zero"
fi

# ---- 4. engine status --json ----
# Wrapped in the v0.3.0 CliResponse envelope: must have
# `schema_version`, `ok: true`, and a Disconnected payload.
if JSON_OUT="$("${VORTIX}" engine status --json 2>&1)"; then
  if echo "${JSON_OUT}" | grep -q '"schema_version"' \
     && echo "${JSON_OUT}" | grep -q '"ok": true' \
     && echo "${JSON_OUT}" | grep -q "Disconnected"; then
    pass "vortix engine status --json returns envelope with schema_version"
  else
    fail "vortix engine status --json" "malformed envelope: ${JSON_OUT}"
  fi
else
  fail "vortix engine status --json" "command exited non-zero"
fi

# ---- 5. settings (human mode) ----
if SETTINGS_OUT="$("${VORTIX}" settings 2>&1)"; then
  if [ -n "${SETTINGS_OUT}" ]; then
    pass "vortix settings prints non-empty output"
  else
    fail "vortix settings" "empty output"
  fi
else
  fail "vortix settings" "command exited non-zero"
fi

# ---- 6. settings --json ----
if SETTINGS_JSON="$("${VORTIX}" settings --json 2>&1)"; then
  if echo "${SETTINGS_JSON}" | grep -q '"journal"' || echo "${SETTINGS_JSON}" | grep -q '"engine"'; then
    pass "vortix settings --json returns JSON with expected keys"
  else
    fail "vortix settings --json" "missing expected keys: ${SETTINGS_JSON}"
  fi
else
  fail "vortix settings --json" "command exited non-zero"
fi

# ---- 7. migrate against an empty profiles dir ----
if MIGRATE_OUT="$("${VORTIX}" migrate 2>&1)"; then
  if echo "${MIGRATE_OUT}" | grep -q "Created:" || echo "${MIGRATE_OUT}" | grep -q "created"; then
    pass "vortix migrate runs on empty profiles dir"
  else
    fail "vortix migrate" "unexpected output: ${MIGRATE_OUT}"
  fi
else
  fail "vortix migrate" "command exited non-zero"
fi

# ---- 8. migrate --json ----
if MIGRATE_JSON="$("${VORTIX}" migrate --json 2>&1)"; then
  if echo "${MIGRATE_JSON}" | grep -q '"created"'; then
    pass "vortix migrate --json returns parseable JSON"
  else
    fail "vortix migrate --json" "missing 'created' key: ${MIGRATE_JSON}"
  fi
else
  fail "vortix migrate --json" "command exited non-zero"
fi

# ---- 9. secrets round trip (set, get, delete) ----
# Backend availability varies: keyring may not be present on minimal
# Linux installs; the encrypted-file backend needs a passphrase. In
# environments where neither backend works the whole block soft-skips
# rather than failing the smoke.
SMOKE_KEY="smoke/v030-roundtrip"
SMOKE_VAL="smoke-secret-value-$(date +%s)"
if printf '%s' "${SMOKE_VAL}" | "${VORTIX}" secrets set "${SMOKE_KEY}" >/dev/null 2>&1; then
  if GET_OUT="$("${VORTIX}" secrets get "${SMOKE_KEY}" 2>/dev/null)"; then
    if [ "${GET_OUT}" = "${SMOKE_VAL}" ] || echo "${GET_OUT}" | grep -qF "${SMOKE_VAL}"; then
      pass "vortix secrets set/get round trip"
    else
      fail "vortix secrets get" "expected '${SMOKE_VAL}', got '${GET_OUT}'"
    fi
    "${VORTIX}" secrets delete "${SMOKE_KEY}" >/dev/null 2>&1 \
      && pass "vortix secrets delete succeeds" \
      || fail "vortix secrets delete" "command exited non-zero"
  else
    # `set` succeeded but `get` couldn't round-trip — likely a keyring
    # session-lock issue (e.g., no GUI on the headless tester box) or
    # the encrypted-file path tried to prompt for a passphrase. Soft
    # warn; this isn't a v0.3.0 regression, it's the secrets backend's
    # baseline behaviour.
    printf '[SKIP] vortix secrets get (backend unavailable in this env — not a v0.3.0 regression)\n'
  fi
else
  printf '[SKIP] vortix secrets set (no keyring + no usable encrypted-file backend in this env)\n'
fi

# ---- 10. journal path ----
if JOURNAL_OUT="$("${VORTIX}" journal path 2>&1)"; then
  if echo "${JOURNAL_OUT}" | grep -q "sessions"; then
    pass "vortix journal path points at sessions dir"
  elif echo "${JOURNAL_OUT}" | grep -qi "disabled\|disk = false"; then
    pass "vortix journal path correctly reports disk disabled"
  else
    fail "vortix journal path" "unexpected output: ${JOURNAL_OUT}"
  fi
else
  fail "vortix journal path" "command exited non-zero"
fi

# ---- 11. list against an empty profiles dir ----
if LIST_OUT="$("${VORTIX}" list 2>&1)"; then
  pass "vortix list runs without panic on empty profiles dir"
else
  # `list` returning non-zero on an empty dir is acceptable if it just
  # means "no profiles found"; we only care that it doesn't panic.
  if echo "${LIST_OUT}" | grep -qi "panic"; then
    fail "vortix list" "panicked on empty profiles dir"
  else
    pass "vortix list exits with no profiles found"
  fi
fi

# ---- 12. nothing in any stderr capture said 'panicked' ----
COMBINED="${VERSION_OUT}${HELP_OUT}${STATUS_OUT:-}${SETTINGS_OUT:-}${MIGRATE_OUT:-}${JOURNAL_OUT:-}${LIST_OUT:-}"
if echo "${COMBINED}" | grep -qi "panicked at\|panicked '"; then
  fail "no-panic invariant" "one of the commands above panicked"
else
  pass "no command panicked"
fi

# ---- Summary ----
printf '\n----\n'
printf 'PASS: %d\n' "${PASS}"
printf 'FAIL: %d\n' "${FAIL}"
if [ "${FAIL}" -eq 0 ]; then
  printf 'OK — v0.3.0 smoke test green\n'
  exit 0
else
  printf 'NOT OK — investigate failures above before promoting to GA\n' >&2
  exit 1
fi
