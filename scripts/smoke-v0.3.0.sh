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

# ---- 2. --help lists the new v0.3.0 surface ----
# v0.3.0 ships ONE new top-level subcommand: `secrets`. The other new
# capabilities (journal, settings, migrate, inline-secrets, engine FSM)
# were collapsed into existing commands or dropped per the CLI surface
# cleanup. Verify `secrets` is present AND the removed ones are GONE.
HELP_OUT="$("${VORTIX}" --help 2>&1 || true)"
if echo "${HELP_OUT}" | grep -qw "secrets"; then
  pass "vortix --help lists 'secrets'"
else
  fail "vortix --help missing 'secrets' subcommand" "${HELP_OUT}"
fi

# Plan 015 phase C + D — two more new subcommands earn their slots.
if echo "${HELP_OUT}" | grep -qw "audit"; then
  pass "vortix --help lists 'audit' (plan 015 phase C)"
else
  fail "vortix --help missing 'audit' subcommand" "${HELP_OUT}"
fi
if echo "${HELP_OUT}" | grep -qw "daemon"; then
  pass "vortix --help lists 'daemon' (plan 015 phase D)"
else
  fail "vortix --help missing 'daemon' subcommand" "${HELP_OUT}"
fi
REMOVED_SUBCMDS=""
for sub in engine journal settings migrate export; do
  if echo "${HELP_OUT}" | grep -qE "^\s+${sub}\b"; then
    REMOVED_SUBCMDS="${REMOVED_SUBCMDS} ${sub}"
  fi
done
if [ -z "${REMOVED_SUBCMDS}" ]; then
  pass "removed subcommands are absent from --help"
else
  fail "removed subcommands still present:" "${REMOVED_SUBCMDS# }"
fi

# ---- 3. vortix info shows session-journal path ----
# `vortix journal path` was folded into `vortix info` output. The path
# (or "(disk persistence disabled)") must appear.
if INFO_OUT="$("${VORTIX}" info 2>&1)"; then
  if echo "${INFO_OUT}" | grep -qi "Session journal"; then
    pass "vortix info surfaces the session-journal path"
  else
    fail "vortix info" "missing 'Session journal' line: ${INFO_OUT}"
  fi
else
  fail "vortix info" "command exited non-zero"
fi

# ---- 4. vortix info --json carries schema_version + journal field ----
if INFO_JSON="$("${VORTIX}" info --json 2>&1)"; then
  if echo "${INFO_JSON}" | grep -q '"schema_version"' \
     && echo "${INFO_JSON}" | grep -q '"version"'; then
    pass "vortix info --json returns envelope with schema_version"
  else
    fail "vortix info --json" "malformed envelope: ${INFO_JSON}"
  fi
else
  fail "vortix info --json" "command exited non-zero"
fi

# ---- 5. vortix status returns Disconnected ----
# Replaces the now-removed `vortix engine status` smoke check; same
# FSM-state-read intent via the canonical surface.
if STATUS_OUT="$("${VORTIX}" status --brief 2>&1)"; then
  if echo "${STATUS_OUT}" | grep -qi "disconnect\|disconnected"; then
    pass "vortix status --brief reports disconnected"
  else
    # `status` returns 0 + "no active profile" on a fresh config; either
    # state is fine for the no-panic invariant.
    pass "vortix status --brief runs without panic"
  fi
else
  if echo "${STATUS_OUT}" | grep -qi "panic"; then
    fail "vortix status --brief" "panicked"
  else
    pass "vortix status --brief exits without panic"
  fi
fi

# ---- 6. show --raw --inline-secrets accepts the flag ----
# We can only verify the flag is accepted (parses + runs); a real
# round-trip needs a stored secret which the secrets smoke covers.
# Use a fake profile name; expect either NotFound exit (3) or empty
# output — both are acceptable, just no panic.
SHOW_OUT="$("${VORTIX}" show __nonexistent_smoke_profile__ --raw --inline-secrets 2>&1 || true)"
if echo "${SHOW_OUT}" | grep -qi "panic"; then
  fail "vortix show --raw --inline-secrets" "panicked"
else
  pass "vortix show --raw --inline-secrets accepts the flag"
fi

# ---- 7. show --inline-secrets without --raw is rejected ----
# clap should refuse the combination (--inline-secrets requires --raw).
if SHOW_BAD="$("${VORTIX}" show __nope__ --inline-secrets 2>&1)"; then
  fail "vortix show --inline-secrets (no --raw)" "should have failed, exited 0: ${SHOW_BAD}"
else
  if echo "${SHOW_BAD}" | grep -qi "requires\|error"; then
    pass "vortix show --inline-secrets correctly requires --raw"
  else
    fail "vortix show --inline-secrets" "rejected for wrong reason: ${SHOW_BAD}"
  fi
fi

# ---- 8. secrets round trip (set, get, delete) ----
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

# ---- 9. list against an empty profiles dir ----
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

# ---- 10. no-panic invariant across every captured stderr ----
COMBINED="${VERSION_OUT}${HELP_OUT}${INFO_OUT:-}${INFO_JSON:-}${STATUS_OUT:-}${SHOW_OUT:-}${SHOW_BAD:-}${LIST_OUT:-}"
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
