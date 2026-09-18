#!/usr/bin/env bash
# Fresh-install UX audit, run as an ordinary user.
#
# The defects this catches are userspace, not kernel: the umask a distro logs
# you in with, whether a file created under sudo stays readable, which DNS
# backend is present, how a missing tool is reported, whether an error names
# something the user can act on. Those reproduce in a container, so this runs
# across distro images instead of needing a machine each.
#
# Deliberately unprivileged. Vortix's dashboard needs root, but every bug found
# so far surfaced on the ordinary-user side of that line, and running as root
# hides exactly the ownership and permission failures worth finding.
#
# Usage: distro_ux_audit.sh <label> <path-to-vortix-binary>

set -uo pipefail

LABEL="${1:?usage: distro_ux_audit.sh <label> <vortix-binary>}"
VORTIX="${2:?usage: distro_ux_audit.sh <label> <vortix-binary>}"

fails=0
note() { printf '  %-58s %s\n' "$1" "$2"; }
check() {
    local what="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        note "$what" "ok"
    else
        note "$what" "FAIL (expected $expected, got $actual)"
        fails=$((fails + 1))
    fi
}

echo "===== $LABEL ====="
echo "  umask=$(umask)  user=$(id -un)  uid=$(id -u)"
printf '  tools:'
for t in wg wg-quick openvpn nft iptables resolvectl resolvconf; do
    command -v "$t" >/dev/null && printf ' %s' "$t"
done
echo

export VORTIX_CONFIG_DIR=""
unset VORTIX_CONFIG_DIR
# `getent` is Linux-only; $HOME is what the process actually uses anyway.
HOME_DIR="${HOME:?HOME must be set}"
rm -rf "${HOME_DIR:?}/.config/vortix" "${HOME_DIR}/.local/share/vortix"

# --- first run creates a private config directory -----------------------------
#
# `create_dir_all` honours the caller's umask, and Debian derivatives log in at
# 002. That produced a group-writable directory which Vortix's own durable-state
# validation then refused, so no profile could be imported at all.
"$VORTIX" list >/dev/null 2>&1
# GNU stat takes -c, BSD/macOS -f. Try both so this can be dry-run anywhere.
mode="$(stat -c %a "${HOME_DIR}/.config/vortix" 2>/dev/null \
    || stat -f %Lp "${HOME_DIR}/.config/vortix" 2>/dev/null || echo missing)"
check "config dir is private (0700)" "700" "$mode"

# --- import works on a fresh install ------------------------------------------
printf 'client\nremote 198.51.100.1 1194\ndev tun\n' >/tmp/audit-sample.ovpn
out="$("$VORTIX" import /tmp/audit-sample.ovpn 2>&1)"; rc=$?
check "import on a fresh install" "0" "$rc"
[ "$rc" -eq 0 ] || echo "      $out" | head -3

# --- listing round-trips ------------------------------------------------------
"$VORTIX" list 2>/dev/null | grep -q 'audit-sample'
check "imported profile is listed" "0" "$?"

# --- the JSON contract holds ---------------------------------------------------
#
# Machine callers parse stdout. Any diagnostic printed there breaks them, and a
# failure with no envelope leaves them with an exit code and nothing else.
json="$("$VORTIX" list --json 2>/dev/null)"
case "$json" in "{"*) r=0 ;; *) r=1 ;; esac
check "list --json stdout is pure JSON" "0" "$r"

"$VORTIX" show does-not-exist >/dev/null 2>&1
check "missing profile exits 3 (not found)" "3" "$?"

err_json="$("$VORTIX" show does-not-exist --json 2>/dev/null)"
case "$err_json" in *'"ok": false'*) r=0 ;; *) r=1 ;; esac
check "failure emits a JSON error envelope" "0" "$r"

# --- kill-switch vocabulary is identical everywhere ----------------------------
"$VORTIX" killswitch auto >/dev/null 2>&1
check "killswitch rejects the 'auto' alias" "1" "$?"
"$VORTIX" killswitch >/dev/null 2>&1
check "killswitch status is read-only" "0" "$?"

# --- privileged operations refuse cleanly, without a backtrace -----------------
out="$("$VORTIX" up audit-sample 2>&1)"; rc=$?
check "connect without root exits 2" "2" "$rc"
case "$out" in *Backtrace*|*panicked*|*"src/main.rs:"*) r=1 ;; *) r=0 ;; esac
check "no backtrace or source path leaked" "0" "$r"

# --- no terminal is a refusal, not a panic -------------------------------------
"$VORTIX" </dev/null >/dev/null 2>&1
rc=$?
panicked=0; [ "$rc" -eq 101 ] && panicked=1
check "dashboard without a TTY does not panic" "0" "$panicked"

# --- report must never block ----------------------------------------------------
timeout 20 "$VORTIX" report </dev/null >/dev/null 2>&1
rc=$?
hung=0; [ "$rc" -eq 124 ] && hung=1
check "report exits without a terminal" "0" "$hung"

echo "  ---- $LABEL: $fails failure(s)"
exit "$fails"
