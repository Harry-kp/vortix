#!/usr/bin/env bash
# The executable half of docs/manual-testing/P0.md: the smoke set, run live
# against real tunnels on macOS or Linux.
#
#   sudo scripts/p0.sh             # every scenario; asks for what it needs
#   sudo scripts/p0.sh S2 S6       # just these
#
# Run it as root from the invoking user's sudo (SUDO_USER must name them).
# It needs `curl`; the TUI scenarios also need `tmux` and are skipped without it.
#
# Profiles are chosen by role, from `vortix list`. Set them in the environment
# or answer the prompts once; answers (never secrets) are kept in
# target/p0.env for the next run. A role left empty skips the scenarios that
# need it.
#   P0_FULL       full-tunnel profile (AllowedIPs 0/0 or redirect-gateway)
#   P0_FULL2      a second full tunnel that declares 0/0 itself (conflict check)
#   P0_SPLIT      a split-route profile
#   P0_OVPN       a full-tunnel OpenVPN profile
#   P0_OVPN_AUTH  an OpenVPN profile that needs a username and password
# Credentials for P0_OVPN_AUTH, when none are saved: P0_OVPN_USER, P0_OVPN_PASS,
# and P0_OVPN_OTP for a static challenge. Taken from the environment or asked
# for with echo off; typed into the TUI through a tmux buffer, never saved.
#
# S6 and S7 cut this machine's internet for a few seconds on purpose; they run
# only after a yes at the prompt, or with P0_ALLOW_BLOCKING=1.
#
# Prints PASS/FAIL/SKIP per check, writes target/p0-results.json, exits 1 on
# any FAIL. Whatever happens, it leaves every tunnel down and the kill switch off.
set -u
cd "$(dirname "$0")/.."
PATH=$PATH:/opt/homebrew/bin:/usr/local/bin

VX=${VX:-$PWD/target/debug/vortix}
OS=$(uname -s)
OUT=target/p0-results.json
ENV_FILE=target/p0.env
TM="tmux -L vortix-p0"

[ "$(id -u)" = 0 ] || { echo "run as root: sudo scripts/p0.sh"; exit 2; }
[ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || { echo "run through sudo from your own account, so SUDO_USER names you"; exit 2; }
[ -x "$VX" ] || { echo "build first: cargo build -p vortix ($VX missing)"; exit 2; }
command -v curl >/dev/null || { echo "curl is required"; exit 2; }
HAVE_TMUX=$(command -v tmux >/dev/null && echo 1)
USER_HOME=$(eval echo "~$SUDO_USER")
CONFIG=$USER_HOME/.config/vortix
export SUDO_UID=${SUDO_UID:-$(id -u "$SUDO_USER")} SUDO_GID=${SUDO_GID:-$(id -g "$SUDO_USER")}

pass=0 fail=0 skip=0 results=()
record() { # status id message
    printf '%-4s %-4s %s\n' "$1" "$2" "$3"
    case $1 in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; *) skip=$((skip + 1)) ;; esac
    results+=("{\"status\":\"$1\",\"id\":\"$2\",\"check\":\"$(printf '%s' "$3" | sed 's/\\/\\\\/g; s/"/\\"/g')\"}")
}
check() { # id message command...
    local id=$1 msg=$2; shift 2
    if "$@" >/dev/null 2>&1; then record PASS "$id" "$msg"; else record FAIL "$id" "$msg"; fi
}
need() { # id var... — skip the scenario unless every role is set
    local id=$1 v; shift
    for v in "$@"; do
        [ -n "${!v:-}" ] || { record SKIP "$id" "no P0_$v profile chosen"; return 1; }
    done
}
need_tmux() { [ -n "$HAVE_TMUX" ] || { record SKIP "$1" "tmux is not installed"; return 1; }; }

vx() { "$VX" "$@"; }
as_user() { sudo -u "$SUDO_USER" -H "$@"; }
rc() { "$@" >/dev/null 2>&1; echo $?; }
contains() { printf '%s' "$1" | grep -qiE -- "$2"; }

# ── setup: which profiles, which credentials ────────────────────────────
PROFILES=$(as_user "$VX" list 2>/dev/null | awk 'NR > 1 && NF >= 2 {print $1}')
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
ask() { # var description
    local var=$1 answer
    [ -n "${!var:-}" ] && return
    [ -t 0 ] || return
    printf '%s — %s (empty to skip): ' "$var" "$2"
    read -r answer
    if [ -n "$answer" ] && ! printf '%s\n' "$PROFILES" | grep -qxF "$answer"; then
        echo "  '$answer' is not in vortix list; skipping $var"
        answer=
    fi
    printf -v "$var" '%s' "$answer"
}
if [ -t 0 ]; then
    missing=0
    for v in P0_FULL P0_FULL2 P0_SPLIT P0_OVPN P0_OVPN_AUTH; do [ -n "${!v:-}" ] || missing=1; done
    [ "$missing" = 1 ] && { echo "Profiles:"; printf '  %s\n' $PROFILES; }
fi
ask P0_FULL "a full-tunnel profile"
ask P0_FULL2 "a second full tunnel that declares 0.0.0.0/0 itself"
ask P0_SPLIT "a split-route profile"
ask P0_OVPN "a full-tunnel OpenVPN profile"
ask P0_OVPN_AUTH "an OpenVPN profile that needs a username and password"
mkdir -p target
for v in P0_FULL P0_FULL2 P0_SPLIT P0_OVPN P0_OVPN_AUTH; do printf '%s=%q\n' "$v" "${!v:-}"; done >"$ENV_FILE"
chown "$SUDO_UID:$SUDO_GID" "$ENV_FILE"
if [ -n "${P0_OVPN_AUTH:-}" ] && [ -z "${P0_OVPN_PASS:-}" ] && [ -t 0 ]; then
    echo "Credentials for $P0_OVPN_AUTH, used only if none are saved (never stored; empty to skip):"
    read -r -p "  username: " P0_OVPN_USER
    [ -n "$P0_OVPN_USER" ] && { read -r -s -p "  password: " P0_OVPN_PASS; echo; read -r -s -p "  OTP (empty if none): " P0_OVPN_OTP; echo; }
fi
if [ -z "${P0_ALLOW_BLOCKING:-}" ] && [ -t 0 ]; then
    read -r -p "S6/S7 block this machine's internet for a few seconds each. Run them? [y/N] " P0_ALLOW_BLOCKING
    case $P0_ALLOW_BLOCKING in [yY]*) P0_ALLOW_BLOCKING=1 ;; *) P0_ALLOW_BLOCKING= ;; esac
fi
FULL=${P0_FULL:-} FULL2=${P0_FULL2:-} SPLIT=${P0_SPLIT:-} OVPN=${P0_OVPN:-} OVPN_AUTH=${P0_OVPN_AUTH:-}

# ── host probes ─────────────────────────────────────────────────────────
tunnels() {
    if [ "$OS" = Darwin ]; then /sbin/ifconfig | grep -c '^utun'; else ip -brief link | grep -cE '^(wg|tun)'; fi
}
fw_rules() {
    if [ "$OS" = Darwin ]; then pfctl -a com.apple/vortix.killswitch -sr 2>/dev/null | wc -l | tr -d ' '
    else nft list table inet vortix_killswitch 2>/dev/null | wc -l | tr -d ' '; fi
}
dns_state() {
    if [ "$OS" = Darwin ]; then scutil --dns | awk '/^resolver #1/{f=1} f&&/nameserver/{print $3} /^resolver #2/{exit}'
    else resolvectl dns 2>/dev/null; fi
}
drop_tunnel() { # simulate an unexpected drop of WireGuard profile $1, and only its tunnel
    if [ "$OS" = Darwin ]; then
        local utun; utun=$(cat "/var/run/wireguard/$1.name" 2>/dev/null) || return 1
        kill "$(lsof -t "/var/run/wireguard/$utun.sock" 2>/dev/null | head -1)"
    else
        ip link del "$1"
    fi
}
pf_reaches_vortix() { # macOS: the main ruleset must pass through the com.apple anchor
    [ "$OS" != Darwin ] || pfctl -sr 2>/dev/null | grep -q '^anchor "com.apple/\*"'
}
may_block() { # id — gate for scenarios that cut egress on purpose
    [ "${P0_ALLOW_BLOCKING:-}" = 1 ] || { record SKIP "$1" "blocks egress; answer yes or set P0_ALLOW_BLOCKING=1"; return 1; }
    pf_reaches_vortix || { record SKIP "$1" "pf's main rules do not reach Vortix's; run: pfctl -f /etc/pf.conf"; return 1; }
    [ "$(egress)" = 200 ] || { record SKIP "$1" "no baseline egress to example.com"; return 1; }
}
# An address that answers without a VPN; a probe that fails with no VPN proves nothing.
PROBE_IP=$(curl -4 -s -m 5 -o /dev/null -w '%{remote_ip}' http://example.com 2>/dev/null)
egress() { curl -4 -s -m 2 -o /dev/null -w '%{http_code}' -H Host:example.com "http://$PROBE_IP" 2>/dev/null || true; }

# ── TUI through a private tmux server ───────────────────────────────────
tui_start() { # cols rows — returns once the VPN service is ready for keys
    local lines i
    $TM kill-server 2>/dev/null
    lines=$(log_lines)
    $TM new-session -d -s vortix-p0 -x "$1" -y "$2" "env SUDO_UID=$SUDO_UID SUDO_GID=$SUDO_GID SUDO_USER=$SUDO_USER $VX"
    for i in $(seq 60); do new_log "$lines" | grep -q "VPN service ready" && break; sleep 0.5; done
    sleep 1
}
key() { $TM send-keys -t vortix-p0 "$@"; sleep "${DELAY:-2}"; }
frame() { $TM capture-pane -p -t vortix-p0 2>/dev/null; }
tui_stop() { $TM send-keys -t vortix-p0 q 2>/dev/null; sleep 2; $TM kill-server 2>/dev/null; }
type_secret() { # paste a value through a tmux buffer: stdin, never a process argument
    printf '%s' "$1" | $TM load-buffer -b p0 -
    $TM paste-buffer -d -b p0 -t vortix-p0
}
tui_connect() { # profile — select its sidebar row and connect it; 1 if not on screen
    local row
    row=$(frame | sed -n '/Profiles/,/└/p' | sed '1d' | grep -anE "^│ .{2} +$1 " | head -1 | cut -d: -f1)
    [ -n "$row" ] || return 1
    # A fresh TUI selects row 1, and the list wraps, so step down from there;
    # Connection Details names the selected profile, which proves the row.
    local i
    for ((i = 1; i < row; i++)); do DELAY=0.15 key j; done
    contains "$(frame)" "Profile *: $1 " || return 1
    key c
}
connected() { # profile — wait up to 30 s for the header to show it connected
    local i
    for i in $(seq 30); do contains "$(frame | head -1)" "CONNECTED \\($1/" && return; sleep 1; done
    return 1
}
log_lines() { cat "$CONFIG"/logs/*.log 2>/dev/null | wc -l | tr -d ' '; }
new_log() { cat "$CONFIG"/logs/*.log 2>/dev/null | tail -n "+$(($1 + 1))"; }

reset_host() {
    [ -n "$HAVE_TMUX" ] && tui_stop
    vx down >/dev/null 2>&1
    vx killswitch off >/dev/null 2>&1
}
trap 'reset_host; echo "host reset: tunnels down, kill switch off"' EXIT

# ── scenarios ───────────────────────────────────────────────────────────
S1() { # startup and privilege: P0-01, P0-04, P0-12a exit 2
    local out
    out=$(as_user "$VX" </dev/null 2>&1)
    check S1 "unprivileged TUI refuses with the sudo hint" contains "$out" "needs administrator access"
    out=$(vx </dev/null 2>&1)
    check S1 "no terminal: refuses and names the headless commands" contains "$out" "interactive terminal"
    check S1 "no panic or source path leaks" test -z "$(printf '%s' "$out" | grep -iE 'panicked|cargo/registry|RUST_BACKTRACE')"
    check S1 "unprivileged down exits 2" test "$(rc as_user "$VX" down)" = 2
    need_tmux S1 || return
    tui_start 80 24
    local win
    win=$($TM new-window -P -F '#{window_id}' -t vortix-p0 "env SUDO_UID=$SUDO_UID SUDO_GID=$SUDO_GID SUDO_USER=$SUDO_USER $VX; sleep 5")
    sleep 2; out=$($TM capture-pane -p -t "$win")
    check S1 "a second instance refuses in one sentence" contains "$out" "Another Vortix process|already running"
    tui_stop
}

S2() { # CLI lifecycle: P0-12, P0-12a, P0-12c
    need S2 FULL || return
    local p out
    for p in "$FULL" $OVPN; do
        check S2 "up $p exits 0" test "$(rc vx up "$p" --timeout 60)" = 0
        out=$(vx up "$p" 2>&1)
        check S2 "up $p again says Connected" contains "$out" "Connected to $p"
        check S2 "reconnect $p exits 0" test "$(rc vx reconnect "$p")" = 0
        check S2 "down $p exits 0" test "$(rc vx down "$p")" = 0
        out=$(vx down "$p" 2>&1)
        check S2 "down $p again says Already disconnected" contains "$out" "Already disconnected"
    done
    check S2 "up of an unknown profile exits 3" test "$(rc vx up no-such-profile-p0)" = 3
    check S2 "no tunnel left behind" test "$(tunnels)" = "$BASE_TUNNELS"
}

S3() { # TUI lifecycle and parity with the CLI: P0-13, P0-39
    need S3 FULL && need_tmux S3 || return
    tui_start 200 50
    tui_connect "$FULL" || { record SKIP S3 "$FULL is not on screen in the sidebar"; tui_stop; return; }
    check S3 "the TUI connects $FULL (header)" connected "$FULL"
    check S3 "CLI status names $FULL primary while the TUI runs" contains "$(vx status --json | tr -d ' \n')" "\"primary\":\"$FULL\""
    DELAY=8 key c
    check S3 "c disconnects (header)" contains "$(frame | head -1)" "DISCONNECTED"
    check S3 "CLI status agrees: nothing connected" contains "$(vx status --json | tr -d ' \n')" '"primary":null'
    tui_stop
}

S4() { # conflicts: P0-19
    need S4 FULL FULL2 || return
    local out code
    vx up "$FULL" >/dev/null 2>&1
    out=$(vx up "$FULL2" 2>&1); code=$?
    check S4 "full over full without --yes exits 4" test "$code" = 4
    check S4 "the refusal names both profiles and --yes" contains "$out" "$FULL2.*$FULL|$FULL.*$FULL2"
    vx up "$FULL2" --yes >/dev/null 2>&1
    out=$(vx status --json | tr -d ' \n')
    check S4 "--yes switches: $FULL2 is up" contains "$out" "\"profile\":\"$FULL2\""
    check S4 "--yes switches: $FULL is stopped" test -z "$(printf '%s' "$out" | grep -o "\"profile\":\"$FULL\"")"
    vx down >/dev/null 2>&1
    [ -n "$OVPN" ] || return
    # A full route that is only pushed coexists at first; then --yes switches.
    vx up "$FULL" >/dev/null 2>&1
    vx up "$OVPN" >/dev/null 2>&1
    vx up "$OVPN" --yes >/dev/null 2>&1; sleep 3
    check S4 "after switching to $OVPN egress still works" test "$(egress)" = 200
    vx down >/dev/null 2>&1
}

S5() { # exit IP and the real-IP cache: P0-29
    need S5 FULL && need_tmux S5 || return
    local before after lines
    before=$(cksum <"$CONFIG/real-ip.cache" 2>/dev/null)
    lines=$(log_lines)
    tui_start 200 50
    tui_connect "$FULL" || { record SKIP S5 "$FULL is not on screen in the sidebar"; tui_stop; return; }
    check S5 "the TUI connects $FULL" connected "$FULL"
    sleep 5
    after=$(cksum <"$CONFIG/real-ip.cache" 2>/dev/null)
    check S5 "connecting never rewrites the real-IP cache" test "$before" = "$after"
    check S5 "no false 'matches the pre-VPN address' warning" test -z "$(new_log "$lines" | grep 'pre-VPN')"
    DELAY=8 key c
    tui_stop
}

S6() { # vpn-only: P0-21 — one short blocked window, between down and off
    need S6 FULL && may_block S6 || return
    local start
    vx up "$FULL" >/dev/null 2>&1
    vx killswitch vpn-only >/dev/null
    check S6 "vpn-only passes traffic through the tunnel" test "$(egress)" = 200
    check S6 "vpn-only installs firewall rules" test "$(fw_rules)" -gt 0
    vx down >/dev/null 2>&1
    start=$SECONDS
    check S6 "vpn-only with no tunnel blocks egress" test "$(egress)" != 200
    vx killswitch off >/dev/null
    check S6 "off restores egress (blocked for $((SECONDS - start)) s)" test "$(egress)" = 200
    check S6 "off leaves no rules" test "$(fw_rules)" = 0
}

S7() { # block-on-drop: P0-22 (WireGuard full tunnel)
    need S7 FULL && need_tmux S7 && may_block S7 || return
    vx killswitch block-on-drop >/dev/null
    tui_start 200 50
    tui_connect "$FULL" || { record SKIP S7 "$FULL is not on screen in the sidebar"; tui_stop; return; }
    check S7 "the TUI connects $FULL" connected "$FULL"
    check S7 "armed while healthy: no rules" test "$(fw_rules)" = 0
    drop_tunnel "$FULL" || { record SKIP S7 "could not find $FULL's WireGuard tunnel"; tui_stop; return; }
    local blocked=0 recovered=0 i start=$SECONDS
    for i in $(seq 20); do
        if [ "$(egress)" = 200 ]; then [ "$blocked" = 1 ] && recovered=1; else blocked=1; fi
        [ "$recovered" = 1 ] && break
        sleep 0.5
    done
    check S7 "a drop blocks egress" test "$blocked" = 1
    check S7 "the automatic reconnect restores egress (after $((SECONDS - start)) s)" test "$recovered" = 1
    DELAY=8 key c
    tui_stop
    vx killswitch off >/dev/null
}

S8() { # DNS applied and restored: P0-25, P0-26
    need S8 FULL || return
    local before p
    before=$(dns_state)
    for p in "$FULL" $OVPN; do
        vx up "$p" >/dev/null 2>&1
        check S8 "$p applies its resolver" test "$(dns_state)" != "$before"
        vx down "$p" >/dev/null 2>&1; sleep 1
        check S8 "$p disconnect restores DNS exactly" test "$(dns_state)" = "$before"
    done
}

S9() { # 80×24 layout: P0-32
    need S9 FULL SPLIT && need_tmux S9 || return
    vx up "$FULL" >/dev/null 2>&1
    tui_start 80 24; sleep 4
    local f; f=$(frame)
    check S9 "sidebar shows $SPLIT by name (or a prefix)" contains "$(printf '%s' "$f" | cut -c1-27)" "${SPLIT:0:3}"
    check S9 "no sidebar name collapsed to bare dots" test -z "$(printf '%s' "$f" | cut -c1-27 | grep -E '│ .{2} +\.\.\. ')"
    check S9 "Security Guard keeps its footer at 80×24" contains "$f" "Updated"
    tui_stop
    vx down >/dev/null 2>&1
}

S10() { # credentials and secrets: P0-14, P0-37
    need S10 OVPN_AUTH || return
    local out files_before
    files_before=$(ls "$CONFIG/auth" 2>/dev/null | wc -l | tr -d ' ')
    out=$(vx up "$OVPN_AUTH" --timeout 60 </dev/null 2>&1)
    if contains "$out" "Connected to $OVPN_AUTH"; then
        record PASS S10 "$OVPN_AUTH connects with its saved credentials, no prompt"
    elif [ -n "${P0_OVPN_PASS:-}" ] && [ -n "$HAVE_TMUX" ]; then
        tui_start 200 50
        tui_connect "$OVPN_AUTH" || { record SKIP S10 "$OVPN_AUTH is not on screen in the sidebar"; tui_stop; return; }
        sleep 2
        key C-u; type_secret "$P0_OVPN_USER"; key Tab
        key C-u; type_secret "$P0_OVPN_PASS"; key Tab
        [ -n "${P0_OVPN_OTP:-}" ] && { type_secret "$P0_OVPN_OTP"; key Tab; }
        key Space; key Tab   # untick "save": this run must not store them
        key Enter
        check S10 "$OVPN_AUTH connects with typed credentials" connected "$OVPN_AUTH"
        check S10 "typed credentials were not saved" test "$(ls "$CONFIG/auth" 2>/dev/null | wc -l | tr -d ' ')" = "$files_before"
    else
        record SKIP S10 "$OVPN_AUTH has no saved credentials and none were given"
        return
    fi
    check S10 "no credential on an OpenVPN command line" test -z "$(ps axww -o args= | grep '[o]penvpn' | grep -E -- '--auth-user-pass +[^/ ]')"
    reset_host
    local hits
    hits=$(grep -rcE 'PrivateKey *=|password *[=:] *[^ ]' "$CONFIG/logs" "$CONFIG/run" 2>/dev/null | awk -F: '{s += $NF} END {print s + 0}')
    check S10 "no key or password in Vortix or OpenVPN logs" test "$hits" = 0
    check S10 "auth files are private" test -z "$(find "$CONFIG/auth" -type f ! -perm 600 2>/dev/null)"
}

# ── run ─────────────────────────────────────────────────────────────────
reset_host
BASE_TUNNELS=$(tunnels)
echo "== P0 on $OS, $(date -u +%FT%TZ), $("$VX" --version 2>/dev/null) =="
[ -n "$PROBE_IP" ] || echo "note: example.com did not resolve; egress checks will be skipped"
[ -n "$HAVE_TMUX" ] || echo "note: tmux is not installed; TUI checks will be skipped"
for s in ${*:-S1 S2 S3 S4 S5 S6 S7 S8 S9 S10}; do
    reset_host
    "$s"
done

{
    printf '{"os":"%s","version":"%s","pass":%d,"fail":%d,"skip":%d,"results":[' \
        "$OS" "$("$VX" --version 2>/dev/null)" "$pass" "$fail" "$skip"
    (IFS=,; printf '%s' "${results[*]}")
    printf ']}\n'
} >"$OUT"
chown "$SUDO_UID:$SUDO_GID" "$OUT"
echo "== PASS=$pass FAIL=$fail SKIP=$skip → $OUT =="
[ "$fail" = 0 ]
