#!/usr/bin/env bash
# P0 CLI-scriptable runner. RUN AS THE NORMAL USER (not sudo) — it calls sudo
# per-command exactly like a real operator. Prints PASS/FAIL/BLOCK per assertion.
# Usage: VX=/path/to/vortix PROFILES=~/.config/vortix/profiles bash p0-cli-run.sh
set -u
VX="${VX:?set VX}"; PROFILES="${PROFILES:?set PROFILES}"
pass=0; fail=0; block=0
ok(){ printf 'PASS   %s\n' "$*"; pass=$((pass+1)); }
no(){ printf 'FAIL   %s\n' "$*"; fail=$((fail+1)); }
skip(){ printf 'BLOCK  %s\n' "$*"; block=$((block+1)); }
rc(){ "$@" >/dev/null 2>&1; echo $?; }
ifc(){ if [ "$(uname)" = Darwin ]; then ifconfig 2>/dev/null|grep -c '^utun[4-9]'; else ip -brief link show 2>/dev/null|grep -cE 'wg|tun'; fi; }
up(){ sudo "$VX" up "$1" --timeout 25 >$TMP/p0up 2>&1; tail -1 $TMP/p0up; }
TMP="$HOME/.p0tmp"; mkdir -p "$TMP"
echo "== P0 CLI run on $(uname -s) — $(date -u +%H:%M:%SZ) =="
sudo "$VX" down --all >/dev/null 2>&1

# P0-01 privilege / tty refusal (invoked as user)
o=$("$VX" 2>&1); echo "$o"|grep -q 'needs administrator access' && ok "P0-01a unpriv refuse" || no "P0-01a ($o)"
e=$(sudo "$VX" </dev/null 2>&1 >/dev/null); c=$?; { echo "$e"|grep -q 'interactive terminal' && [ "$c" = 1 ]; } && ok "P0-01b non-tty refuse exit1" || no "P0-01b (exit=$c $e)"
echo "$e"|grep -qiE 'ratatui|cargo/registry|panicked|BACKTRACE' && no "P0-01c leak" || ok "P0-01c no panic/path leak"

# P0-06 report
c=$(rc bash -c "sudo \"$VX\" report </dev/null"); [ "$c" = 0 ] && ok "P0-06 report non-tty exit0" || no "P0-06 (exit=$c)"

# P0-12 cold lifecycle
r=$(up wg07); echo "$r"|grep -qi 'Connected to wg07' && ok "P0-12 up wg07" || no "P0-12 up wg07 ($r)"
r=$(sudo "$VX" status 2>&1|head -1); echo "$r"|grep -qi Connected && ok "P0-12 status connected" || no "P0-12 status ($r)"
cj=$(sudo "$VX" status --json 2>/dev/null|tr -d ' \n'|grep -o '"profile":"[^"]*"')
echo "$cj"|grep -qi wg07 && ok "P0-12 json lists wg07 connection" || no "P0-12 json conn ($cj)"
# P0-12a idempotent up
r=$(sudo "$VX" up wg07 2>&1); echo "$r"|grep -qi 'Already connected' && ok "P0-12a up-twice" || no "P0-12a up-twice ($r)"
c=$(rc sudo "$VX" down wg07); [ "$c" = 0 ] && ok "P0-12 down exit0" || no "P0-12 down (exit=$c)"
r=$(sudo "$VX" down wg07 2>&1); echo "$r"|grep -qi 'Already disconnected' && ok "P0-12a down-twice" || no "P0-12a down-twice ($r)"

# P0-12a exit-code taxonomy
c=$(rc sudo "$VX" up no-such-profile); [ "$c" = 3 ] && ok "P0-12a notfound=3" || no "P0-12a notfound (exit=$c, want 3)"
r=$(sudo "$VX" up no-such-profile 2>&1); { echo "$r"|grep -qi 'not found' && echo "$r"|grep -qi 'vortix list'; } && ok "P0-12a notfound-msg" || no "P0-12a notfound-msg ($r)"
r=$(sudo "$VX" import $TMP/empty.conf 2>&1); c=$?

# P0-19 / P0-12a conflict taxonomy (exit 4)
up wg07 >/dev/null
c=$(rc sudo "$VX" up wg10); [ "$c" = 4 ] && ok "P0-12a conflict=4" || no "P0-12a conflict (exit=$c)"
r=$(sudo "$VX" up wg10 2>&1); { echo "$r"|grep -qi overlaps && echo "$r"|grep -qi -- '--yes'; } && ok "P0-19 conflict names both+bypass" || no "P0-19 conflict-msg ($r)"
r=$(sudo "$VX" status --json 2>/dev/null|tr -d ' \n'); echo "$r"|grep -qi '"profile":"wg07"' && ok "P0-19 first tunnel survives" || no "P0-19 survive ($(echo "$r"|head -c80))"
sudo "$VX" down --all >/dev/null 2>&1

# P0-12c reconnect
up wg08 >/dev/null
c=$(rc sudo "$VX" reconnect wg08); r=$(sudo "$VX" status 2>&1|head -1)
{ [ "$c" = 0 ] && echo "$r"|grep -qi Connected; } && ok "P0-12c reconnect ends connected" || no "P0-12c reconnect (exit=$c $r)"
c=$(rc sudo "$VX" reconnect wg08 --timeout 5); [ "$c" != 0 ] && ok "P0-12c reconnect rejects --timeout" || no "P0-12c --timeout"
sudo "$VX" down --all >/dev/null 2>&1

# P0-17 selective disconnect
up wg07 >/dev/null; up wg08 >/dev/null
sudo "$VX" down wg07 >/dev/null 2>&1; r=$(sudo "$VX" status --json 2>/dev/null|tr -d ' \n')
{ echo "$r"|grep -q '"profile":"wg08"' && ! echo "$r"|grep -q '"profile":"wg07"'; } && ok "P0-17 selective disconnect" || no "P0-17 ($(echo "$r"|head -c100))"
sudo "$VX" down --all >/dev/null 2>&1; [ "$(ifc)" = 0 ] && ok "P0-17 down --all → 0" || no "P0-17 leftover"

# P0-16 unreachable peer cleans up, host usable
sed 's/^Endpoint =.*/Endpoint = 192.0.2.99:51820/' "$PROFILES/wg07.conf" > $TMP/wgdead.conf 2>/dev/null
"$VX" import $TMP/wgdead.conf >/dev/null 2>&1
sudo "$VX" up wgdead --timeout 20 >$TMP/dead 2>&1; sleep 2
[ "$(ifc)" = 0 ] && ok "P0-16 dead peer cleaned (no iface)" || no "P0-16 leftover iface"
if [ "$(uname)" = Darwin ]; then dr=$(netstat -rn -f inet|awk '$1=="default"{print $NF;exit}'); else dr=$(ip route show default 2>/dev/null|grep -oE 'dev [^ ]+'|awk '{print $2}'|head -1); fi
echo "$dr"|grep -qiE 'wg|tun|utun' && no "P0-16 default route in tunnel ($dr)" || ok "P0-16 host route intact ($dr)"
"$VX" delete wgdead >/dev/null 2>&1

# P0-08 malformed refusals (unprivileged import)
printf '' >$TMP/empty.conf; printf '[Interface]\nPrivateKey = x\n' >$TMP/nopeer.conf
head -c 2000000 /dev/zero|tr '\0' 'x' >$TMP/huge.conf
r=$("$VX" import $TMP/empty.conf 2>&1); echo "$r"|grep -qi empty && ok "P0-08 empty" || no "P0-08 empty ($r)"
r=$("$VX" import $TMP/nopeer.conf 2>&1); echo "$r"|grep -qi Peer && ok "P0-08 no-peer" || no "P0-08 no-peer ($r)"
r=$("$VX" import $TMP/huge.conf 2>&1); echo "$r"|grep -qiE 'too large|under 1' && ok "P0-08 huge" || no "P0-08 huge ($r)"

# P0-11 stray meta
touch "$PROFILES/.stray.meta.toml"
r=$("$VX" list 2>&1); { echo "$r"|grep -q '.stray.meta.toml' && echo "$r"|grep -qi 'mv '; } && ok "P0-11 stray names path+mv" || no "P0-11 stray"
rm -f "$PROFILES/.stray.meta.toml"

# P0-37 auth perms
if ls ~/.config/vortix/auth/* >/dev/null 2>&1; then
  bad=$(find ~/.config/vortix/auth -type f ! -perm 600 2>/dev/null|wc -l)
  [ "$bad" = 0 ] && ok "P0-37 auth files 0600" || no "P0-37 auth perms ($bad loose)"
else skip "P0-37 no saved creds"; fi

# P0-02 config dirs private
CFG=~/.config/vortix
if [ "$(uname)" = Darwin ]; then STATF="stat -f %Lp"; else STATF="stat -c %a"; fi
loose=$(for d in "$CFG" "$CFG/profiles" ~/.local/share/vortix ~/.local/share/vortix/sessions; do [ -d "$d" ] && $STATF "$d" 2>/dev/null; done | grep -vc '^700$')
[ "${loose:-1}" = 0 ] && ok "P0-02 config dirs 0700" || no "P0-02 loose dirs ($loose non-700)"

# P0-03 unprivileged read commands + ownership
uid=$(id -u); "$VX" list >/dev/null 2>&1; ll=$?; "$VX" status >/dev/null 2>&1; ss=$?
{ [ "$ll" = 0 ] && [ "$ss" = 0 ]; } && ok "P0-03 unpriv list+status exit0" || no "P0-03 (list=$ll status=$ss)"
ro=$(find "$CFG/profiles" -maxdepth 1 -type f ! -uid "$uid" 2>/dev/null | wc -l | tr -d ' ')
[ "${ro:-1}" = 0 ] && ok "P0-03 profile files owned by user" || no "P0-03 $ro root-owned"

# P0-07 import batch partial success + no secret in --json
B="$TMP/batch"; mkdir -p "$B"; cp "$PROFILES/wg07.conf" "$B/imp1.conf" 2>/dev/null; printf '' > "$B/bad.conf"
bo=$("$VX" import "$B" 2>&1); bc=$?
{ echo "$bo"|grep -qiE 'imp1|imported|admitted' && [ "$bc" != 0 ]; } && ok "P0-07 batch partial-success" || no "P0-07 batch (exit=$bc $(echo "$bo"|tr '\n' ' '|head -c60))"
"$VX" delete imp1 >/dev/null 2>&1
jo=$("$VX" import "$PROFILES/wg07.conf" --json 2>&1); echo "$jo"|grep -qiE 'PrivateKey|BEGIN ' && no "P0-07 --json leaks key" || ok "P0-07 --json no secret"
"$VX" delete wg07copy imp1 >/dev/null 2>&1

# P0-34 RUST_LOG silence + trace
q=0; for v in "" "RUST_LOG=" "RUST_LOG=off" "RUST_LOG=!!!bogus"; do n=$(env $v "$VX" list 2>&1 >/dev/null | wc -l | tr -d ' '); [ "$n" != 0 ] && q=1; done
[ "$q" = 0 ] && ok "P0-34 silent RUST_LOG = 0 stderr" || no "P0-34 stderr bleed"
[ "$(RUST_LOG=trace "$VX" list 2>&1 >/dev/null | wc -l | tr -d ' ')" -gt 0 ] && ok "P0-34 trace prints" || no "P0-34 trace silent"

skip "P0-38 needs manual (hash-named auth, profile-specific)"

sudo "$VX" down --all >/dev/null 2>&1
echo "== totals: PASS=$pass FAIL=$fail BLOCK=$block =="
