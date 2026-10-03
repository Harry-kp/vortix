#!/usr/bin/env bash
# Everything a new user does on this machine, from nothing: install through
# each channel the README offers for this distro, first run, import, connect
# from the CLI and the dashboard, a missing dependency, the kill switch, then
# uninstall and check nothing is left behind.
#
#   sudo scripts/p0-journey.sh <tag> <profile-dir>
#
# Meant for a disposable VM (scripts/p0-vms.sh runs it on the lab's Arch,
# CachyOS and Fedora VMs). It removes every Vortix install, creates a fresh
# user `vxnew`, and does the rest as that user. <profile-dir> holds the P0
# role profiles (full.conf, split.conf, ovpn.ovpn); they are imported, never
# printed. Prints PASS/FAIL/SKIP per step, exits 1 on any FAIL.
set -u
TAG=${1:?usage: p0-journey.sh <tag> <profile-dir>}
PROFILES=${2:?usage: p0-journey.sh <tag> <profile-dir>}
VERSION=${TAG#v}
URL=https://github.com/Harry-kp/vortix/releases/download/$TAG
NEW=vxnew
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
# Only these two: os-release also sets VERSION, which would clobber ours on Fedora.
ID=$(. /etc/os-release && echo "$ID")
PRETTY_NAME=$(. /etc/os-release && echo "$PRETTY_NAME")

pass=0 fail=0
record() { printf '%-4s %s\n' "$1" "$2"; case $1 in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; esac; }
check() { local msg=$1; shift; if "$@" >/dev/null 2>&1; then record PASS "$msg"; else record FAIL "$msg"; fi; }
# A login shell as the new user: their PATH, umask and rc files, like a real session.
as_new() { su -l "$NEW" -c "$*"; }
out_new() { su -l "$NEW" -c "$*" 2>&1; }

case $ID in
    # Arch does not support a partial upgrade: -Sy alone pulled a nodejs newer than its libraries.
    arch | cachyos) pkg_install="pacman -Syu --noconfirm --needed"; pkg_remove="pacman -Rns --noconfirm"; native="pacman -S vortix" ;;
    fedora) pkg_install="dnf install -y -q"; pkg_remove="dnf remove -y -q"; native="dnf install ./vortix-$VERSION-1.x86_64.rpm" ;;
    *) echo "unsupported distro: $ID"; exit 2 ;;
esac

remove_everything() {
    $pkg_remove vortix >/dev/null 2>&1 || true
    npm uninstall -g @harry-kp/vortix >/dev/null 2>&1 || true
    rm -f /usr/local/bin/vortix
    id "$NEW" >/dev/null 2>&1 && rm -f "$(eval echo "~$NEW")/.cargo/bin/vortix"
    hash -r
}
restore_wg_quick() { [ -e /usr/bin/wg-quick.p0-hidden ] && mv /usr/bin/wg-quick.p0-hidden /usr/bin/wg-quick; }
cleanup() {
    restore_wg_quick
    command -v vortix >/dev/null && { vortix down --all >/dev/null 2>&1; vortix killswitch off >/dev/null 2>&1; }
    su -l "$NEW" -c 'tmux kill-server' >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== new-user journey on $PRETTY_NAME, vortix $TAG"
remove_everything
userdel -r "$NEW" >/dev/null 2>&1 || true
useradd -m -s /bin/bash "$NEW"
echo "$NEW ALL=(ALL) NOPASSWD: ALL" >/etc/sudoers.d/90-vxnew
chmod 440 /etc/sudoers.d/90-vxnew
check "fresh user has no vortix on PATH" sh -c "! su -l $NEW -c 'command -v vortix'"
before_ip=$(curl -4 -s -m 10 https://ifconfig.me)

# ── install channels: each must give `vortix` and `sudo vortix` ─────────
channel_ok() { # name — the binary answers as the user and under sudo
    local name=$1
    check "$name: vortix --version is $VERSION" sh -c "su -l $NEW -c 'vortix --version' | grep -qF '$VERSION'"
    check "$name: sudo vortix --version works" sh -c "su -l $NEW -c 'sudo vortix --version' | grep -qF '$VERSION'"
}

if [ "$ID" = fedora ]; then
    as_new "curl -fsSLO $URL/vortix-$VERSION-1.x86_64.rpm && sudo $pkg_install ./vortix-$VERSION-1.x86_64.rpm" >/dev/null 2>&1
    channel_ok ".rpm ($native)"
    check ".rpm: brought wireguard-tools and openvpn" sh -c 'command -v wg-quick && command -v openvpn'
    remove_everything
else
    as_new "sudo $pkg_install vortix" >/dev/null 2>&1
    have=$(out_new 'vortix --version' | awk '{print $2}')
    if [ "$have" = "$VERSION" ]; then channel_ok "$native"
    else record FAIL "$native installs ${have:-nothing}, not $VERSION (the Arch package lags)"; fi
    remove_everything
fi

as_new "curl --proto '=https' --tlsv1.2 -LsSf $URL/vortix-installer.sh | sh" >/dev/null 2>&1
check "shell installer: vortix --version is $VERSION" sh -c "su -l $NEW -c 'vortix --version' | grep -qF '$VERSION'"
check "shell installer: plain sudo vortix fails (documented)" sh -c "! su -l $NEW -c 'sudo vortix --version'"
as_new 'sudo ln -sf ~/.cargo/bin/vortix /usr/local/bin/vortix'
check "shell installer: the README symlink fixes sudo" sh -c "su -l $NEW -c 'sudo vortix --version' | grep -qF '$VERSION'"
remove_everything

$pkg_install nodejs npm >/dev/null 2>&1
if command -v npm >/dev/null; then
    as_new "sudo npm install -g @harry-kp/vortix@$VERSION" >/dev/null 2>&1
    channel_ok "npm"
    remove_everything
else
    record SKIP "npm: nodejs/npm not installable here"
fi

as_new "curl -fsSL $URL/vortix-x86_64-unknown-linux-musl.tar.xz | tar -xJ && sudo install -m 755 vortix-x86_64-unknown-linux-musl/vortix /usr/local/bin/vortix" >/dev/null 2>&1
channel_ok "static musl archive"

# ── first run and onboarding, with the musl install ─────────────────────
check "first run: unprivileged dashboard refuses with the sudo hint" sh -c "su -l $NEW -c 'vortix </dev/null' 2>&1 | grep -q 'sudo vortix'"
out=$(out_new 'vortix list')
check "first run: empty profile list says how to import" sh -c "printf '%s' \"$out\" | grep -qi import"
for f in "$PROFILES"/*; do
    install -m 600 -o "$NEW" "$f" "/tmp/${f##*/}"
    as_new "cd /tmp && vortix import /tmp/${f##*/}" >/dev/null 2>&1
    rm -f "/tmp/${f##*/}"
done
check "import: all role profiles listed" sh -c "[ \$(su -l $NEW -c 'vortix list --names-only' | wc -l) -ge $(ls "$PROFILES" | wc -l) ]"
check "config dir is private and owned by the user" sh -c "[ \"\$(stat -c '%a %U' $(eval echo "~$NEW")/.config/vortix)\" = '700 $NEW' ]"

mv /usr/bin/wg-quick /usr/bin/wg-quick.p0-hidden
out=$(out_new 'sudo vortix up full; echo "exit=$?"')
restore_wg_quick
case $ID in arch | cachyos) hint=pacman ;; fedora) hint=dnf ;; esac
check "missing wireguard-tools: exit 5 and a $hint install hint" sh -c "printf '%s' \"$out\" | grep -q 'exit=5' && printf '%s' \"$out\" | grep -q '$hint'"

check "CLI: sudo vortix up full connects" as_new 'sudo vortix up full'
# Unprivileged, status cannot see a WireGuard tunnel and says so; the user runs it with sudo.
check "CLI: sudo vortix status reports it connected" sh -c "su -l $NEW -c 'sudo vortix status --json' | grep -qE '\"state\": *\"connected\"'"
during_ip=$(curl -4 -s -m 10 https://ifconfig.me)
check "CLI: public IP changes through the tunnel" test -n "$during_ip" -a "$during_ip" != "$before_ip"
check "CLI: kill switch vpn-only applies" as_new 'sudo vortix killswitch vpn-only'
check "CLI: nftables table present while vpn-only" nft list table inet vortix_killswitch
check "CLI: kill switch off" as_new 'sudo vortix killswitch off'
check "CLI: sudo vortix down disconnects" as_new 'sudo vortix down full'
check "CLI: public IP back to the real one" test "$(curl -4 -s -m 10 https://ifconfig.me)" = "$before_ip"

as_new 'tmux new-session -d -s j -x 100 -y 30 "sudo vortix"'
sleep 8
frame=$(out_new 'tmux capture-pane -p -t j')
check "TUI: opens on a fresh install" sh -c "printf '%s' \"$frame\" | grep -q 'Profiles'"
as_new 'tmux send-keys -t j 1'
connected=
for _ in $(seq 30); do out_new 'tmux capture-pane -p -t j' | head -1 | grep -q CONNECTED && { connected=1; break; }; sleep 1; done
check "TUI: digit 1 connects the first profile" test -n "$connected"
as_new 'tmux send-keys -t j D'
sleep 5
check "TUI: D disconnects" sh -c "su -l $NEW -c 'tmux capture-pane -p -t j' | head -1 | grep -q DISCONNECTED"
as_new 'tmux send-keys -t j q'
sleep 2

check "report runs without blocking" timeout 20 su -l "$NEW" -c 'vortix report'
check "update names the right way for a non-cargo install" sh -c "su -l $NEW -c 'vortix update' 2>&1 | grep -q 'only updates a'"

# ── uninstall leaves nothing running ────────────────────────────────────
remove_everything
check "uninstall: no vortix on PATH" sh -c "! su -l $NEW -c 'command -v vortix'"
check "uninstall: no kill-switch table left" sh -c '! nft list table inet vortix_killswitch'
check "uninstall: no tunnel interface left" sh -c '! ip -o link | grep -qE "wg|tun[0-9]"'

echo "== journey: $pass passed, $fail failed"
[ "$fail" = 0 ]
