#!/usr/bin/env bash
# Check a release on the Linux lab's distro VMs (Arch, CachyOS, Fedora), as a
# new user would meet it and as P0 exercises it.
#
#   scripts/p0-vms.sh                  # every VM: arch cachyos fedora44
#   scripts/p0-vms.sh fedora44         # just these
#   P0_TAG=v0.5.2 scripts/p0-vms.sh    # journey for this release (default: latest)
#   VX=/path/to/vortix scripts/p0-vms.sh   # smoke-test another binary
#   P0_SMOKE=0 scripts/p0-vms.sh       # journey only (after publishing a release)
#
# Per VM, two phases:
#   1. scripts/p0-journey.sh: a fresh user installs P0_TAG through every channel
#      the README offers for that distro, onboards, connects, uninstalls.
#   2. scripts/p0.sh: the P0 smoke set against VX.
#
# Run it on the lab host, from this checkout. By default it tests this checkout,
# built as a static musl binary so one build runs on every distro. For each VM it
# boots it if needed, copies in the binary, p0.sh and the current P0-role profiles, replacing
# the VM's copies (roles come from target/p0.env of the lab's own p0 run), runs p0.sh there with
# the blocking scenarios allowed (only the VM loses its network), collects
# target/p0-vms/<vm>.json, and shuts down a VM it started. Exits 1 on any FAIL.
set -euo pipefail
cd "$(dirname "$0")/.."

VMS=("$@")
[ ${#VMS[@]} -gt 0 ] || VMS=(arch cachyos fedora44)
KEY=${P0_VM_KEY:-$HOME/.ssh/distrolab}
PROFILES=$HOME/.config/vortix/profiles
[ -f target/p0.env ] || { echo "run scripts/p0.sh on the lab first: its roles (target/p0.env) are reused"; exit 2; }
. target/p0.env
ROLES="P0_FULL=${P0_FULL:-} P0_FULL2=${P0_FULL2:-} P0_SPLIT=${P0_SPLIT:-} P0_OVPN=${P0_OVPN:-}"

TAG=${P0_TAG:-$(curl -fsSL https://api.github.com/repos/Harry-kp/vortix/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')}
echo "journey installs $TAG"

profile_file() { # name — the lab's file for this profile, if any
    local ext
    for ext in conf ovpn; do [ -f "$PROFILES/$1.$ext" ] && { echo "$PROFILES/$1.$ext"; return; }; done
    return 0
}

BIN=${VX:-}
if [ -z "$BIN" ]; then
    cargo build -q -p vortix --target x86_64-unknown-linux-musl
    BIN=target/x86_64-unknown-linux-musl/debug/vortix
fi
echo "testing $("$BIN" --version) from $BIN"
mkdir -p target/p0-vms
failed=0

for vm in "${VMS[@]}"; do
    echo "== $vm"
    started=
    if [ "$(sudo -n virsh domstate "$vm")" != running ]; then
        sudo -n virsh start "$vm" >/dev/null
        started=1
    fi
    ip=
    for _ in $(seq 60); do
        ip=$(sudo -n virsh domifaddr "$vm" | awk '/ipv4/ {split($4, a, "/"); print a[1]}')
        [ -n "$ip" ] && break
        sleep 3
    done
    vm_ssh() { ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "harrykp@$ip" "$@"; }
    vm_put() { scp -q -i "$KEY" "$1" "harrykp@$ip:$2"; }
    for _ in $(seq 60); do vm_ssh true 2>/dev/null && break; sleep 3; done

    vm_ssh 'mkdir -p ~/vx-p0/scripts ~/vx-p0/target/debug && rm -f ~/vx-p0/target/p0-results.json ~/vx-p0/target/p0.log'
    vm_put "$BIN" vx-p0/target/debug/vortix
    vm_put scripts/p0.sh vx-p0/scripts/p0.sh
    for profile in ${P0_FULL:-} ${P0_FULL2:-} ${P0_SPLIT:-} ${P0_OVPN:-}; do
        file=$(profile_file "$profile")
        [ -n "$file" ] || { echo "  $profile: not on the lab, its scenarios will skip"; continue; }
        vm_put "$file" "/tmp/${file##*/}"
        # Replaced every run (a new droplet kills the old copy); delete exits 3 for a missing one.
        if vm_ssh "chmod 600 '/tmp/${file##*/}' && cd /tmp && { ~/vx-p0/target/debug/vortix delete '$profile' --yes >/dev/null 2>&1; rc=\$?; [ \$rc = 0 ] || [ \$rc = 3 ]; } && ~/vx-p0/target/debug/vortix import '/tmp/${file##*/}' >/dev/null; rc=\$?; rm -f '/tmp/${file##*/}'; exit \$rc"; then
            echo "  imported $profile"
        else
            echo "  $profile: could not replace the VM's copy (a tunnel still using it?)"
            failed=1
        fi
    done

    # Phase 1: the journey, with the role profiles under the names it expects.
    vm_ssh 'rm -rf /tmp/p0-journey ~/vx-p0/target/journey.log && mkdir -m 700 /tmp/p0-journey'
    vm_put scripts/p0-journey.sh vx-p0/scripts/p0-journey.sh
    for pair in full:${P0_FULL:-} split:${P0_SPLIT:-} ovpn:${P0_OVPN:-}; do
        role=${pair%%:*} profile=${pair#*:}
        file=$(profile_file "$profile")
        [ -n "$profile" ] && [ -n "$file" ] && vm_put "$file" "/tmp/p0-journey/$role.${file##*.}"
    done
    vm_ssh "cd ~/vx-p0 && setsid nohup sudo bash scripts/p0-journey.sh $TAG /tmp/p0-journey </dev/null >target/journey.log 2>&1 &"
    for _ in $(seq 120); do
        vm_ssh 'grep -q "^== journey:" ~/vx-p0/target/journey.log' 2>/dev/null && break
        sleep 10
    done
    vm_ssh 'rm -rf /tmp/p0-journey'
    scp -q -i "$KEY" "harrykp@$ip:vx-p0/target/journey.log" "target/p0-vms/$vm-journey.log" || true
    grep -E '^(FAIL|== journey)' "target/p0-vms/$vm-journey.log" | sed 's/^/  /' || { echo "  journey did not finish; see target/p0-vms/$vm-journey.log"; failed=1; }
    grep -q '^FAIL' "target/p0-vms/$vm-journey.log" && failed=1

    if [ "${P0_SMOKE:-1}" = 0 ]; then
        [ -n "$started" ] && sudo -n virsh shutdown "$vm" >/dev/null
        continue
    fi

    # Phase 2. Detached with no terminal, so p0.sh never prompts and survives the moments
    # S6/S7 cut the VM's network (and this SSH session with it).
    vm_ssh "cd ~/vx-p0 && setsid nohup sudo env $ROLES P0_OVPN_AUTH= P0_ALLOW_BLOCKING=1 scripts/p0.sh </dev/null >target/p0.log 2>&1 &"
    for _ in $(seq 180); do
        vm_ssh 'test -s ~/vx-p0/target/p0-results.json' 2>/dev/null && break
        sleep 10
    done
    scp -q -i "$KEY" "harrykp@$ip:vx-p0/target/p0-results.json" "target/p0-vms/$vm.json" || echo '[]' >"target/p0-vms/$vm.json"
    scp -q -i "$KEY" "harrykp@$ip:vx-p0/target/p0.log" "target/p0-vms/$vm.log" || true
    counts=$(grep -o '"status":"[A-Z]*"' "target/p0-vms/$vm.json" | sort | uniq -c | tr -s ' ' | tr '\n' ' ')
    echo "  ${counts:-no results; see target/p0-vms/$vm.log}"
    grep -E '^FAIL' "target/p0-vms/$vm.log" | sed 's/^/  /' || true
    grep -q '"status":"FAIL"' "target/p0-vms/$vm.json" && failed=1
    grep -q '"status":"PASS"' "target/p0-vms/$vm.json" || failed=1
    [ -n "$started" ] && sudo -n virsh shutdown "$vm" >/dev/null
done
exit "$failed"
