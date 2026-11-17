#!/usr/bin/env bash
# The smoke scenarios of scripts/p0.sh that need neither the internet nor an OpenVPN server,
# run inside the client namespace against the netns WireGuard peer: S1 startup and privilege,
# S2 the CLI lifecycle, S3 the TUI and CLI agreeing, S9 the 80×24 layout. Runs after
# setup-netns.sh; VX overrides the binary (default target/release/vortix).
set -euo pipefail

NS_A="vortix-test-a"
NS_B="vortix-test-b"
FIXTURE_DIR="tests/integration/fixtures"
P0_USER="vortix-p0"
VX=${VX:-$PWD/target/release/vortix}
WORK=$(mktemp -d)

cleanup() {
  ip netns exec "$NS_A" wg-quick down "$FIXTURE_DIR/wg-a.conf" 2>/dev/null || true
  ip -n "$NS_B" route del default 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

id "$P0_USER" >/dev/null 2>&1 || useradd -m "$P0_USER"
CONFIG_DIR="$(eval echo "~$P0_USER")/.config/vortix"
rm -rf "$CONFIG_DIR"

ip netns exec "$NS_A" wg-quick up "$FIXTURE_DIR/wg-a.conf"
# A full tunnel pins its server through the default gateway, which the namespace lacks.
ip -n "$NS_B" route replace default via 10.99.0.1

sed 's#^AllowedIPs = .*#AllowedIPs = 0.0.0.0/0#' "$FIXTURE_DIR/wg-b.conf" >"$WORK/p0full.conf"
cp "$FIXTURE_DIR/wg-b.conf" "$WORK/p0split.conf"
sed 's#^Address = .*#&\nDNS = 10.99.99.1#' "$WORK/p0full.conf" >"$WORK/p0dns.conf"
chown -R "$P0_USER" "$WORK"
chmod 700 "$WORK"
chmod 600 "$WORK"/*.conf
for profile in p0full p0split p0dns; do
  runuser -u "$P0_USER" -- "$VX" import "$WORK/$profile.conf" >/dev/null
done
runuser -u "$P0_USER" -- tee "$CONFIG_DIR/config.toml" >/dev/null <<'TOML'
ping_targets = ["10.99.99.1"]
TOML
runuser -u "$P0_USER" -- tee "$CONFIG_DIR/settings.toml" >/dev/null <<'TOML'
[engine]
wireguard_health_targets = ["10.99.99.1"]
TOML

ip netns exec "$NS_B" env SUDO_USER="$P0_USER" VX="$VX" P0_ENV_FILE="$WORK/p0.env" \
  P0_FULL=p0full P0_SPLIT=p0split P0_FULL2= P0_OVPN= P0_OVPN_AUTH= \
  bash scripts/p0.sh S1 S2 S3 S9 </dev/null
# Every check here can run, so a skip is a regression, not a missing prerequisite.
grep -q '"skip":0,' target/p0-results.json || { echo "a P0 check was skipped" >&2; exit 1; }

# A connect whose network settings fail is rolled back, not left running. A stub resolvconf
# passes the DNS tool check but fails every change, so the full tunnel's DNS cannot be applied.
if [[ -L /etc/resolv.conf ]]; then
  echo "SKIP rollback check: systemd-resolved manages DNS here" >&2
  exit 0
fi
printf '#!/bin/sh\n[ "$1" = --version ]\n' >"$WORK/resolvconf"
chmod 755 "$WORK/resolvconf"
set +e
UP_OUT=$(ip netns exec "$NS_B" env SUDO_USER="$P0_USER" PATH="$WORK:$PATH" \
  "$VX" up p0dns --timeout 8 2>&1)
UP_STATUS=$?
set -e
if [[ "$UP_STATUS" -eq 0 ]] || ! grep -q "network settings not applied" <<<"$UP_OUT"; then
  echo "expected the p0dns connect to fail its network settings: $UP_OUT" >&2
  exit 1
fi
if ip -n "$NS_B" link show p0dns >/dev/null 2>&1; then
  echo "a connect that failed its network settings left its tunnel running" >&2
  exit 1
fi
echo "OK: a connect whose network settings fail is rolled back"
