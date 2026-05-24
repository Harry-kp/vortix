#!/usr/bin/env bash
# WireGuard happy-path integration test (plan 015 phase B U6 / plan 012).
#
# Runs inside the Docker harness after setup-netns.sh. Two peers face
# each other via the veth pair created by setup. Verifies the full
# vortix connect-status-disconnect lifecycle drives wg-quick correctly
# and that the resulting tunnel is bidirectional.

set -euo pipefail

NS_A="vortix-test-a"   # peer (server-equivalent)
NS_B="vortix-test-b"   # vortix-driven client
FIXTURE_DIR="tests/integration/fixtures"
PROFILE_DIR="$(mktemp -d)/profiles"
mkdir -p "$PROFILE_DIR"

cleanup() {
  # Bring tunnels down in case of partial-run failure.
  ip netns exec "$NS_A" wg-quick down "$FIXTURE_DIR/wg-a.conf" 2>/dev/null || true
  ip netns exec "$NS_B" wg-quick down "$FIXTURE_DIR/wg-b.conf" 2>/dev/null || true
}
trap cleanup EXIT

# Bring up the peer side first (the "server").
ip netns exec "$NS_A" wg-quick up "$FIXTURE_DIR/wg-a.conf"

# Place the client profile in vortix's profile dir + drive it via the CLI.
cp "$FIXTURE_DIR/wg-b.conf" "$PROFILE_DIR/integration.conf"

# vortix needs root for kill switch / iface manipulation; the container
# runs as root so just invoke directly.
export VORTIX_CONFIG_DIR="$(dirname "$PROFILE_DIR")"
ip netns exec "$NS_B" target/release/vortix up integration

# Verify the tunnel is up + bidirectional.
ip netns exec "$NS_B" target/release/vortix status --brief | grep -qi connected
ip netns exec "$NS_B" ping -c 2 -W 2 10.99.99.1
ip netns exec "$NS_A" ping -c 2 -W 2 10.99.99.2

# Disconnect cleanly.
ip netns exec "$NS_B" target/release/vortix down

echo "OK: vortix WG happy-path lifecycle (up + status + ping + down)"

# TODO follow-up coverage (deferred): handshake-fail with unreachable
# peer, daemon-died-mid-session adoption (depends on plan 015 phase D
# IPC layer), DNS-leak guards under the tunnel.
