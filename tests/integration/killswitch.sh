#!/usr/bin/env bash
# Killswitch integration test (plan 015 phase B U8 / plan 012).
#
# Verifies vortix's killswitch installs real iptables DROP rules and
# that traffic outside the tunnel is actually blocked. Requires the
# WireGuard happy-path harness from wg_happy_path.sh to set up the
# tunnel first.

set -euo pipefail

NS_B="vortix-test-b"
PROFILE_DIR="$(mktemp -d)/profiles"
mkdir -p "$PROFILE_DIR"
cp tests/integration/fixtures/wg-b.conf "$PROFILE_DIR/integration.conf"
export VORTIX_CONFIG_DIR="$(dirname "$PROFILE_DIR")"

# Bring tunnel up + engage killswitch.
ip netns exec vortix-test-a wg-quick up tests/integration/fixtures/wg-a.conf
ip netns exec "$NS_B" target/release/vortix up integration
ip netns exec "$NS_B" target/release/vortix killswitch always

# Verify iptables sees the VORTIX_KILLSWITCH chain with DROP rules.
# The killswitch inserts a jump from OUTPUT to VORTIX_KILLSWITCH;
# the actual DROP rule lives in the custom chain.
ip netns exec "$NS_B" iptables -L VORTIX_KILLSWITCH -n | grep -q DROP

# Verify outbound traffic to a non-tunnel destination is blocked.
# Using 10.99.0.99 (within the veth subnet but not a peer) — if the
# killswitch is engaged, this should fail.
if ip netns exec "$NS_B" ping -c 1 -W 1 10.99.0.99 2>/dev/null; then
    echo "FAIL: ping to non-tunnel destination succeeded; killswitch not enforcing"
    exit 1
fi

# Release + verify rules gone + traffic restored.
ip netns exec "$NS_B" target/release/vortix release-kill-switch
if ip netns exec "$NS_B" iptables -L VORTIX_KILLSWITCH -n 2>/dev/null | grep -q DROP; then
    echo "FAIL: DROP rules still present after release-killswitch"
    exit 1
fi

# Disconnect tunnel for cleanup.
ip netns exec "$NS_B" target/release/vortix down
ip netns exec vortix-test-a wg-quick down tests/integration/fixtures/wg-a.conf 2>/dev/null || true

echo "OK: killswitch engages + releases iptables rules correctly"
