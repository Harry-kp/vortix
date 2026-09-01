#!/usr/bin/env bash
# Kill-switch integration test.
#
# Verifies the nftables policy behavior with a destination that is reachable
# before engagement, blocked while vpn-only is active, and reachable again
# after release. It also proves Vortix preserves unrelated host nftables
# state and that a failed owned-table replacement leaves the prior policy.

set -euo pipefail

NS_B="vortix-test-b"
PROFILE_DIR="$(mktemp -d)/profiles"
mkdir -p "$PROFILE_DIR"
cp tests/integration/fixtures/wg-b.conf "$PROFILE_DIR/integration.conf"
export VORTIX_CONFIG_DIR="$(dirname "$PROFILE_DIR")"

# Install a real, reachable non-private destination behind the peer. A test
# that starts with an unreachable address cannot distinguish firewall
# enforcement from ordinary routing failure.
PUBLIC_TEST_IP="198.51.100.1"
ip -n vortix-test-a addr replace "$PUBLIC_TEST_IP/32" dev vortix-veth-a
ip -n "$NS_B" route replace "$PUBLIC_TEST_IP/32" via 10.99.0.1 dev vortix-veth-b
ip netns exec "$NS_B" ping -c 1 -W 2 "$PUBLIC_TEST_IP" >/dev/null

# Bring tunnel up + engage killswitch.
ip netns exec vortix-test-a wg-quick up tests/integration/fixtures/wg-a.conf
ip netns exec "$NS_B" target/release/vortix up integration
ip netns exec "$NS_B" target/release/vortix killswitch vpn-only

# The destination proved reachable above must now be blocked. RFC1918/DHCP
# allowances cannot accidentally make this assertion pass.
if ip netns exec "$NS_B" ping -c 1 -W 1 "$PUBLIC_TEST_IP" 2>/dev/null; then
    echo "FAIL: ping to non-tunnel destination succeeded; killswitch not enforcing"
    exit 1
fi

# Exercise the native nft backend and failed transaction semantics while the
# same namespace/tunnel fixture is live.
bash tests/integration/nft_killswitch.sh

# Release the kill switch and verify only Vortix-owned state disappears.
ip netns exec "$NS_B" target/release/vortix release-killswitch

if ip netns exec "$NS_B" nft list table inet vortix_killswitch 2>/dev/null; then
    echo "FAIL: Vortix nftables table remains after release"
    exit 1
fi
ip netns exec "$NS_B" nft list table inet host_sentinel >/dev/null
ip netns exec "$NS_B" ping -c 1 -W 2 "$PUBLIC_TEST_IP" >/dev/null

# Disconnect tunnel for cleanup.
ip netns exec "$NS_B" target/release/vortix down
ip netns exec vortix-test-a wg-quick down tests/integration/fixtures/wg-a.conf 2>/dev/null || true

echo "OK: nft kill switch blocks real traffic, releases it, and preserves host policy"
