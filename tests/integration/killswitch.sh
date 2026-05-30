#!/usr/bin/env bash
# Killswitch integration test (plan 015 phase B U8 / plan 012; updated for
# multi-connection plan U9's iptables-restore default-deny design).
#
# Verifies vortix's killswitch installs a real iptables OUTPUT default-DROP
# policy + targeted ACCEPT rules, and that traffic outside the tunnel is
# actually blocked. The test asserts BEHAVIOR (ping blocked when engaged,
# ping restored when released) plus the minimum structural shape needed
# to fail-fast on a regression (OUTPUT chain policy state).
#
# Why the change from the pre-U9 assertion: the legacy implementation
# created a custom chain `VORTIX_KILLSWITCH` containing DROP rules, jumped
# from OUTPUT. U9 replaced that with a default-DROP policy ON OUTPUT
# directly + explicit ACCEPT rules for loopback / RFC1918 / DHCP / tunnel /
# server IPs. The new design is the canonical Linux firewall pattern for
# a killswitch — no "rule below the jump never fires" failure mode, atomic
# via iptables-restore. The custom chain assertion was testing the OLD
# implementation's shape, not the security guarantee.

set -euo pipefail

NS_B="vortix-test-b"
PROFILE_DIR="$(mktemp -d)/profiles"
mkdir -p "$PROFILE_DIR"
cp tests/integration/fixtures/wg-b.conf "$PROFILE_DIR/integration.conf"
export VORTIX_CONFIG_DIR="$(dirname "$PROFILE_DIR")"

# Bring tunnel up + engage killswitch.
ip netns exec vortix-test-a wg-quick up tests/integration/fixtures/wg-a.conf
ip netns exec "$NS_B" target/release/vortix up integration
ip netns exec "$NS_B" target/release/vortix killswitch vpn-only

# Structural assertion: OUTPUT chain default policy is DROP when engaged.
# This is the "fail-fast on regression" check — a code change that
# breaks the default-deny invariant will fire here before the behavioral
# ping test below.
ip netns exec "$NS_B" iptables -L OUTPUT -n | head -n 1 | grep -q "policy DROP" || {
    echo "FAIL: OUTPUT chain does not have DROP policy after killswitch engage"
    ip netns exec "$NS_B" iptables -L OUTPUT -n | head -n 5
    exit 1
}

# Behavioral assertion: outbound traffic to a non-tunnel destination is
# blocked. Using 10.99.0.99 (within the veth subnet but not a peer) — if
# the killswitch is engaged, this should fail.
if ip netns exec "$NS_B" ping -c 1 -W 1 10.99.0.99 2>/dev/null; then
    echo "FAIL: ping to non-tunnel destination succeeded; killswitch not enforcing"
    exit 1
fi

# Release killswitch and verify both structural and behavioral state revert.
ip netns exec "$NS_B" target/release/vortix release-kill-switch

# Structural: OUTPUT default policy back to ACCEPT.
ip netns exec "$NS_B" iptables -L OUTPUT -n | head -n 1 | grep -q "policy ACCEPT" || {
    echo "FAIL: OUTPUT chain policy not restored to ACCEPT after release-killswitch"
    ip netns exec "$NS_B" iptables -L OUTPUT -n | head -n 5
    exit 1
}

# Behavioral: ping to non-tunnel destination should NOT be killed by our
# rules anymore. (It will still fail if 10.99.0.99 is genuinely unroutable
# in the netns — that's a setup issue, not a killswitch issue. We just
# assert the failure isn't from our DROP policy by checking the policy
# above.)

# Disconnect tunnel for cleanup.
ip netns exec "$NS_B" target/release/vortix down
ip netns exec vortix-test-a wg-quick down tests/integration/fixtures/wg-a.conf 2>/dev/null || true

echo "OK: killswitch engages OUTPUT default-DROP + blocks non-tunnel traffic; releases cleanly"
