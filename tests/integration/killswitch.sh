#!/usr/bin/env bash
# Killswitch integration test (plan 015 phase B U8 / plan 012; updated for
# multi-connection plan U9's iptables-restore default-deny design).
#
# Verifies Vortix owns only its ip/ip6tables chains, preserves unrelated host
# policy, and enforces both address families regardless of endpoint family.
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

# Host-owned sentinels must survive engage, refresh, and release.
ip netns exec "$NS_B" iptables -N HOST_SENTINEL
ip netns exec "$NS_B" iptables -A HOST_SENTINEL -j RETURN
ip netns exec "$NS_B" iptables -A OUTPUT -d 203.0.113.1 -j HOST_SENTINEL
ip netns exec "$NS_B" ip6tables -N HOST_SENTINEL
ip netns exec "$NS_B" ip6tables -A HOST_SENTINEL -j RETURN
ip netns exec "$NS_B" ip6tables -A OUTPUT -d 2001:db8::1 -j HOST_SENTINEL
ip netns exec "$NS_B" target/release/vortix killswitch vpn-only

# The host OUTPUT policy stays untouched; Vortix installs one owned jump and
# an owned chain ending in DROP for each family.
ip netns exec "$NS_B" iptables -C OUTPUT -j VORTIX_KILLSWITCH
ip netns exec "$NS_B" iptables -S VORTIX_KILLSWITCH | grep -q -- '-j DROP'
ip netns exec "$NS_B" ip6tables -C OUTPUT -j VORTIX_KILLSWITCH
ip netns exec "$NS_B" ip6tables -S VORTIX_KILLSWITCH | grep -q -- '-j DROP'
ip netns exec "$NS_B" iptables -C OUTPUT -d 203.0.113.1 -j HOST_SENTINEL
ip netns exec "$NS_B" ip6tables -C OUTPUT -d 2001:db8::1 -j HOST_SENTINEL

# Behavioral assertion: outbound traffic to a non-tunnel destination is
# blocked. Using 10.99.0.99 (within the veth subnet but not a peer) — if
# the killswitch is engaged, this should fail.
if ip netns exec "$NS_B" ping -c 1 -W 1 10.99.0.99 2>/dev/null; then
    echo "FAIL: ping to non-tunnel destination succeeded; killswitch not enforcing"
    exit 1
fi

# Exercise the native nft backend and failed transaction semantics while the
# same namespace/tunnel fixture is live.
bash tests/integration/nft_killswitch.sh

# Release killswitch and verify only Vortix-owned state disappears.
ip netns exec "$NS_B" target/release/vortix release-kill-switch

if ip netns exec "$NS_B" iptables -S VORTIX_KILLSWITCH 2>/dev/null; then
    echo "FAIL: Vortix IPv4 chain remains after release"
    exit 1
fi
if ip netns exec "$NS_B" ip6tables -S VORTIX_KILLSWITCH 2>/dev/null; then
    echo "FAIL: Vortix IPv6 chain remains after release"
    exit 1
fi
ip netns exec "$NS_B" iptables -C OUTPUT -d 203.0.113.1 -j HOST_SENTINEL
ip netns exec "$NS_B" ip6tables -C OUTPUT -d 2001:db8::1 -j HOST_SENTINEL

# Behavioral: ping to non-tunnel destination should NOT be killed by our
# rules anymore. (It will still fail if 10.99.0.99 is genuinely unroutable
# in the netns — that's a setup issue, not a killswitch issue. We just
# assert the failure isn't from our DROP policy by checking the policy
# above.)

# Disconnect tunnel for cleanup.
ip netns exec "$NS_B" target/release/vortix down
ip netns exec vortix-test-a wg-quick down tests/integration/fixtures/wg-a.conf 2>/dev/null || true

echo "OK: killswitch owns isolated dual-stack chains and preserves host policy"
