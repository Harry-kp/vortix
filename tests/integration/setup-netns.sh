#!/usr/bin/env bash
# Create the two-netns harness for vortix integration tests (plan 015
# phase B / plan 012).
#
# Idempotent: rerunning is safe — existing netns/veth are torn down
# before creation. Must run inside a privileged Linux container or as
# root on a real Linux host.

set -euo pipefail

NS_A="vortix-test-a"
NS_B="vortix-test-b"
VETH_A="vortix-veth-a"
VETH_B="vortix-veth-b"
IP_A="10.99.0.1/24"
IP_B="10.99.0.2/24"

cleanup_existing() {
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  ip link del "$VETH_A" 2>/dev/null || true
  ip link del "$VETH_B" 2>/dev/null || true
}

cleanup_existing

ip netns add "$NS_A"
ip netns add "$NS_B"

# veth pair, one end in each netns
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

# Address + up
ip -n "$NS_A" addr add "$IP_A" dev "$VETH_A"
ip -n "$NS_B" addr add "$IP_B" dev "$VETH_B"
ip -n "$NS_A" link set "$VETH_A" up
ip -n "$NS_B" link set "$VETH_B" up
ip -n "$NS_A" link set lo up
ip -n "$NS_B" link set lo up

echo "OK: created netns $NS_A and $NS_B with veth pair (10.99.0.0/24)"
