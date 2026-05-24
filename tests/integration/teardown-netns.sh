#!/usr/bin/env bash
# Teardown for the two-netns vortix integration harness (plan 015 phase B
# / plan 012). Idempotent: missing netns/veth are silently ignored.

set -uo pipefail

ip netns del vortix-test-a 2>/dev/null || true
ip netns del vortix-test-b 2>/dev/null || true
ip link del vortix-veth-a 2>/dev/null || true
ip link del vortix-veth-b 2>/dev/null || true

echo "OK: torn down vortix integration netns"
