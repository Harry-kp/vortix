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
CONFIG_DIR="$(dirname "$PROFILE_DIR")"

cleanup() {
  # Bring tunnels down in case of partial-run failure.
  ip netns exec "$NS_A" wg-quick down "$FIXTURE_DIR/wg-a.conf" 2>/dev/null || true
  ip netns exec "$NS_B" wg-quick down "$FIXTURE_DIR/wg-b.conf" 2>/dev/null || true
}
trap cleanup EXIT

# Bring up the peer side first (the "server").
ip netns exec "$NS_A" wg-quick up "$FIXTURE_DIR/wg-a.conf"

# Place both client profiles before the first vortix invocation so the
# identity migration inventories the complete fixture set atomically.
cp "$FIXTURE_DIR/wg-b.conf" "$PROFILE_DIR/integration.conf"
cp "$FIXTURE_DIR/wg-b.conf" "$PROFILE_DIR/unreachable.conf"
cat >"$CONFIG_DIR/config.toml" <<'EOF'
ping_targets = ["10.99.99.1"]
wireguard_handshake_timeout_secs = 4
EOF
cat >"$CONFIG_DIR/settings.toml" <<'EOF'
[engine]
wireguard_handshake_timeout_secs = 4
wireguard_health_targets = ["10.99.99.1"]
EOF

# vortix needs root for kill switch / iface manipulation; the container
# runs as root so just invoke directly.
export VORTIX_CONFIG_DIR="$CONFIG_DIR"
ip netns exec "$NS_B" target/release/vortix up integration

# Verify the tunnel is up + bidirectional. Connected must be backed by the
# durable Vortix-issued generation/health receipt, not merely by interface
# presence or a scanner display string.
STATUS_JSON="$(ip netns exec "$NS_B" target/release/vortix status --json)"
grep -Eq '"state"[[:space:]]*:[[:space:]]*"connected"' <<<"$STATUS_JSON"
grep -Eq '"generation"[[:space:]]*:[[:space:]]*[1-9][0-9]*' <<<"$STATUS_JSON"
grep -Eq '"status"[[:space:]]*:[[:space:]]*"healthy"' <<<"$STATUS_JSON"
ip netns exec "$NS_B" ping -c 2 -W 2 10.99.99.1
ip netns exec "$NS_A" ping -c 2 -W 2 10.99.99.2

# Disconnect cleanly.
ip netns exec "$NS_B" target/release/vortix down

# Interface creation is not success: an unreachable peer must stay
# Handshaking, fail the bounded gate, and leave no owned interface behind.
ip netns exec "$NS_A" wg-quick down "$FIXTURE_DIR/wg-a.conf"
set +e
RUST_LOG="vortix::process=info,vortix::tunnel::wireguard=info" \
  ip netns exec "$NS_B" target/release/vortix up unreachable >"$CONFIG_DIR/unreachable.log" 2>&1 &
UP_PID=$!
sleep 1
if ! ip netns exec "$NS_B" target/release/vortix status --brief | grep -qi handshaking; then
  echo "unreachable WireGuard peer did not remain Handshaking" >&2
  kill "$UP_PID" 2>/dev/null || true
  wait "$UP_PID" 2>/dev/null || true
  exit 1
fi
wait "$UP_PID"
UP_STATUS=$?
set -e
if [[ "$UP_STATUS" -eq 0 ]]; then
  echo "unreachable WireGuard peer was reported connected" >&2
  exit 1
fi
if ! grep -Eqi \
  "current-generation peer handshake|WireGuard handshake failed" \
  "$CONFIG_DIR/unreachable.log"; then
  echo "unreachable WireGuard failure did not report the handshake gate" >&2
  cat "$CONFIG_DIR/unreachable.log" >&2
  exit 1
fi
if ip netns exec "$NS_B" ip link show unreachable >/dev/null 2>&1; then
  echo "attempt-owned unreachable interface leaked after timeout" >&2
  exit 1
fi

echo "OK: vortix WG handshake-gated valid + unreachable lifecycle"

# TODO follow-up coverage (deferred): daemon-died-mid-session adoption
# (depends on Background-mode IPC), DNS-leak guards under the tunnel.
