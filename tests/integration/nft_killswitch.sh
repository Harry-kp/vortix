#!/usr/bin/env bash
# nft-only kill-switch integration: multi-tunnel/dual-stack owned-table
# transaction and failed-replacement preservation.

set -euo pipefail

NS_B="vortix-test-b"
REAL_NFT="$(command -v nft)"
PATH_DIR="$(mktemp -d)"
trap 'rm -rf "$PATH_DIR"' EXIT

# Expose required Vortix children but deliberately omit iptables so backend
# detection exercises native nft even on images that install both tools.
for program in bash cat nft wg wg-quick ip resolvectl resolvconf openvpn; do
    resolved="$(command -v "$program" 2>/dev/null || true)"
    if [[ -n "$resolved" ]]; then
        ln -s "$resolved" "$PATH_DIR/$program"
    fi
done

ip netns exec "$NS_B" env PATH="$PATH_DIR" target/release/vortix killswitch vpn-only
nft_before="$(ip netns exec "$NS_B" "$REAL_NFT" list table inet vortix_killswitch)"
grep -q 'policy drop' <<<"$nft_before"
grep -q 'vortix-policy:' <<<"$nft_before"

# An unrelated host-owned table must remain untouched.
ip netns exec "$NS_B" "$REAL_NFT" add table inet host_sentinel
ip netns exec "$NS_B" "$REAL_NFT" list table inet host_sentinel >/dev/null

# Force only the transactional replacement to fail. The prior table must
# remain active, while Vortix persists a non-Blocking effective state.
rm "$PATH_DIR/nft"
cat >"$PATH_DIR/nft" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then exec "$REAL_NFT" "\$@"; fi
if [[ "\${1:-}" == "-f" ]]; then cat >/dev/null; exit 1; fi
exec "$REAL_NFT" "\$@"
EOF
chmod +x "$PATH_DIR/nft"

set +e
human_error="$(ip netns exec "$NS_B" env PATH="$PATH_DIR" target/release/vortix killswitch vpn-only 2>&1)"
human_status=$?
set -e
if [[ $human_status -eq 0 ]]; then
    echo "FAIL: forced nft replacement returned success"
    exit 1
fi
grep -qi 'protection is degraded' <<<"$human_error"

json_error="$(ip netns exec "$NS_B" env PATH="$PATH_DIR" target/release/vortix --json killswitch vpn-only 2>/dev/null || true)"
grep -q '"code":"protection_degraded"' <<<"$json_error"
if ip netns exec "$NS_B" env PATH="$PATH_DIR" target/release/vortix --quiet killswitch vpn-only; then
    echo "FAIL: quiet forced nft replacement returned success"
    exit 1
fi

nft_after="$(ip netns exec "$NS_B" "$REAL_NFT" list table inet vortix_killswitch)"
[[ "$nft_after" == "$nft_before" ]] || {
    echo "FAIL: failed nft replacement changed the prior owned table"
    exit 1
}
grep -q '"state": "Armed"' "$VORTIX_CONFIG_DIR/killswitch.state"
grep -q '"effective_state": "Degraded"' "$VORTIX_CONFIG_DIR/killswitch.state"
ip netns exec "$NS_B" "$REAL_NFT" list table inet host_sentinel >/dev/null

echo "OK: nft replacement is owned, atomic on failure, and degrades truth"
