#!/usr/bin/env bash
# Prove that several live tunnels are each carrying the traffic they claim.
#
# Two connected dots say two processes exist. They do not say the split
# tunnel's subnet leaves through the split tunnel, that general egress leaves
# through the full tunnel, or that either one isn't quietly riding the other's
# interface — which is exactly what happens when two tunnels reach the same
# server and OpenVPN hands the kernel a gateway with no device.
#
# Read-only: it inspects the kernel and sends probe traffic. It never changes
# routing, and it never needs sudo except to read the firewall.
#
# Usage:
#   ./scripts/verify-multi-tunnel.sh                 # split target defaults to 10.250.0.1
#   SPLIT_TARGET=10.250.0.1 ./scripts/verify-multi-tunnel.sh
#   INTERNET_TARGET=1.1.1.1 ./scripts/verify-multi-tunnel.sh

set -uo pipefail

readonly INTERNET_TARGET="${INTERNET_TARGET:-1.1.1.1}"
readonly SPLIT_TARGET="${SPLIT_TARGET:-10.250.0.1}"
readonly VORTIX_BIN="${VORTIX_BIN:-vortix}"

passed=0
failed=0
skipped=0

green() { printf '\033[32m%s\033[0m' "$1"; }
red() { printf '\033[31m%s\033[0m' "$1"; }
grey() { printf '\033[90m%s\033[0m' "$1"; }

ok() {
  printf '  %s  %-44s %s\n' "$(green PASS)" "$1" "${2:-}"
  passed=$((passed + 1))
}
no() {
  printf '  %s  %-44s %s\n' "$(red FAIL)" "$1" "${2:-}"
  failed=$((failed + 1))
}
skip() {
  printf '  %s  %-44s %s\n' "$(grey SKIP)" "$1" "${2:-}"
  skipped=$((skipped + 1))
}
section() { printf '\n%s\n' "$1"; }

# Which device and source address the kernel picks for one destination.
route_dev() { ip route get "$1" 2>/dev/null | head -1 | grep -o 'dev [^ ]*' | awk '{print $2}'; }
route_src() { ip route get "$1" 2>/dev/null | head -1 | grep -o 'src [^ ]*' | awk '{print $2}'; }
iface_addr() { ip -4 -br addr show "$1" 2>/dev/null | awk '{print $3}' | cut -d/ -f1; }

mapfile -t tunnels < <(ip -br link show 2>/dev/null | awk '/^(tun|tap|wg)/ {print $1}')

printf 'Multi-tunnel evidence — %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf 'Tunnels up: %s\n' "${tunnels[*]:-none}"

if [ "${#tunnels[@]}" -lt 2 ]; then
  printf '\n%s\n' "Fewer than two tunnels are up, so there is nothing multi-tunnel to prove."
  printf '%s\n' "Connect a second profile and run this again."
  exit 2
fi

section "Interfaces"
declare -A addr_of
distinct_addrs=1
for tun in "${tunnels[@]}"; do
  a="$(iface_addr "$tun")"
  addr_of["$tun"]="$a"
  if [ -n "$a" ]; then
    ok "$tun has its own address" "$a"
  else
    no "$tun has its own address" "none found"
  fi
done
# Two tunnels sharing one address is the collision that takes a host offline.
mapfile -t addrs < <(printf '%s\n' "${addr_of[@]}" | grep -v '^$' | sort)
mapfile -t uniq_addrs < <(printf '%s\n' "${addrs[@]}" | sort -u)
if [ "${#addrs[@]}" -eq "${#uniq_addrs[@]}" ]; then
  ok "every tunnel has a distinct address" "${uniq_addrs[*]}"
else
  no "every tunnel has a distinct address" "duplicate: ${addrs[*]}"
  distinct_addrs=0
fi

section "Traffic separation — the point of multi-tunnel"
exit_dev="$(route_dev "$INTERNET_TARGET")"
exit_src="$(route_src "$INTERNET_TARGET")"
split_dev="$(route_dev "$SPLIT_TARGET")"
split_src="$(route_src "$SPLIT_TARGET")"

if [ -n "$exit_dev" ]; then
  ok "general egress has an owner" "$INTERNET_TARGET -> $exit_dev (src $exit_src)"
else
  no "general egress has an owner" "no route to $INTERNET_TARGET"
fi

if [ -n "$split_dev" ]; then
  ok "split subnet has an owner" "$SPLIT_TARGET -> $split_dev (src $split_src)"
else
  skip "split subnet has an owner" "no route to $SPLIT_TARGET"
fi

# The failure this catches: one tunnel's routes bound to another tunnel's
# device, so the second tunnel is decorative and its traffic leaves with the
# first tunnel's identity.
if [ -n "$exit_dev" ] && [ -n "$split_dev" ]; then
  if [ "$exit_dev" != "$split_dev" ]; then
    ok "the two destinations use different tunnels" "$exit_dev vs $split_dev"
  else
    no "the two destinations use different tunnels" \
      "both ride $exit_dev — the other tunnel is carrying nothing"
  fi
fi

# Source address must belong to the device carrying the packet. A mismatch
# means the route was bound to a device that does not own that address.
for pair in "egress:$exit_dev:$exit_src" "split:$split_dev:$split_src"; do
  label="${pair%%:*}"
  rest="${pair#*:}"
  dev="${rest%%:*}"
  src="${rest#*:}"
  [ -z "$dev" ] && continue
  own="${addr_of[$dev]:-}"
  if [ -z "$own" ]; then
    skip "$label source belongs to its device" "$dev is not a tunnel"
  elif [ "$own" = "$src" ]; then
    ok "$label source belongs to its device" "$dev owns $src"
  else
    no "$label source belongs to its device" "$dev carries src $src but owns $own"
  fi
done

section "Host integrity"
default_dev="$(ip route show default 2>/dev/null | head -1 | grep -o 'dev [^ ]*' | awk '{print $2}')"
case "$default_dev" in
tun* | tap* | wg*)
  no "LAN default route left alone" "default sits on $default_dev"
  ;;
"")
  no "LAN default route left alone" "no default route at all"
  ;;
*)
  ok "LAN default route left alone" "default via $default_dev"
  ;;
esac

# Each tunnel's own transport must not be routed inside a tunnel.
endpoints="$(pgrep -a openvpn 2>/dev/null | grep -o 'remote [0-9.]*' | awk '{print $2}' | sort -u)"
if [ -z "$endpoints" ]; then
  endpoints="$(ip route show 2>/dev/null | grep -E '^[0-9.]+ via .* dev (en|eth|wl)' | awk '{print $1}')"
fi
if [ -z "$endpoints" ]; then
  skip "VPN servers reached outside the tunnels" "no server address found"
else
  bad=""
  for ep in $endpoints; do
    d="$(route_dev "$ep")"
    case "$d" in tun* | tap* | wg*) bad="$bad $ep->$d" ;; esac
  done
  if [ -z "$bad" ]; then
    ok "VPN servers reached outside the tunnels" "$(echo "$endpoints" | tr '\n' ' ')"
  else
    no "VPN servers reached outside the tunnels" "routed into a tunnel:$bad"
  fi
fi

section "Real traffic, not just the routing table"
if command -v curl >/dev/null 2>&1; then
  seen_exit="$(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null)"
  if [ -n "$seen_exit" ]; then
    if [ -n "$exit_dev" ]; then
      through_iface="$(curl -4 -s --max-time 8 --interface "$exit_dev" https://api.ipify.org 2>/dev/null)"
      if [ -n "$through_iface" ] && [ "$through_iface" = "$seen_exit" ]; then
        ok "internet exit really is the exit tunnel" "$seen_exit via $exit_dev"
      elif [ -n "$through_iface" ]; then
        no "internet exit really is the exit tunnel" "host sees $seen_exit, $exit_dev gives $through_iface"
      else
        skip "internet exit really is the exit tunnel" "$exit_dev could not reach the probe"
      fi
    fi
  else
    skip "internet exit really is the exit tunnel" "no internet reachable"
  fi
else
  skip "internet exit really is the exit tunnel" "curl not installed"
fi

if [ -n "$split_dev" ]; then
  if ping -c 2 -W 3 -I "$split_dev" "$SPLIT_TARGET" >/dev/null 2>&1; then
    ok "split subnet answers through its own tunnel" "$SPLIT_TARGET via $split_dev"
  else
    no "split subnet answers through its own tunnel" "no reply on $split_dev"
  fi
fi

section "DNS"
if command -v resolvectl >/dev/null 2>&1; then
  any_dns=0
  for tun in "${tunnels[@]}"; do
    scopes="$(resolvectl status "$tun" 2>/dev/null | grep -c 'Current Scopes: DNS')"
    servers="$(resolvectl status "$tun" 2>/dev/null | sed -n 's/.*DNS Servers: //p' | head -1)"
    if [ "$scopes" -gt 0 ]; then
      ok "$tun carries its own resolvers" "${servers:-present}"
      any_dns=1
    fi
  done
  if [ "$any_dns" -eq 0 ]; then
    no "a tunnel carries VPN resolvers" "every link reads 'Current Scopes: none' — DNS is going to the LAN"
  fi
else
  skip "a tunnel carries VPN resolvers" "resolvectl not available"
fi

section "Vortix's own view"
if command -v "$VORTIX_BIN" >/dev/null 2>&1 || [ -x "$VORTIX_BIN" ]; then
  reported="$("$VORTIX_BIN" status --json 2>/dev/null | grep -o '"state"' | wc -l | tr -d ' ')"
  if [ "$reported" = "${#tunnels[@]}" ]; then
    ok "status reports every live tunnel" "$reported of ${#tunnels[@]}"
  elif [ -z "$reported" ] || [ "$reported" = "0" ]; then
    skip "status reports every live tunnel" "status produced no JSON"
  else
    no "status reports every live tunnel" "reports $reported, kernel has ${#tunnels[@]}"
  fi
else
  skip "status reports every live tunnel" "$VORTIX_BIN not found"
fi

if command -v nft >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  ruleset="$(sudo nft list ruleset 2>/dev/null)"
  if printf '%s' "$ruleset" | grep -q vortix; then
    missing=""
    for tun in "${tunnels[@]}"; do
      printf '%s' "$ruleset" | grep -q "\"$tun\"" || missing="$missing $tun"
    done
    if [ -z "$missing" ]; then
      ok "kill switch allows every tunnel" "${tunnels[*]}"
    else
      no "kill switch allows every tunnel" "no rule for:$missing"
    fi
  else
    skip "kill switch allows every tunnel" "kill switch is off"
  fi
else
  skip "kill switch allows every tunnel" "needs passwordless sudo and nft"
fi

printf '\n%s passed, %s failed, %s skipped\n' "$passed" "$failed" "$skipped"
[ "$failed" -eq 0 ] && [ "$distinct_addrs" -eq 1 ]
