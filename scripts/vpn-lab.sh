#!/usr/bin/env bash
# One-droplet, ephemeral VPN compatibility lab for Vortix.
#
# Usage:
#   ./scripts/vpn-lab.sh up                 # create, provision, download profiles
#   ./scripts/vpn-lab.sh status             # show the active droplet and elapsed time
#   ./scripts/vpn-lab.sh ssh                # open a root shell on the lab
#   ./scripts/vpn-lab.sh down               # destroy the droplet (keeps profiles)
#   ./scripts/vpn-lab.sh down --yes         # non-interactive destruction
#   ./scripts/vpn-lab.sh self-test          # validate embedded provisioning script
#
# Configuration:
#   DO_REGION=blr1                          DigitalOcean region
#   DO_SIZE=s-1vcpu-512mb-10gb              smallest suitable droplet
#   DO_IMAGE=ubuntu-24-04-x64               image slug
#   DO_SSH_KEY=<DigitalOcean key name>      defaults to first account key
#   DO_SSH_KEY_FILE=~/.ssh/id_ed25519       local private key override
#   VPN_LAB_PROFILE_DIR=/secure/path        download destination override
#   VPN_LAB_KEEP_ON_FAILURE=1               retain a failed droplet for debugging

set -euo pipefail

readonly REGION="${DO_REGION:-blr1}"
readonly SIZE="${DO_SIZE:-s-1vcpu-512mb-10gb}"
readonly IMAGE="${DO_IMAGE:-ubuntu-24-04-x64}"
readonly SSH_KEY_NAME="${DO_SSH_KEY:-}"
SSH_KEY_FILE="${DO_SSH_KEY_FILE:-}"
readonly LAB_TAG="vortix-ephemeral-vpn-lab"
readonly STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/vortix/vpn-lab"
readonly STATE_FILE="${STATE_DIR}/active"
readonly EXPECTED_PROFILES=(
  01-openvpn-udp-full-inline.ovpn
  02-openvpn-udp-split-route.ovpn
  03-openvpn-tcp-password-full.ovpn
  04-openvpn-tcp-static-challenge.ovpn
  05-openvpn-udp-multi-remote.ovpn
  06-openvpn-conf-extension.conf
  wg07.conf
  wg08.conf
  wg09.conf
  wg10.conf
  wg11.conf
  wg12.conf
  wg13.conf
  wg14.conf
  wg15.conf
)

die() {
  printf '\033[31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

info() {
  printf '\033[36m==>\033[0m %s\n' "$*"
}

ok() {
  printf '\033[32m ✓\033[0m %s\n' "$*"
}

warn() {
  printf '\033[33m !\033[0m %s\n' "$*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required"
}

state_value() {
  local key="$1"
  [[ -f "$STATE_FILE" ]] || return 1
  awk -F '\t' -v wanted="$key" '$1 == wanted { print substr($0, index($0, "\t") + 1); exit }' "$STATE_FILE"
}

write_state() {
  local id="$1" name="$2" ipv4="$3" ipv6="$4" created="$5" profiles="$6"
  install -d -m 700 "$STATE_DIR"
  umask 077
  {
    printf 'id\t%s\n' "$id"
    printf 'name\t%s\n' "$name"
    printf 'ipv4\t%s\n' "$ipv4"
    printf 'ipv6\t%s\n' "$ipv6"
    printf 'created\t%s\n' "$created"
    printf 'profiles\t%s\n' "$profiles"
  } >"${STATE_FILE}.tmp"
  mv "${STATE_FILE}.tmp" "$STATE_FILE"
}

clear_state() {
  rm -f "$STATE_FILE"
}

ssh_key_id() {
  local key_id
  if [[ -n "$SSH_KEY_NAME" ]]; then
    key_id=$(doctl compute ssh-key list --format ID,Name --no-header |
      awk -v wanted="$SSH_KEY_NAME" '$2 == wanted { print $1; exit }')
  else
    key_id=$(doctl compute ssh-key list --format ID --no-header | awk 'NR == 1 { print; exit }')
  fi
  [[ "$key_id" =~ ^[0-9]+$ ]] || die "No DigitalOcean SSH key found; add one or set DO_SSH_KEY"
  printf '%s\n' "$key_id"
}

resolve_ssh_key_file() {
  [[ -n "$SSH_KEY_FILE" ]] && {
    [[ -f "$SSH_KEY_FILE" ]] || die "DO_SSH_KEY_FILE does not exist: ${SSH_KEY_FILE}"
    return
  }

  local fingerprint
  if [[ -n "$SSH_KEY_NAME" ]]; then
    fingerprint=$(doctl compute ssh-key list --format Name,FingerPrint --no-header |
      awk -v wanted="$SSH_KEY_NAME" '$1 == wanted { print $2; exit }')
  else
    fingerprint=$(doctl compute ssh-key list --format FingerPrint --no-header |
      awk 'NR == 1 { print; exit }')
  fi
  [[ -n "$fingerprint" ]] || die "Cannot resolve the selected DigitalOcean SSH key fingerprint"

  local public_key local_fingerprint
  for public_key in "${HOME}"/.ssh/*.pub; do
    [[ -f "$public_key" ]] || continue
    local_fingerprint=$(ssh-keygen -l -E md5 -f "$public_key" 2>/dev/null |
      awk '{ sub(/^MD5:/, "", $2); print $2 }')
    if [[ "$local_fingerprint" == "$fingerprint" ]]; then
      SSH_KEY_FILE="${public_key%.pub}"
      return
    fi
  done
  die "No local private key matches DigitalOcean fingerprint ${fingerprint}; set DO_SSH_KEY_FILE"
}

lab_ssh() {
  resolve_ssh_key_file
  ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
    -i "$SSH_KEY_FILE" "$@"
}

lab_scp() {
  resolve_ssh_key_file
  scp -q -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new \
    -i "$SSH_KEY_FILE" "$@"
}

active_tagged_droplets() {
  doctl compute droplet list --tag-name "$LAB_TAG" --format ID,Name,PublicIPv4,Status --no-header
}

ensure_no_active_lab() {
  local active
  active=$(active_tagged_droplets)
  [[ -z "$active" ]] || die "A Vortix lab already exists:\n${active}\nRun '$0 down' before creating another"
}

wait_for_ssh() {
  local ipv4="$1" deadline=$((SECONDS + 180))
  info "Waiting for SSH on ${ipv4}"
  until lab_ssh "root@${ipv4}" true >/dev/null 2>&1; do
    ((SECONDS < deadline)) || die "SSH did not become ready within 3 minutes"
    sleep 3
  done
}

wait_for_provisioning() {
  local ipv4="$1" deadline=$((SECONDS + 900)) status
  info "Provisioning OpenVPN and WireGuard (usually 3–6 minutes)"
  while ((SECONDS < deadline)); do
    status=$(lab_ssh "root@${ipv4}" \
      'if test -f /root/.vortix-lab-ready; then echo ready; elif test -f /root/.vortix-lab-failed; then echo failed; else echo pending; fi' \
      2>/dev/null || printf 'pending')
    case "$status" in
      ready) return ;;
      failed)
        lab_ssh "root@${ipv4}" 'tail -n 120 /var/log/vortix-lab-provision.log' || true
        die "Lab provisioning failed; the diagnostic tail is shown above"
        ;;
    esac
    printf '.'
    sleep 8
  done
  printf '\n'
  lab_ssh "root@${ipv4}" 'tail -n 120 /var/log/vortix-lab-provision.log' || true
  die "Lab provisioning did not finish within 15 minutes"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

validate_archive_entries() {
  local archive="$1" entry
  while IFS= read -r entry; do
    case "$entry" in
      profiles | profiles/ | profiles/*) ;;
      *) die "Downloaded archive contains an unexpected path: ${entry}" ;;
    esac
    [[ "$entry" != *'/../'* && "$entry" != '../'* ]] ||
      die "Downloaded archive contains a parent traversal: ${entry}"
  done < <(tar -tzf "$archive")
}

verify_profile_matrix() {
  local directory="$1" profile
  for profile in "${EXPECTED_PROFILES[@]}"; do
    [[ -s "${directory}/${profile}" ]] || die "Generated profile is missing: ${profile}"
  done
  [[ -s "${directory}/README.txt" ]] || die "Generated profile README is missing"
  [[ -s "${directory}/credentials.txt" ]] || die "Generated test credentials are missing"
}

download_profiles() {
  local ipv4="$1" output="$2" archive expected actual
  archive=$(mktemp "${TMPDIR:-/tmp}/vortix-vpn-lab-archive.XXXXXX")
  trap 'rm -f "${archive:-}"' RETURN
  install -d -m 700 "$output"
  [[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
    die "Profile output directory must be empty: ${output}"

  info "Downloading the generated profile matrix"
  lab_scp "root@${ipv4}:/root/vortix-vpn-lab-profiles.tar.gz" "$archive"
  expected=$(lab_ssh "root@${ipv4}" 'cat /root/vortix-vpn-lab-profiles.sha256')
  actual=$(sha256_file "$archive")
  [[ "$actual" == "$expected" ]] || die "Profile archive checksum mismatch"
  validate_archive_entries "$archive"
  tar -xzf "$archive" --strip-components=1 -C "$output"
  chmod -R go-rwx "$output"
  verify_profile_matrix "$output"
  trap - RETURN
  rm -f "$archive"
}

render_user_data() {
  cat <<'USER_DATA'
#!/usr/bin/env bash
set -euo pipefail
exec > >(tee -a /var/log/vortix-lab-provision.log) 2>&1
trap 'touch /root/.vortix-lab-failed' ERR
export DEBIAN_FRONTEND=noninteractive

# The 512 MiB SKU is the cheapest suitable droplet. Give apt/OpenSSL enough
# headroom without paying for a larger VM; the swap disappears with the lab.
fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl easy-rsa nftables openvpn wireguard

install -d -m 700 /root/profiles /etc/wireguard/vortix-keys
install -d -m 755 /etc/openvpn/server /etc/openvpn/ccd-udp /etc/openvpn/ccd-tcp

PUBLIC_V4=$(curl -fsS http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)
PUBLIC_V6=$(curl -fsS http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address)
PUBLIC_IF=$(ip route show default | awk '/^default/ { print $5; exit }')
[[ -n "$PUBLIC_V4" && -n "$PUBLIC_V6" && -n "$PUBLIC_IF" ]]

cat >/etc/sysctl.d/90-vortix-lab.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system

cat >/usr/local/sbin/vortix-lab-network <<EOF
#!/bin/sh
set -eu
ip link show vortix-test0 >/dev/null 2>&1 || ip link add vortix-test0 type dummy
ip addr replace 10.250.0.1/24 dev vortix-test0
ip link set vortix-test0 up
nft delete table inet vortix_lab_filter >/dev/null 2>&1 || true
nft delete table ip vortix_lab_nat >/dev/null 2>&1 || true
nft delete table ip6 vortix_lab_nat6 >/dev/null 2>&1 || true
nft -f - <<'NFT'
table inet vortix_lab_filter {
  chain forward {
    type filter hook forward priority filter; policy accept;
    ct state established,related accept
    iifname { "tun-vu", "tun-vt", "wg-lab0", "wg-lab1" } accept
  }
}
table ip vortix_lab_nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "wg-lab0" ip saddr 10.200.0.8 udp dport 53 dnat to 208.67.222.222
    iifname "wg-lab0" ip saddr 10.200.0.8 tcp dport 53 dnat to 208.67.222.222
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr { 10.80.0.0/24, 10.81.0.0/24, 10.200.0.0/24, 10.201.0.0/24, 10.202.0.0/24 } oifname "${PUBLIC_IF}" masquerade
  }
}
table ip6 vortix_lab_nat6 {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip6 saddr fd42:200::/64 oifname "${PUBLIC_IF}" masquerade
  }
}
NFT
EOF
chmod 755 /usr/local/sbin/vortix-lab-network

cat >/etc/systemd/system/vortix-lab-network.service <<'EOF'
[Unit]
Description=Vortix ephemeral VPN lab networking
Before=wg-quick@wg-lab0.service wg-quick@wg-lab1.service openvpn-server@vortix-udp.service openvpn-server@vortix-tcp.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vortix-lab-network
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# OpenVPN PKI and two servers (UDP certificate matrix + TCP credential matrix).
install -d -m 700 /etc/openvpn/vortix-easy-rsa
cp -a /usr/share/easy-rsa/. /etc/openvpn/vortix-easy-rsa/
cd /etc/openvpn/vortix-easy-rsa
export EASYRSA_BATCH=1 EASYRSA_CERT_EXPIRE=30 EASYRSA_CA_EXPIRE=30
./easyrsa init-pki
EASYRSA_REQ_CN='Vortix Ephemeral VPN Lab CA' ./easyrsa build-ca nopass
./easyrsa build-server-full server nopass
for common_name in \
  ovpn-udp-full ovpn-udp-split ovpn-tcp-auth-full \
  ovpn-tcp-static-challenge ovpn-udp-failover ovpn-conf-extension; do
  ./easyrsa build-client-full "$common_name" nopass
done
openvpn --genkey secret /etc/openvpn/vortix-tls-crypt.key
install -m 644 pki/ca.crt pki/issued/server.crt /etc/openvpn/server/
install -m 600 pki/private/server.key /etc/openvpn/server/

cat >/etc/openvpn/server/vortix-udp.conf <<'EOF'
port 1194
proto udp4
dev tun-vu
server 10.80.0.0 255.255.255.0
topology subnet
mssfix 1300 mtu
ca ca.crt
cert server.crt
key server.key
dh none
ecdh-curve prime256v1
tls-crypt /etc/openvpn/vortix-tls-crypt.key
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
client-config-dir /etc/openvpn/ccd-udp
ccd-exclusive
keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup
verb 3
explicit-exit-notify 1
EOF

cat >/etc/openvpn/server/vortix-tcp.conf <<'EOF'
port 443
proto tcp4-server
dev tun-vt
server 10.81.0.0 255.255.255.0
topology subnet
ca ca.crt
cert server.crt
key server.key
dh none
ecdh-curve prime256v1
tls-crypt /etc/openvpn/vortix-tls-crypt.key
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
auth-user-pass-verify /etc/openvpn/vortix-auth.sh via-env
script-security 3
client-config-dir /etc/openvpn/ccd-tcp
ccd-exclusive
keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup
verb 3
EOF

cat >/etc/openvpn/vortix-auth.sh <<'EOF'
#!/bin/sh
set -eu
[ "${username:-}" = vortix ] || exit 1
case "${common_name:-}" in
  ovpn-tcp-auth-full)
    [ "${password:-}" = vortix-pass ]
    ;;
  ovpn-tcp-static-challenge)
    [ "${password:-}" = 'SCRV1:dm9ydGl4LXBhc3M=:MTIzNDU2' ]
    ;;
  *) exit 1 ;;
esac
EOF
# `user nobody` above means the server has already dropped privileges by the
# time it runs this. Mode 700 root:root made every auth-user-pass profile
# unauthenticatable — exec failed with EACCES and OpenVPN reported that as
# AUTH_FAILED, indistinguishable from a wrong password. Group-execute for
# nogroup, still unreadable to everyone else.
chown root:nogroup /etc/openvpn/vortix-auth.sh
chmod 750 /etc/openvpn/vortix-auth.sh

cat >/etc/openvpn/ccd-udp/ovpn-udp-full <<'EOF'
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
EOF
cat >/etc/openvpn/ccd-udp/ovpn-udp-split <<'EOF'
push "route 10.250.0.0 255.255.255.0 vpn_gateway 25"
EOF
cp /etc/openvpn/ccd-udp/ovpn-udp-full /etc/openvpn/ccd-udp/ovpn-udp-failover
cp /etc/openvpn/ccd-udp/ovpn-udp-split /etc/openvpn/ccd-udp/ovpn-conf-extension
cat >/etc/openvpn/ccd-tcp/ovpn-tcp-auth-full <<'EOF'
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
EOF
cat >/etc/openvpn/ccd-tcp/ovpn-tcp-static-challenge <<'EOF'
push "route 10.250.0.0 255.255.255.0 vpn_gateway 25"
EOF

write_openvpn_profile() {
  local common_name="$1" destination="$2" protocol="$3" remote_lines="$4" extra="$5"
  {
    printf 'client\ndev tun\nproto %s\n%s\n' "$protocol" "$remote_lines"
    printf '%s\n' 'nobind' 'persist-key' 'persist-tun' 'remote-cert-tls server'
    printf '%s\n' 'tls-version-min 1.2' 'data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305'
    printf '%s\n' 'auth SHA256' 'auth-nocache' 'mssfix 1300 mtu' 'verb 3'
    [[ -z "$extra" ]] || printf '%s\n' "$extra"
    printf '<ca>\n'; cat pki/ca.crt; printf '</ca>\n'
    printf '<cert>\n'; openssl x509 -in "pki/issued/${common_name}.crt"; printf '</cert>\n'
    printf '<key>\n'; cat "pki/private/${common_name}.key"; printf '</key>\n'
    printf '<tls-crypt>\n'; cat /etc/openvpn/vortix-tls-crypt.key; printf '</tls-crypt>\n'
  } >"/root/profiles/${destination}"
}

write_openvpn_profile ovpn-udp-full 01-openvpn-udp-full-inline.ovpn udp \
  "remote ${PUBLIC_V4} 1194" ''
write_openvpn_profile ovpn-udp-split 02-openvpn-udp-split-route.ovpn udp \
  "remote ${PUBLIC_V4} 1194" ''
write_openvpn_profile ovpn-tcp-auth-full 03-openvpn-tcp-password-full.ovpn tcp-client \
  "remote ${PUBLIC_V4} 443" 'auth-user-pass'
write_openvpn_profile ovpn-tcp-static-challenge 04-openvpn-tcp-static-challenge.ovpn tcp-client \
  "remote ${PUBLIC_V4} 443" $'auth-user-pass\nstatic-challenge "Vortix lab OTP" 1'
write_openvpn_profile ovpn-udp-failover 05-openvpn-udp-multi-remote.ovpn udp \
  $'remote 192.0.2.1 1194\nremote '"${PUBLIC_V4}"$' 1194' \
  $'connect-timeout 3\nconnect-retry 1 3\nconnect-retry-max 2'
write_openvpn_profile ovpn-conf-extension 06-openvpn-conf-extension.conf udp \
  "remote ${PUBLIC_V4} 1194" ''

# WireGuard: one main server plus a second peer endpoint for the multi-peer case.
cd /etc/wireguard/vortix-keys
for key_name in server0 server1 split full hostname ipv6 dual tuned multi leak marked; do
  wg genkey | tee "${key_name}.key" | wg pubkey >"${key_name}.pub"
done
wg genpsk >tuned.psk
chmod 600 ./*.key ./*.psk

SERVER0_PRIVATE=$(cat server0.key)
SERVER0_PUBLIC=$(cat server0.pub)
SERVER1_PRIVATE=$(cat server1.key)
SERVER1_PUBLIC=$(cat server1.pub)

cat >/etc/wireguard/wg-lab0.conf <<EOF
[Interface]
Address = 10.200.0.1/24, fd42:200::1/64
ListenPort = 51820
PrivateKey = ${SERVER0_PRIVATE}

[Peer]
PublicKey = $(cat split.pub)
AllowedIPs = 10.200.0.2/32

[Peer]
PublicKey = $(cat full.pub)
AllowedIPs = 10.200.0.3/32

[Peer]
PublicKey = $(cat hostname.pub)
AllowedIPs = 10.200.0.4/32

[Peer]
PublicKey = $(cat ipv6.pub)
AllowedIPs = 10.200.0.5/32

[Peer]
PublicKey = $(cat dual.pub)
AllowedIPs = 10.200.0.6/32, fd42:200::6/128

[Peer]
PublicKey = $(cat tuned.pub)
PresharedKey = $(cat tuned.psk)
AllowedIPs = 10.200.0.7/32

[Peer]
PublicKey = $(cat multi.pub)
AllowedIPs = 10.202.0.2/32

[Peer]
PublicKey = $(cat leak.pub)
AllowedIPs = 10.200.0.8/32

[Peer]
PublicKey = $(cat marked.pub)
AllowedIPs = 10.200.0.9/32
EOF

cat >/etc/wireguard/wg-lab1.conf <<EOF
[Interface]
Address = 10.201.0.1/24
ListenPort = 51821
PrivateKey = ${SERVER1_PRIVATE}
Table = off
PostUp = ip route replace 10.202.0.2/32 dev %i table 201; ip rule delete priority 10201 2>/dev/null || true; ip rule add priority 10201 from 10.201.0.0/24 lookup 201
PreDown = ip rule delete priority 10201 2>/dev/null || true; ip route delete 10.202.0.2/32 dev %i table 201 2>/dev/null || true

[Peer]
PublicKey = $(cat multi.pub)
AllowedIPs = 10.202.0.2/32
EOF
chmod 600 /etc/wireguard/wg-lab0.conf /etc/wireguard/wg-lab1.conf

write_wireguard_profile() {
  local destination="$1" private_key="$2" address="$3" dns="$4" mtu="$5" peer_body="$6"
  local interface_extra="${7:-}"
  {
    printf '[Interface]\nPrivateKey = %s\nAddress = %s\n' "$private_key" "$address"
    [[ -z "$dns" ]] || printf 'DNS = %s\n' "$dns"
    [[ -z "$mtu" ]] || printf 'MTU = %s\n' "$mtu"
    [[ -z "$interface_extra" ]] || printf '%s\n' "$interface_extra"
    printf '\n%s\n' "$peer_body"
  } >"/root/profiles/${destination}"
}

write_wireguard_profile wg07.conf "$(cat split.key)" '10.200.0.2/32' '' '' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
Endpoint = ${PUBLIC_V4}:51820
AllowedIPs = 10.200.0.0/24, 10.250.0.0/24
PersistentKeepalive = 25"

write_wireguard_profile wg08.conf "$(cat full.key)" '10.200.0.3/32' '1.1.1.1, 1.0.0.1' '' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
Endpoint = ${PUBLIC_V4}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"

HOSTNAME_ENDPOINT="${PUBLIC_V4//./-}.sslip.io"
write_wireguard_profile wg09.conf "$(cat hostname.key)" '10.200.0.4/32' '' '' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
Endpoint = ${HOSTNAME_ENDPOINT}:51820
AllowedIPs = 10.200.0.0/24, 10.250.0.0/24
PersistentKeepalive = 25"

write_wireguard_profile wg10.conf "$(cat ipv6.key)" '10.200.0.5/32' '' '' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
Endpoint = [${PUBLIC_V6}]:51820
AllowedIPs = 10.200.0.0/24, 10.250.0.0/24
PersistentKeepalive = 25"

write_wireguard_profile wg11.conf "$(cat dual.key)" '10.200.0.6/32, fd42:200::6/128' \
  '1.1.1.1, 2606:4700:4700::1111' '' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
Endpoint = ${PUBLIC_V4}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25"

write_wireguard_profile wg12.conf "$(cat tuned.key)" '10.200.0.7/32' '' '1280' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
PresharedKey = $(cat tuned.psk)
Endpoint = ${PUBLIC_V4}:51820
AllowedIPs = 10.200.0.0/24, 10.250.0.0/24
PersistentKeepalive = 15"

write_wireguard_profile wg13.conf "$(cat multi.key)" '10.202.0.2/32' '' '' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
Endpoint = ${PUBLIC_V4}:51820
AllowedIPs = 10.200.0.0/24
PersistentKeepalive = 25

[Peer]
PublicKey = ${SERVER1_PUBLIC}
Endpoint = ${PUBLIC_V4}:51821
AllowedIPs = 10.201.0.0/24
PersistentKeepalive = 25"

write_wireguard_profile wg14.conf "$(cat leak.key)" '10.200.0.8/32' '9.9.9.9' '' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
Endpoint = ${PUBLIC_V4}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"

write_wireguard_profile wg15.conf "$(cat marked.key)" '10.200.0.9/32' '' '' \
  "[Peer]
PublicKey = ${SERVER0_PUBLIC}
Endpoint = ${PUBLIC_V4}:51820
AllowedIPs = 10.200.0.0/24, 10.250.0.0/24
PersistentKeepalive = 25" 'FwMark = 51820'

cat >/root/profiles/credentials.txt <<'EOF'
OpenVPN test credentials (profiles 03 and 04)
Username: vortix
Password: vortix-pass
Static challenge / OTP for profile 04: 123456
EOF

cat >/root/profiles/README.txt <<EOF
Vortix ephemeral VPN compatibility matrix
Droplet IPv4: ${PUBLIC_V4}
Droplet IPv6: ${PUBLIC_V6}

01  OpenVPN UDP, certificate-only, full IPv4 tunnel, inline material
02  OpenVPN UDP, certificate-only, split route to 10.250.0.0/24
03  OpenVPN TCP/443, username/password, full IPv4 tunnel
04  OpenVPN TCP/443, username/password + static challenge, split route
05  OpenVPN UDP, unreachable first remote then working fallback, full tunnel
06  OpenVPN split tunnel using the .conf extension
07  WireGuard split IPv4 route
08  WireGuard full IPv4 tunnel with DNS
09  WireGuard hostname endpoint, split IPv4 route
10  WireGuard IPv6 endpoint, split IPv4 route
11  WireGuard full dual-stack tunnel with IPv4 + IPv6 DNS
12  WireGuard split route with preshared key, MTU 1280, keepalive 15
13  WireGuard two-peer split routing (10.200.0.0/24 and 10.201.0.0/24)
14  WireGuard full IPv4 with intentional DNS-provider hijack (negative test)
15  WireGuard split route with explicit FwMark 51820

WireGuard names are intentionally short: Darwin maps profile names to interface
names and rejects long names. Vortix should explain this at import time.

Useful checks:
  Split tunnel: route -n get 10.250.0.1; ping -c 3 10.250.0.1
  Full tunnel:  curl -4 --max-time 15 https://cloudflare.com/cdn-cgi/trace
  Dual stack:   curl -6 --max-time 15 https://cloudflare.com/cdn-cgi/trace
  Multi-peer:   ping -c 3 10.200.0.1; ping -c 3 10.201.0.1
EOF

chmod 600 /root/profiles/*
systemctl daemon-reload
systemctl enable --now vortix-lab-network.service
systemctl enable --now wg-quick@wg-lab0.service wg-quick@wg-lab1.service
systemctl enable --now openvpn-server@vortix-udp.service openvpn-server@vortix-tcp.service

systemctl is-active --quiet vortix-lab-network.service
systemctl is-active --quiet wg-quick@wg-lab0.service
systemctl is-active --quiet wg-quick@wg-lab1.service
systemctl is-active --quiet openvpn-server@vortix-udp.service
systemctl is-active --quiet openvpn-server@vortix-tcp.service
ip route get 10.202.0.2 from 10.201.0.1 | grep -q 'dev wg-lab1.*table 201'

cd /root
tar -czf vortix-vpn-lab-profiles.tar.gz profiles
sha256sum vortix-vpn-lab-profiles.tar.gz | awk '{ print $1 }' >vortix-vpn-lab-profiles.sha256
touch /root/.vortix-lab-ready
rm -f /root/.vortix-lab-failed
USER_DATA
}

command_up() {
  (($# == 0)) || die "Usage: $0 up"
  require_cmd doctl
  require_cmd ssh
  require_cmd scp
  require_cmd ssh-keygen
  require_cmd tar
  doctl account get >/dev/null
  ensure_no_active_lab

  local key_id name user_data id ipv4 ipv6 addresses created output keep_failed=0
  key_id=$(ssh_key_id)
  resolve_ssh_key_file
  name="vortix-vpn-lab-$(date -u +%Y%m%d-%H%M%S)"
  user_data=$(mktemp "${TMPDIR:-/tmp}/vortix-vpn-lab-userdata.XXXXXX")
  render_user_data >"$user_data"
  chmod 600 "$user_data"

  cleanup_failed_up() {
    local failed_ids attempt
    rm -f "${user_data:-}"
    if [[ "$keep_failed" -eq 0 && "${VPN_LAB_KEEP_ON_FAILURE:-0}" != 1 ]]; then
      failed_ids="${id:-}"
      if [[ -z "$failed_ids" ]]; then
        # If Ctrl-C interrupted `doctl create` before it printed the ID, query
        # only this invocation's unique name. Never bulk-delete by the shared
        # tag: another workstation could have raced us after the initial check.
        for attempt in 1 2 3; do
          failed_ids=$(active_tagged_droplets 2>/dev/null |
            awk -v wanted="$name" '$2 == wanted { print $1 }' | tr '\n' ' ' || true)
          [[ -n "$failed_ids" ]] && break
          sleep 2
        done
      fi
      if [[ -n "$failed_ids" ]]; then
        warn "Provisioning did not complete; deleting droplet(s) ${failed_ids} to stop billing"
        # shellcheck disable=SC2086
        doctl compute droplet delete $failed_ids --force >/dev/null 2>&1 || true
      fi
      clear_state
    fi
  }
  trap cleanup_failed_up EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  info "Creating one ${SIZE} droplet in ${REGION}"
  id=$(doctl compute droplet create "$name" \
    --region "$REGION" --size "$SIZE" --image "$IMAGE" \
    --ssh-keys "$key_id" --tag-names "$LAB_TAG" --enable-ipv6 \
    --user-data-file "$user_data" --wait --format ID --no-header)
  [[ "$id" =~ ^[0-9]+$ ]] || die "DigitalOcean returned an invalid droplet ID: ${id}"

  local address_deadline=$((SECONDS + 60))
  while ((SECONDS < address_deadline)); do
    addresses=$(doctl compute droplet get "$id" --format PublicIPv4,PublicIPv6 --no-header)
    read -r ipv4 ipv6 <<<"$addresses"
    [[ -n "$ipv4" && "$ipv4" != '<nil>' && -n "$ipv6" && "$ipv6" != '<nil>' ]] && break
    sleep 2
  done
  [[ -n "$ipv4" && "$ipv4" != '<nil>' ]] || die "Droplet has no public IPv4 address"
  [[ -n "$ipv6" && "$ipv6" != '<nil>' ]] ||
    die "Droplet has no public IPv6 address; the wg10/wg11 matrix cannot be generated"
  created=$(date +%s)
  output="${VPN_LAB_PROFILE_DIR:-${HOME}/Downloads/${name}-profiles}"
  [[ "$output" != *$'\n'* && "$output" != *$'\t'* ]] ||
    die "VPN_LAB_PROFILE_DIR cannot contain tabs or newlines"
  write_state "$id" "$name" "$ipv4" "$ipv6" "$created" "$output"

  wait_for_ssh "$ipv4"
  wait_for_provisioning "$ipv4"
  download_profiles "$ipv4" "$output"
  keep_failed=1
  rm -f "$user_data"
  trap - EXIT INT TERM

  ok "Lab ready: ${name} (${ipv4})"
  ok "${#EXPECTED_PROFILES[@]} profiles downloaded to ${output}"
  printf '\nRead %s/README.txt, then import the directory into Vortix.\n' "$output"
  printf 'When testing is finished, stop billing with:\n  %s down\n' "$0"
}

command_status() {
  (($# == 0)) || die "Usage: $0 status"
  require_cmd doctl
  local id created profiles details elapsed
  id=$(state_value id || true)
  if [[ ! "$id" =~ ^[0-9]+$ ]]; then
    details=$(active_tagged_droplets)
    [[ -n "$details" ]] || {
      printf 'No active Vortix VPN lab.\n'
      return
    }
    warn "A tagged lab exists without local state:\n${details}"
    return
  fi
  details=$(doctl compute droplet get "$id" --format ID,Name,PublicIPv4,PublicIPv6,Status --no-header 2>/dev/null || true)
  [[ -n "$details" ]] || {
    warn "Recorded droplet ${id} no longer exists; clearing stale state"
    clear_state
    return
  }
  created=$(state_value created)
  profiles=$(state_value profiles)
  elapsed=$((($(date +%s) - created + 59) / 60))
  printf '%s\nElapsed: %s minute(s) of billable lifetime\nProfiles: %s\n' "$details" "$elapsed" "$profiles"
}

command_down() {
  require_cmd doctl
  (($# <= 1)) || die "Usage: $0 down [--yes]"
  [[ "${1:-}" == --yes || -z "${1:-}" ]] || die "Usage: $0 down [--yes]"
  local assume_yes=0 id name profiles answer details recorded
  [[ "${1:-}" != --yes ]] || assume_yes=1
  id=$(state_value id || true)
  name=$(state_value name || true)
  profiles=$(state_value profiles || true)
  if [[ ! "$id" =~ ^[0-9]+$ ]]; then
    details=$(active_tagged_droplets)
    [[ -z "$details" ]] && {
      clear_state
      printf 'No active Vortix VPN lab.\n'
      return
    }
    die "Tagged lab exists but local ownership state is missing; delete it explicitly with doctl:\n${details}"
  fi
  [[ "$name" == vortix-vpn-lab-* ]] || die "Refusing to delete unexpected recorded droplet name: ${name}"
  recorded=$(doctl compute droplet get "$id" --format Name,Tags --no-header 2>/dev/null || true)
  [[ -n "$recorded" ]] || {
    warn "Recorded droplet ${id} no longer exists; clearing stale state"
    clear_state
    return
  }
  [[ "$recorded" == "$name"* && "$recorded" == *"$LAB_TAG"* ]] ||
    die "Recorded droplet ${id} no longer matches Vortix lab ownership; refusing deletion"

  if ((assume_yes == 0)); then
    [[ -t 0 ]] || die "Non-interactive destruction requires: $0 down --yes"
    printf 'Destroy %s (droplet %s)? Profiles remain at %s [y/N] ' "$name" "$id" "$profiles"
    read -r answer
    [[ "$answer" == y || "$answer" == Y ]] || die "Destruction cancelled"
  fi
  info "Deleting ${name} (${id})"
  doctl compute droplet delete "$id" --force
  clear_state
  ok "Droplet destroyed; downloaded profiles were retained"
}

command_ssh() {
  (($# == 0)) || die "Usage: $0 ssh"
  local ipv4
  ipv4=$(state_value ipv4 || true)
  [[ -n "$ipv4" ]] || die "No active lab; run '$0 up' first"
  lab_ssh "root@${ipv4}"
}

command_self_test() {
  (($# == 0)) || die "Usage: $0 self-test"
  require_cmd bash
  local rendered profile bytes
  rendered=$(mktemp "${TMPDIR:-/tmp}/vortix-vpn-lab-userdata.XXXXXX")
  trap 'rm -f "$rendered"' RETURN
  render_user_data >"$rendered"
  bash -n "$rendered"
  bytes=$(wc -c <"$rendered" | tr -d ' ')
  ((bytes <= 65536)) || die "Embedded user data is ${bytes} bytes; DigitalOcean limit is 65536"
  for profile in "${EXPECTED_PROFILES[@]}"; do
    grep -Fq "$profile" "$rendered" || die "Provisioner does not generate ${profile}"
  done
  grep -Fq 'ip route get 10.202.0.2 from 10.201.0.1' "$rendered" ||
    die "Multi-peer return-path health check is missing"
  rm -f "$rendered"
  trap - RETURN
  ok "Shell syntax, 64 KiB user-data bound, ${#EXPECTED_PROFILES[@]}-profile matrix, and multi-peer route guard passed"
}

usage() {
  cat <<EOF
Usage: $0 <command>

Commands:
  up              Create one droplet, provision all profiles, and download them
  status          Show the active droplet, elapsed lifetime, and profile path
  ssh             Open an SSH shell on the active lab
  down [--yes]    Destroy the active droplet; downloaded profiles are retained
  self-test       Validate the embedded provisioner without using DigitalOcean

The script never imports profiles automatically and never deletes downloaded keys.
EOF
}

case "${1:-}" in
  up) shift; command_up "$@" ;;
  status) shift; command_status "$@" ;;
  ssh) shift; command_ssh "$@" ;;
  down) shift; command_down "$@" ;;
  self-test) shift; command_self_test "$@" ;;
  help | --help | -h | '') usage ;;
  *) die "Unknown command: $1 (run '$0 help')" ;;
esac
