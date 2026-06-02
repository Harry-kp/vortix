#!/usr/bin/env bash
# scripts/test-infra.sh — On-demand VPN test infrastructure on DigitalOcean
#
# Spins up throwaway droplets running WireGuard / OpenVPN in various auth
# configurations, generates client profiles, downloads them, and optionally
# imports them into vortix.  Tears everything down when you're done.
#
# Prerequisites:
#   brew install doctl wireguard-tools  (or apt-get on Linux)
#   doctl auth init                     (one-time)
#
# Usage:
#   ./scripts/test-infra.sh up          # create all VPN servers
#   ./scripts/test-infra.sh up wg-full wg-split ovpn-cert
#                                       # create only the named flavors
#   ./scripts/test-infra.sh status      # show droplet IPs + readiness
#   ./scripts/test-infra.sh profiles    # download client configs
#   ./scripts/test-infra.sh import      # download + vortix import
#   ./scripts/test-infra.sh down        # destroy everything
#   ./scripts/test-infra.sh ssh <name>  # SSH into a droplet
#
# Available flavors:
#   wg-full      WireGuard, AllowedIPs = 0.0.0.0/0 (full tunnel / primary)
#   wg-split     WireGuard, AllowedIPs = 10.8.0.0/24 (split tunnel / secondary)
#   wg-fwmark    WireGuard, AllowedIPs = 0.0.0.0/0, FwMark = 51820
#   ovpn-cert    OpenVPN, certificate-only auth (no user/pass)
#   ovpn-auth    OpenVPN, username + password auth
#   ovpn-totp    OpenVPN, username + password + TOTP (google-authenticator)
#
# All resources are tagged "vortix-test-<session>" for easy bulk cleanup.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

REGION="${DO_REGION:-fra1}"
SIZE="${DO_SIZE:-s-1vcpu-512mb-10gb}"
IMAGE="${DO_IMAGE:-ubuntu-24-04-x64}"
SSH_KEY_NAME="${DO_SSH_KEY:-}"                  # blank = auto-detect first key
SSH_KEY_FILE="${DO_SSH_KEY_FILE:-}"             # blank = auto-detect from DO fingerprint
SESSION_FILE="${TMPDIR:-/tmp}/vortix-test-session"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_DIR="${SCRIPT_DIR}/test-profiles"
ALL_FLAVORS=(wg-full wg-split wg-fwmark ovpn-cert ovpn-auth ovpn-totp)

# ── Helpers ──────────────────────────────────────────────────────────────────

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m ✓\033[0m  %s\n' "$*"; }
warn() { printf '\033[33m !\033[0m  %s\n' "$*"; }

require_cmd() {
    command -v "$1" &>/dev/null || die "'$1' not found. Install it first."
}

session_id() {
    if [[ -f "$SESSION_FILE" ]]; then
        cat "$SESSION_FILE"
    else
        local id="vortix-test-$(date +%s | tail -c 7)"
        echo "$id" > "$SESSION_FILE"
        echo "$id"
    fi
}

tag() { echo "$(session_id)"; }

ssh_key_id() {
    if [[ -n "$SSH_KEY_NAME" ]]; then
        doctl compute ssh-key list --format ID,Name --no-header \
            | awk -v name="$SSH_KEY_NAME" '$2 == name { print $1; exit }'
    else
        doctl compute ssh-key list --format ID --no-header | head -1
    fi
}

# Find the local private key file that matches the DO SSH key fingerprint.
# Caches result in SSH_KEY_FILE for the rest of the session.
resolve_ssh_key_file() {
    [[ -n "$SSH_KEY_FILE" ]] && return

    local do_fp
    if [[ -n "$SSH_KEY_NAME" ]]; then
        do_fp=$(doctl compute ssh-key list --format Name,FingerPrint --no-header \
                | awk -v name="$SSH_KEY_NAME" '$1 == name { print $2; exit }')
    else
        do_fp=$(doctl compute ssh-key list --format FingerPrint --no-header | head -1)
    fi

    [[ -z "$do_fp" ]] && die "Cannot resolve DO SSH key fingerprint."

    for pub in ~/.ssh/*.pub; do
        [[ -f "$pub" ]] || continue
        local local_fp
        local_fp=$(ssh-keygen -l -E md5 -f "$pub" 2>/dev/null | awk '{print $2}' | sed 's/^MD5://')
        if [[ "$local_fp" == "$do_fp" ]]; then
            SSH_KEY_FILE="${pub%.pub}"
            return
        fi
    done

    die "No local SSH key matches DO fingerprint ${do_fp}. Set DO_SSH_KEY_FILE=/path/to/key"
}

# Wrapper: SSH with the correct identity file
# Uses -n to prevent consuming stdin (safe inside while-read loops).
do_ssh() {
    resolve_ssh_key_file
    ssh -n -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        -i "$SSH_KEY_FILE" "$@"
}

# Wrapper: SCP with the correct identity file
do_scp() {
    resolve_ssh_key_file
    scp -o StrictHostKeyChecking=no -o BatchMode=yes \
        -i "$SSH_KEY_FILE" "$@"
}

droplet_ip() {
    local name="$1"
    doctl compute droplet list --tag-name "$(tag)" --format Name,PublicIPv4 --no-header \
        | awk -v n="$name" '$1 == n { print $2 }'
}

wait_ssh() {
    local ip="$1" max_wait=120 elapsed=0
    while ! do_ssh "root@${ip}" true 2>/dev/null; do
        sleep 5
        elapsed=$((elapsed + 5))
        [[ $elapsed -ge $max_wait ]] && die "SSH to ${ip} timed out after ${max_wait}s"
    done
}

wait_cloud_init() {
    local ip="$1" max_wait=300 elapsed=0
    info "Waiting for cloud-init on ${ip}..."
    while true; do
        local status
        status=$(do_ssh "root@${ip}" \
                     "cloud-init status --format json 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"status\"])'" 2>/dev/null || echo "pending")
        case "$status" in
            done)  ok "cloud-init finished on ${ip}"; return 0 ;;
            error) die "cloud-init FAILED on ${ip}. Run: ssh root@${ip} 'cat /var/log/cloud-init-output.log'" ;;
        esac
        sleep 10
        elapsed=$((elapsed + 10))
        [[ $elapsed -ge $max_wait ]] && die "cloud-init on ${ip} timed out after ${max_wait}s"
    done
}

# ── Cloud-init generators ───────────────────────────────────────────────────
# Each function prints a cloud-init YAML to stdout.
# The server generates client configs and drops them in /root/client-profiles/.

cloudinit_wg_full() {
    cat <<'CLOUD_INIT'
#cloud-config
package_update: true
packages: [wireguard, qrencode]

write_files:
  - path: /root/setup-wg.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      set -euo pipefail
      mkdir -p /root/client-profiles

      # Generate keys
      SERVER_PRIV=$(wg genkey)
      SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
      CLIENT_PRIV=$(wg genkey)
      CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
      PSK=$(wg genpsk)

      SERVER_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)
      # Detect the actual egress interface -- DO droplets sometimes ship
      # with `ens3` rather than `eth0`, and hardcoding `eth0` makes the
      # MASQUERADE rule fire on a non-existent interface -> 100% packet
      # loss for clients with no signal from the server side.
      PUBLIC_IF=$(ip route show default | awk '/^default/ {print $5; exit}')

      # Server config
      cat > /etc/wireguard/wg0.conf <<EOF
      [Interface]
      PrivateKey = ${SERVER_PRIV}
      Address = 10.66.66.1/24
      ListenPort = 51820
      PostUp = iptables -t nat -A POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT
      PostDown = iptables -t nat -D POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT

      [Peer]
      PublicKey = ${CLIENT_PUB}
      PresharedKey = ${PSK}
      AllowedIPs = 10.66.66.2/32
      EOF

      # Client config -- full tunnel (0.0.0.0/0)
      cat > /root/client-profiles/wg-full.conf <<EOF
      [Interface]
      PrivateKey = ${CLIENT_PRIV}
      Address = 10.66.66.2/24
      DNS = 1.1.1.1

      [Peer]
      PublicKey = ${SERVER_PUB}
      PresharedKey = ${PSK}
      Endpoint = ${SERVER_IP}:51820
      AllowedIPs = 0.0.0.0/0, ::/0
      PersistentKeepalive = 25
      EOF

      # Strip leading whitespace from heredoc indentation
      sed -i 's/^      //' /etc/wireguard/wg0.conf /root/client-profiles/wg-full.conf

      # Enable IP forwarding
      sysctl -w net.ipv4.ip_forward=1
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

      # Firewall

      # Start
      systemctl enable wg-quick@wg0
      systemctl start wg-quick@wg0

      echo "READY" > /root/.vpn-ready

runcmd:
  - bash /root/setup-wg.sh
CLOUD_INIT
}

cloudinit_wg_split() {
    cat <<'CLOUD_INIT'
#cloud-config
package_update: true
packages: [wireguard]

write_files:
  - path: /root/setup-wg.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      set -euo pipefail
      mkdir -p /root/client-profiles

      SERVER_PRIV=$(wg genkey)
      SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
      CLIENT_PRIV=$(wg genkey)
      CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)

      SERVER_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)
      # See `cloudinit_wg_full` for why we don't hardcode `eth0`.
      PUBLIC_IF=$(ip route show default | awk '/^default/ {print $5; exit}')

      cat > /etc/wireguard/wg0.conf <<EOF
      [Interface]
      PrivateKey = ${SERVER_PRIV}
      Address = 10.8.0.1/24
      ListenPort = 51821
      PostUp = iptables -t nat -A POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT
      PostDown = iptables -t nat -D POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT

      [Peer]
      PublicKey = ${CLIENT_PUB}
      AllowedIPs = 10.8.0.2/32
      EOF

      cat > /root/client-profiles/wg-split.conf <<EOF
      [Interface]
      PrivateKey = ${CLIENT_PRIV}
      Address = 10.8.0.2/24
      DNS = 1.0.0.1

      [Peer]
      PublicKey = ${SERVER_PUB}
      Endpoint = ${SERVER_IP}:51821
      AllowedIPs = 10.8.0.0/24
      PersistentKeepalive = 25
      EOF

      sed -i 's/^      //' /etc/wireguard/wg0.conf /root/client-profiles/wg-split.conf

      sysctl -w net.ipv4.ip_forward=1
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
      systemctl enable wg-quick@wg0
      systemctl start wg-quick@wg0
      echo "READY" > /root/.vpn-ready

runcmd:
  - bash /root/setup-wg.sh
CLOUD_INIT
}

cloudinit_wg_fwmark() {
    cat <<'CLOUD_INIT'
#cloud-config
package_update: true
packages: [wireguard]

write_files:
  - path: /root/setup-wg.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      set -euo pipefail
      mkdir -p /root/client-profiles

      SERVER_PRIV=$(wg genkey)
      SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
      CLIENT_PRIV=$(wg genkey)
      CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
      PSK=$(wg genpsk)

      SERVER_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)
      # See `cloudinit_wg_full` for why we don't hardcode `eth0`.
      PUBLIC_IF=$(ip route show default | awk '/^default/ {print $5; exit}')

      cat > /etc/wireguard/wg0.conf <<EOF
      [Interface]
      PrivateKey = ${SERVER_PRIV}
      Address = 10.77.77.1/24
      ListenPort = 51822
      FwMark = 51820
      PostUp = iptables -t nat -A POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT
      PostDown = iptables -t nat -D POSTROUTING -o ${PUBLIC_IF} -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT

      [Peer]
      PublicKey = ${CLIENT_PUB}
      PresharedKey = ${PSK}
      AllowedIPs = 10.77.77.2/32
      EOF

      cat > /root/client-profiles/wg-fwmark.conf <<EOF
      [Interface]
      PrivateKey = ${CLIENT_PRIV}
      Address = 10.77.77.2/24
      DNS = 1.1.1.1
      FwMark = 51820

      [Peer]
      PublicKey = ${SERVER_PUB}
      PresharedKey = ${PSK}
      Endpoint = ${SERVER_IP}:51822
      AllowedIPs = 0.0.0.0/0, ::/0
      PersistentKeepalive = 25
      EOF

      sed -i 's/^      //' /etc/wireguard/wg0.conf /root/client-profiles/wg-fwmark.conf

      sysctl -w net.ipv4.ip_forward=1
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
      systemctl enable wg-quick@wg0
      systemctl start wg-quick@wg0
      echo "READY" > /root/.vpn-ready

runcmd:
  - bash /root/setup-wg.sh
CLOUD_INIT
}

cloudinit_ovpn_cert() {
    cat <<'CLOUD_INIT'
#cloud-config
package_update: true
packages: [openvpn, easy-rsa]

write_files:
  - path: /root/setup-ovpn.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      set -euo pipefail
      mkdir -p /root/client-profiles

      SERVER_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)

      # Init PKI
      export EASYRSA_BATCH=1
      make-cadir /etc/openvpn/easy-rsa
      cd /etc/openvpn/easy-rsa

      ./easyrsa init-pki
      EASYRSA_REQ_CN="vortix-test-ca" ./easyrsa build-ca nopass
      ./easyrsa build-server-full server nopass
      ./easyrsa build-client-full client-cert nopass
      ./easyrsa gen-dh
      openvpn --genkey secret /etc/openvpn/easy-rsa/pki/ta.key

      # Server config
      cat > /etc/openvpn/server.conf <<EOF
      port 1194
      proto udp
      dev tun
      ca /etc/openvpn/easy-rsa/pki/ca.crt
      cert /etc/openvpn/easy-rsa/pki/issued/server.crt
      key /etc/openvpn/easy-rsa/pki/private/server.key
      dh /etc/openvpn/easy-rsa/pki/dh.pem
      tls-auth /etc/openvpn/easy-rsa/pki/ta.key 0
      server 10.9.0.0 255.255.255.0
      push "redirect-gateway def1 bypass-dhcp"
      push "dhcp-option DNS 1.1.1.1"
      push "dhcp-option DNS 1.0.0.1"
      keepalive 10 120
      cipher AES-256-GCM
      auth SHA256
      persist-key
      persist-tun
      verb 3
      mssfix 1400
      tun-mtu 1400
      push "mssfix 1400"
      push "tun-mtu 1400"
      status /var/log/openvpn-status.log
      EOF

      sed -i 's/^      //' /etc/openvpn/server.conf

      # Client config -- cert only, no user/pass
      CA=$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
      CERT=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/client-cert.crt)
      KEY=$(cat /etc/openvpn/easy-rsa/pki/private/client-cert.key)
      TA=$(cat /etc/openvpn/easy-rsa/pki/ta.key)

      cat > /root/client-profiles/ovpn-cert.ovpn <<EOF
      client
      dev tun
      proto udp
      remote ${SERVER_IP} 1194
      resolv-retry infinite
      nobind
      persist-key
      persist-tun
      remote-cert-tls server
      cipher AES-256-GCM
      auth SHA256
      key-direction 1
      verb 3

      <ca>
      ${CA}
      </ca>

      <cert>
      ${CERT}
      </cert>

      <key>
      ${KEY}
      </key>

      <tls-auth>
      ${TA}
      </tls-auth>
      EOF

      sed -i 's/^      //' /root/client-profiles/ovpn-cert.ovpn

      # Enable forwarding + NAT
      sysctl -w net.ipv4.ip_forward=1
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
      # Detect the actual egress interface -- see cloudinit_wg_full for
      # why hardcoding `eth0` is fatal on DO droplets that ship `ens3`.
      PUBLIC_IF=$(ip route show default | awk '/^default/ {print $5; exit}')
      iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$PUBLIC_IF" -j MASQUERADE
      iptables -A FORWARD -i tun0 -j ACCEPT
      iptables -A FORWARD -o tun0 -j ACCEPT

      # Persist iptables so the rules survive a droplet reboot (without
      # iptables-persistent they vanish on next boot and the tunnel
      # silently stops forwarding).
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
      netfilter-persistent save


      systemctl enable openvpn@server
      systemctl start openvpn@server

      # Diagnostic dump: `./scripts/test-infra.sh ssh ovpn-cert` +
      # `cat /root/setup-diag.txt` is enough to verify forwarding is set
      # up correctly without rooting around in iptables manually.
      {
        echo "PUBLIC_IF=$PUBLIC_IF"
        echo "--- ip route show default"
        ip route show default
        echo "--- iptables -t nat -L POSTROUTING -v -n"
        iptables -t nat -L POSTROUTING -v -n
        echo "--- iptables -L FORWARD -v -n"
        iptables -L FORWARD -v -n
      } > /root/setup-diag.txt
      echo "READY" > /root/.vpn-ready

runcmd:
  - bash /root/setup-ovpn.sh
CLOUD_INIT
}

cloudinit_ovpn_auth() {
    cat <<'CLOUD_INIT'
#cloud-config
package_update: true
packages: [openvpn, easy-rsa, libpam-pwdfile, whois]

write_files:
  - path: /root/setup-ovpn.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      set -euo pipefail
      mkdir -p /root/client-profiles

      SERVER_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)

      # Init PKI
      export EASYRSA_BATCH=1
      make-cadir /etc/openvpn/easy-rsa
      cd /etc/openvpn/easy-rsa

      ./easyrsa init-pki
      EASYRSA_REQ_CN="vortix-test-ca" ./easyrsa build-ca nopass
      ./easyrsa build-server-full server nopass
      ./easyrsa build-client-full client-auth nopass
      ./easyrsa gen-dh
      openvpn --genkey secret /etc/openvpn/easy-rsa/pki/ta.key

      # Create PAM auth for OpenVPN -- htpasswd style
      TEST_USER="vortix"
      TEST_PASS="testpass123"
      HASH=$(mkpasswd -m sha-512 "$TEST_PASS")
      echo "${TEST_USER}:${HASH}" > /etc/openvpn/credentials
      chmod 600 /etc/openvpn/credentials

      # PAM config for openvpn
      cat > /etc/pam.d/openvpn <<PAMEOF
      auth    required    pam_pwdfile.so pwdfile=/etc/openvpn/credentials
      account required    pam_permit.so
      PAMEOF

      # Server config with auth-user-pass-verify via PAM plugin
      cat > /etc/openvpn/server.conf <<EOF
      port 1195
      proto udp
      dev tun
      ca /etc/openvpn/easy-rsa/pki/ca.crt
      cert /etc/openvpn/easy-rsa/pki/issued/server.crt
      key /etc/openvpn/easy-rsa/pki/private/server.key
      dh /etc/openvpn/easy-rsa/pki/dh.pem
      tls-auth /etc/openvpn/easy-rsa/pki/ta.key 0
      server 10.10.0.0 255.255.255.0
      push "redirect-gateway def1 bypass-dhcp"
      push "dhcp-option DNS 1.1.1.1"
      keepalive 10 120
      cipher AES-256-GCM
      auth SHA256
      persist-key
      persist-tun
      plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so openvpn
      verify-client-cert optional
      username-as-common-name
      verb 3
      mssfix 1400
      tun-mtu 1400
      push "mssfix 1400"
      push "tun-mtu 1400"
      status /var/log/openvpn-status.log
      EOF

      sed -i 's/^      //' /etc/openvpn/server.conf /etc/pam.d/openvpn

      # Client config
      CA=$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
      CERT=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/client-auth.crt)
      KEY=$(cat /etc/openvpn/easy-rsa/pki/private/client-auth.key)
      TA=$(cat /etc/openvpn/easy-rsa/pki/ta.key)

      cat > /root/client-profiles/ovpn-auth.ovpn <<EOF
      client
      dev tun
      proto udp
      remote ${SERVER_IP} 1195
      resolv-retry infinite
      nobind
      persist-key
      persist-tun
      remote-cert-tls server
      cipher AES-256-GCM
      auth SHA256
      key-direction 1
      auth-user-pass
      verb 3

      <ca>
      ${CA}
      </ca>

      <cert>
      ${CERT}
      </cert>

      <key>
      ${KEY}
      </key>

      <tls-auth>
      ${TA}
      </tls-auth>
      EOF

      sed -i 's/^      //' /root/client-profiles/ovpn-auth.ovpn

      # Write credentials hint
      cat > /root/client-profiles/ovpn-auth-credentials.txt <<EOF
      username: vortix
      password: testpass123
      EOF

      sysctl -w net.ipv4.ip_forward=1
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
      # Detect actual egress interface (see cloudinit_wg_full).
      PUBLIC_IF=$(ip route show default | awk '/^default/ {print $5; exit}')
      iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o "$PUBLIC_IF" -j MASQUERADE
      iptables -A FORWARD -i tun0 -j ACCEPT
      iptables -A FORWARD -o tun0 -j ACCEPT
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
      netfilter-persistent save

      systemctl enable openvpn@server
      systemctl start openvpn@server

      {
        echo "PUBLIC_IF=$PUBLIC_IF"
        echo "--- ip route show default"
        ip route show default
        echo "--- iptables -t nat -L POSTROUTING -v -n"
        iptables -t nat -L POSTROUTING -v -n
        echo "--- iptables -L FORWARD -v -n"
        iptables -L FORWARD -v -n
      } > /root/setup-diag.txt
      echo "READY" > /root/.vpn-ready

runcmd:
  - bash /root/setup-ovpn.sh
CLOUD_INIT
}

cloudinit_ovpn_totp() {
    cat <<'CLOUD_INIT'
#cloud-config
package_update: true
packages: [openvpn, easy-rsa, libpam-google-authenticator, whois, libpam-pwdfile]

write_files:
  - path: /root/setup-ovpn.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      set -euo pipefail
      mkdir -p /root/client-profiles

      SERVER_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)

      # Create system user for TOTP
      TEST_USER="vortix"
      TEST_PASS="testpass123"
      useradd -m -s /bin/false "$TEST_USER" || true
      echo "${TEST_USER}:${TEST_PASS}" | chpasswd

      # Generate TOTP secret for the user.
      #
      # Standard production layout: the secret lives under
      #   /etc/openvpn/google-auth/<user>/.google_authenticator
      # NOT under /home/<user>/. This is what the upstream
      # openvpn-2fa tutorials (incl. DigitalOcean's) recommend and is
      # required by systemd-hardened openvpn units that set
      # ProtectHome=yes (the packaged Ubuntu openvpn@.service does).
      # With ProtectHome=yes the unit's mount namespace makes /home
      # invisible -- pam_google_authenticator would fail to read its
      # secret no matter what perms or path expansion you tried.
      # (ASCII-only in this heredoc -- cloud-init YAML rejects high bytes.)
      # chown BEFORE the su -- vortix must own the target directory
      # before google-authenticator (running as vortix) tries to
      # write the secret file into it.
      mkdir -p /etc/openvpn/google-auth/"$TEST_USER"
      chown "$TEST_USER":"$TEST_USER" /etc/openvpn/google-auth/"$TEST_USER"
      chmod 0700 /etc/openvpn/google-auth/"$TEST_USER"
      su -s /bin/bash - "$TEST_USER" -c \
        "google-authenticator -t -d -f -C -r 3 -R 30 -w 3 -Q NONE -i 'vortix-test' -s /etc/openvpn/google-auth/$TEST_USER/.google_authenticator" \
        > /root/client-profiles/ovpn-totp-setup.txt 2>&1
      chmod 0400 /etc/openvpn/google-auth/"$TEST_USER"/.google_authenticator

      # Extract the secret key for the tester
      TOTP_SECRET=$(head -1 /etc/openvpn/google-auth/${TEST_USER}/.google_authenticator)

      # Init PKI
      export EASYRSA_BATCH=1
      make-cadir /etc/openvpn/easy-rsa
      cd /etc/openvpn/easy-rsa

      ./easyrsa init-pki
      EASYRSA_REQ_CN="vortix-test-ca" ./easyrsa build-ca nopass
      ./easyrsa build-server-full server nopass
      ./easyrsa build-client-full client-totp nopass
      ./easyrsa gen-dh
      openvpn --genkey secret /etc/openvpn/easy-rsa/pki/ta.key

      # PAM: password + TOTP.
      #
      # Two non-obvious bits about pam_google_authenticator.so:
      #
      # 1. The "secret=" path supports the \${USER} magic token -- it's
      #    expanded by the module's C source at auth time to the
      #    authenticating user's name. NOT shell expansion (PAM doesn't
      #    do shell expansion), and NOT a generic env var. Just this one
      #    token plus a few siblings (\${HOME}, ~).
      # 2. There is no "user=\${USER}" option that would work -- the
      #    "user=" parameter expects a fixed UID/name and calls
      #    getpwnam() on the literal value. Default behavior (no "user="
      #    given) is to run as the authenticating user, which is what
      #    we want, so we omit the option entirely.
      #
      # Path matches the cloud-init's google-authenticator output above.
      # We put secrets under /etc/openvpn/google-auth/ (not /home) so
      # the systemd-hardened openvpn unit (ProtectHome=yes) can see
      # them through its mount namespace.
      cat > /etc/pam.d/openvpn-totp <<PAMEOF
      auth    required    pam_unix.so
      auth    required    pam_google_authenticator.so secret=/etc/openvpn/google-auth/\${USER}/.google_authenticator
      account required    pam_permit.so
      PAMEOF

      # Server config
      cat > /etc/openvpn/server.conf <<EOF
      port 1196
      proto udp
      dev tun
      ca /etc/openvpn/easy-rsa/pki/ca.crt
      cert /etc/openvpn/easy-rsa/pki/issued/server.crt
      key /etc/openvpn/easy-rsa/pki/private/server.key
      dh /etc/openvpn/easy-rsa/pki/dh.pem
      tls-auth /etc/openvpn/easy-rsa/pki/ta.key 0
      server 10.11.0.0 255.255.255.0
      push "redirect-gateway def1 bypass-dhcp"
      push "dhcp-option DNS 1.1.1.1"
      keepalive 10 120
      cipher AES-256-GCM
      auth SHA256
      persist-key
      persist-tun
      plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so openvpn-totp
      verify-client-cert optional
      username-as-common-name
      verb 3
      mssfix 1400
      tun-mtu 1400
      push "mssfix 1400"
      push "tun-mtu 1400"
      status /var/log/openvpn-status.log
      EOF

      sed -i 's/^      //' /etc/openvpn/server.conf /etc/pam.d/openvpn-totp

      # Client config
      CA=$(cat /etc/openvpn/easy-rsa/pki/ca.crt)
      CERT=$(openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/client-totp.crt)
      KEY=$(cat /etc/openvpn/easy-rsa/pki/private/client-totp.key)
      TA=$(cat /etc/openvpn/easy-rsa/pki/ta.key)

      cat > /root/client-profiles/ovpn-totp.ovpn <<EOF
      client
      dev tun
      proto udp
      remote ${SERVER_IP} 1196
      resolv-retry infinite
      nobind
      persist-key
      persist-tun
      remote-cert-tls server
      cipher AES-256-GCM
      auth SHA256
      key-direction 1
      auth-user-pass
      static-challenge "Enter TOTP code" 1
      verb 3

      <ca>
      ${CA}
      </ca>

      <cert>
      ${CERT}
      </cert>

      <key>
      ${KEY}
      </key>

      <tls-auth>
      ${TA}
      </tls-auth>
      EOF

      sed -i 's/^      //' /root/client-profiles/ovpn-totp.ovpn

      # Write credentials + TOTP hint
      cat > /root/client-profiles/ovpn-totp-credentials.txt <<EOF
      username: vortix
      password: testpass123
      totp_secret: ${TOTP_SECRET}

      To generate a TOTP code:
        oathtool --totp -b "${TOTP_SECRET}"
      Or add the secret to any authenticator app.
      EOF

      sysctl -w net.ipv4.ip_forward=1
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
      # Detect actual egress interface (see cloudinit_wg_full).
      PUBLIC_IF=$(ip route show default | awk '/^default/ {print $5; exit}')
      iptables -t nat -A POSTROUTING -s 10.11.0.0/24 -o "$PUBLIC_IF" -j MASQUERADE
      iptables -A FORWARD -i tun0 -j ACCEPT
      iptables -A FORWARD -o tun0 -j ACCEPT
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
      netfilter-persistent save

      systemctl enable openvpn@server
      systemctl start openvpn@server

      {
        echo "PUBLIC_IF=$PUBLIC_IF"
        echo "--- ip route show default"
        ip route show default
        echo "--- iptables -t nat -L POSTROUTING -v -n"
        iptables -t nat -L POSTROUTING -v -n
        echo "--- iptables -L FORWARD -v -n"
        iptables -L FORWARD -v -n
      } > /root/setup-diag.txt
      echo "READY" > /root/.vpn-ready

runcmd:
  - bash /root/setup-ovpn.sh
CLOUD_INIT
}

# ── Commands ─────────────────────────────────────────────────────────────────

cmd_up() {
    require_cmd doctl
    require_cmd ssh

    local key_id
    key_id=$(ssh_key_id)
    [[ -z "$key_id" ]] && die "No SSH key found in your DO account. Add one: doctl compute ssh-key create"

    local flavors=("$@")
    [[ ${#flavors[@]} -eq 0 ]] && flavors=("${ALL_FLAVORS[@]}")

    local sid
    sid=$(session_id)
    info "Session: ${sid}"
    info "Region: ${REGION}, Size: ${SIZE}, Image: ${IMAGE}"
    info "Flavors: ${flavors[*]}"
    echo

    for flavor in "${flavors[@]}"; do
        local name="${sid}-${flavor}"
        local existing
        existing=$(doctl compute droplet list --tag-name "$(tag)" --format Name --no-header | grep -c "^${name}$" || true)
        if [[ "$existing" -gt 0 ]]; then
            warn "${name} already exists, skipping"
            continue
        fi

        info "Creating droplet: ${name}"

        local cloud_init_file
        cloud_init_file=$(mktemp)
        case "$flavor" in
            wg-full)    cloudinit_wg_full    > "$cloud_init_file" ;;
            wg-split)   cloudinit_wg_split   > "$cloud_init_file" ;;
            wg-fwmark)  cloudinit_wg_fwmark  > "$cloud_init_file" ;;
            ovpn-cert)  cloudinit_ovpn_cert  > "$cloud_init_file" ;;
            ovpn-auth)  cloudinit_ovpn_auth  > "$cloud_init_file" ;;
            ovpn-totp)  cloudinit_ovpn_totp  > "$cloud_init_file" ;;
            *)          die "Unknown flavor: ${flavor}. Available: ${ALL_FLAVORS[*]}" ;;
        esac

        doctl compute droplet create "$name" \
            --region "$REGION" \
            --size "$SIZE" \
            --image "$IMAGE" \
            --ssh-keys "$key_id" \
            --tag-name "$(tag)" \
            --user-data-file "$cloud_init_file" \
            --wait \
            --no-header \
            --format ID,Name,PublicIPv4

        rm -f "$cloud_init_file"
        ok "Droplet ${name} created"
    done

    echo
    info "Droplets are provisioning via cloud-init. Run './scripts/test-infra.sh status' to check readiness."
    info "Provisioning typically takes 2-4 minutes."
}

cmd_status() {
    require_cmd doctl

    local sid
    if [[ ! -f "$SESSION_FILE" ]]; then
        die "No active session. Run './scripts/test-infra.sh up' first."
    fi
    sid=$(session_id)

    info "Session: ${sid}"
    echo

    local droplets
    droplets=$(doctl compute droplet list --tag-name "$(tag)" --format Name,PublicIPv4,Status --no-header)

    if [[ -z "$droplets" ]]; then
        warn "No droplets found for session ${sid}"
        return
    fi

    printf '%-35s %-18s %-10s %s\n' "NAME" "IP" "DROPLET" "VPN"
    printf '%-35s %-18s %-10s %s\n' "----" "--" "-------" "---"

    while IFS= read -r line; do
        local name ip status vpn_status
        name=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        status=$(echo "$line" | awk '{print $3}')

        if [[ "$status" != "active" ]]; then
            vpn_status="booting..."
        else
            vpn_status=$(do_ssh "root@${ip}" "cat /root/.vpn-ready 2>/dev/null" 2>/dev/null || echo "provisioning...")
        fi

        printf '%-35s %-18s %-10s %s\n' "$name" "$ip" "$status" "$vpn_status"
    done <<< "$droplets"
}

cmd_profiles() {
    require_cmd doctl
    require_cmd scp

    if [[ ! -f "$SESSION_FILE" ]]; then
        die "No active session. Run './scripts/test-infra.sh up' first."
    fi

    mkdir -p "$PROFILE_DIR"
    info "Downloading profiles to ${PROFILE_DIR}/"
    echo

    local droplets
    droplets=$(doctl compute droplet list --tag-name "$(tag)" --format Name,PublicIPv4 --no-header)

    while IFS= read -r line; do
        local name ip
        name=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')

        local ready
        ready=$(do_ssh "root@${ip}" "cat /root/.vpn-ready 2>/dev/null" 2>/dev/null || echo "")

        if [[ "$ready" != "READY" ]]; then
            warn "${name}: not ready yet, skipping"
            continue
        fi

        do_scp "root@${ip}:/root/client-profiles/*" "$PROFILE_DIR/" 2>/dev/null || true
        ok "${name}: profiles downloaded"
    done <<< "$droplets"

    echo
    info "Profiles saved to: ${PROFILE_DIR}/"
    ls -la "$PROFILE_DIR/"
}

cmd_down() {
    require_cmd doctl

    if [[ ! -f "$SESSION_FILE" ]]; then
        die "No active session."
    fi

    local sid
    sid=$(session_id)
    info "Tearing down session: ${sid}"

    local ids
    ids=$(doctl compute droplet list --tag-name "$(tag)" --format ID --no-header | tr '\n' ' ')

    if [[ -z "${ids// /}" ]]; then
        warn "No droplets found for session ${sid}"
    else
        info "Deleting droplets: ${ids}"
        # shellcheck disable=SC2086
        doctl compute droplet delete $ids --force
        ok "Droplets deleted"
    fi

    # Clean up profiles from vortix
    # Clean up local profile downloads
    if [[ -d "$PROFILE_DIR" ]]; then
        rm -rf "$PROFILE_DIR"
        ok "Removed ${PROFILE_DIR}"
    fi
    rm -f "$SESSION_FILE"
    ok "Session ${sid} destroyed"
}

cmd_ssh() {
    require_cmd doctl

    local target="$1"

    if [[ ! -f "$SESSION_FILE" ]]; then
        die "No active session."
    fi

    # Try exact match first, then prefix match
    local ip
    ip=$(doctl compute droplet list --tag-name "$(tag)" --format Name,PublicIPv4 --no-header \
        | awk -v t="$target" '$1 == t || $1 ~ t { print $2; exit }')

    [[ -z "$ip" ]] && die "No droplet matching '${target}' found. Run './scripts/test-infra.sh status'"

    resolve_ssh_key_file
    info "SSH to ${target} (${ip})"
    exec ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" "root@${ip}"
}

# ── Interactive menu ──────────────────────────────────────────────────────────

# Read a single keypress (works on macOS + Linux)
read_key() {
    local key
    IFS= read -rsn1 key
    echo "$key"
}

# Render a single-select menu. Arrows/j/k to move, Enter to confirm.
# Usage: pick "prompt" option1 option2 ... ; result is in $REPLY
pick() {
    local prompt="$1"; shift
    local -a opts=("$@")
    local cur=0 total=${#opts[@]} key

    # Hide cursor
    printf '\033[?25l'
    # Ensure cursor is restored on exit / ctrl-c
    trap 'printf "\033[?25l"' RETURN  # will be overridden below
    trap 'printf "\033[?25h"; exit 130' INT

    while true; do
        # Print header
        printf '\n\033[1m%s\033[0m\n' "$prompt"
        for i in "${!opts[@]}"; do
            if [[ $i -eq $cur ]]; then
                printf '  \033[36m> %s\033[0m\n' "${opts[$i]}"
            else
                printf '    %s\n' "${opts[$i]}"
            fi
        done

        # Read key
        key=$(read_key)
        case "$key" in
            A|k) cur=$(( (cur - 1 + total) % total )) ;;  # up
            B|j) cur=$(( (cur + 1) % total )) ;;           # down
            '')  break ;;                                   # enter
        esac

        # Move cursor up to redraw (prompt line + option lines + blank line)
        printf "\033[%dA\033[J" $((total + 2))
    done

    printf '\033[?25h'  # restore cursor
    REPLY="${opts[$cur]}"
}

# Multi-select menu. Space to toggle, Enter to confirm.
# Usage: multi_pick "prompt" option1 option2 ... ; result in MULTI_REPLY array
multi_pick() {
    local prompt="$1"; shift
    local -a opts=("$@")
    local -a selected=()
    local cur=0 total=${#opts[@]} key

    # Init all as unselected
    for ((i=0; i<total; i++)); do selected[$i]=0; done

    printf '\033[?25l'
    trap 'printf "\033[?25h"; exit 130' INT

    while true; do
        printf '\n\033[1m%s\033[0m  \033[2m(space = toggle, enter = confirm)\033[0m\n' "$prompt"
        for i in "${!opts[@]}"; do
            local check=" "
            [[ ${selected[$i]} -eq 1 ]] && check="\033[32mx\033[0m"
            if [[ $i -eq $cur ]]; then
                printf '  \033[36m> [%b] %s\033[0m\n' "$check" "${opts[$i]}"
            else
                printf '    [%b] %s\n' "$check" "${opts[$i]}"
            fi
        done

        key=$(read_key)
        case "$key" in
            A|k) cur=$(( (cur - 1 + total) % total )) ;;
            B|j) cur=$(( (cur + 1) % total )) ;;
            ' ') selected[$cur]=$(( 1 - selected[$cur] )) ;;
            '')  break ;;
        esac

        printf "\033[%dA\033[J" $((total + 2))
    done

    printf '\033[?25h'
    MULTI_REPLY=()
    for i in "${!opts[@]}"; do
        [[ ${selected[$i]} -eq 1 ]] && MULTI_REPLY+=("${opts[$i]}")
    done
}

# Confirm yes/no. Returns 0 for yes, 1 for no.
confirm() {
    local prompt="$1"
    printf '\033[1m%s\033[0m [y/N] ' "$prompt"
    local ans
    IFS= read -rsn1 ans
    echo "$ans"
    [[ "$ans" == "y" || "$ans" == "Y" ]]
}

# ── Interactive flow ─────────────────────────────────────────────────────────

interactive_up() {
    echo
    pick "Which flavors do you want to spin up?" \
        "All 6 flavors (full test matrix)" \
        "Let me pick specific ones"

    local -a flavors=()
    if [[ "$REPLY" == "All 6 flavors (full test matrix)" ]]; then
        flavors=("${ALL_FLAVORS[@]}")
    else
        multi_pick "Select the VPN servers you need:" \
            "wg-full      WireGuard full tunnel (0.0.0.0/0)" \
            "wg-split     WireGuard split tunnel (10.8.0.0/24)" \
            "wg-fwmark    WireGuard full tunnel + FwMark=51820" \
            "ovpn-cert    OpenVPN certificate-only (no user/pass)" \
            "ovpn-auth    OpenVPN username + password" \
            "ovpn-totp    OpenVPN username + password + TOTP"

        if [[ ${#MULTI_REPLY[@]} -eq 0 ]]; then
            die "No flavors selected. Aborting."
        fi

        for item in "${MULTI_REPLY[@]}"; do
            flavors+=("$(echo "$item" | awk '{print $1}')")
        done
    fi

    local count=${#flavors[@]}
    echo
    info "Will create ${count} droplet(s): ${flavors[*]}"
    info "Region: ${REGION} | Size: ${SIZE} | Cost: ~\$$(printf '%.2f' "$(echo "${count} * 0.01" | bc)")/hr"
    echo
    if ! confirm "Proceed?"; then
        echo
        warn "Aborted."
        return
    fi
    echo
    cmd_up "${flavors[@]}"
}

interactive_ssh() {
    require_cmd doctl

    if [[ ! -f "$SESSION_FILE" ]]; then
        die "No active session. Spin up servers first."
    fi

    local droplets
    droplets=$(doctl compute droplet list --tag-name "$(tag)" --format Name --no-header)

    if [[ -z "$droplets" ]]; then
        die "No droplets found in current session."
    fi

    local -a names=()
    while IFS= read -r line; do
        names+=("$line")
    done <<< "$droplets"

    pick "Which server do you want to SSH into?" "${names[@]}"
    echo
    cmd_ssh "$REPLY"
}

interactive_down() {
    if [[ ! -f "$SESSION_FILE" ]]; then
        die "No active session. Nothing to tear down."
    fi

    local sid
    sid=$(session_id)

    local count
    count=$(doctl compute droplet list --tag-name "$(tag)" --format ID --no-header | wc -l | tr -d ' ')

    echo
    warn "This will destroy ${count} droplet(s) in session ${sid}"
    warn "and remove downloaded profiles from scripts/test-profiles/."
    echo
    if ! confirm "Are you sure?"; then
        echo
        warn "Aborted."
        return
    fi
    echo
    cmd_down
}

interactive_menu() {
    local has_session=false
    [[ -f "$SESSION_FILE" ]] && has_session=true

    printf '\n\033[1;36m'
    cat <<'BANNER'
             _   _
 __   _____ _ __| |_(_)_  __
 \ \ / / _ \| '__| __| \ \/ /
  \ V / (_) | |  | |_| |>  <
   \_/ \___/|_|   \__|_/_/\_\  test infra
BANNER
    printf '\033[0m\n'

    if $has_session; then
        local sid
        sid=$(session_id)
        local count
        count=$(doctl compute droplet list --tag-name "$(tag)" --format ID --no-header 2>/dev/null | wc -l | tr -d ' ')
        printf '  \033[2mActive session: %s (%s droplets)\033[0m\n\n' "$sid" "$count"
    else
        printf '  \033[2mNo active session\033[0m\n\n'
    fi

    # Build menu options based on state
    local -a menu_opts=()
    if $has_session; then
        menu_opts+=(
            "1. Check status          — see which servers are ready"
            "2. Download profiles     — fetch .conf/.ovpn to scripts/test-profiles/"
            "3. SSH into a server     — debug a specific droplet"
            "4. Spin up more servers  — add flavors to current session"
            "5. Tear down everything  — destroy all droplets + clean up"
        )
    else
        menu_opts+=(
            "1. Spin up VPN servers   — create test infrastructure on DigitalOcean"
        )
    fi

    pick "What do you want to do?" "${menu_opts[@]}"

    # Extract the number prefix
    local choice="${REPLY%%.*}"
    echo

    if $has_session; then
        case "$choice" in
            1) cmd_status ;;
            2) cmd_profiles ;;
            3) interactive_ssh ;;
            4) interactive_up ;;
            5) interactive_down ;;
        esac
    else
        case "$choice" in
            1) interactive_up ;;
        esac
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

# If called with arguments, run non-interactively (for scripting).
# If called bare, launch the interactive menu.

case "${1:-}" in
    up)       shift; cmd_up "$@" ;;
    status)   cmd_status ;;
    profiles) cmd_profiles ;;
    down)     cmd_down ;;
    ssh)
        [[ -z "${2:-}" ]] && die "Usage: $0 ssh <droplet-name>"
        cmd_ssh "$2"
        ;;
    -h|--help)
        cat <<EOF
Usage: $0 [command] [args...]

Run without arguments for interactive mode.

Commands (non-interactive):
  up [flavor...]   Create VPN server droplets (default: all 6)
  status           Show droplet IPs and readiness
  profiles         Download client configs to scripts/test-profiles/
  down             Destroy all droplets + clean up
  ssh <name>       SSH into a droplet

Flavors: wg-full, wg-split, wg-fwmark, ovpn-cert, ovpn-auth, ovpn-totp
EOF
        ;;
    *)        interactive_menu ;;
esac
