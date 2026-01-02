# Vortix

[![CI](https://github.com/Harry-kp/vortix/actions/workflows/ci.yml/badge.svg)](https://github.com/Harry-kp/vortix/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A terminal UI for managing WireGuard and OpenVPN connections on macOS.

```
┌─ VORTIX v0.1.0 ──────────────────────────────────────────────────────────┐
│ Status: ● CONNECTED (nl-amsterdam)  IP: 185.xx.xx.xx  Uptime: 02:15:33   │
├──────────────────────┬───────────────────────────────────────────────────┤
│  PROFILES            │  THROUGHPUT                                       │
│  ───────────────     │  ↓ 2.4 MB/s  ████████████░░░░░░░░                 │
│  > nl-amsterdam  🟢  │  ↑ 0.3 MB/s  ██░░░░░░░░░░░░░░░░░░                 │
│    us-east       ○   │                                                   │
│    tokyo-1       ○   │  SECURITY GUARD                                   │
│    uk-london     ○   │  ✓ IPv6 Leak:  None detected                      │
│                      │  ✓ DNS Leak:   Protected (10.x.x.1)               │
│  DETAILS             │  ✓ Protocols:  No insecure traffic                │
│  ─────────           │                                                   │
│  Endpoint: 45.x.x.x  │  EVENT LOG                                        │
│  Handshake: 45s ago  │  16:42:01 Connected to nl-amsterdam               │
│  Transfer: ↓1.2 GB   │  16:42:00 Handshake completed                     │
│            ↑89 MB    │  16:41:58 Initializing WireGuard tunnel           │
└──────────────────────┴───────────────────────────────────────────────────┘
```

## Why?

I wanted a single interface to:
- See connection status, throughput, and latency at a glance
- Detect IPv6/DNS leaks without running separate tools
- Switch between VPN profiles without remembering CLI flags

Existing options (`wg show`, NetworkManager, Tunnelblick) either lack real-time telemetry or require a GUI.

## Features

- **WireGuard & OpenVPN** — Auto-detects `.conf` and `.ovpn` files
- **Live telemetry** — Throughput graphs, latency, connection uptime
- **Leak detection** — Monitors for IPv6 leaks and DNS leaks in real-time
- **Keyboard-driven** — No mouse required

## Requirements

- macOS (uses `ifconfig`, `netstat`, `wg` commands)
- Rust 1.75+ (for building from source)
- WireGuard: `brew install wireguard-tools`
- OpenVPN: `brew install openvpn`

Linux support is planned but not yet implemented.

## Installation

**From source:**
```bash
git clone https://github.com/Harry-kp/vortix.git
cd vortix
cargo install --path .
```

**From releases:**
```bash
# Apple Silicon (M1/M2/M3)
curl -LO https://github.com/Harry-kp/vortix/releases/latest/download/vortix-aarch64-apple-darwin.tar.gz
tar -xzf vortix-aarch64-apple-darwin.tar.gz
sudo mv vortix /usr/local/bin/

# Intel Mac
curl -LO https://github.com/Harry-kp/vortix/releases/latest/download/vortix-x86_64-apple-darwin.tar.gz
tar -xzf vortix-x86_64-apple-darwin.tar.gz
sudo mv vortix /usr/local/bin/
```

## Usage

```bash
# Launch TUI (requires root for network interface access)
sudo vortix

# Import a profile
vortix import ~/Downloads/my-vpn.conf
```

Profiles are stored in `~/.config/vortix/profiles/` with `chmod 600`.

### Keybindings

| Key | Action |
|-----|--------|
| `?` | Help |
| `Tab` | Switch panels |
| `1-5` | Quick connect |
| `c` | Connect |
| `d` | Disconnect |
| `i` | Import profile |
| `q` | Quit |

## How It Works

**Telemetry:** A background thread polls `netstat -ib` every second to calculate throughput. Public IP and ISP info come from `ipinfo.io/json`.

**Leak Detection:**
- IPv6: Attempts connection to `api6.ipify.org`. Success while VPN is active = leak.
- DNS: Parses `/etc/resolv.conf` and warns if nameserver isn't the VPN's DNS.

**WireGuard Integration:** Parses `wg show <interface>` for handshake timing, transfer stats, and endpoint info. Interface names are resolved via `/var/run/wireguard/*.name` files on macOS.

## Architecture

```
src/
├── main.rs        # Entry point, TUI event loop
├── app.rs         # Application state (~1000 LOC)
├── scanner.rs     # Detects active VPN sessions
├── telemetry.rs   # Background network stats collection
├── vpn/mod.rs     # Profile parsing (.conf, .ovpn)
└── ui/            # Ratatui widgets and layout
```

Built with [Ratatui](https://github.com/ratatui/ratatui) and [color-eyre](https://github.com/eyre-rs/color-eyre).

## Development

```bash
cargo build
cargo test
cargo clippy -- -D warnings
```

## Known Limitations

- macOS only (Linux planned)
- OpenVPN status parsing is limited compared to WireGuard
- Requires `sudo` for all operations

## License

MIT
