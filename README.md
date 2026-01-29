# Vortix

[![Crates.io](https://img.shields.io/crates/v/vortix.svg)](https://crates.io/crates/vortix)
[![CI](https://github.com/Harry-kp/vortix/actions/workflows/ci.yml/badge.svg)](https://github.com/Harry-kp/vortix/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Terminal UI for WireGuard and OpenVPN with real-time telemetry and leak guarding.

![Vortix Demo](assets/demo.gif)

## Why?

I wanted a single interface to:
- See connection status, throughput, and latency at a glance
- Detect IPv6/DNS leaks without running separate tools
- Switch between VPN profiles without remembering CLI flags

Existing options (`wg show`, NetworkManager, Tunnelblick) either lack real-time telemetry or require a GUI.

## Features

- **WireGuard & OpenVPN** — Auto-detects `.conf` and `.ovpn` files
- **Advanced Telemetry** — Real-time throughput, latency, **jitter**, and **packet loss**
- **Geo-Location** — Instant detection of your exit IP's city and country
- **Leak detection** — Monitors for IPv6 leaks and DNS leaks in real-time
- **Kill Switch** — Built-in firewall management for maximum security
- **Interactive Import** — Easily add new profiles directly within the TUI
- **Config Viewer** — Inspect profile configurations directly within the TUI
- **Keyboard-driven** — No mouse required

## Requirements

- macOS (uses `ifconfig`, `netstat`, `wg`, `ps` commands)
- Rust 1.75+ (for building from source)
- WireGuard: `brew install wireguard-tools`
- OpenVPN: `brew install openvpn`

Linux support is planned but not yet implemented.

## Installation

**From crates.io (Recommended):**
```bash
cargo install vortix
```

**Quick install (Binary):**
```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Harry-kp/vortix/releases/latest/download/vortix-installer.sh | sh
```

**From source:**
```bash
git clone https://github.com/Harry-kp/vortix.git
cd vortix
cargo install --path .
```

Profiles are stored in `~/.config/vortix/profiles/` with `chmod 600`.

### Keybindings

| Key | Action |
|-----|--------|
| `Tab` | Cycle Focus (All Panels) |
| `1-9` | Connect to Quick-Slot 1-9 |
| `Enter` | Connect / Toggle Profile |
| `d` | Disconnect Active Session |
| `r` | Reconnect Active Session |
| `i` | Import Profile (Direct) |
| `v` | View Profile Configuration |
| `y` | Copy Public IP to Clipboard |
| `K` | Toggle Kill Switch (Shift+K) |
| `z` | Toggle Zoom View (Panel) |
| `x` | Open Action Menu (Contextual) |
| `b` | Open Bulk Menu |
| `Del` | Delete Profile (Sidebar) |
| `q` | Quit Application |

## How It Works

**Telemetry:** A background thread polls `netstat -ib` every second for throughput. Network quality (latency, jitter, loss) is calculated using multi-packet ICMP probes. Public IP, ISP, and Geo-location data are fetched via `ipinfo.io/json`.

**Security (Kill Switch & Leak Detection):**
- **Kill Switch:** Advanced PF (Packet Filter) firewall integration on macOS. Automatically blocks all non-VPN traffic when connection drops.
- **IPv6 Leak:** Active monitoring via `api6.ipify.org`. Any IPv6 traffic detected while VPN is active triggers a leak warning.
- **DNS Leak:** Monitors `/etc/resolv.conf` to ensure nameservers and search domains align with the secure tunnel.

**WireGuard Integration:** Resolves interface names via `/var/run/wireguard/*.name`. Parses `wg show` for handshake timing, transfer stats, and endpoint metadata.

**OpenVPN Integration:** Tracks session uptime and connection status via `ps` proc parsing and log monitoring.

## Development

```bash
cargo build         # Build binary
cargo test          # Run unit/integration tests
cargo clippy        # Enforce code quality (Fail-fast via pre-commit)
```

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Harry-kp/vortix&type=Date)](https://star-history.com/#Harry-kp/vortix&Date)
