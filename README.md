# Vortix

[![Test](https://github.com/Harry-kp/vortix/actions/workflows/test.yml/badge.svg)](https://github.com/Harry-kp/vortix/actions/workflows/test.yml)
[![Lint](https://github.com/Harry-kp/vortix/actions/workflows/lint.yml/badge.svg)](https://github.com/Harry-kp/vortix/actions/workflows/lint.yml)
[![Crates.io](https://img.shields.io/crates/v/vortix.svg)](https://crates.io/crates/vortix)
[![Homebrew](https://img.shields.io/badge/Homebrew-tap-orange?logo=homebrew)](https://github.com/Harry-kp/homebrew-tap)
[![Arch Linux](https://img.shields.io/badge/Arch_Linux-extra-1793D1?logo=archlinux&logoColor=white)](https://archlinux.org/packages/extra/x86_64/vortix/)
[![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=white)](https://github.com/Harry-kp/vortix)
[![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)](https://github.com/Harry-kp/vortix)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Harry-kp/vortix/blob/main/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/Harry-kp/vortix?style=social)](https://github.com/Harry-kp/vortix)

Terminal UI for WireGuard and OpenVPN with multi-tunnel control, real-time telemetry, and leak guarding.

![Vortix Demo](https://raw.githubusercontent.com/Harry-kp/vortix/main/assets/demo.gif)

<details>
<summary><strong>See multi-connection, leak detection, split-tunnel, and profile-management demos</strong></summary>

<br>

<table>
  <tr>
    <td align="center" width="50%" valign="top">
      <b>Multi-connection</b><br>
      <img src="https://raw.githubusercontent.com/Harry-kp/vortix/main/assets/multi-connection.gif" alt="Vortix multi-connection demo" />
    </td>
    <td align="center" width="50%" valign="top">
      <b>Leak detection</b><br>
      <img src="https://raw.githubusercontent.com/Harry-kp/vortix/main/assets/leak-detection.gif" alt="Vortix leak-detection demo" />
    </td>
  </tr>
  <tr>
    <td align="center" width="50%" valign="top">
      <b>Split tunnel</b><br>
      <img src="https://raw.githubusercontent.com/Harry-kp/vortix/main/assets/split-tunnel.gif" alt="Vortix split-tunnel demo" />
    </td>
    <td align="center" width="50%" valign="top">
      <b>Profile management</b><br>
      <img src="https://raw.githubusercontent.com/Harry-kp/vortix/main/assets/profile-management.gif" alt="Vortix profile-management demo" />
    </td>
  </tr>
</table>

</details>

## Why Vortix?

Vortix gives WireGuard and OpenVPN users one keyboard-driven view of their tunnels and the network around them. It is useful when plain `wg-quick` or `openvpn` provides too little visibility, while a full desktop VPN client is too heavy or tied to one provider.

- Connect multiple profiles and distinguish the default-route tunnel from split-route tunnels.
- See throughput, latency, jitter, packet loss, exit identity, DNS policy, and encryption state.
- Detect IPv4, IPv6, and DNS-policy exposure instead of assuming a successful handshake means traffic is protected.
- Control the same engine from the TUI, CLI, or versioned JSON output.
- Work locally, over SSH, and across macOS and Linux.

Vortix orchestrates the system `wg`, `wg-quick`, and `openvpn` implementations; it does not implement either VPN protocol itself.

## Quick start

Install the protocol tools first:

```bash
# macOS
brew install wireguard-tools openvpn

# Ubuntu / Debian
sudo apt install wireguard-tools openvpn

# Fedora
sudo dnf install wireguard-tools openvpn
```

Then install Vortix using your preferred channel:

| Channel | Install |
|---|---|
| Homebrew | `brew install Harry-kp/tap/vortix` |
| Arch Linux | `sudo pacman -S vortix` |
| Cargo | `cargo install vortix` |
| npm | `npm install -g @harry-kp/vortix` |
| Nix | `nix profile install github:Harry-kp/vortix` |
| Shell installer | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Harry-kp/vortix/releases/latest/download/vortix-installer.sh \| sh` |
| Static Linux binary | Download the musl archive from [Releases](https://github.com/Harry-kp/vortix/releases) |

Import a profile and connect:

```bash
vortix import ./work.conf       # .conf, .ovpn, URL, or directory
sudo vortix                    # interactive dashboard

# Or stay in the CLI
sudo vortix up work
vortix status
sudo vortix down work
```

Tunnel and firewall changes require root. Read-only commands such as `list`, `show`, and `status` do not. If `sudo vortix` cannot find a Cargo-installed binary on Linux, link it once with `sudo ln -s ~/.cargo/bin/vortix /usr/local/bin/vortix`.

See the [usage guide](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md) for command and keybinding references.

## Highlights

| Area | What Vortix provides |
|---|---|
| Protocols | WireGuard `.conf` and OpenVPN `.ovpn` / `.conf` profiles |
| Multi-tunnel | Concurrent tunnels, default-route ownership, split routes, conflict checks, and per-profile state |
| Telemetry | Throughput, latency, jitter, packet loss, public IP, ISP, and location |
| Security Guard | IPv4/IPv6 exposure, active DNS policy, encryption posture, and kill-switch state |
| Kill switch | `off`, `block-on-drop`, and `vpn-only`, using PF on macOS or atomic nftables on Linux |
| Automation | Human output, a versioned JSON envelope, NDJSON watch streams, and shell completions |
| Diagnostics | Event logs, session journals, per-process socket audit, and `vortix report` |
| Appearance | Seven built-in themes, including terminal-native light/dark colors |

## Platform support

| | macOS | Linux |
|---|---|---|
| VPN tools | Homebrew `wireguard-tools`, `openvpn` | Distribution `wireguard-tools`, `openvpn` |
| Kill switch | PF (`pfctl`) | nftables (`nft`) |
| DNS integration | System Configuration | systemd-resolved, NetworkManager, resolvconf, or `/etc/resolv.conf` fallback |
| CI coverage | macOS | Ubuntu and Fedora |

macOS is the primary development platform. Linux is tested continuously, but distributions vary in resolver, firewall, kernel, and privilege configuration. Reports from other distributions are valuable—include `vortix report` when possible.

Source builds require Rust 1.85 or newer. Linux kernel 5.6 or newer is recommended for native WireGuard.

## Security model

Vortix runs privileged only because tunnel, route, DNS, and firewall mutation require it. The privileged path is intentionally narrow:

- Protocol execution stays in protocol-specific adapters around the installed `wg`, `wg-quick`, and `openvpn` binaries.
- Platform adapters own firewall, DNS, route, and kernel inspection behavior.
- Profile identity, process ownership, durable operations, and read-back checks fail closed when Vortix cannot prove the state it is managing.
- Sensitive profile and credential material is bounded, owner-checked, and kept out of normal logs and JSON output.
- Telemetry uses public IP/geolocation providers; Vortix has no hosted control plane or DNS-test service.

Kill-switch rules survive a Vortix restart within the same boot, but the OS may flush them during reboot. Re-arm `vpn-only` after each boot.

For the trust boundaries and threat analysis, read the [privileged-helper threat model](https://github.com/Harry-kp/vortix/blob/main/docs/security/privileged-helper-threat-model.md).

## Command overview

```text
vortix import <PATH|URL>       Add one profile or a directory
vortix list                    List profiles
vortix show <PROFILE>          Inspect a profile with secrets masked
sudo vortix up <PROFILE>       Connect
sudo vortix down [PROFILE]     Disconnect one or every active tunnel
sudo vortix reconnect [NAME]   Reconnect one or every active tunnel
vortix status [--watch]        Show or stream state
vortix killswitch [MODE]       Inspect or set off/block-on-drop/vpn-only
vortix audit                   Inspect process sockets and tunnel routing
vortix report                  Generate diagnostics for a bug report
```

Every command supports `--json`; watch commands emit NDJSON. Run `vortix <COMMAND> --help` for authoritative options.

Common TUI keys:

| Key | Action | Key | Action |
|---|---|---|---|
| `j` / `k` | Move through profiles | `c` / `Enter` | Connect or disconnect |
| `Tab` / `Shift-Tab` | Move between panels | `x` | Context action menu |
| `b` | Bulk action menu | `p` | Switch color theme |
| `i` | Import profile | `K` | Cycle kill-switch mode |
| `/` | Search profiles | `?` | Full in-app help |
| `q` | Quit | `z` | Zoom focused panel |

## Documentation

### For users

| Guide | Covers |
|---|---|
| [Usage](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md) | TUI keys, CLI commands, JSON, multi-tunnel behavior, and automation |
| [Configuration](https://github.com/Harry-kp/vortix/blob/main/docs/configuration.md) | Paths, files, themes, settings, DNS integration, and precedence |
| [Troubleshooting](https://github.com/Harry-kp/vortix/blob/main/docs/troubleshooting.md) | Startup, permissions, DNS, WireGuard, OpenVPN, firewall, and reporting |
| [Migration](https://github.com/Harry-kp/vortix/blob/main/docs/MIGRATION.md) | Upgrade and profile-storage changes |
| [Manual test backlog](https://github.com/Harry-kp/vortix/blob/main/docs/manual-testing/backlog.md) | Real-kernel and real-terminal checks not covered by automation |

### For contributors and agents

| Guide | Covers |
|---|---|
| [Contributing](https://github.com/Harry-kp/vortix/blob/main/CONTRIBUTING.md) | Development workflow and contribution entry points |
| [CI parity](https://github.com/Harry-kp/vortix/blob/main/docs/ci-parity.md) | The exact checks to run before pushing |
| [Architecture migration](https://github.com/Harry-kp/vortix/blob/main/docs/architecture-migration-v1.md) | Control-plane boundaries and migration direction |
| [Privileged-helper threat model](https://github.com/Harry-kp/vortix/blob/main/docs/security/privileged-helper-threat-model.md) | Authority, ownership, replay, and recovery invariants |
| [Project board](https://github.com/users/Harry-kp/projects/6) | Active and planned work |

## Contributing

Contributions and real-world testing are welcome:

- Start with a [good first issue](https://github.com/Harry-kp/vortix/labels/good%20first%20issue).
- Run a scenario from the [manual-testing backlog](https://github.com/Harry-kp/vortix/blob/main/docs/manual-testing/backlog.md).
- Share Linux results in the [Linux tester discussion](https://github.com/Harry-kp/vortix/discussions/184).
- Use [Discussions](https://github.com/Harry-kp/vortix/discussions) for questions and ideas.

Development starts with `cargo build`, `cargo test`, and the full [CI parity](https://github.com/Harry-kp/vortix/blob/main/docs/ci-parity.md) suite before pushing. Nix users can run `nix develop` for the project shell.

## Featured in

[awesome-rust](https://github.com/rust-unofficial/awesome-rust) · [awesome-ratatui](https://github.com/ratatui/awesome-ratatui) · [awesome-tuis](https://github.com/rothgar/awesome-tuis) · [Arch Linux extra](https://archlinux.org/packages/extra/x86_64/vortix/) · [Terminal Trove](https://terminaltrove.com/vortix/) · [LinuxLinks](https://www.linuxlinks.com/vortix-terminal-ui-wireguard-openvpn/) · [Orhun Parmaksız's spotlight](https://bsky.app/profile/orhun.dev/post/3medp5icbf22y) · [RustNation UK talk deck](https://github.com/orhun/rat-tools/blob/main/ratdeck/intro.md#L213-L219) · [JustTUI](https://github.com/musichen/justtuit/blob/main/README.md#L610)

## Star history

[![Star History Chart](https://star-history.dera.page/svg?repos=Harry-kp/vortix&type=Date)](https://star-history.dera.page/#Harry-kp/vortix&Date)
