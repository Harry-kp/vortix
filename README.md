# Vortix

[![Test](https://github.com/Harry-kp/vortix/actions/workflows/test.yml/badge.svg)](https://github.com/Harry-kp/vortix/actions/workflows/test.yml)
[![Lint](https://github.com/Harry-kp/vortix/actions/workflows/lint.yml/badge.svg)](https://github.com/Harry-kp/vortix/actions/workflows/lint.yml)
[![Crates.io](https://img.shields.io/crates/v/vortix.svg)](https://crates.io/crates/vortix)
[![Homebrew](https://img.shields.io/badge/Homebrew-tap-orange?logo=homebrew)](https://github.com/Harry-kp/homebrew-tap)
[![Arch Linux](https://img.shields.io/badge/Arch_Linux-extra-1793D1?logo=archlinux&logoColor=white)](https://archlinux.org/packages/extra/x86_64/vortix/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Harry-kp/vortix/blob/main/LICENSE)

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

# Arch / CachyOS / Manjaro
sudo pacman -S wireguard-tools openvpn

# Fedora
sudo dnf install wireguard-tools openvpn
```

Installing Vortix does not pull these in, whichever channel you use — Vortix drives
`wg-quick` and `openvpn` as subprocesses, so without them a profile imports but cannot
connect. `vortix up` names the missing package and the install command for your distro.

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

Changing tunnels, routes, DNS or the firewall needs root; `list`, `show` and `status` do not. If `sudo vortix` is not found after `cargo install` or the shell installer, link it once: `sudo ln -s ~/.cargo/bin/vortix /usr/local/bin/vortix`.

Every command, key and panel is in the [usage guide](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md).

## Highlights

| Area | What Vortix provides |
|---|---|
| [Protocols](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md#profiles) | WireGuard `.conf` and OpenVPN `.ovpn` / `.conf` profiles, up to 1024 routes each |
| [Multi-tunnel](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md#several-tunnels-at-once) | Full and split tunnels side by side, one default-route owner, and a Switch or Cancel choice on conflicts |
| [Telemetry](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md#panels) | Throughput, latency, jitter, packet loss, public IP, ISP, and location |
| [Security Guard](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md#security-guard) | IPv4/IPv6 exposure, DNS, encryption and kill-switch state, with one verdict |
| [Kill switch](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md#kill-switch) | `off`, `block-on-drop`, and `vpn-only`, using PF on macOS or nftables on Linux |
| [Automation](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md#json-and-exit-codes) | A versioned JSON envelope, NDJSON watch streams, stable exit codes, shell completions and [hooks](https://github.com/Harry-kp/vortix/blob/main/docs/configuration.md#hooks) |
| [Diagnostics](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md#diagnostics) | Event logs, OpenVPN daemon logs, session journals, per-process socket audit, and `vortix report` |
| [Appearance](https://github.com/Harry-kp/vortix/blob/main/docs/configuration.md#configtoml) | Seven built-in themes, including one that follows your terminal's colors |

## Platform support

| | macOS | Linux |
|---|---|---|
| VPN tools | Homebrew `wireguard-tools`, `openvpn` | Distribution `wireguard-tools`, `openvpn` |
| Kill switch | PF (`pfctl`) | nftables (`nft`) |
| DNS | System Configuration | systemd-resolved or `resolvconf` |
| CI | macOS | Ubuntu and Fedora |

macOS is the primary development platform; Linux is tested on every change and live before each release. Reports from other distributions help: include `vortix report`.

Source builds need Rust 1.85 or newer. Linux 5.6 or newer is recommended for in-kernel WireGuard.

Vortix runs as root only to change tunnels, routes, DNS and the firewall, never runs commands from a profile, and has no server of its own. What it does with privilege and data is in [SECURITY.md](https://github.com/Harry-kp/vortix/blob/main/SECURITY.md).

## Documentation

| For users | |
|---|---|
| [Usage](https://github.com/Harry-kp/vortix/blob/main/docs/usage.md) | Commands, keys, panels, multiple tunnels, the kill switch, JSON |
| [Configuration](https://github.com/Harry-kp/vortix/blob/main/docs/configuration.md) | Files, `config.toml`, `settings.toml`, hooks, DNS |
| [Troubleshooting](https://github.com/Harry-kp/vortix/blob/main/docs/troubleshooting.md) | What an error means and what to do |
| [Upgrading](https://github.com/Harry-kp/vortix/blob/main/docs/MIGRATION.md) | Steps when upgrading from an older version |

| For contributors | |
|---|---|
| [Contributing](https://github.com/Harry-kp/vortix/blob/main/CONTRIBUTING.md) | How to build, test and send a change |
| [CLAUDE.md](https://github.com/Harry-kp/vortix/blob/main/CLAUDE.md) | The project's rules and architecture, for people and coding agents |
| [Project board](https://github.com/users/Harry-kp/projects/6) | Planned and active work |

## Contributing

Contributions and real-world testing are welcome:

- Start with a [good first issue](https://github.com/Harry-kp/vortix/labels/good%20first%20issue).
- Run a scenario from the [release test plan](https://github.com/Harry-kp/vortix/blob/main/docs/manual-testing/P0.md).
- Share Linux results in the [Linux tester discussion](https://github.com/Harry-kp/vortix/discussions/184).
- Use [Discussions](https://github.com/Harry-kp/vortix/discussions) for questions and ideas.

See [CONTRIBUTING.md](https://github.com/Harry-kp/vortix/blob/main/CONTRIBUTING.md) to get started; Nix users can run `nix develop`.

## Featured in

[awesome-rust](https://github.com/rust-unofficial/awesome-rust) · [awesome-ratatui](https://github.com/ratatui/awesome-ratatui) · [awesome-tuis](https://github.com/rothgar/awesome-tuis) · [Arch Linux extra](https://archlinux.org/packages/extra/x86_64/vortix/) · [Terminal Trove](https://terminaltrove.com/vortix/) · [LinuxLinks](https://www.linuxlinks.com/vortix-terminal-ui-wireguard-openvpn/) · [Orhun Parmaksız's spotlight](https://bsky.app/profile/orhun.dev/post/3medp5icbf22y) · [RustNation UK talk deck](https://github.com/orhun/rat-tools/blob/main/ratdeck/intro.md#L213-L219) · [JustTUI](https://github.com/musichen/justtuit/blob/main/README.md#L610)

## Also by the author

[mercury](https://github.com/Harry-kp/mercury) — keyboard-first API client for the terminal. 5 MB, 50 ms startup. · [afk](https://github.com/Harry-kp/afk) — menu bar break reminder, 2.8 MB.

## Star history

[![Star History Chart](https://star-history.dera.page/svg?repos=Harry-kp/vortix&type=Date)](https://star-history.dera.page/#Harry-kp/vortix&Date)

---

WireGuard® is a registered trademark of Jason A. Donenfeld. OpenVPN® is a registered trademark of OpenVPN Inc. Vortix is not affiliated with either.
