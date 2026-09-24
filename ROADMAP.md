# Roadmap

Vortix exists because managing VPN connections from the terminal should feel as natural as `git` or `vim`: fast, keyboard-driven, and transparent about what's happening with your network.

---

## Shipped (through v0.4.x)

- **Multi-tunnel WireGuard + OpenVPN.** Concurrent tunnels on macOS and Linux. The newest full tunnel owns the default route and DNS; split-route tunnels run beside it, with route-conflict checks.
- **Split tunnels.** Profiles with narrow `AllowedIPs` / routes carry only their subnets.
- **Kill switch** with three modes: `off`, `block-on-drop`, `vpn-only`. pf on macOS, nftables on Linux.
- **Full CLI with JSON.** Every TUI action has a headless equivalent (`up`, `down`, `reconnect`, `status`, `list`, `import`, `killswitch`, `report`, ...). `--json` returns a versioned envelope for scripts and agents.
- **Lifecycle hooks** (issue [#36](https://github.com/Harry-kp/vortix/issues/36)). Shell commands on connect/disconnect/failure, configured via `[[hooks]]` in `settings.toml`.
- **Socket audit** (issues [#168](https://github.com/Harry-kp/vortix/issues/168), [#166](https://github.com/Harry-kp/vortix/issues/166)). `vortix audit` lists per-process sockets and whether they route through a tunnel.
- **Session journal.** JSONL event log per run under `${XDG_DATA_HOME}/vortix/sessions/`.
- **CI integration tests** (issue [#162](https://github.com/Harry-kp/vortix/issues/162)). Real `wg-quick`, `openvpn` and nftables in privileged containers across Linux distros.

Vortix runs as root (`sudo vortix`). A privilege-separated daemon/helper design was built and then removed by product decision; it is archived on the `archive/background-mode` branch.

---

## Next

- **macOS integration tests** in CI (Linux only today).
- **Auto-connect on startup.** A default profile, with systemd / launchd examples.
- **Profile groups.** Collapsible sections ("Work", "Personal") in the sidebar.
- **What's New overlay** for upgrading users (issue [#164](https://github.com/Harry-kp/vortix/issues/164)).

## Later

- Windows support
- IKEv2/IPSec alongside WireGuard and OpenVPN
- Credentials encrypted at rest

---

## Release Philosophy

- **Each release earns something.** The headline is what the user can now do, not the bug count.
- **Features ship with quality.** Tests, consistent UI and docs land with the feature, or it waits.

## How to Contribute

1. **Pick an issue**: [`good first issue`](https://github.com/Harry-kp/vortix/labels/good%20first%20issue)
2. **Vote on features**: react with 👍 on [Feature Requests](https://github.com/Harry-kp/vortix/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
3. **Propose ideas**: [GitHub Discussions](https://github.com/Harry-kp/vortix/discussions)
4. **Submit PRs**: see [CONTRIBUTING.md](CONTRIBUTING.md)
