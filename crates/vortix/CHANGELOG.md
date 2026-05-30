# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Highlights

- **Run multiple VPNs at the same time.** Connect to several WireGuard / OpenVPN profiles concurrently; one owns the kernel default route (the *primary*), the rest are *split tunnels* reachable on their declared `AllowedIPs`.
- **Friendlier kill switch.** Modes are now `off`, `block-on-drop`, and `vpn-only` — the same words in the TUI, the CLI, and the JSON output. The `vpn-only` mode actually stays engaged whether the VPN is up or down (the v0.3.x `AlwaysOn` mode sat unarmed while the VPN was up, leaving a leak window between a drop and reconnect).
- **Polished Security Guard panel.** New `Identity` / `Defense` layout, calmer colour treatment, and the encryption row now grades your cipher (`modern AEAD`, `strong`, `deprecated`, or `INSECURE`) instead of just printing the name.

### Added

- Connect to multiple VPN profiles concurrently. Each gets its own retry budget and reconnect schedule.
- Auto-adopt: tunnels you started outside vortix (e.g. `wg-quick up corp` from another terminal) appear in the TUI within a second.
- Takeover overlay: when a second tunnel wants the default route, choose `[S]witch` (replace), `[B]oth` (keep both up, the new one becomes the exit), or `[N]o`.
- Auto-promote banner: if the primary drops and a secondary takes over, a one-line banner explains what happened and offers `[u]` to revert.
- Cipher strength annotation on the Security Guard `Encryption` row, with bright alarms for `INSECURE` ciphers (BF-CBC, DES, RC4, NULL, CAST5, IDEA, RC2).
- `vortix up <name> --yes` to skip the takeover prompt for scripts and CI.
- Multi-tunnel keybindings: `Shift+D` (disconnect every active tunnel with confirm), `c` (cancel an in-flight connect from Connection Details), `B` (Both from the takeover overlay), `u` (revert auto-promote).
- JSON status reports every connected tunnel in `data.connections[]` plus `data.primary`. The legacy `data.connection` field stays populated when only one tunnel is up (back-compat for v1 consumers).
- Sigil legend (`✓ ✗ ⚠ ─`) in the `?` help overlay.

### Changed

- **Breaking — CLI killswitch verbs.** `vortix killswitch off | block-on-drop | vpn-only` replaces `off | auto | always | always-on`. The old verbs are no longer accepted; the parser rejects them with `Use: off, block-on-drop, vpn-only`.
- **Breaking — JSON killswitch values.** `data.security.killswitch_mode` now emits `off` / `block-on-drop` / `vpn-only` instead of `off` / `auto` / `alwayson`. `data.security.killswitch_state` emits `Inactive` / `Watching` / `Blocking` instead of `disabled` / `armed` / `blocking`. Scripts parsing the old values need to switch.
- **Kill switch `vpn-only`** stays engaged whether the VPN is up or down. In v0.3.x the `AlwaysOn + Connected` combination resolved to `Armed` with no actual firewall enforcement, so a drop between checks could leak. Now: default-DROP egress + per-tunnel ACCEPT rules are in place at all times when this mode is selected.
- `vortix down` with no profile argument now disconnects every active tunnel (was single-tunnel only). `vortix down <name>` keeps the per-tunnel behaviour.
- `vortix reconnect` cycles every currently-connected tunnel.
- Telemetry switched from `reqwest` / `curl` / `ping` shell-outs to in-process HTTP (`ureq`) + raw-ICMP (`socket2`). Smaller binary, faster startup, no transient child processes.
- Interface and process lookups on Linux / macOS go through `libc` directly (`getifaddrs`, `sysctlbyname`, `kill`) instead of parsing `ip addr show` / `ifconfig` / `ps` output. Fewer locale-dependent parser bugs.

### Fixed

- CLI's `vortix up <name>` now refuses pre-2.4 OpenVPN before attempting to connect (matches what the TUI already did in v0.3.x; pre-fix the CLI would proceed and could leak pushed DNS through the primary's resolver).

### Removed

- The Security Guard panel no longer renders the sigil legend inline (moved to the `?` help overlay) or the `Real IP: <ip> (hidden)` sub-bullet (avoids leaking the real IP in screenshots of an otherwise-clean panel).

## [0.3.1] - 2026-05-25

### Changed

- **Flattened to single crate.** Merged all 8 internal crates into the main `vortix` crate as modules. Enables `cargo install vortix` from crates.io. No functional changes.
- Internal modules marked `#[doc(hidden)]` to keep public API surface clean.

## [0.3.0] - 2026-05-24

### Architecture

- **Cargo workspace split.** Codebase restructured into 12 internal crates under `crates/` (vortix-core, vortix-process, vortix-config, vortix-platform-{linux,macos,windows}, vortix-protocol-{wireguard,openvpn}, xtask). Single published binary remains `vortix`.
- **Capability ports.** 7 trait-based ports (Tunnel, Killswitch, DNS, Interface, NetworkStats, RouteTable, CommandRunner) in `vortix-core` with per-OS implementations behind them. Adding new protocols or platforms is now mechanical.
- **Engine FSM.** Internal connection state is now a typed 5-variant state machine (`Disconnected`, `Connecting`, `Connected`, `Disconnecting`, `AwaitingUserInput`) with compile-time transition enforcement.
- **CI boundary lints.** Three `cargo xtask` lints enforce that `Command::new` only appears in `vortix-process`, `cfg(target_os)` only in platform crates, and protocol strings only in protocol crates.

### Added

- **Session journal.** Every session writes a JSONL event log to `${XDG_DATA_HOME}/vortix/sessions/*.jsonl` with 30-day / 30-file retention. Path surfaced via `vortix info`.
- **`vortix secrets {set,get,delete}`** -- Layered secret store backed by OS keyring (Keychain / Secret Service) with AES-256-GCM + argon2id on-disk fallback. Opt-in; existing `.auth` files keep working.
- **`vortix audit`** -- Per-process socket snapshot for VPN leak detection. `--pid <N>` filters to one process, `--vpn-only` to tunnel sockets, `--json` for structured output. Linux (`/proc/net`) + macOS (`lsof`) implementations.
- **`vortix daemon`** -- IPC server skeleton with Unix socket (mode 0600) and length-prefixed JSON framing. Engine routing through daemon completes in v0.3.x.
- **`vortix show --raw --inline-secrets`** -- Streams profile config to stdout with stored credentials appended as `# vortix-secret:<base64>` trailing comment.
- **CI integration tests.** Privileged Docker container with network namespaces running real `wg-quick` + killswitch engage/release end-to-end.
- **`settings.toml`** -- Figment-layered config (defaults -> system -> user -> env). Not required; runtime defaults match v0.2.x behavior.
- **JSON `schema_version`.** Every `--json` envelope now includes `"schema_version": 1`.
- **Windows stub crate.** `vortix-platform-windows` compiles on Windows; every port returns `PlatformUnsupported`.
- **Startup orphan scan.** Warn-only detection of leftover `wg-quick`/`openvpn` processes from previous runs.
- **Cold-start performance test.** CI ceiling on `vortix --version` startup time.

### Fixed

- **WireGuard shows Connected with no handshake on invalid server address** ([#31](https://github.com/Harry-kp/vortix/issues/31)). FSM now requires a real `TunnelUp` event before entering `Connected` state.
- **CLI hardening** ([#177](https://github.com/Harry-kp/vortix/issues/177)). Typed errors via `thiserror` at every port boundary, config value masking in output.

### Changed

- Profile sidecar backfill runs automatically at first launch. A `<name>.meta.toml` appears next to each `.conf`/`.ovpn`. Idempotent; v0.2.x ignores these files.
- Killswitch state and active VPN sessions survive the binary upgrade unchanged.

### Documentation

- `docs/MIGRATION.md` -- upgrade guide from v0.2.x
- `docs/v0.3.0-RELEASE-NOTES.md` -- full release notes
- `docs/v0.3.0-FAQ.md` -- common upgrade questions
- `docs/architecture-migration-v1.md` -- technical surface map
- `docs/RELEASE-PLAYBOOK-v0.3.0.md` -- maintainer runbook
- `SECURITY.md` updated with daemon authentication model
- 15 plan documents in `docs/plans/` (001-015)

### Not in v0.3.0 (deferred)

- No Windows binary (stub only, [#17](https://github.com/Harry-kp/vortix/issues/17))
- Daemon engine routing (skeleton only, [#16](https://github.com/Harry-kp/vortix/issues/16))
- Privilege separation / no-sudo ([#153](https://github.com/Harry-kp/vortix/issues/153))
- Lifecycle hooks (backed out after UX iteration, [#36](https://github.com/Harry-kp/vortix/issues/36))
