# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Multi-tunnel support via `TunnelRegistry`: multiple VPN profiles can be Connected concurrently. The tunnel that owns the kernel default route is the *primary*; secondaries are *addressable* (reachable on their declared `AllowedIPs` only).
- Per-profile retry and auto-reconnect (`HashMap<ProfileId, RetryState>` replaces the single-slot retry triple). Concurrent failures on multiple profiles each get their own retry budget and exponential-backoff schedule instead of overwriting one another.
- Per-profile scanner loop in `handle_sync_system_state`: every registry entry is reconciled against the scanner's active sessions independently — drop detection, refresh, and Connecting → Connected promotion all run per-tunnel.
- Auto-adopt of externally-started VPNs: when the scanner sees an active session for a catalog profile that isn't in the registry (e.g., the user ran `wg-quick up X` outside vortix, or vortix restarted while a tunnel was already up), the tunnel is registered into the registry on the next scanner tick.
- `vortix up X --yes` flag to bypass the multi-tunnel conflict gate (default-route takeover, route overlap) for scripted/non-interactive callers.
- Multi-tunnel TUI keybindings: `D` (disconnect all with confirm when N > 1), `Tab` in Connection Details (cycle focus across active tunnels), `c` (cancel an in-flight `Connecting` profile from the Details panel), `B` (Both — connect both tunnels from the takeover overlay), `u` (revert auto-promote banner action).
- JSON v2 status envelope with `data.connections[]` + `data.primary` for multi-tunnel introspection. The legacy `data.connection` field stays populated when exactly one tunnel is up (back-compat for v1 consumers).
- Shared `VpnRuntime::check_dependencies` now runs the OpenVPN 2.4+ probe (`--pull-filter` baseline for multi-tunnel DNS scoping) — both TUI and CLI surfaces refuse the same dep set.
- `Cidr::intersects` + `vortix_core::cidr::overlapping_cidrs` for CIDR-overlap detection shared between the CLI conflict gate and the registry's future R10 v2 route-overlap detection.

### Changed

- **Kill switch `AlwaysOn`** now keeps the firewall engaged regardless of connection state. Previously: `AlwaysOn + Connected → Armed` left no actual blocking in place; the gap between a VPN drop and reconnect could leak. New semantic: default-DROP OUTPUT policy + per-tunnel ACCEPT rules stay engaged whether VPN is up or not. This is the canonical Linux killswitch shape and the integration test (`tests/integration/killswitch.sh`) enforces it. Users with `Connected + AlwaysOn` previously saw "Armed (Strict)" with no enforcement; now they see "Blocking (Strict)" with the firewall actually enforced.
- `vortix down` with no profile argument now disconnects EVERY active tunnel (previously single-tunnel only). `vortix down <profile>` keeps the per-tunnel disconnect.
- `vortix reconnect` now cycles every currently-Connected tunnel (re-up via the registry path).
- All TUI panels (Header, Sidebar, Connection Details, Security Guard, Logs) read their state from `app.registry` snapshots exclusively. Renderers no longer consult the legacy `connection_state` field — single source of truth for active VPN state.
- CLI killswitch sync now persists every kernel-visible tunnel's `ActiveTunnelInfo` (via `VpnRuntime::killswitch_view_from_scanner`), so a CLI `vortix down A` no longer clobbers the persisted slice for a still-up B.

### Fixed

- Multi-tunnel kill switch: secondary tunnels' `AllowedIPs` are now allow-listed in the firewall, not just the primary's. Pre-multi-tunnel the killswitch could block valid secondary egress.
- CLI's `vortix up X` now runs the OpenVPN 2.4+ probe that the TUI's connect path already ran; previously a user could connect with OpenVPN 2.3 and silently leak pushed DNS through the primary's resolver (the exact failure plan 001 R13 prevents).
- CLI's `vortix down A` while another terminal's TUI was tracking A+B no longer clobbers the persisted killswitch state with an empty slice; the on-disk slice always reflects every kernel-visible tunnel.

### Removed

- Legacy `pub connection_state: ConnectionState` field on `VpnRuntime`. The App layer reads `app.registry`; the CLI's blocking helpers carry their own local state. The `ConnectionState` enum itself remains as a CLI-local shape and as the return type of `App::legacy_state()` (a derived view from registry primary, used by the few remaining single-tunnel readers).
- `vortix down` no longer requires `point_engine_at_session` orchestration; `VpnRuntime::disconnect_and_wait` now takes `(profile_name, pid, force, timeout)` explicitly.

## [0.2.2] - 2026-04-23

### Miscellaneous

- Update Cargo.lock dependencies



## [0.2.1] - 2026-04-04

### Fixed

- Detect missing `resolvconf` before WireGuard connect on Linux ([#186](https://github.com/Harry-kp/vortix/issues/186), [#187](https://github.com/Harry-kp/vortix/pull/187)) — Vortix now shows clear install instructions instead of cryptic wg-quick errors when DNS is configured but resolvconf isn't available on Arch/Fedora
- Add CLI dependency check to catch missing tools before connection attempts

### Documentation

- Add comprehensive Arch Linux troubleshooting FAQ and distribution-specific guidance in README
- Add WireGuard configuration guide explaining AllowedIPs, cloud provider limitations, and routing best practices
- Add quick error reference table for common connection issues



## [0.2.0] - 2026-03-31

### Added

- Add a CLI-first headless mode with structured JSON output for scripting, automation, and AI-agent workflows, including `vortix status` for scriptable connection and kill-switch visibility ([#156](https://github.com/Harry-kp/vortix/issues/156), [#176](https://github.com/Harry-kp/vortix/pull/176)).
- Add the new flip-panel dashboard interaction with animated card transitions ([#165](https://github.com/Harry-kp/vortix/pull/165)).

### Changed

- VPN sessions can now keep running after the TUI or CLI exits, so leaving the interface no longer tears down an active connection unexpectedly ([#155](https://github.com/Harry-kp/vortix/issues/155), [#176](https://github.com/Harry-kp/vortix/pull/176)).
- Make `vortix down` wait for the OpenVPN daemon to fully exit before reporting success ([#176](https://github.com/Harry-kp/vortix/pull/176)).

### Fixed

- Remove the stale quit confirmation now that active connections can continue independently of the UI process ([#179](https://github.com/Harry-kp/vortix/issues/179), [#182](https://github.com/Harry-kp/vortix/pull/182)).
- Fix help overlay scrolling edge cases, including opening before the first resize and clamping scroll correctly after keyboard and mouse input ([#180](https://github.com/Harry-kp/vortix/issues/180), [#182](https://github.com/Harry-kp/vortix/pull/182)).
- Harden CLI lifecycle handling around disconnect flow, error paths, and config isolation ([#176](https://github.com/Harry-kp/vortix/pull/176)).

### Documentation

- Clarify current Linux support expectations and improve Linux bug-reporting guidance for distro-specific issues ([#185](https://github.com/Harry-kp/vortix/pull/185)).

### CI

- Add Fedora 41 CI coverage for `cargo check`, `cargo clippy`, `cargo test`, and `cargo doc`, including unprivileged test execution for Linux-specific validation ([#160](https://github.com/Harry-kp/vortix/issues/160), [#183](https://github.com/Harry-kp/vortix/pull/183)).



## [0.1.8] - 2026-03-19

### Features

- Add centralized theming system — all colors now flow through `theme.rs`, replacing hardcoded `Color::Rgb` across 13 UI files ([#109](https://github.com/Harry-kp/vortix/issues/109), [#147](https://github.com/Harry-kp/vortix/issues/147))
- Add mouse click-to-select for profiles in the sidebar ([#139](https://github.com/Harry-kp/vortix/issues/139))
- Add Wayland clipboard support via `wl-copy`, with `xclip`/`xsel` fallback on X11 ([#107](https://github.com/Harry-kp/vortix/issues/107))
- Add word-wrapped log messages with accurate scroll using `Paragraph::line_count()` — long OpenVPN errors no longer truncate

### Bug Fixes

- Fix OpenVPN error messages not shown in UI — vortix now reads the daemon log file when stderr is empty due to `--daemon --log` ([#154](https://github.com/Harry-kp/vortix/issues/154))
- Fix footer truncating Help and Quit hints first on narrow terminals — critical hints now have priority, with unicode-aware width calculation ([#134](https://github.com/Harry-kp/vortix/issues/134))
- Fix cursor style inconsistent across overlays — all text fields now use the same blinking block cursor ([#135](https://github.com/Harry-kp/vortix/issues/135))
- Fix URL import leaving temp files behind in system temp directory ([#136](https://github.com/Harry-kp/vortix/issues/136))
- Fix race condition where temp file could be deleted before import completes on TUI URL import
- Fix clipboard copy reporting success without checking the tool's exit status
- Fix toast messages logged at wrong severity level (e.g., connection failures logged as INFO instead of ERROR)

### Refactor

- Generalize `centered_rect` helper to support both percentage-based and fixed-size centering, removing duplicate code ([#123](https://github.com/Harry-kp/vortix/issues/123))
- Eliminate per-frame `String` allocations in footer hint rendering

### Testing

- Add unit tests for rename-profile path traversal validation with rejection assertions ([#137](https://github.com/Harry-kp/vortix/issues/137))
- Add unit tests for `cleanup_temp_download`, footer hint width calculations, `centered_rect` variants, and theme alias consistency

### Miscellaneous

- **deps:** Bump the rust-minor group with 2 updates ([#152](https://github.com/Harry-kp/vortix/pull/152))



## [0.1.7] - 2026-03-11

### Bug Fixes

- Fix Escape/CloseOverlay resetting zoomed panel back to normal layout ([#105](https://github.com/Harry-kp/vortix/issues/105))
- Fix sidebar "Reconnect" action disconnecting instead of reconnecting the selected profile ([#106](https://github.com/Harry-kp/vortix/issues/106), [#145](https://github.com/Harry-kp/vortix/issues/145))
- Fix exponential backoff overflow causing infinite retry delays at high attempt counts ([#110](https://github.com/Harry-kp/vortix/issues/110))
- Fix renaming a profile breaking reconnect by not updating `last_connected_profile` ([#111](https://github.com/Harry-kp/vortix/issues/111))
- Fix deleting a profile during Connecting or Disconnecting state causing state corruption ([#112](https://github.com/Harry-kp/vortix/issues/112))
- Fix "IP unchanged" warning flooding logs every telemetry poll cycle while connected ([#113](https://github.com/Harry-kp/vortix/issues/113))
- Fix 0ms latency falsely showing EXCELLENT quality instead of UNKNOWN ([#146](https://github.com/Harry-kp/vortix/issues/146))

### Features

- Add `ConnectSelected` action: sidebar `r` key now connects the highlighted profile rather than the last-used one
- Add `Unknown` quality state when no metrics have arrived yet, displayed as "─────" in header and "UNKNOWN" in details
- Include latency in connection quality scoring (Poor ≥ 300ms, Fair ≥ 100ms)
- Cap retry backoff at configurable `connect_retry_max_delay_secs` (default 300s)

### Documentation

- Rewrite ROADMAP as a product journey with themed releases and user stories

### Miscellaneous

- **deps:** Bump the rust-minor group with 3 updates ([#149](https://github.com/Harry-kp/vortix/pull/149))



## [0.1.6] - 2026-03-08

### Bug Fixes

- Fix `pkill openvpn` killing all system OpenVPN processes instead of only Vortix-managed ones ([#95](https://github.com/Harry-kp/vortix/issues/95))
- Fix kill switch state file written to world-readable `/tmp/` ([#96](https://github.com/Harry-kp/vortix/issues/96))
- Fix kill switch displaying "Blocking" without root, giving a false sense of security ([#97](https://github.com/Harry-kp/vortix/issues/97))
- Fix Unicode text input causing panic in text field handlers ([#98](https://github.com/Harry-kp/vortix/issues/98))
- Add `Drop` impl on `App` to clean up kill switch rules and VPN processes on panic ([#99](https://github.com/Harry-kp/vortix/issues/99))
- Fix disconnect failure leaving app in "Disconnected" state while VPN process may still be running ([#100](https://github.com/Harry-kp/vortix/issues/100))
- Fix spurious "VPN dropped" auto-reconnect triggered by force-kill
- Fix config viewer overlay not loading file contents on open
- Fix minimum terminal size check causing blank screen on small terminals
- Fix search and rename cursor position on multi-byte UTF-8 input
- Fix mouse events passing through overlays to background panels
- Fix help overlay not being scrollable
- Fix ISP and location text truncated too aggressively on narrow terminals ([#104](https://github.com/Harry-kp/vortix/issues/104))
- Fix connection details panel mostly empty when disconnected ([#102](https://github.com/Harry-kp/vortix/issues/102))
- Fix import overlay closing immediately on URL import or empty directory
- Fix `g`/`G`/Home/End keys not routing correctly when logs panel is focused
- Fix mouse scroll not working on hovered panel (only worked on focused panel)
- Fix profile names overflowing sidebar column when names are long
- Fix password mask using byte count instead of character count for multi-byte input
- Enable config viewer overlay to be scrollable with mouse
- Fix action menus not listing all available panel actions (Sort, Rename, Filter, Kill Switch)

### Features

- Add human-readable connection duration format (e.g., "2h 15m" instead of seconds)
- Add throughput chart with upload/download speed labels and color legend ([#103](https://github.com/Harry-kp/vortix/issues/103))
- Add active connection badge (checkmark) next to connected profile in sidebar
- Clear stale telemetry data on disconnect to avoid showing previous session info
- Add keyboard accessibility for all panels with Tab/Shift+Tab cycling
- Add panel-specific keyboard shortcuts displayed in context footer
- Add log level filtering (Error/Warn/Info) with `f` key
- Show protocol tag (WG/OVPN) in cockpit header bar when connected
- Show DNS server provider name (Cloudflare, Google, Quad9) in security panel
- Add confirmation dialog when switching profiles while connected
- Add confirmation dialog when quitting with an active VPN connection
- Add profile sorting (name, protocol, last used) with `s` key
- Add connection quality thresholds (Poor/Fair/Excellent) based on latency, jitter, and packet loss
- Move toast notifications from bottom-right to top-right for better visibility

### Refactor

- Split 2081-line `dashboard.rs` into 13 focused per-panel modules ([#114](https://github.com/Harry-kp/vortix/issues/114))
- Extract shared confirmation dialog component to reduce code duplication
- Adopt `tempfile` crate for panic-safe test cleanup across all 31 test sites ([#116](https://github.com/Harry-kp/vortix/issues/116))
- Sanitize profile names with strict ASCII-only validation for process management
- Consolidate confirmation dialog input handling into shared `handle_confirm_keys`
- Route inline key handlers (rename, search, help, log filter) through Message dispatch for TEA consistency

### Testing

- Enable 6 previously-ignored auth tests to run without root privileges
- Add 19 new tests covering confirm dialog keys, Home/End panel awareness, profile name sanitization, truncation edge cases, and import overlay behavior
- Migrate all test temp file creation to `tempfile` crate for automatic cleanup on panic

### CI

- Pin Rust 1.91.0 in CI and fix remaining lint issues



## [0.1.5] - 2026-02-16

### Bug Fixes

- Address PR review feedback for bug report feature

### Documentation

- Add roadmap and feature voting links to README
- Add vortix report and Nix installation to README
- Rearrange badges, add Nix flake and npm downloads badges

### Features

- Add `vortix report` bug report command

### Miscellaneous

- **deps:** Bump the rust-minor group with 2 updates ([#40](https://github.com/Harry-kp/vortix/pull/40))



## [0.1.4] - 2026-02-12

### Documentation

- Add sudo PATH troubleshooting for cargo install on Linux
- Restructure README for clarity and fix misleading info
- Move sudo PATH fix to prominent section after installation

### Features

- Add Homebrew and npm package manager support



## [0.1.3] - 2026-02-11

### Bug Fixes

- Prevent TUI freeze when no network connection is available
- **ci:** Gate macOS-only symbols behind cfg to resolve Linux dead_code errors
- Prevent UTF-8 panic when truncating log messages in TUI

### Documentation

- **readme:** Add installation for arch linux ([#27](https://github.com/Harry-kp/vortix/pull/27))
- Add directory structure and configuration guide to README
- Clarify file ownership and permissions in README
- Update configuration reference with all configurable settings

### Features

- Configurable config directory with settings, migration, and sudo ownership
- Harden VPN lifecycle, structured logging, and configurable settings
- Startup dependency check with toast warning for missing tools



## [0.1.2] - 2026-02-07

### Bug Fixes

- Resolve clippy errors on Linux CI (Rust 1.93)

### Documentation

- Add star history graph to README
- Add ROADMAP and GitHub Sponsors funding
- Add downloads and stars badges to README
- Add Terminal Trove feature mention
- Fix roadmap links to point to feature requests
- Add comparison table, CONTRIBUTING.md, and issue/PR templates
- Add macOS, Rust, Sponsors, and PRs Welcome badges

### Features

- Add Linux platform support with cross-platform abstraction layer
- Robust VPN state machine and strict config import validation
- OpenVPN credential management and UX improvements

### Miscellaneous

- **deps:** Bump clap from 4.5.54 to 4.5.56 in the rust-minor group ([#23](https://github.com/Harry-kp/vortix/pull/23))



## [0.1.1] - 2026-01-14

### Bug Fixes

- Address Clippy and Copilot review comments

### Miscellaneous

- **deps:** Bump nix from 0.29.0 to 0.30.1 ([#7](https://github.com/Harry-kp/vortix/pull/7))
- **deps:** Bump libc from 0.2.179 to 0.2.180 in the rust-minor group ([#9](https://github.com/Harry-kp/vortix/pull/9))

### Refactor

- Centralized logging, optimized deps, improved UI



## [0.1.0] - 2026-01-02

### Added
- Initial release of Vortix VPN Manager
- TUI dashboard with real-time network telemetry
- WireGuard profile support (.conf files)
- OpenVPN profile support (.ovpn files)
- Quick slots (1-5) for favorite connections
- Profile import via TUI (`i` key) and CLI (`vortix import`)
- Self-update command (`vortix update`)
- IPv6 leak detection
- DNS leak detection
- Insecure protocol detection (HTTP, FTP, Telnet)
- Live throughput monitoring (upload/download speeds)
- Connection uptime tracking
- Nordic Frost color theme
- Keyboard-driven interface with help overlay (`?` key)

### Security
- Config files stored with 600 permissions
- Root privilege requirement for network interface management

[Unreleased]: https://github.com/Harry-kp/vortix/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/Harry-kp/vortix/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/Harry-kp/vortix/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/Harry-kp/vortix/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Harry-kp/vortix/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Harry-kp/vortix/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Harry-kp/vortix/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Harry-kp/vortix/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Harry-kp/vortix/releases/tag/v0.1.0
