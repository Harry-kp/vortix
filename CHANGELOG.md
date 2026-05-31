# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- TUI no longer freezes when connecting to OpenVPN — even on misbehaving / slow / broken servers. Four interacting bugs would each park the UI thread for seconds at a time on a connect; together they could lock the panel for 30+ seconds and queue keystrokes. Fixed by removing every synchronous subprocess call from the UI thread's connect-success path:
  - `openvpn --daemon` forks + detaches, but the daemonized grandchild inherited vortix's stdout/stderr pipes — `wait_with_output()` blocked forever waiting for pipe EOF that never came. Subprocesses can now declare themselves as daemonizing; the runner routes their stdio to `/dev/null` and uses `child.wait()` instead.
  - `openvpn --version` dependency probe ran synchronously on the UI thread with no timeout. A slow first-run probe (Gatekeeper / Spotlight / antivirus on macOS) froze the panel until it returned. The probe now has a 10-second cap.
  - `route get default` / `ip route show default` ran inline on the UI thread every time the registry's `recompute_primary` fired (which is every connect, every disconnect, and every scanner tick). Right after a VPN claims the default route, the macOS kernel takes up to 30 seconds to answer that query. The query now lives in the scanner's background thread; its result is fed into a registry-side cache that the UI thread reads instantly. Subprocess timeout is also bounded at 1 second as defense in depth.
  - `handle_connect_result` dropped its own success result as "stale" if the scanner had already adopted the tunnel as Connected by the time the connect thread reported back (~1s race window). The post-connect bookkeeping — `last_used` timestamp, kill-switch sync, `STATUS: Connected` log line — was silently skipped, leaving the UI in a half-connecting state. Now accepts `Connected{this profile}` as a non-stale arrival.
- TUI stays responsive on broken VPN servers. When a tunnel comes up but its server's routing is misconfigured (everything behind the VPN times out), the scanner and network-monitor threads were both probing the kernel's default-route every 1-2 seconds and each hitting their 1s timeout — burning two tokio runtime workers continuously and starving the scanner of cycles to do useful session work. The probe now shares a process-wide failure backoff: first 1-2 failures retry immediately, 3-5 cool down 5s, 6-10 cool down 15s, 10+ cap at 60s. Reset on any successful probe.
- Aggressive scroll-spam in the `v` config viewer no longer wedges the TUI. Two compounding causes: (1) every keystroke ran `content.lines().count()` for scroll bounds AND a full per-line re-parse + re-highlight for the render. On a multi-thousand-line `.ovpn` (typical when certs/keys are inlined), that was ~4N string-iterations per arrow-key. (2) Mouse wheels emit 30+ events per second; the event loop processed one event per render, so a fast scroll burst queued hundreds of events and the TUI ground through them long after the user stopped scrolling. Fix: a `CachedConfigView` is built once when the viewer opens (pre-counted line total + pre-highlighted `Vec<Line>`); the main event loop now drains every queued event into state before rendering, so a 100-event scroll burst lands in one render frame at the final position.
- Connection-Details "Role" now correctly shows `Primary` for OpenVPN profiles whose server pushes `redirect-gateway` at runtime. The previous logic only inspected the client `.ovpn` (which has no `redirect-gateway` directive — the server pushes it via `PUSH_REPLY` after handshake), so every OpenVPN connect rendered as `Split tunnel` regardless of whether the tunnel actually owned the kernel default route. Now the kernel routing table is the source of truth: any profile whose interface owns the default route renders as `Primary` regardless of what its static config declared.
- New observability: any `Message` handler that holds the UI thread for more than 50ms emits a `tracing::warn` (silent by default; turn on with `RUST_LOG=vortix::app=warn`). Future regressions of this class surface immediately instead of being chased down with ad-hoc instrumentation.

### Removed

- The Security Guard panel no longer renders the sigil legend inline (moved to the `?` help overlay) or the `Real IP: <ip> (hidden)` sub-bullet (avoids leaking the real IP in screenshots of an otherwise-clean panel).

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
