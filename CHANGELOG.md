# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Harry-kp/vortix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Harry-kp/vortix/releases/tag/v0.1.0
