# Roadmap

Vortix exists because managing VPN connections from the terminal should feel as natural as `git` or `vim` — fast, keyboard-driven, and transparent about what's happening with your network.

This roadmap describes the journey from "useful CLI tool" to "the VPN manager people recommend to friends."

---

## Where We Are: v0.1.6

A developer installs Vortix, imports a profile, connects. It works. They see real-time telemetry, a kill switch, profile management. But they notice rough edges: the quality indicator says "EXCELLENT" before any data arrives, the activity log fills with duplicate warnings, renaming a profile quietly breaks reconnect. They think: *"This is cool, but can I trust it?"*

That question drives everything that follows.

---

## v0.1.7 — "Dependable"

**The promise:** You can rely on Vortix for your daily VPN without second-guessing what it tells you.

**What changes for the user:**

1. **Connection quality monitoring becomes real.** Today, the quality indicator shows "EXCELLENT" with no data, and doesn't factor in latency at all. After v0.1.7, you see "Measuring..." until real telemetry arrives, and then a meaningful Excellent/Fair/Poor rating based on latency, jitter, and packet loss combined. The number in the dashboard means something.

2. **Reconnect does what you expect.** Today, pressing `r` reconnects to a hidden "last connected" profile — not the one you're looking at in the sidebar. After v0.1.7, reconnect in the sidebar context operates on the selected profile. The label says exactly what happens.

3. **The state machine is bulletproof.** Rename a profile that was previously connected? Reconnect still finds it. Delete a profile while it's connecting? Blocked with a clear message. Retry loop after a failed connection? Capped at 5 minutes, not 12 days.

4. **The activity log is useful again.** Today, "IP unchanged" warnings fire every 30 seconds while connected — 120 lines per hour of noise. After v0.1.7, each warning fires once per session. The log shows things worth reading.

**What this unlocks:** After v0.1.7, a user can connect in the morning, work all day, and trust that Vortix is accurately monitoring their connection. This is the minimum bar for anyone to adopt it as their daily VPN tool.

---

## v0.1.8 — "Feels Like One Product"

**The promise:** Every pixel and interaction feels intentionally designed — not bolted together from different sprints.

**What changes for the user:**

1. **A real theming system.** Today, colors are hardcoded in 13 different UI files. After v0.1.8, every color comes from `theme.rs`. This isn't just code cleanup — it's the foundation for user-selectable themes (Nord, Dracula, Solarized) in a future release. The app looks cohesive because it IS cohesive.

2. **The sidebar becomes a workspace.** Click a profile to select it (not just keyboard). See your profiles organized and navigable. The sidebar stops being a dumb list and starts being a control panel.

3. **It works on every terminal.** Narrow terminal? The footer degrades gracefully — Help and Quit are always visible. Wayland? Clipboard copy works. Small screen? No truncation artifacts. The app respects your environment instead of fighting it.

4. **Consistent interactions everywhere.** Same cursor style in every text field. Same overlay behavior. Same keyboard patterns. A user who learns one overlay has learned them all.

**What this unlocks:** After v0.1.8, Vortix screenshots look good in a README. People share it on Reddit and Hacker News because it *looks* like a tool worth trying. First impressions matter.

---

## v0.2.0 — "Universal"

**The promise:** If you use a terminal, Vortix works on your OS.

**What changes for the user:**

Today, Vortix is a macOS-first tool that happens to compile on Linux. v0.2.0 makes Linux a first-class citizen:

1. **Platform-aware networking.** WireGuard interface detection works on both macOS (`utun3`) and Linux (`wg0`). No more handshake check failures because the OS names interfaces differently. `ifconfig`/`netstat` replaced with cross-platform alternatives.

2. **CI guarantees.** Every commit is tested on macOS, Ubuntu, and Fedora. Platform bugs are caught before release, not by users.

3. **Distro-native installation.** Homebrew (macOS), AUR (Arch), Nix flake, cargo install. One command to install, everywhere.

**What this unlocks:** The addressable market doubles. Linux VPN users — sysadmins, security researchers, privacy advocates — can adopt Vortix. This is where community growth accelerates.

---

## v0.2.1 — "CLI First" ✅

**The promise:** Vortix is just as powerful from a script or AI agent as it is from the TUI.

**What changed:**

1. **Full CLI support.** Every TUI operation has a CLI equivalent: `up`, `down`, `status`, `list`, `show`, `delete`, `rename`, `killswitch`, `completions`. The TUI is the default; every subcommand is headless CLI.

2. **JSON-first output.** `--json` on every command produces a consistent envelope (`ok`, `command`, `data`, `error`, `next_actions`) — designed for `jq`, AI agents, and monitoring pipelines.

3. **Agent-friendly design.** Structured errors with codes and fix hints. `next_actions` in JSON responses for self-discovery. Semantic exit codes (0-6). Idempotent operations (disconnect when disconnected = success).

4. **Shell completions.** `vortix completions bash/zsh/fish` for tab completion in every major shell.

5. **VpnEngine extraction.** The core VPN logic (connection lifecycle, kill switch, profiles, telemetry) is now a standalone `VpnEngine` that works headlessly. The TUI `App` delegates to it via `Deref/DerefMut`.

**What this unlocks:** CI/CD pipelines, cron jobs, SSH automation, and AI coding agents can now use Vortix as a first-class VPN management tool.

---

## v0.3.0 — "Architectural Migration v1 + Deferred Subsystems Bundle" ✅

**The promise:** Vortix's internals are ready for the next two years of feature work, AND the deferred-subsystem bundle (lifecycle hooks, socket audit, CI integration tests, IPC daemon, privilege-separation docs) ships in the same release.

**What changes for the user:**

1. **Existing CLI unchanged.** `vortix up`, `down`, `status`, `list`, `import`, `killswitch` — all preserved exactly. Profiles, killswitch state, and `.auth` files keep working unchanged.

2. **Two new top-level subcommands:**
   - `vortix audit [--pid N] [--vpn-only] [--json]` — per-process socket inventory; useful for answering "is this traffic actually routing through the VPN?" (issues [#168](https://github.com/Harry-kp/vortix/issues/168), [#166](https://github.com/Harry-kp/vortix/issues/166)).
   - `vortix daemon [--socket PATH]` — long-running IPC server for `EngineHandle::Remote` (issue [#16](https://github.com/Harry-kp/vortix/issues/16)). Skeleton + wire-contract ships in v0.3.0; engine routing through the daemon lands in v0.3.x.

   *(A `vortix secrets {set,get,delete}` keyring-backed credential store also shipped in v0.3.0 and was retired in v0.3.1 — the macOS keyring lied about persistence for unsigned binaries and the TUI's connect path never consulted the store; auth credentials now flow only through the existing `auth/<profile>.auth` files and the TUI's prompt overlay.)*

3. **Lifecycle hooks** ([plan 009](docs/plans/2026-05-24-009-feat-lifecycle-hooks-plan.md), issue [#36](https://github.com/Harry-kp/vortix/issues/36)). Run shell commands on FSM transitions (pre/post connect/disconnect, connect_failed, reconnecting). Configure via `[[hooks]]` in `settings.toml`. Empty by default, zero overhead.

4. **Session event journal.** Every run writes a JSONL event log to `${XDG_DATA_HOME}/vortix/sessions/` with 30-day retention. `vortix info` surfaces the current session's path; users tail it with shell tools.

5. **CI integration tests** ([plan 012](docs/plans/2026-05-24-012-feat-ci-integration-tests-plan.md), issue [#162](https://github.com/Harry-kp/vortix/issues/162)). New `.github/workflows/integration-tests.yml` drives real `wg-quick` + `openvpn` + `iptables` in a privileged Docker container with network namespaces.

6. **Versioned `--json` output.** Every structured envelope carries `schema_version: 1`.

**What lands as docs-only in v0.3.0 and grows in v0.3.x:**

- Daemon engine routing (`vortix daemon` accepts clients + parses frames; engine wiring completes in v0.3.x)
- `SO_PEERCRED` / `getpeereid` auth (architecture documented in [`SECURITY.md`](SECURITY.md), enforcement lands with engine routing)
- Read-only ops bypass-daemon optimization
- macOS CI integration parity (Ubuntu-only at v0.3.0; macOS deferred)

See [`docs/v0.3.0-RELEASE-NOTES.md`](docs/v0.3.0-RELEASE-NOTES.md) for the full surface and [`docs/architecture-migration-v1.md`](docs/architecture-migration-v1.md) for the technical map.

---

## v0.3.x — Hardening + Daemon Engine Wiring

**The promise:** Finish what v0.3.0 set up.

1. **Daemon engine wiring.** The `dispatch()` skeleton in `vortix daemon` returns `IpcError::Internal("engine wiring not yet connected")` for `Execute`/`Snapshot`/`Subscribe`. Connecting it requires sharing main.rs's tunnel-factory setup with the daemon — a clean refactor that lands as v0.3.1.

2. **`SO_PEERCRED` / `getpeereid` enforcement.** The architecture is documented in `SECURITY.md`; the enforcement code lands alongside the engine routing.

3. **Read-only-ops bypass.** `vortix status`, `vortix list`, `vortix audit` continue to work without a running daemon. Privileged ops auto-route through the daemon when present.

4. **`OvpnTunnel` happy-path integration test.** The harness scaffolding from v0.3.0 ships with a WireGuard test + killswitch test; OpenVPN test fixtures (cert generation + stub server) land here.

---

## v0.4.0 — "Set and Forget"

**The promise:** Vortix manages your VPN so you don't have to think about it. Now that the daemon routing is solid, daemon-mode comes online.

1. **Auto-connect on startup.** Configure a default profile; vortix connects the moment your shell opens. systemd / launchd one-liners shipped as examples in v0.3.0.

2. **Profile groups.** Your 20 profiles in collapsible sections — "Work", "Personal", "Testing". `g`-key assignment for instant switching.

3. **What's New overlay.** In-TUI update nudge that surfaces v0.4.0 highlights to users upgrading from v0.3.x (issue [#164](https://github.com/Harry-kp/vortix/issues/164)).

---

## v0.5.0 — "Least Privilege"

**The promise:** Vortix runs as your user; only the parts that actually need root do.

1. **Independent security audit** of the daemon auth model documented in `SECURITY.md`. v0.3.0 ships the posture; v0.5.0 should ship the audited version.

2. **Capability-token auth** as an alternative to `SO_PEERCRED`. Frontend sessions get a fresh token on first connect; subsequent ops carry it. Defends against the UID race documented in SECURITY.md.

3. **seccomp filters** narrowing the daemon's syscall surface. AppArmor / SELinux reference profiles shipped under `examples/`.

---

## v1.0 — "For Everyone"

**The promise:** Production-grade VPN management for individuals and teams.

- **Split tunneling** — route only specific traffic through the VPN
- **Windows support** — the last platform barrier
- **Multi-protocol** — IKEv2/IPSec alongside WireGuard and OpenVPN
- **Config encryption** — credentials encrypted at rest
- **Audit logging** — who connected where, when
- **Centralized management** — shared config for teams

---

## Release Philosophy

- **Each release earns something.** v0.1.7 earns trust. v0.1.8 earns admiration. v0.2.0 earns reach. v0.3.0 earns *durability* (architecture that survives the next 1–2 years of feature work). v0.4.0 earns loyalty. v1.0 earns revenue.
- **Bugs are table stakes.** Every release fixes bugs, but that's not the headline. The headline is what the user can now DO.
- **Features ship with quality.** No feature lands without tests, without consistent UI, without documentation. A half-shipped feature is worse than no feature.

## How to Contribute

1. **Pick an issue** — Issues tagged [`good first issue`](https://github.com/Harry-kp/vortix/labels/good%20first%20issue) have detailed implementation plans
2. **Vote on features** — React with 👍 on [Feature Requests](https://github.com/Harry-kp/vortix/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
3. **Propose ideas** — Start a thread in [GitHub Discussions](https://github.com/Harry-kp/vortix/discussions)
4. **Submit PRs** — See [CONTRIBUTING.md](CONTRIBUTING.md)
