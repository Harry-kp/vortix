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

## v0.3.0 — "Architectural Migration v1" ✅

**The promise:** Vortix's internals are now ready for the next two years of feature work.

**What changes for the user:**

1. **Existing CLI unchanged.** `vortix up`, `down`, `status`, `list`, `import`, `killswitch` — all preserved exactly. Profiles, killswitch state, and `.auth` files keep working unchanged.

2. **One new top-level subcommand:** `vortix secrets {set,get,delete}` for an optional OS-keyring-backed encrypted credential store (AES-256-GCM + argon2id fallback for headless installs). Existing `.auth` files still work; the store is opt-in.

3. **Session event journal.** Every run writes a JSONL event log to `${XDG_DATA_HOME}/vortix/sessions/` with 30-day retention. `vortix info` surfaces the current session's path; users tail it with shell tools.

4. **Versioned `--json` output.** Every structured envelope now carries `schema_version: 1`. Consumers detect breaking changes instead of finding them at runtime.

**What this unlocks:**

The internal architecture (Cargo workspace, capability ports, Tunnel trait, Engine FSM, layered config, secret store) is the foundation for the next plan series — daemon mode, lifecycle hooks, privilege separation, Windows, per-process socket audit. Each future feature plugs into existing seams instead of re-litigating architecture.

See [`docs/v0.3.0-RELEASE-NOTES.md`](docs/v0.3.0-RELEASE-NOTES.md) for the full surface and [`docs/architecture-migration-v1.md`](docs/architecture-migration-v1.md) for the technical map.

---

## v0.4.0 — "Set and Forget"

**The promise:** Vortix manages your VPN so you don't have to think about it. Built on the v0.3.0 architecture.

**What changes for the user:**

1. **Lifecycle hooks** ([plan 009](docs/plans/2026-05-24-009-feat-lifecycle-hooks-plan.md), issue [#36](https://github.com/Harry-kp/vortix/issues/36)). Run a script before connecting (check trusted network, update firewall rules) or after disconnecting (flush DNS, restart services). Composable with your existing workflow.

2. **Auto-connect on startup / daemon mode** ([plan 010](docs/plans/2026-05-24-010-feat-ipc-engine-handle-remote-plan.md), issue [#16](https://github.com/Harry-kp/vortix/issues/16)). Configure a default profile and Vortix connects the moment you open a terminal — or runs as a background daemon. Builds on the new `EngineHandle::Remote` IPC layer.

3. **CI integration tests against real `wg`/`openvpn`** ([plan 012](docs/plans/2026-05-24-012-feat-ci-integration-tests-plan.md), issue [#162](https://github.com/Harry-kp/vortix/issues/162)). Higher release confidence; fewer manual smoke runs per release.

**What this unlocks:** The "I use it every day" users. The ones who put Vortix in their dotfiles.

---

## v0.5.0 — "Least Privilege"

**The promise:** Vortix runs as your user; only the parts that actually need root do.

1. **Privilege separation** ([plan 011](docs/plans/2026-05-24-011-feat-privilege-separation-plan.md), issue [#153](https://github.com/Harry-kp/vortix/issues/153)). Privileged daemon worker + unprivileged TUI/CLI frontend. `vortix status`, `vortix list` work without sudo; only `up`/`down`/`killswitch` route to the daemon. Auditable, principle-of-least-privilege.

2. **Per-process socket audit** ([plan 013](docs/plans/2026-05-24-013-feat-socket-audit-port-plan.md), issues [#168](https://github.com/Harry-kp/vortix/issues/168) and [#166](https://github.com/Harry-kp/vortix/issues/166)). `vortix audit` answers "what's actually routing through the tunnel?" — leak-detection complement to the existing IPv6/DNS guards.

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
