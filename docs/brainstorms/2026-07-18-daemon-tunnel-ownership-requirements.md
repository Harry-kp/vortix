---
date: 2026-07-18
topic: daemon-tunnel-ownership
---

# Daemon as Tunnel Owner — the end-state supervision architecture

## Summary

Complete the daemon as vortix's single tunnel owner: registry, supervision (drop detection, retry, network monitoring), and kill-switch enforcement move into one root, boot-started, headless process; the TUI and CLI become views over the existing IPC socket. Optionality is a capability ladder, not a cliff — without the daemon installed vortix behaves exactly as today, with it installed users gain no-sudo operation, boot persistence, headless reconnect, and a kill switch re-armed from early boot.

---

## Problem Frame

Every disruption-handling gap vortix has traces to one root: **no long-lived process owns the tunnels.** VPN daemons deliberately outlive the launching process (openvpn reparents to init; WireGuard lives in the kernel), while every protective loop — drop detection, the per-profile retry ladder, network-change handling, kill-switch state sync — runs only inside the TUI process. Consequences, all observed or verified against the codebase (full inventory in the 2026-07-18 investigation comment on issue #234):

- A CLI-started tunnel that drops later stays down; nothing is watching.
- Logout kills all supervision while the tunnels keep running, orphaned.
- The kill switch's `vpn-only` promise silently fails between reboot and the next vortix launch (issue #250) — firewall rules are runtime state, flushed at boot, while the state file still claims `Blocking`.
- "Supervised vs orphaned" process identity is unknowable from point-in-time scans — the source of the false orphan warnings hardened in PR #249.
- Every mutation surface (TUI, CLI) must re-derive world state from kernel scans; TUI↔CLI mutations still race.
- `sudo vortix` on every invocation (issue #153) — there is no privilege boundary to delegate to.

An independent investigation (2026-07-18) compared four architectures against prior art (tailscaled, Mullvad, upstream WireGuard's unit-only model, OpenVPN 3 Linux, NetworkManager) and against the codebase. OS-native units alone were rejected for the end-state: they cannot express auth-failure-aware retry (a bad-credential OpenVPN profile under `Restart=on-failure` loops forever), cannot arbitrate concurrent mutations, and cannot provide live ownership identity — every surveyed production tool converged on a resident owner for exactly these reasons. The codebase has been architected toward this end-state since v0.3.0: `EngineHandle` is `#[non_exhaustive]` awaiting a `Remote` variant, the IPC vocabulary reserves `RegistrySnapshot`, and a UID-gated daemon socket already ships.

---

## Actors

- A1. Interactive TUI user: runs `vortix`, expects live multi-tunnel state, connects/disconnects, may close the TUI and expect tunnels to stay supervised.
- A2. CLI/script user: runs `vortix up/down/status` from shells and scripts (possibly several terminals at once); after this arc, without `sudo` when the daemon is installed.
- A3. The daemon (`vortix daemon`): root, boot-started via systemd/launchd, owns the registry + supervision loops + kill-switch enforcement; the only writer of tunnel state.
- A4. Headless/boot context: no user session at all — early boot (kill-switch re-arm window), post-logout, SSH-only servers.

---

## Key Flows

- F1. Connect via CLI with daemon installed
  - **Trigger:** A2 runs `vortix up <profile>` (no sudo).
  - **Actors:** A2, A3.
  - **Steps:** CLI detects the daemon socket → sends the connect command over IPC → daemon (root) validates, arbitrates conflicts against the registry, spawns the tunnel, arms the kill switch → streams progress/result back → CLI prints and exits.
  - **Outcome:** Tunnel up and supervised by A3; CLI process gone; no root prompt was needed.
  - **Covered by:** R1, R2, R6, R12.

- F2. Drop while no UI is running
  - **Trigger:** A tunnel dies (network glitch, wake-from-sleep, process crash) with no TUI or CLI process alive.
  - **Actors:** A3.
  - **Steps:** Daemon's scanner detects the drop → kill-switch engages per mode → retry ladder schedules reconnect with existing backoff/attempt policy (auth-failure aware) → tunnel restored or gives up per policy; every transition journaled.
  - **Outcome:** Same reconnect behavior the TUI provides today, headless.
  - **Covered by:** R5, R7.

- F3. Boot with a persisted profile and vpn-only kill switch
  - **Trigger:** Machine boots; user previously enabled boot persistence for a profile and `vpn-only` mode.
  - **Actors:** A3, A4.
  - **Steps:** Early-boot blocking unit applies default-deny (with DHCP/link-local carve-outs) before networking → daemon starts, re-arms the full kill-switch ruleset, takes over from the early-boot unit → brings up persisted profile(s) → normal supervision begins.
  - **Outcome:** No leak window between boot and daemon start; the #250 gap is closed.
  - **Covered by:** R8, R9.

- F4. TUI attach/detach
  - **Trigger:** A1 launches the TUI while the daemon is running (tunnels possibly already up).
  - **Actors:** A1, A3.
  - **Steps:** TUI connects a Remote handle → fetches registry snapshot → subscribes to events → renders live state with no rescan flicker; on TUI exit nothing changes for the tunnels.
  - **Outcome:** TUI is a pure view; state and telemetry continuity across TUI restarts.
  - **Covered by:** R3, R4, R10.

- F5. Daemon absent (fallback)
  - **Trigger:** Any surface invoked on a machine where the daemon was never installed or is stopped.
  - **Actors:** A1 or A2.
  - **Steps:** Socket probe fails fast → surface falls back to today's Local path (direct spawn under sudo, kernel-scan status, TUI-local supervision) → output notes nothing unless asked.
  - **Outcome:** Current behavior preserved bit-for-bit; the daemon is an upgrade, never a requirement.
  - **Covered by:** R11.

---

## Requirements

**Ownership and IPC**

- R1. The daemon owns the multi-tunnel registry as the single source of truth; all tunnel mutations (connect, disconnect, reconnect, kill-switch changes) execute inside the daemon when it is running.
- R2. The CLI's mutating commands (`up`, `down`, `reconnect`, `killswitch`) route through the daemon over IPC when the socket is present, and are serialized by the daemon (superseding the client-side flock for daemon-mode operation).
- R3. The TUI attaches as a client: registry snapshots and a live event stream over IPC replace its in-process scanner/registry when the daemon is running.
- R4. The IPC surface carries multi-tunnel state (registry snapshot) and server-pushed events (state transitions, telemetry ticks), completing the currently stubbed subscribe operation.

**Supervision**

- R5. The daemon runs the supervision loops currently living in the TUI — kernel scanner + adoption, per-profile retry ladder with the existing backoff and attempt-cap policy (auth-failure aware for OpenVPN), network-change monitor — identically whether or not any UI is attached.
- R6. Concurrent mutations from any mix of surfaces are arbitrated by the daemon; the same profile cannot be double-spawned and conflicting commands resolve deterministically.
- R7. Tunnels survive daemon restart/upgrade: on start, the daemon adopts already-running tunnels (reusing scanner adoption) rather than tearing down or double-connecting. A daemon crash never kills a healthy tunnel.

**Boot integration**

- R8. When the daemon is installed as a system service, kill-switch modes survive reboot: an early-boot blocking unit applies default-deny (with DHCP/link-local carve-outs) until the daemon re-arms the full ruleset. Closes issue #250.
- R9. Profiles can be marked for boot persistence; the daemon brings them up at start. Auto-connect-on-boot (issue #16) is satisfied by this mechanism.

**Privilege separation**

- R10. With the daemon installed, interactive surfaces run unprivileged: the root daemon performs privileged operations after the existing UID gate authorizes the caller. `sudo vortix` is no longer required for daily use (issue #153).

**Optionality and installation**

- R11. Without the daemon, every surface behaves exactly as today (Local path). No feature regresses; daemon-only capabilities degrade gracefully and are discoverable (e.g., `vortix status` notes when supervision is inactive because no daemon is installed).
- R12. A first-class install/uninstall flow (`vortix service install` / `uninstall` or equivalent) manages the daemon's systemd unit / launchd plist, the early-boot unit, and clean removal. Uninstall leaves no zombie firewall rules or units.

**Compatibility**

- R13. Version skew between client and daemon is detected and fails with an actionable message (never silent mis-parse); the wire protocol carries a version marker.

---

## Acceptance Examples

- AE1. **Covers R2, R10.** Given the daemon is installed and running, when a non-root user runs `vortix up corp`, the tunnel connects without any sudo prompt and `vortix status` in a second terminal shows it supervised.
- AE2. **Covers R5.** Given a tunnel connected via CLI and no TUI running, when the tunnel's process is killed externally, the daemon detects the drop within its scan cadence, engages the kill switch per mode, and reconnects using the existing backoff policy.
- AE3. **Covers R5.** Given an OpenVPN profile with wrong credentials and auto-reconnect on, when connect fails with an auth error, retries stop after the configured attempt cap — no infinite loop.
- AE4. **Covers R7.** Given two tunnels up and supervised, when the daemon is restarted (upgrade or crash), both tunnels remain up throughout and appear re-adopted in `vortix status` within one scan cadence, with no duplicate spawn.
- AE5. **Covers R8.** Given `vpn-only` mode and a persisted profile, when the machine reboots, no non-carve-out egress succeeds at any point between boot and tunnel-up.
- AE6. **Covers R11.** Given the daemon was never installed, when the user runs any vortix command, behavior is identical to v0.4.x (sudo required, TUI-local supervision), and nothing nags about the daemon outside explicit discovery surfaces.
- AE7. **Covers R6.** Given `vortix up corp` racing from two terminals, exactly one spawn occurs; the second returns "already connected" (or waits) — no orphaned duplicate daemons.
- AE8. **Covers R13.** Given a v0.4.x client against a newer daemon socket, the command fails with a version-mismatch message naming both versions, not a hang or silent fallback that masks the mismatch.

---

## Success Criteria

- A user who installs the daemon can close every vortix UI, log out, or reboot, and their VPN posture (tunnels + kill switch) behaves exactly as if the TUI had stayed open.
- `sudo` disappears from daily vortix usage on daemon-installed machines.
- Issues #234, #250, #153, and #16 are closed by this arc; #249's tier-1 mitigations become redundant on daemon-installed machines (and remain as the no-daemon fallback).
- Downstream handoff: ce-plan can sequence this into phases without inventing product behavior — every phase's user-visible behavior is pinned by the R-IDs and AEs above.

---

## Scope Boundaries

- Windows support — the platform layer stubs remain; no daemon work targets Windows.
- Multi-user ACLs (several human users sharing one daemon) — single-user semantics only; the UID gate admits exactly the installing user (and root).
- Auto-spawn-on-demand (daemon starting implicitly when a command needs it) — deferred; installation is explicit in this arc. Revisit after real-world feedback.
- Per-tunnel OS units (the protocol-split alternative) — subsumed by the daemon; deliberately not built to avoid shipping mechanism the daemon replaces.
- New TUI panels or daemon-status UI beyond minimal discovery signals — density principle applies; supervision is signaled, not dashboarded.
- Remote administration (network-exposed daemon API) — the socket stays local-only, UID-gated.

---

## Key Decisions

- **Resident daemon over OS-native units for the end-state**: units cannot express auth-aware retry, cross-tunnel arbitration, or live ownership identity; every surveyed production VPN converged on a resident owner. Decided with time-abundance explicitly stated by the maintainer — the incremental protocol-split alternative was considered and set aside (recorded in this doc's git history and the #234 analysis).
- **Capability ladder over mandatory daemon**: the no-daemon path is preserved bit-for-bit so "single binary, works over SSH, lightweight" identity survives; the daemon is an upgrade. Cost: two code paths behind one handle, accepted.
- **Privilege separation is in-arc** (R10): it is the natural payoff of the daemon boundary and the shipped UID gate; deferring it would leave the daemon's biggest daily-life win unrealized.
- **Tunnels survive daemon death** (R7): the alternative (daemon exit tears down tunnels) makes the daemon a new single point of failure — worse than today. Adoption-on-start already exists in scanner code and becomes the recovery mechanism.
- **Early-boot blocking unit follows Mullvad's pattern** (R8): a second, earlier unit applying default-deny with DHCP/link-local carve-outs. Fail-closed risk accepted as the meaning of `vpn-only`; carve-outs keep boot recoverable.
- **WireGuard supervision is presence-only**: WG is protocol-stateless (re-handshakes on next packet); the daemon's WG duty is interface presence + kill-switch coherence, not reconnect logic. Avoids inventing supervision WG doesn't need.

---

## Dependencies / Assumptions

- The shipped IPC skeleton (UID-gated socket, framed wire protocol, `Execute`/`Snapshot` ops) is sound and extensible — verified 2026-07-18; `Subscribe` streaming and registry-over-IPC are the known unbuilt halves.
- The scanner's source-agnostic adoption (verified: `wg-quick up` from another terminal appears in the TUI ~1s) is reusable as the daemon's re-adoption mechanism (R7).
- `examples/systemd/vortix-daemon.service` and `examples/launchd/com.vortix.daemon.plist` exist and become the basis for R12's managed install.
- macOS boot integration requires a root LaunchDaemon (Tailscale/Mullvad both do this); no lighter macOS mechanism exists for root, logout-surviving supervision.
- Assumption: single-user machines dominate the user base; multi-user demand is unproven (hence the ACL deferral).

---

## Outstanding Questions

### Deferred to Planning

- [Affects R3][Technical] Whether the TUI's Remote path replaces its scanner entirely or keeps a local scanner as a cross-check in v1 (drift detection vs simplicity).
- [Affects R4][Technical] Event-stream transport shape on the existing framed socket (long-lived subscribe connection vs poll-with-cursor), and backpressure policy for slow TUI consumers.
- [Affects R8][Needs research] Exact early-boot ordering on both init systems (`Before=network-pre.target` semantics; launchd equivalent) and the minimal carve-out set that keeps DHCP/NDP working on both platforms.
- [Affects R12][Technical] Install-flow UX for macOS's privileged plist placement (prompt shape, uninstall verification).
- [Affects R13][Technical] Where the version marker lives (frame header vs hello op) given the current wire format.
