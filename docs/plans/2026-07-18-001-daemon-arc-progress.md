# Daemon-tunnel-ownership arc — progress & resume notes

Companion to `docs/plans/2026-07-18-001-feat-daemon-tunnel-ownership-plan.md`
(the decision artifact — do **not** edit its body; state lives here + in git).

**Last updated:** 2026-07-18 (session 2)

## Where it lives

- **PR:** #251 — `feat(daemon): tunnel-ownership arc — U1-U6 phased as commits`
- **Branch:** `origin/feat/daemon-u1-remote-handle` (PR head). The local
  mirror `tmp-daemon-arc` is identical to it. **The local branch
  `feat/daemon-u1-remote-handle` is STALE** (ahead 2 / behind 12) — ignore it.
- **HEAD:** `d220ba5` — registry now served AND consumed end-to-end
  (`vortix status` renders multi-tunnel state from a live daemon).
- **Do NOT merge** until the already-shipped fixes are released. User decision:
  release existing work first, daemon PRs merge after. (Independent of PR #252,
  the release-notes workflow.)

## Delivery shape (user's explicit choice)

One PR, commit-wise phases (not 6 separate PRs). Each commit leaves the tree
green. Comprehensive **live testing is deferred to the very end** — user runs
the flow list (bottom of this doc); we don't stop mid-arc to live-test.

Resequence already applied (see plan's resequence note): **U4 folded into U2.**
A real RegistrySnapshot requires the daemon to *own* registry + supervision, so
U2 now carries U4's body, delivered as sub-commits (a)–(g). U3/U5/U6 unchanged.

## Done (commits `3d1a507` → `60edbdd`)

| Commit | Unit | What shipped |
|---|---|---|
| `3d1a507` | docs | brainstorm + phased plan committed as first commit |
| `508d04a` | U1 | protocol version handshake + `EngineHandle::Remote` read path (`snapshot_remote`); `vortix status` sources primary FSM via Remote; **version mismatch = loud typed error naming both versions; socket absent = silent Local fallback** |
| `e9ef11e` | — | merge main (v0.4.3) into arc |
| `1c5289b` | U2a | concurrent accept loop — per-client `tokio::spawn` (was serial) |
| `e38baf3` | docs | record U2+U4 merge in plan |
| `69cc913` | U2b | `RegistryHandle` async actor wrapping `TunnelRegistry` |
| `4dc0e58` | — | clippy: silence `needless_pass_by_value` on owner loop |
| `e955367` | U2c prep | extract pure `backoff_delay_secs` + `has_retry_budget` (`state/retry.rs`) |
| `1c2daf7` | U2c | extract pure `classify()` reconcile decision table (`engine/reconcile.rs`) |
| `50726b1` | U2d | `RegistryHandle::apply()` generic mutation channel |
| `d3dcdde` | U2e | supervisor `reconcile_tick()` pure fn — headless drop detection (`daemon/supervisor.rs`) |
| `60edbdd` | U2f | serve `IpcOp::RegistrySnapshot` over IPC (**server side only**) |
| `a437b9f` | U2 | `RemoteHandle::registry_snapshot_remote()` — client consumer |
| `c53b5f8` | U2 | supervisor adopts kernel sessions absent from the registry (`set_connected` + placeholder engine); `ScannerView`→`ScannedSession`, `reconcile_tick`→`ReconcileOutcome{dropped,adopted}` |
| `a2ccca5` | U2 | daemon boot spawns a `RegistryHandle` + `run_supervisor` loop (2s cadence) + `with_registry_handle`; `IpcOp::RegistrySnapshot` now serves live state |
| `ba4bb4b` | U2 | `vortix status` renders multi-tunnel from the registry (JSON `connections[]`/`primary`), scanner counters overlaid on primary; 3-tier fallback registry→single-FSM→scanner; no-daemon path unchanged |
| `d220ba5` | — | rustdoc link fix |

Full CI parity set green on this branch as of 2026-07-18 session 2 (fmt,
check, clippy --workspace --all-targets, test --workspace, rustdoc, all 4
xtask leak checks). macOS host caveat: the Linux SO_PEERCRED block in
`server.rs` isn't compiled locally — untouched by these commits; watch the
Linux CI leg. End-to-end smoke: `vortix status --json` routes through a
live daemon's registry (empty when no VPN up; multi-tunnel is live-test #2).

## Remaining — in dependency order

### Still inside the merged U2/U4 phase

1. **RegistrySnapshot client consumer + multi-tunnel `status`.**
   **DONE** (`a437b9f` consumer, `ba4bb4b` status render). Also DONE this
   session: supervisor **adoption** (`c53b5f8`) + **boot wiring** (`a2ccca5`)
   — the daemon now owns a registry populated by a 2s supervisor loop and
   serves it, so `vortix status` shows live multi-tunnel state. Discovery that
   drove the ordering: the daemon's connects flow through a single FSM, so
   without adoption the registry stayed empty and the whole path was a no-op.

2. **Supervisor drop follow-up (kill-switch + retry).** `reconcile_tick`
   detects drops and returns them, and `run_supervisor` logs them — but the
   kill-switch arming and auto-reconnect scheduling for a dropped tunnel are
   not wired yet. **Characterization-first** for the retry ladder: capture
   today's TUI retry behavior (attempt counts, delays via `backoff_delay_secs`,
   auth-failure stop via `has_retry_budget`) in tests before re-homing the
   driver out of `app/update.rs` (AE3 parity proven, not assumed). Also fold in
   `RefreshConnected` detail-resync for existing Connected entries (currently a
   no-op arm in `reconcile_tick`).

3. **Restart adoption at startup (R7).** The supervisor adopts on its *periodic*
   tick, so restart-survivors get picked up within one cadence (~2s). For the
   R7 guarantee (present in the *first* snapshot, zero connect commands), run
   one adoption pass in `daemon/mod.rs`/boot *before* serving. Test: restart
   with 2 adopted sessions → both in first snapshot, zero connects.

4. **Subscribe event streaming.** Currently a stub on both ends:
   - Server: `daemon/server.rs:316-319` — Subscribe is acked synchronously;
     the streaming half is unbuilt. Turn the ack into a long-lived push loop.
     Event source candidate = the journal broadcast channel
     (`vortix_core/journal/`); **verify at execution** whether it carries
     engine events or the registry needs its own notify hook. Backpressure:
     state transitions never dropped (coalesce latest per tunnel); telemetry
     ticks drop-oldest.
   - Client: `EngineHandle::Remote::subscribe` returns "not supported yet"
     (`handle.rs:201`). Consume the event frame stream.
   - Tests: two clients concurrently (subscriber + command client), slow
     subscriber drops telemetry not transitions, disconnect → no fd leak.

5. **TUI Remote cutover (R3).** Gate the in-process scanner/retry/netmon in
   `app/update.rs` + `app/telemetry_poll.rs` behind "no daemon present". When
   daemon present: translate subscribe events → existing `Message` variants
   (keep render handlers untouched); `app/connection.rs` TUI connect → Remote
   execute. Local path stays fully compiled for the no-daemon case. Test: TUI
   with daemon starts no local scanner thread; without daemon = today's behavior.

### U3 — CLI writes via daemon + arbitration + input hardening

- `EngineHandle::Remote::execute` is stubbed "not supported yet — lands with
  daemon-writes U3" (`handle.rs:161`). Route `up`/`down`/`reconnect`/
  `killswitch` through Remote when socket present; Local otherwise.
- Daemon executes against the registry engine under a **per-profile mutex**
  (arbitration). Client disconnect ≠ cancel; daemon-side completion is
  independent of the connection.
- **Server-side input hardening** (the plan-011 essentials ship here, not
  later): profile name/path canonicalization (reject `../` traversal, overlong
  names, non-catalog profiles), command allow-list.
- OpenVPN OTP: client collects credentials, sends in-band with the command
  (replaces SCRV1 file handoff for daemon mode); no-log guard + wipe-after-use.
- Covers **AE1** (no sudo for daemon users), **AE7** (cross-terminal race).

### U5 — Boot integration

- `vortix service install/uninstall` — generate + install systemd units /
  launchd plists (templates: `examples/systemd/vortix-daemon.service`,
  `examples/launchd/com.vortix.daemon.plist`) + the early-boot blocking unit.
- Early-boot unit = static artifact (`Before=network-pre.target`): default-deny
  + DHCP/DHCPv6/ND/link-local carve-outs from persisted kill-switch state,
  replaced by the daemon's full ruleset once it starts (Mullvad pattern).
  `Before=network-pre.target` exactness / launchd boot semantics flagged
  `[Needs research]` — resolve on a real VM/droplet per platform.
- Persisted-profile sidecar flag; daemon brings up flagged set at startup.
- Elevation = plain `sudo` on both platforms (no macOS GUI auth dialog —
  preserves works-over-SSH identity). Uninstall verifies zero leftover
  artifacts (R12 no-zombie).
- Covers **AE5**; closes **#250** (reboot kill-switch gap), **#16** (boot
  persistence).

### U6 — Hardening audit, docs, fallback parity, closure

- No-daemon **golden parity suite** across `up/down/status/reconnect/
  killswitch` — byte-parity with v0.4.x captured outputs (modulo version
  strings). This is AE6 and the standing regression guard for R11.
- Security review over the daemon boundary; README daemon section (capability
  ladder, install flow, fixed kill-switch reboot story); `docs/manual-testing/
  backlog.md` rows per phase; CHANGELOG.
- Discovery signal for missing supervision = **one status line**, not a panel
  (TUI density principle). Renders only when daemon absent AND a state exists
  it would improve.
- Close **#234, #250, #153, #16** with evidence links; retire superseded
  plan-010 pointer.

## Constraints & gotchas (carry every session)

- **Build:** `CARGO_TARGET_DIR=/tmp/vortix-build cargo ...` — repo `target/`
  has root-owned files from earlier `sudo cargo run`.
- **Before every push:** full CI parity set per `docs/ci-parity.md` (fmt --all
  --check, check, clippy --workspace --all-targets -D warnings, test --workspace,
  RUSTDOCFLAGS='-D warnings' cargo doc, all 4 xtask leak checks). "Passes
  locally" = full command output, not a claim.
- **Architectural boundaries** enforced by `cargo xtask check-*-leak`:
  `vortix_core` imports nothing platform/protocol/process; protocol subprocess
  calls only in `vortix_protocol_*`. Daemon code lives in the binary crate.
- **macOS host can't validate Linux-cfg paths** (`vortix_platform_linux/*`,
  SO_PEERCRED block) — those need the droplet.
- **No `connection_state` field on `VpnRuntime`** — multi-tunnel reads go
  through registry snapshots; single-tunnel-shaped reads via `App::legacy_state()`.
- **Kill-switch vocabulary:** slug everywhere (`off`/`block-on-drop`/`vpn-only`),
  route through `vortix_core::state::killswitch` helpers, never hardcode strings.
- Version-skew rule (U1, keep intact): **socket absent = silent Local fallback;
  socket speaks wrong version = loud typed error naming both.** The distinction
  matters — a silent fallback on version mismatch would mask real bugs.

## Live-test flow list (run at the very end, on the droplet)

Maps to acceptance examples. Infra: `scripts/test-infra.sh` (DigitalOcean;
flavors wg-full/wg-split/wg-v6/ovpn-cert/etc.). Do not commit per-droplet TOTP
secrets.

1. **AE8 version skew:** client with protocol version N+1 vs daemon N → loud
   error naming both versions, non-zero exit, no scanner fallback.
2. **Multi-client (U2):** TUI open + `vortix status` simultaneously against one
   daemon → no serialization deadlock; both see identical multi-tunnel state.
3. **AE1 no-sudo (U3):** non-root `vortix up <profile>` via installed daemon
   connects, no privilege error.
4. **AE7 arbitration (U3):** two concurrent `vortix up <same profile>` from two
   terminals → one spawn, second gets already-connected/queued (the #249 race,
   now centrally arbitrated).
5. **AE2 headless reconnect (U4):** connect via CLI, close all clients, `kill`
   the openvpn process → tunnel returns within retry policy, kill-switch fired
   on the gap.
6. **AE3 retry cap (U4):** force an auth failure → retries stop at configured
   cap, final state Failed, journaled.
7. **AE4 restart survival (U4):** restart the daemon mid-session → `wg show` /
   status unchanged, zero reconnect commands issued; TUI re-attach shows
   continuity without rescan flicker.
8. **AE5 reboot leak window (U5):** reboot with vpn-only armed + a persisted
   profile → timestamped `curl` probes fail from earliest SSH-reachable moment
   until tunnel-up; DHCP renews fine. Then `service uninstall` → verify zero
   leftover units/rulesets.
9. **AE6 fallback parity (U6):** with no socket, `up/down/status/reconnect/
   killswitch` byte-identical to v0.4.x.

## How to resume

```
git checkout tmp-daemon-arc              # == origin/feat/daemon-u1-remote-handle
git log --oneline origin/main..HEAD      # confirm HEAD is 60edbdd (U2f) or later
```
Pick up at **Remaining item 1** (RegistrySnapshot client consumer), then work
down the list. Commit each sub-phase green; push to
`origin/feat/daemon-u1-remote-handle` (PR #251). Full CI parity before each push.
