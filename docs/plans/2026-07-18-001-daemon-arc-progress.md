# Daemon-tunnel-ownership arc — progress & resume notes

Companion to `docs/plans/2026-07-19-001-feat-daemon-single-source-of-truth-plan.md`
(the current decision artifact — supersedes the 2026-07-18 phased plan — do **not** edit its body; state lives here + in git).

**Last updated:** 2026-07-19 session 2 (P4 TUI cutover built; live validation next)

## North Star re-architecture (active plan: `2026-07-19-001-...-single-source-of-truth-plan.md`)

Goal: daemon owns ALL state (a registry of per-profile engines) = single
source of truth; CLI/TUI/GUI are thin clients; always in sync; persistent.
Four scenarios (S1 persistence-across-exit, S2 instant attach, S3 bidirectional
sync, S4 many-clients-one-state) are the acceptance tests.

**DONE — P1 (daemon owns per-profile engines) + P2 (owner auth):**
- `39354d2` RegistryHandle per-profile `connect`/`disconnect`/`reconnect` commands.
- `6edb262` daemon IPC dispatch routes Execute + Snapshot through the registry;
  shared single FSM retired (kept only as Subscribe's journal source). F1–F4
  bug class gone by construction.
- `811ebb7` supervisor auto-reconnect drives `registry.connect` (recovered
  tunnels become real, drivable entries).
- `dcf4315` owner-based auth: gate accepts owner uid (VORTIX_OWNER_UID/SUDO_UID),
  socket chowned to owner → root daemon serves its unprivileged owner (no-sudo).

**DONE — P4 TUI Remote cutover (task #21), built 2026-07-19:**
- **Pure mirror:** `TunnelRegistry::apply_remote_snapshot(snapshot, keep_local,
  engine_factory)` (registry.rs) upserts wire tunnels via the new
  `Engine::seed_state` (verbatim `Connection`, incl. Reconnecting/health),
  drops daemon-unknown entries, takes wire `primary` + killswitch state
  verbatim (NO local recompute — client route cache is unfed in remote mode),
  recovers `allowed_ips` from the wire `Role`. 5 unit tests.
- **Bootstrap:** `main.rs::probe_daemon()` — one blocking `RegistrySnapshot`
  probe before the event loop. Attach + first-frame daemon state on success
  (S2); attach-deferred on Timeout (daemon busy mid-connect — its registry
  actor is serial); **loud eyre exit on VersionMismatch (AE8)**; silent local
  fallback otherwise (R11). Attached → `EngineHandle::Remote` set, local
  engine-handle/journal-nudge block skipped.
- **Scanner swap:** `App.daemon: Option<DaemonLink>` (`app/daemon_link.rs`
  — existence = attached; bundles socket, spawn-on-demand poll slot,
  in-flight write markers, deferred auth cleanup, staleness counter; detach
  = drop). `handle_tick` runs `poll_daemon_state()` instead of
  `poll_scanner()` when attached. `Message::SyncDaemonState` →
  `handle_sync_daemon_state` mirrors into `app.registry` + feeds the real-IP
  gate fields. Poll errors: Timeout=keep last state + staleness warning
  after 5 consecutive (wedged-daemon signal, recovery logged);
  VersionMismatch=loud toast+detach; else detach with toast → local pipeline
  resumes next tick and re-adopts kernel tunnels. Connect-timeout safeguard
  is local-only now.
- **Writes:** `spawn_daemon_execute` worker → `Message::DaemonCommandResult`
  with typed `DaemonWriteStatus` (Completed/Failed/**TimedOut** — timeout =
  "may still be working", never Failed; matches the CLI's Execute-timeout
  contract). `connect_profile_inner` (root check skipped when attached; 2FA
  static-challenge refused with toast, as in the CLI; conflict overlay gate
  stays client-side — the daemon Executes Connect with force=true),
  `disconnect_specific`/`force_disconnect`/`cancel_connect` route
  Disconnect/ForceDisconnect. In-flight markers (70s expiry > 60s Execute
  timeout) pin the optimistic ◐/◑ badge against poll overwrites. One-time
  OpenVPN auth files are deleted only after the daemon write concludes
  (deferred via `DaemonLink`, Drop-safe) — an immediate delete starved the
  daemon's openvpn of credentials.
- **Kill switch in attached mode (interim honesty rule until P6):** nothing
  enforces it while attached — the scanner's drop-handler is parked and the
  daemon has no firewall logic yet. So `attach_daemon` disarms a persisted
  Armed state (with log+toast), `sync_killswitch` early-returns, and the `k`
  toggle refuses with a pointer. Header/Security read `runtime.killswitch_*`
  and honestly render KS:Off. P6 moves ownership daemon-side and reverses
  this.
- **Adversarial review (2 workflow passes, 4 lenses):** confirmed findings
  all fixed in-tree — Execute-timeout collapse (→ typed TimedOut), attached
  kill-switch misrepresentation (→ honesty rule above), one-time-credential
  starvation (→ deferred cleanup), silent stale state under a wedged daemon
  (→ staleness warning).
- Delivers **S2/S3/S4** pending live validation (backlog rows 102–105).
  Deferred within P4 scope: subscribe-push (poll-per-tick is sufficient at
  TUI tick cadence; streaming stays loopback-tested), live re-attach after a
  detach (restart the TUI), in-band 2FA.

**NEXT (resume here):** live-validate P4 (backlog rows 102–105 + flow list
below) → P5 boot service (#22 — also fixes the cross-uid socket PATH agreement
P2 flagged: a canonical system socket path both daemon + client use) → P6
closure (#23). Known P1 follow-up: externally-adopted tunnels get a placeholder
engine (daemon-`down` on one is a no-op) until adoption seeds a real
protocol-correct engine. See the plan for full detail.

## Code review (2026-07-19)

Five independent reviewers (correctness, security, adversarial, reliability,
testing) audited the arc. Headline finding: the U4 auto-reconnect was a
false-success no-op (drove reconnects through the shared single-tunnel FSM,
which never hears about drops → `Connect` no-op'd → verified against its own
stale snapshot). All correctly-raised findings are now fixed (commits
`f5513da`→`0d484de`):

- **F1/F2** auto-reconnect now uses a fresh per-profile engine + scanner-
  confirmed success; multi-tunnel-independent.
- **F3/F4** daemon `up`/`down`/`reconnect` report honestly (profile-matched
  success; `down` re-scans and reports only what actually went away).
- **Security P1** client refuses a foreign-owned socket (fake-daemon spoof).
- **Reliability** Execute-timeout no longer double-connects; subscribe idle
  leak reaped via heartbeat; accept idle timeout; SIGTERM graceful shutdown +
  socket cleanup; `MissedTickBehavior::Skip`; bounded scan.
- **Tests** supervisor scheduling (pure) + no-daemon `down` idempotency.

**Still architecturally deferred (per-profile "registry of engines"):**
genuinely *targeting* an arbitrary tunnel for daemon-routed `down B`/`up B`
in a multi-tunnel session (the single FSM can't); today those report honest
failure instead of acting on the wrong tunnel. Kill-switch-on-drop and the
TUI cutover remain (need live iteration).

## Where it lives

- **PR:** #251 — `feat(daemon): tunnel-ownership arc — U1-U6 phased as commits`
- **Branch:** `origin/feat/daemon-u1-remote-handle` (PR head). The local
  mirror `tmp-daemon-arc` is identical to it. **The local branch
  `feat/daemon-u1-remote-handle` is STALE** (ahead 2 / behind 12) — ignore it.
- **HEAD:** `0d484de` — U1–U3 complete + U4 core + **all code-review fixes**
  (see the review section below). The daemon owns tunnels, serves multi-tunnel
  state, streams events, executes writes no-sudo, and auto-reconnects
  correctly. Remaining: TUI cutover, kill-switch-on-drop, per-profile targeted
  writes, U5 boot, U6 closure.
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
| `17ee6e8` | U3 | client-side `execute_remote` + op-aware transport timeout (60s for Execute); `EngineHandle::Remote::execute` routes user commands |
| `c402cbb` | U3 | CLI `up`/`down`/`reconnect` route through the daemon when present (no sudo); connect verifies resulting state (no false "connected"); lifecycle lock moved to local path only; 2FA connects refused on daemon path |
| `68e86ab` | U3 | daemon-boundary profile-id validation (reject `..`, separators, overlong, empty) — R10 hardening |
| `9d04838` | — | rustdoc pub→private link fix |
| `15e98a5` | U4 | headless auto-reconnect in the supervisor (`reconnect_delay_for_attempt` + `run_supervisor`/`drive_due_reconnects`); retry ladder re-homed, characterization-tested (AE2/AE3) |
| `e814e49` | U2 | **Subscribe event streaming** — server push loop (`stream_events`) + client reader thread (`UnixTransport::subscribe`) + `IpcResult::Event`; two loopback tests |
| `d667ea3` | U4 | adopt running tunnels once before serving (R7 first-snapshot guarantee) |

Full CI parity set green on this branch as of 2026-07-18 session 2 (fmt,
check, clippy --workspace --all-targets, test --workspace, rustdoc, all 4
xtask leak checks). macOS host caveat: the Linux SO_PEERCRED block in
`server.rs` isn't compiled locally — untouched by these commits; watch the
Linux CI leg. End-to-end smoke: `vortix status --json` routes through a
live daemon's registry (empty when no VPN up; multi-tunnel is live-test #2).

## DONE this session (U1–U3 + U4 core)

- **U1** version handshake + Remote read + `status` via Remote.
- **U2** full: concurrent accept loop, `RegistryHandle` actor, adoption, boot
  wiring, multi-tunnel `status`, and **Subscribe event streaming** (server push
  + client reader thread, two loopback tests).
- **U3** full: client `execute` + CLI `up`/`down`/`reconnect` routed through the
  daemon **no-sudo** (connect verifies resulting state; lifecycle lock local-path
  only), and daemon-boundary **profile-id validation** (R10). 2FA connects are
  refused on the daemon path (in-band OTP delivery deferred). Covers AE1; AE7
  (central serialization via the single engine actor) is live-verified.
- **U4 core**: headless **auto-reconnect** (retry ladder re-homed, AE2/AE3
  characterization-tested) + **R7 startup adoption** (first-snapshot survival).

## Remaining

1. **Kill-switch on drop** (part of U4). On a `was_connected` drop the
   supervisor should engage the kill switch per mode. Needs the daemon to load
   kill-switch **mode** config + apply **root firewall** rules
   (`core::killswitch::enable_blocking_multi`). Best validated live (firewall
   effects are only observable as root on a real host) — build + live-test
   together.

2. **TUI Remote cutover (R3).** Gate the in-process scanner/retry/netmon in
   `app/update.rs` + `app/telemetry_poll.rs` behind "no daemon present"; when a
   daemon is up, translate `subscribe_remote` events → existing `Message`
   variants and route `app/connection.rs` connects through Remote. **Highest
   regression risk of anything left**: it changes the live TUI message loop, and
   its correctness (does the attached TUI render smoothly? does the no-daemon
   default path stay intact?) is only verifiable by running the actual terminal
   UI — not by unit tests. **Do this with live TUI iteration, not blind.** The
   streaming + registry it consumes are already built and loopback-tested, so
   live-validating those first (flows #2, #5–#7) de-risks it.

3. **U5 — Boot integration.** `vortix service install/uninstall` generating
   systemd units / launchd plists + the early-boot blocking unit; persisted-
   profile flag. Unit/plist generation is unit-testable (golden strings), but
   the *value* (does it start at boot? does the early-boot firewall close the
   leak window?) is purely live (AE5, reboot on a droplet). Details below.

4. **U6 — Closure.** No-daemon golden parity suite (AE6/R11 — guards the default
   path my U3 changes touched; the existing workspace test suite currently
   passes, so no regression is known), README daemon section, manual-testing
   backlog rows, CHANGELOG, close #234/#250/#153/#16. Best written after live
   validation confirms the described behavior.

### U5 — Boot integration (detail)

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
