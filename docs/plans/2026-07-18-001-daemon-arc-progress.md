# Daemon-tunnel-ownership arc — progress & resume notes

Companion to `docs/plans/2026-07-18-001-feat-daemon-tunnel-ownership-plan.md`
(the decision artifact — do **not** edit its body; state lives here + in git).

**Last updated:** 2026-07-18 (session 2, cont.)

## Where it lives

- **PR:** #251 — `feat(daemon): tunnel-ownership arc — U1-U6 phased as commits`
- **Branch:** `origin/feat/daemon-u1-remote-handle` (PR head). The local
  mirror `tmp-daemon-arc` is identical to it. **The local branch
  `feat/daemon-u1-remote-handle` is STALE** (ahead 2 / behind 12) — ignore it.
- **HEAD:** `d667ea3` — U1–U3 complete + U4 core (adoption, boot, headless
  auto-reconnect, event streaming, R7 startup adoption). The daemon owns
  tunnels, serves multi-tunnel state, streams events, and executes writes
  no-sudo. Remaining: TUI cutover, kill-switch-on-drop, U5 boot, U6 closure.
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
