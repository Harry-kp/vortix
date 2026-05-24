---
date: 2026-05-24
topic: engine-fsm-event-journal-and-handle
---

# Engine FSM + Event Journal + `EngineHandle` (Phase A of Daemon-First)

## Summary

Two architectural moves in one bundled PR scope:

1. **Engine FSM + Event Journal (idea 3 of 7).** Replace today's ad-hoc state mutation in `src/engine/connection.rs` with an explicit 5-state finite-state machine on `Connection` (`Disconnected`, `Connecting`, `Connected { health }`, `Reconnecting`, `Disconnecting`) whose transitions emit typed `EngineEvent` values into a per-session JSONL journal at `~/.local/share/vortix/sessions/<ISO-timestamp>-<pid>.jsonl` and broadcast them in-memory to live subscribers. The FSM is `async` and consumes `CommandRunner` (idea 1) for all I/O, making the connection lifecycle fully unit-testable in CI without root or real `wg`/`openvpn`. This delivers v0.1.7's "Dependable" promises — retry cap, rename-safe reconnect, deduped "IP unchanged" warnings, accurate quality indicator.

2. **`EngineHandle` and App-as-View (Phase A of idea 4 of 7).** Decouple `App` from `VpnEngine` by introducing a typed `EngineHandle` — a clone-able Command/Query/Subscribe API consumed by every surface (CLI today, TUI today, future daemon, future Tauri/MCP/system-tray). `App: Deref<Target = VpnEngine>` goes away; every callsite (`app.profiles`, `app.connection_state`, etc.) switches to handle-mediated access. The handle is implemented as an in-process tokio actor wrapping the FSM; it's an `enum EngineHandle { Local(LocalHandle) }` today, designed so a `Remote(RemoteHandle)` variant lands cleanly later. **No daemon process ships here** — Phase B (the actual `vortixd`, IPC transport, install story) is a separate later brainstorm.

The two moves are bundled because the FSM's broadcast channel IS the handle's subscription mechanism; splitting them would mean shipping the FSM with a temporary access pattern that the handle then replaces.

---

## Problem Frame

vortix's current connection lifecycle lives at `src/engine/connection.rs` (669 lines) and `src/engine/mod.rs` (525 lines), with state recorded in a 4-variant enum at `src/state/connection.rs`: `Disconnected`, `Connecting { started, profile: String }`, `Connected { since, profile: String, server_location, latency_ms, details }`, `Disconnecting { started, profile: String }`. State transitions happen via direct field assignment inside the engine, sometimes corrected by the scanner module (`src/core/scanner.rs`) which "is the source of truth and will override Connecting/Disconnecting states based on actual system state" per its own source comment.

Four named pains compound on this shape.

**Failure modes have no explicit place to live.** When `wg-quick up` fails, the engine drops back to `Disconnected` with no record of what failed. v0.1.7's ROADMAP promise of a "bulletproof state machine" — retry cap, blocked deletion during connecting, clear reconnect semantics — cannot land without first making failure a first-class state with a reason payload. Today the failure path is a sequence of side effects (log a message, set state to Disconnected, fire-and-forget).

**Profile identity is the filename.** `ConnectionState::Connecting { profile: String }` stores the user-visible profile name. If the user renames `corp.conf` while the connection is reconnecting, the engine looks up the wrong profile or fails entirely. v0.1.7's "rename-safe reconnect" promise depends on a stable identifier, but the current state shape doesn't have one. The WireGuard public key is already captured (in `DetailedConnectionInfo.public_key`) but the FSM doesn't use it as the identity key.

**Telemetry and state are entangled.** The 30-second "IP unchanged" warning that fires 120 times per hour ships through the same path as state transitions. There is no separate event bus where a subscriber could say "dedupe these warnings once per session." Audit logging, lifecycle hooks (v0.3.0), and the JSON envelope's `next_actions` field all need to react to engine events, but there is no event stream — only mutation-by-side-effect.

**Tests can only exercise this code on the maintainer's laptop.** Connection flows require real `wg`, real root, real network. CI cannot reach them. The retry-cap fix, the rename-safe-reconnect fix, the warning-dedup fix — all of v0.1.7's promises — live in code paths that no test in `app/tests.rs` exercises. Until I/O is mockable (idea 1's `CommandRunner`) AND the FSM is deterministic in response to mocked I/O, the test coverage gap is structural, not effort-bound.

The compounding cost is the v0.1.7 release itself: "Dependable" is the milestone that earns user trust ("a user can connect in the morning, work all day, and trust that Vortix is accurately monitoring their connection"). Without this refactor, v0.1.7 ships as a sequence of in-place patches to the ad-hoc state machine — patches that are themselves untestable and that the next regression can silently break. With this refactor, v0.1.7's promises become typed transitions with named test scenarios.

---

## Actors

- A1. **End user starting a VPN connection** — types `vortix up corp`, expects either a fast success or a fast clear failure (not a 30-minute zombie retry).
- A2. **End user with flaky Wi-Fi** — wants the connection to auto-recover when Wi-Fi comes back; doesn't want to manually reconnect every café switch.
- A3. **End user diagnosing a failed connection** — wants to attach a structured log to a bug report, not paste 500 lines of `vortix` stdout.
- A4. **Contributor writing a test for a connection regression** — wants to write a unit test that exercises a state transition without setting up real WireGuard.
- A5. **TUI** — subscribes to FSM events to repaint the connection panel, quality indicator, and activity log without polling engine state every frame.
- A6. **Future audit log subscriber (v1.0)** — subscribes to a filtered subset of `EngineEvent`s and persists them with stronger durability guarantees than the broadcast channel offers.
- A7. **Future lifecycle hooks subscriber (v0.3.0)** — subscribes to specific events (`TunnelUp`, `TunnelDown`, `IpChanged`) and runs user-defined scripts.
- A8. **Future daemon `vortixd` (Phase B of idea 4 — deferred)** — owns the FSM instance, owns the broadcast sender, and re-publishes events to remote clients over the IPC channel. Out of scope for this PR; consumes the `EngineHandle` trait designed here.
- A9. **Future embedding consumer** — a Tauri wrapper, MCP server, system tray app, or Raycast extension. Constructs an `EngineHandle::Local` against `vortix-core` directly. Phase A's typed Command/Query/Subscribe API is the embedding surface.

---

## Key Flows

- F1. **Connect on flaky Wi-Fi with auto-reconnect**
  - **Trigger:** User runs `vortix up corp` from a café. WireGuard handshake succeeds. 90 seconds later, Wi-Fi drops.
  - **Actors:** A2, A5
  - **Steps:**
    1. FSM transitions `Disconnected → Connecting → Connected { health: Unknown }`. Initial event: `TunnelUp`.
    2. Telemetry tick measures latency; FSM transitions to `Connected { health: Healthy }`. Event: `ConnectionHealthChanged { from: Unknown, to: Healthy }`.
    3. Wi-Fi drops. Network monitor detects link change, emits `NetworkLinkLost`. FSM transitions `Connected → Reconnecting { attempt: 1, started_at, deadline }`. Event: `HandshakeStale` precedes if applicable.
    4. FSM invokes `Tunnel::up` again via CommandRunner. Wait, exponential backoff, retry.
    5. Wi-Fi returns within retry budget. Handshake succeeds. FSM transitions `Reconnecting → Connected { health: Unknown }`. Events: `TunnelUp`, then later `ConnectionHealthChanged` once telemetry catches up.
  - **Outcome:** User experiences a brief "Reconnecting…" indicator and a successful recovery without manual intervention. The journal captures every transition.
  - **Covered by:** R1, R2, R5, R6, R8, R12

- F2. **Connect failure with retry cap exhausted**
  - **Trigger:** User runs `vortix up corp` but the WireGuard endpoint is unreachable (corporate gateway down).
  - **Actors:** A1, A5
  - **Steps:**
    1. FSM transitions `Disconnected → Connecting`. Event: `ConnectAttemptStarted { profile_id }`.
    2. `Tunnel::up` returns `Err(HandshakeTimeout)`. FSM stays in `Connecting`, increments attempt counter, fires `RetryScheduled { attempt, backoff_ms }`. Backoff doubles on each retry, capped by remaining budget.
    3. After 5 minutes of wall-clock with no successful handshake, FSM transitions `Connecting → Disconnected { last_failure: Some(RetryBudgetExhausted { attempts, elapsed_secs }) }`. Event: `RetryBudgetExhausted` + `ConnectAttemptFailed`.
    4. CLI's JSON envelope `next_actions` is populated from `last_failure`: `[{"action": "check_endpoint_reachability"}, {"action": "view_session_journal", "path": "<journal-path>"}]`. Exit code is the semantic "connection failed" code.
  - **Outcome:** User sees a clear failure within 5 minutes (not 30). Both the human-readable error and the structured `next_actions` point at the journal.
  - **Covered by:** R1, R2, R7, R8, R9, R13

- F3. **Contributor writes a test for retry-budget exhaustion**
  - **Trigger:** Contributor adds `engine::tests::retry_budget_exhausts_after_5_minutes`.
  - **Actors:** A4
  - **Steps:**
    1. Test constructs a `MockRunner` that scripts `wg-quick up <iface>` to always return exit 1 with stderr `"timeout"`.
    2. Test constructs an `Engine` with the mock runner, a mock clock (`tokio::time::pause`), a default retry-budget config.
    3. Test advances mock clock past 5 minutes while feeding `Tick` inputs to the FSM.
    4. Test asserts the FSM is now in `Disconnected { last_failure: Some(RetryBudgetExhausted { .. }) }` and the journal contains `RetryBudgetExhausted` as its last event.
  - **Outcome:** Test runs in CI in under 100ms (real time), no root, no `wg`, no network.
  - **Covered by:** R10, R11

- F4. **Profile renamed mid-reconnect**
  - **Trigger:** User connects to `corp.conf`. Wi-Fi drops. While `Reconnecting`, the user (or the file system) renames `corp.conf` to `work-vpn.conf`.
  - **Actors:** A1, A5
  - **Steps:**
    1. FSM is in `Reconnecting { profile_id: <wg_pubkey_hash>, .. }`.
    2. Profile store fires `ProfileRenamed { id, old_name, new_name }`. FSM is identified by `profile_id` (the WG public key hash), not by name.
    3. Reconnect continues. FSM updates its cached `display_name` for UI purposes but does not change identity.
    4. Reconnect succeeds. Event: `TunnelUp { profile_id, display_name: "work-vpn" }`.
  - **Outcome:** Rename does not interrupt the reconnect; the new name surfaces in the TUI on the next repaint.
  - **Covered by:** R3, R4

---

## Requirements

**State enumeration**

- R1. `Connection` is modeled as a tagged enum with exactly five states: `Disconnected { last_failure: Option<FailureReason> }`, `Connecting { profile_id, started_at, attempt, retry_budget_remaining }`, `Connected { profile_id, since, health: ConnectionHealth, details: DetailedConnectionInfo }`, `Reconnecting { profile_id, started_at, attempt, retry_budget_remaining, last_error }`, `Disconnecting { profile_id, started_at }`. The existing `DetailedConnectionInfo` type is preserved (no field-by-field churn beyond the addition of `profile_id`).
- R2. `ConnectionHealth` is a separate three-variant enum: `Healthy`, `Degraded { reason: DegradedReason }`, `Unknown`. `Unknown` is the default at transition into `Connected` and replaces today's "EXCELLENT with no data" misindication — it surfaces in the TUI as "Measuring…" per v0.1.7's first promise.
- R3. `profile_id` is the **stable identifier**, distinct from the user-visible `display_name`. For WireGuard tunnels, it's the SHA-256 hash of the WG public key (already captured in `DetailedConnectionInfo.public_key`). For OpenVPN / IKEv2 tunnels (future), the corresponding `Tunnel` impl supplies a protocol-appropriate stable string. The FSM never branches on `display_name` for control flow.
- R4. The state machine survives profile renames: when the profile store fires `ProfileRenamed { id, old, new }`, FSM updates only its cached `display_name`; `profile_id` is unchanged; in-flight reconnects continue.

**Transition function and effects**

- R5. The FSM is implemented as `impl Engine { async fn handle(&mut self, input: Input) -> Vec<EngineEvent> }`. Inputs are: `UserCommand { Connect, Disconnect, Reconnect }`, `Tick`, `NetworkLinkChanged`, `TelemetryReport`, `ProfileChanged`, `TunnelStatusObserved`. Transitions may `.await` on `CommandRunner`, `Platform` capability ports, and `Tunnel` adapters — these are dependency-injected at construction.
- R6. The transition function is **interleaved async**, not Elm-style effects-as-data. Determinism for tests comes from `MockRunner` (idea 1) and `tokio::time::pause()`, not from a returned `Vec<Action>` list. Effects-as-data decomposition is reserved for idea 10/25's Plan/Apply work.
- R7. Every transition emits one or more `EngineEvent`s. The complete day-one event set includes (non-exhaustive — `#[non_exhaustive]` enum): `ConnectAttemptStarted`, `ConnectAttemptFailed`, `TunnelUp`, `TunnelDown`, `HandshakeStale`, `ConnectionHealthChanged`, `IpChanged`, `KillswitchEngaged`, `KillswitchDisengaged`, `RetryScheduled`, `RetryBudgetExhausted`, `NetworkLinkLost`, `NetworkLinkRestored`, `ProfileRenamed`, `ProfileDeletionRequested`. Telemetry-derived metric events (`HandshakeAge`, `RxBytes`, `TxBytes`, `PingLatency`) flow on the same channel and are written to the same journal.

**Retry budget**

- R8. Retry behavior is bounded by a per-connection-attempt **wall-clock budget** with a default of 300 seconds (5 minutes). The budget is configurable via `[engine] retry_budget_secs = <n>` in the config layer (idea 7). Inside `Connecting` and `Reconnecting`, the FSM uses exponential backoff between attempts (initial backoff 2s, doubling, capped by the remaining budget).
- R9. When the budget is exhausted, the FSM transitions to `Disconnected { last_failure: Some(RetryBudgetExhausted { attempts, elapsed_secs }) }` and emits both `RetryBudgetExhausted` and `ConnectAttemptFailed`. The CLI's JSON envelope serializes the failure reason into `next_actions`; the exit code is the semantic "connection failed" code from the existing 0-6 set.

**Event journal**

- R10. Engine events are persisted to a per-session JSONL journal at `${XDG_DATA_HOME}/vortix/sessions/<ISO-timestamp>-<pid>.jsonl` (Linux), `~/Library/Application Support/vortix/sessions/<ISO-timestamp>-<pid>.jsonl` (macOS), `%APPDATA%\vortix\sessions\<ISO-timestamp>-<pid>.jsonl` (Windows future). Path resolution goes through `directories` crate via idea 7's config layer.
- R11. Each journal record is a JSON object with at least: `schema_version: u32` (starts at 1), `timestamp: RFC3339`, `event: EngineEvent`. The wrapper is stable across `EngineEvent`'s `#[non_exhaustive]` evolution.
- R12. The journal is **per-session** — one file per `Engine` instance (a single `vortix up` invocation or a single daemon run). On startup, a retention pass deletes session files older than 30 days OR beyond the most recent 30 files (whichever pruning is more conservative). Retention is configurable: `[journal] retention_days = 30`, `[journal] retention_count = 30`.
- R13. The journal writer is **non-lossy** — it runs as a dedicated `tokio` task draining an unbounded mpsc channel from the FSM. The journal channel does not drop events under backpressure; the broadcast channel (for live subscribers like TUI) is allowed to drop for slow subscribers.
- R14. Users can opt out of disk persistence via `[journal] disk = false`. With disk persistence off, events flow only on the in-memory broadcast channel and a fixed-size ring buffer (kept for `vortix bug-report`).
- R15. `vortix bug-report` collects the current session's journal file (plus the immediately preceding session if available) and bundles it into the report. No additional logging surface needed.

**Subscriber model and backpressure**

- R16. A `tokio::sync::broadcast` channel fans events to live subscribers (TUI, telemetry-aggregator, future hooks, future daemon-IPC re-publisher). The broadcast channel has a fixed capacity (1024 events); slow subscribers receive `Lagged` errors and re-sync from the engine's current state snapshot — they are not blocked.
- R17. The journal writer subscribes via a dedicated mpsc (not broadcast), guaranteeing every event reaches disk regardless of broadcast lag.

**Scanner integration**

- R18. The existing scanner module's role (observing system state and correcting the engine) is preserved as a `TunnelStatusObserved` input to the FSM. The scanner becomes an *input source*, not a direct state mutator. The scanner-as-source-of-truth comment in `src/state/connection.rs` is replaced by: "Scanner observations are inputs to the FSM; the FSM is the source of truth."

**Telemetry boundary**

- R19. Telemetry (`src/core/telemetry.rs` today) becomes a separate periodic-tick actor that subscribes to the broadcast channel for state context and publishes its own metric events back into the channel. The FSM owns *state-change events*; telemetry owns *metric events*. Both kinds land in the same journal file.
- R20. The "IP unchanged" warning dedup happens in the telemetry actor: it tracks `last_warned_at_session_start: bool` and suppresses subsequent fires until session restart. This satisfies v0.1.7's "once per session" promise.

**Cross-cutting and integration**

- R21. The FSM types and event schema live in `vortix-core::engine` (per idea 2's workspace split). The journal writer and broadcast plumbing live in `vortix-core::journal`. Concrete I/O dependencies (`CommandRunner`, `Tunnel` adapters, `Platform` ports) are injected at engine construction.
- R22. Phase B of idea 4 (the daemon process, `vortix-daemon` crate, Unix socket / Windows named pipe transport, on-the-wire protocol, lifecycle, install-as-service question, multi-user auth, version-skew handling) is **out of scope for this PR** and will be brainstormed separately. The `EngineHandle` trait designed in R23-R30 below is intentionally shaped so a future `Remote(RemoteHandle)` variant lands as an additive change.

**EngineHandle and App-as-View (Phase A of idea 4)**

- R23. Define `enum EngineHandle { Local(LocalHandle) }` as the single public access point to engine functionality. The enum is `Clone + Send + Sync` (clones share the same underlying actor). Adding `Remote(RemoteHandle)` later is additive and requires no callsite changes outside the handle module. Dispatch is via `enum_dispatch` (or hand-coded match), mirroring idea 1's `CommandRunner` and idea 5's `TunnelKind` patterns.
- R24. The handle exposes three method classes:
  - **Commands** (mutating): `async fn execute(&self, cmd: EngineCommand) -> Result<CommandAck, EngineError>` where `EngineCommand` is a tagged enum (`Connect { profile_id }`, `Disconnect`, `Reconnect`, `ImportProfile { source }`, `DeleteProfile { profile_id }`, `RenameProfile { profile_id, new_name }`, …). The ack is acknowledgement only; effects observed via the event stream.
  - **Queries** (read-only): `async fn query(&self, q: EngineQuery) -> Result<QueryResponse, EngineError>` where `EngineQuery` is a tagged enum (`Snapshot`, `ListProfiles`, `GetProfile { profile_id }`, `JournalTail { count }`, …) and `QueryResponse` is the matching tagged response.
  - **Subscription**: `fn subscribe(&self) -> EngineSubscription` returning a struct containing the current `Snapshot` plus a `broadcast::Receiver<EngineEvent>`. Subscribers render initial state from the snapshot, then apply events.
- R25. `LocalHandle` wraps a single tokio actor (`tokio::spawn`'d task) that owns the `Engine` (the FSM from R1-R22). Clones of `LocalHandle` share the same underlying mpsc sender for commands/queries and the same `broadcast::Sender` for events.
- R26. `App` is restructured as `struct App { engine_handle: EngineHandle, tui_state: TuiState }`. The current `pub engine: VpnEngine` field is removed. `impl Deref for App` and `impl DerefMut for App` are removed. All callsites that today use `app.profiles`, `app.connection_state`, `app.fetch_telemetry()`, etc., switch to either:
  - `app.engine_handle.query(EngineQuery::Snapshot).await` for read access (rare in TUI loop — subscription is preferred), or
  - `app.engine_handle.execute(EngineCommand::Connect { … }).await` for mutation, or
  - `app.tui_state.profiles_view_snapshot` for cached view data the TUI projects from event history.
- R27. The TUI subscribes once at startup. Its main loop drains events from the broadcast receiver and applies them to `TuiState` (a TUI-only projection of engine state); rendering reads only from `TuiState`. On `Lagged` errors from the broadcast (slow TUI, per R16), the TUI re-queries `EngineQuery::Snapshot` to re-sync and resumes draining.
- R28. CLI commands construct a `LocalHandle`, execute one command or query, print the result (using the JSON envelope when `--json` is set), and exit. There is no persistent state between CLI invocations in Phase A.
- R29. `EngineHandle` is `pub` from `vortix-core` per idea 2's minimum-public-surface rule. `EngineCommand`, `EngineQuery`, `QueryResponse`, `Snapshot`, `EngineError`, and `EngineSubscription` are all `pub` — they collectively are the embedding API for future Tauri/MCP consumers.
- R30. `App::new_test()` (today) is replaced by `EngineHandle::for_test() -> EngineHandle` which constructs a `LocalHandle` over an `Engine` built with `MockRunner` (idea 1) and a test `Tunnel`/`Platform` fixture. This is the supported testing seam for both engine unit tests and TUI integration tests.

---

## Acceptance Examples

- AE1. **Covers R1, R2.** Given an `Engine` in state `Connecting { profile_id, attempt: 1, .. }`, when the tunnel becomes `Up`, then the state transitions to `Connected { profile_id, health: ConnectionHealth::Unknown, .. }` (not `Healthy` — the initial health is Unknown until telemetry measures it), and a `TunnelUp` event is emitted.

- AE2. **Covers R3, R4.** Given an `Engine` in `Reconnecting { profile_id: H1, display_name: "corp" }` where `H1` is the SHA-256 hash of the active WireGuard public key, when a `ProfileRenamed { id: H1, old: "corp", new: "work" }` input is delivered, then the state's `display_name` updates to `"work"` and `profile_id` is unchanged, and the in-flight reconnect attempt continues without restart.

- AE3. **Covers R5, R6.** When a unit test constructs an `Engine` with a `MockRunner` scripting `wg-quick up <any>` to return exit 0 with valid stdout, and the test feeds `UserCommand::Connect { profile_id }` to `engine.handle(input).await`, then the returned `Vec<EngineEvent>` contains `[ConnectAttemptStarted, TunnelUp]` in that order, and `engine.state()` is `Connected { health: Unknown, .. }`. The test runs in under 50ms wall-clock with no root, no `wg`, no network.

- AE4. **Covers R8, R9.** When an `Engine` is in `Connecting` and its retry-budget elapses (default 300s), with `tokio::time::pause()` driving the clock, then the FSM transitions to `Disconnected { last_failure: Some(RetryBudgetExhausted { attempts, elapsed_secs: 300 }) }`, emits `RetryBudgetExhausted` and `ConnectAttemptFailed` events in that order, and the CLI's JSON envelope `next_actions` field contains a `check_endpoint_reachability` action.

- AE5. **Covers R10, R11, R12.** When an `Engine` is constructed with default config and runs for 30 seconds emitting events, then a file at `${XDG_DATA_HOME}/vortix/sessions/<timestamp>-<pid>.jsonl` exists, each line parses as JSON with `schema_version: 1`, `timestamp: <RFC3339>`, and an `event` field whose tag matches the emitted `EngineEvent` variant.

- AE6. **Covers R13, R16.** Given a slow TUI subscriber that has not polled in 5 seconds while the FSM emitted 2000 events, when the TUI polls next, then the broadcast channel returns `Lagged(N)` errors (not blocking the FSM), AND the journal file on disk still contains every one of those 2000 events. Slow subscribers degrade visibility; they never drop disk persistence.

- AE7. **Covers R20.** When an `Engine` runs for 10 minutes of `Connected` state with `IpChanged` never firing, then the journal contains exactly one `IpUnchangedNoted` event (or zero), not 20 ("once per session"). The dedup logic lives in the telemetry actor; the FSM does not enforce it.

- AE8. **Covers R14.** When `[journal] disk = false` is set in config, then no file is created in the sessions directory during the run; live subscribers still receive every event on the broadcast channel; `vortix bug-report` collects events from the in-memory ring buffer instead.

- AE9. **Covers R12.** When `vortix` starts and 35 prior session files exist in the sessions directory, then the retention pass deletes the 5 oldest before opening the new session file, and a `JournalRetentionApplied { deleted: 5 }` event is emitted as the first event of the new session.

- AE10. **Covers R23, R29.** When a downstream consumer imports `vortix_core::EngineHandle`, then they can call `EngineHandle::Local::new(config)` to construct a handle and have access to `execute`, `query`, and `subscribe` methods. They cannot pattern-match on the enum's variants exhaustively because `EngineHandle` is `#[non_exhaustive]` (preparing for `Remote`).

- AE11. **Covers R26, R27.** When `App` is constructed, then it holds `engine_handle: EngineHandle` and `tui_state: TuiState` and nothing else engine-related. A `grep impl Deref` over `crates/vortix/` returns zero matches.

- AE12. **Covers R27.** Given a TUI subscribed via `engine_handle.subscribe()` that has stalled for 10 seconds while 500 `EngineEvent`s emitted, when the TUI resumes draining, then it receives a `Lagged(N)` error from the broadcast receiver, the TUI calls `engine_handle.query(EngineQuery::Snapshot).await` to re-sync, and the next render reflects the current state. No events are dropped from the journal (R13).

- AE13. **Covers R30.** When a test calls `EngineHandle::for_test()`, then it receives a fully-constructed handle backed by a `MockRunner` and stub adapters; the test can `handle.execute(EngineCommand::Connect { profile_id }).await` and assert on the resulting `EngineEvent` stream without root, network, or real `wg`.

---

## Success Criteria

- v0.1.7's four "Dependable" promises (real quality monitoring; reconnect uses sidebar context; bulletproof state machine; useful activity log) all land as side effects of this refactor, each backed by named test scenarios that run in CI.
- A contributor writing a regression test for any of those v0.1.7 behaviors can express the test in under 30 lines using `MockRunner` + `tokio::time::pause()`, without setting up real `wg` or root.
- A user diagnosing a failed connection can run `vortix bug-report` and the bundle contains a structured per-session JSONL file that an issue triager can replay locally.
- A future audit-log subscriber (v1.0) is added by writing one `tokio::spawn` that subscribes to a filtered slice of the broadcast channel — no engine changes required.
- A future lifecycle-hooks subscriber (v0.3.0) is added the same way — no engine changes required.
- Phase B of idea 4 (the daemon process) constructs a `LocalHandle` server-side and exposes a `RemoteHandle` to clients over IPC; the engine itself and the `EngineHandle` public API are unchanged when Phase B lands.
- After this PR, `grep impl Deref` over `crates/vortix/` returns zero matches; every engine access goes through `EngineHandle`.
- A future Tauri / MCP / system-tray consumer can build against `vortix-core` by constructing `EngineHandle::Local::new(config)` and consuming the same Command/Query/Subscribe API the TUI uses.

---

## Scope Boundaries

- **Lifecycle hooks execution** (v0.3.0) is out of scope. The hook *mechanism* will be a subscriber on the broadcast channel that this PR creates; the actual hook definition, configuration, and execution lives in idea-3-adjacent later work.
- **Audit log durable persistence guarantees beyond JSONL append** (e.g., fsync per event, encryption at rest, tamper-evidence) are out of scope. JSONL with `schema_version` is the day-one foundation; richer audit machinery ships with v1.0 audit logging.
- **`curl → ureq` migration in telemetry** is out of scope (already deferred from idea 1's follow-up PR). The FSM consumes telemetry metrics regardless of how they are collected.
- **Profile delete-while-connecting enforcement** is out of scope — the gate lives in the profile store (idea 7). The FSM emits a `ProfileDeletionRequested` event but does not enforce the block.
- **The 4 `curl` HTTP probe callsites in `src/core/telemetry.rs`** are migrated through `CommandRunner` by idea 1 and replaced with `ureq` by idea 1's follow-up. This PR does not re-touch them.
- **Schema migration tooling** (`v1 → v2` journal upgrades) is out of scope. `schema_version: 1` is recorded; explicit migration code lands when `schema_version: 2` first ships.
- **TUI changes** (the "Measuring…" indicator, reconnect-uses-sidebar-context UI work, deduped-warning rendering) are out of scope — they are TUI subscriber changes that consume the new events. They land in their own PRs against `crates/vortix/src/tui/`.
- **`Failed`, `WaitingForNetwork`, `Quarantined`, or other additional states** are out of scope. The 5-state set is intentional. Add only with evidence from real bugs that the 5 are insufficient.
- **Replacing the existing scanner module** is out of scope. The scanner remains; its role changes from "direct state mutator" to "input source." The implementation of the scanner-as-input-source is detail for ce-plan.

- **Phase B of idea 4 — the daemon process itself** (the `vortix-daemon` crate, Unix socket / Windows named pipe transport, on-the-wire NDJSON/MessagePack/JSON-RPC choice, daemon lifecycle model — auto-spawn vs always-on system service vs hybrid, per-user vs root socket location, multi-user authorization on the IPC channel, version-skew handling between client and daemon, `vortix install-daemon` system-service installer, `RemoteHandle` impl that implements the `EngineHandle` enum's future second variant). All out of scope. A separate Phase B brainstorm will land later, ideally after ideas 5-7 and stabilization of the engine surface.

- **The privilege-escalation UX** does not change in this PR. Idea 1's fail-fast model and `next_actions` (`"sudo vortix up"`, `"install vortixd"`) remain in place. The structural fix arrives with Phase B's daemon-as-root option.

- **TUI rendering rewrites** are out of scope. Ratatui widgets and layout stay. What changes is the source of truth: `TuiState` is now derived from `EngineEvent` subscription, not from direct engine field access.

---

## Key Decisions

- **Five states, with `health` as a field on `Connected`.** Degraded-ness is a *property* of being connected (tunnel up, quality bad), not a separate lifecycle phase. `Failed` is `Disconnected { last_failure }`, not a separate state. Minimal evolution from today's 4-state shape (`Reconnecting` is the one new state); avoids the 7-state aviation-style explosion.
- **Interleaved async transitions, not effects-as-data.** `MockRunner` from idea 1 provides the test determinism that effects-as-data would otherwise be necessary for. A pure-function interpreter adds bugs at vortix's scale without adding capability. Effects-as-data deferred to idea 10/25.
- **WireGuard public-key hash as stable identity.** Already captured in `DetailedConnectionInfo.public_key`. No new UUID scheme needed. Future protocols supply their own stable string via the `Tunnel` impl.
- **300-second retry budget by default.** Reasonable middle ground between snappy failure (60s, too aggressive for café Wi-Fi) and patient retry (10 min, too slow when the gateway is actually down). Configurable. Number isn't in `ROADMAP.md` explicitly but matches the seed and product intuition.
- **Per-session JSONL journal in XDG data dir.** Diagnostic-friendly granularity (one file per `vortix up` invocation). JSONL is human-readable, append-only, easy to attach to bug reports, and trivial to parse. Sled or a binary format would be premature.
- **Retention: 30 days OR 30 files, whichever prunes more.** Belt-and-suspenders against runaway disk growth on long-lived daemons and against losing recent context on short-session users. Both configurable.
- **Non-lossy journal mpsc; lossy broadcast.** Journal must not drop (audit, forensics). Broadcast may drop for slow live subscribers (TUI redraws fine from a fresh snapshot). Two separate channels with different guarantees.
- **Scanner becomes an input source.** Preserves the existing pattern (system observation correcting in-memory state) without keeping it as direct mutation. The FSM is the source of truth; scanner observations are inputs.
- **Telemetry stays a separate actor.** FSM emits state-change events; telemetry emits metric events; both land in the same journal. The "IP unchanged" dedup lives in the telemetry actor's local state.
- **`#[non_exhaustive]` on `EngineEvent` from day one.** External consumers (Tauri wrappers, MCP servers, future audit log) cannot pattern-match exhaustively, so new event variants do not break them.
- **No new state for "WaitingForNetwork".** When the link is down before a connect attempt, vortix returns a clear error (`NoNetworkLink`) and exits; no separate state needed. Reconnecting handles transient drops during an active session.

- **Two architectural moves bundled in one PR (FSM + EngineHandle decoupling), not split.** The FSM's broadcast channel IS the handle's subscription mechanism; splitting them would mean shipping the FSM with a temporary access pattern (direct field access) that the handle would then replace in a follow-up PR — gratuitous churn. Bundling keeps the diff coherent.
- **`EngineHandle` is an `enum_dispatch` enum, not a `dyn Trait`.** Matches idea 1's `CommandRunner` and idea 5's `TunnelKind`. Static dispatch, native AFIT-compatible, supports `enum EngineHandle { Local(LocalHandle) }` today and `Local | Remote` later as a closed-set extension.
- **`App` becomes a pure view.** `engine_handle: EngineHandle` and `tui_state: TuiState`. No `Deref`. The 70%+ of the migration diff is callsite updates from `app.field` to handle-mediated access — mechanical but wide.
- **Daemon process deferred to a separate Phase B brainstorm.** Phase A delivers the structural decoupling, embedding API, and testability win. Phase B (daemon, IPC, install story) introduces user-visible lifecycle/install/version-skew decisions that deserve their own conversation, ideally after ideas 5-7 stabilize the engine surface.

---

## Dependencies / Assumptions

- **Idea 1 (CommandRunner) lands before this PR.** The FSM consumes `CommandRunner` for all subprocess I/O. Idea 1's brainstorm doc covers the trait shape.
- **Idea 2 (workspace split) lands before this PR.** The FSM types live in `crates/vortix-core/src/engine/`. Idea 2's brainstorm doc covers the workspace layout.
- **Tokio and `tokio::sync::broadcast` are available.** Idea 1 commits to tokio adoption; this PR inherits.
- **`tokio::time::pause()` works for deterministic time-based tests** of retry-budget and backoff behavior. Verified in tokio docs; planner should write a sanity test.
- **The `directories` crate** is added as a workspace dependency (also used by idea 7). It resolves XDG / macOS / Windows paths.
- **The `time` crate** (already a dependency) handles RFC3339 timestamp formatting for journal records.
- **JSONL append on the maintainer's primary platforms (Linux, macOS) is atomic at line granularity** when each write is a single `write(2)` of `<=PIPE_BUF` bytes. This holds for typical engine events. Long events (debug payloads) may need explicit framing; deferred.
- **The scanner module continues to function unchanged in semantics** during this migration. The PR refactors it from "direct state mutator" to "FSM input emitter" but does not change its observation logic.

---

## Outstanding Questions

### Resolve Before Planning

(None — all material decisions resolved in the synthesis.)

### Deferred to Planning

- [Affects R1, R2][Technical] Exact field set on each state variant — `started_at` vs `since_epoch_secs`, whether to keep `Box<DetailedConnectionInfo>` or inline. Mechanical; planner picks.
- [Affects R7][Technical] Exact field set on each `EngineEvent` variant — what context goes on each. The brainstorm names the variants; planner designs the payload schema.
- [Affects R8][Technical] Initial backoff value (2s default in this doc), doubling factor (2x default), and jitter strategy (full vs decorrelated). Mechanical tuning; planner picks based on standard backoff libraries (`backon`, `tokio-retry`).
- [Affects R10, R11][Technical] Whether journal records use `serde_json::to_writer` (line-buffered) or a more explicit framing. Standard JSONL is fine; planner picks.
- [Affects R12][Technical] Retention pass implementation — synchronous on engine start vs background-task on a timer. Sync on start is simpler; long-running daemons want a periodic re-prune.
- [Affects R16][Technical] Broadcast channel capacity — 1024 events is a stake-in-the-ground. May need tuning if telemetry tick rate is high. Mechanical.
- [Affects R18][Technical] Mapping from scanner observations to `TunnelStatusObserved` input — what observation classes there are, how often the scanner ticks. Inherits today's scanner cadence by default.
- [Affects R3][Needs research] For OpenVPN profiles (future idea 5 protocol), what's the stable identity? `<remote_host>:<remote_port>` plus a hash of the auth cert? Decided when OpenVPN tunnel impl lands.
