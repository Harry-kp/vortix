---
date: 2026-05-24
title: "feat: Engine FSM + event journal + EngineHandle decoupling"
status: active
type: feat
origin: docs/brainstorms/2026-05-24-engine-fsm-event-journal-requirements.md
prerequisite: docs/plans/2026-05-24-004-refactor-tunnel-trait-enum-dispatch-plan.md
related_brainstorms:
  - docs/brainstorms/2026-05-24-daemon-engine-handle-requirements.md
---

# feat: Engine FSM + event journal + EngineHandle decoupling

## Summary

Replace today's ad-hoc state mutation in `crates/vortix/src/engine/connection.rs` with an explicit 5-state finite-state machine on `Connection` (`Disconnected { last_failure }`, `Connecting`, `Connected { health }`, `Reconnecting`, `Disconnecting`) emitting typed `EngineEvent` values into a per-session JSONL journal at `~/.local/share/vortix/sessions/<ISO-timestamp>-<pid>.jsonl` plus an in-memory broadcast channel for live subscribers. Bundle this with **Phase A of idea 4 (`EngineHandle` decoupling)**: introduce a typed `enum EngineHandle { Local(LocalHandle) }` as a clone-able Command/Query/Subscribe API; remove `App: Deref<Target = VpnEngine>`; restructure `App` as `{ engine_handle, tui_state }` where the TUI subscribes to events and renders snapshots. The engine and handle live in `vortix-core` (per plan #001). Daemon process Phase B remains deferred. Delivers v0.1.7 "Dependable" promises (retry cap, rename-safe reconnect, deduped "IP unchanged" warning, accurate quality indicator) with named CI-testable scenarios.

This is the most behaviorally consequential PR of the migration — it changes both internal architecture and resolves multiple v0.1.7 ROADMAP correctness commitments.

---

## Problem Frame

After plans #001–#004 land, the engine still has the same structure it has today:
- `App` embeds `VpnEngine` via `Deref<Target = VpnEngine>` (porous boundary).
- Connection state is a 4-variant enum (`Disconnected | Connecting | Connected | Disconnecting`) mutated directly by the engine. No `Failed`, no `Reconnecting`, no `health` indicator.
- The scanner observes system state and corrects the engine ("scanner is source of truth" per the source comment) — but this correction is ad-hoc mutation, not a typed input.
- Profile identity for state purposes is the `String` filename — breaks on rename (v0.1.7 ROADMAP item 3).
- "IP unchanged" warning fires every 30 seconds in the activity log (v0.1.7 ROADMAP item 4 — 120 lines/hour of noise).
- Retry has no upper bound (v0.1.7 ROADMAP item 3 implies bounded retry; current code may loop indefinitely on Wi-Fi flap).
- Engine code is sync; TUI and CLI both consume the engine directly.

This PR fixes all of the above with one coherent architectural move.

---

## System-Wide Impact

- **End users (v0.1.7 promises delivered):** Accurate "Measuring…" quality indicator until telemetry arrives. Reconnect uses sidebar profile context. State machine bulletproof under rename / delete-while-connecting. "IP unchanged" warnings fire once per session, not every 30 seconds.
- **Diagnostic surface (new):** `vortix bug-report` automatically attaches the current session's JSONL journal — an issue triager can replay locally.
- **TUI:** Re-architected as a *pure view* — subscribes to engine events, renders from a derived `TuiState`. Today's direct `app.connection_state` field access disappears.
- **CLI:** Each command constructs a `LocalHandle`, executes one command/query, prints result, exits. Same external behavior; internal use of the handle is new.
- **Future audit log (v1.0):** One `tokio::spawn` subscribing to a filtered `EngineEvent` stream — no engine changes required.
- **Future lifecycle hooks (v0.3.0):** Same — another filtered subscriber.
- **Future daemon `vortixd` (Phase B of idea 4):** Constructs `LocalHandle` server-side and exposes a `RemoteHandle` to clients over IPC. The `EngineHandle` trait designed here is unchanged when Phase B lands.
- **Dependency footprint:** No new top-level deps (`tokio` and `tracing` already in via plan #002). Adds `sled = "0.34"` OR rolls a JSONL writer hand-rolled — see Key Decisions. Adds `tokio::sync::broadcast` (already in tokio).
- **Privacy:** Users can opt out via `[journal] disk = false`. Default is per-session JSONL; events don't contain credentials (per plan #002's redaction).

---

## Key Technical Decisions

- **5 states with `health` as a field on `Connected`** (not 7 with `Degraded` as its own state). `Failed` is `Disconnected { last_failure: Option<FailureReason> }`. Minimal evolution from today's 4-state shape. (Origin: brainstorm R1, R2, Key Decisions.)
- **Interleaved async FSM** (`async fn handle(&mut self, input: Input) -> Vec<EngineEvent>`), NOT Elm-style effects-as-data. `MockRunner` (plan #002) + `MockTunnel` (plan #004) + `Platform::for_test()` (plan #003) provide test determinism. Effects-as-data deferred to a hypothetical future Plan/Apply PR. (Origin: brainstorm R5, R6.)
- **Stable identity = SHA-256 of WireGuard public key / OpenVPN cert fingerprint.** Per protocol, via `Tunnel::parse_profile` (plan #004). (Origin: brainstorm R3, R4.)
- **Scanner becomes a `TunnelStatusObserved` input source**, not a direct state mutator. (Origin: brainstorm R18.)
- **Per-session JSONL journal** at `${XDG_DATA_HOME}/vortix/sessions/<ISO-timestamp>-<pid>.jsonl`. Retention: 30 days OR 30 files (whichever prunes more). Opt-out via `[journal] disk = false`. (Origin: brainstorm R10, R12, R14.)
- **Non-lossy journal mpsc, lossy broadcast.** Journal writer is a dedicated `tokio::spawn`'d task draining an unbounded mpsc; broadcast is `tokio::sync::broadcast` with capacity 1024 (slow subscribers get `Lagged`, re-sync from snapshot). (Origin: brainstorm R13, R16, R17.)
- **300s retry budget default**, exponential backoff (initial 2s, doubling, capped by remaining budget). Configurable via `[engine] retry_budget_secs`. (Origin: brainstorm R8.)
- **Telemetry stays a separate actor.** FSM emits state-change events; telemetry emits metric events. Same broadcast channel, same journal file. "IP unchanged" dedup lives in telemetry actor's local state. (Origin: brainstorm R19, R20.)
- **15 day-one `EngineEvent` variants** + `#[non_exhaustive]` enum. (Origin: brainstorm R7.)
- **`enum EngineHandle { Local(LocalHandle) }`,** `enum_dispatch`, `#[non_exhaustive]`. Future `Remote(RemoteHandle)` variant lands additively when Phase B brainstormed. (Origin: brainstorm R23.)
- **`App` restructured to `{ engine_handle, tui_state }`.** No `Deref`. TUI subscribes once at startup, drains events into `TuiState`, renders from `TuiState`. (Origin: brainstorm R26, R27.)
- **`EngineHandle::for_test()`** replaces `App::new_test()`. Works with `MockRunner` + `MockTunnel` + `Platform::for_test()`. (Origin: brainstorm R30.)
- **JSONL append-only is non-atomic at multi-line writes** but is atomic at single-line writes when the line is `<= PIPE_BUF` bytes. Events are designed to fit in one `write(2)` call. (Origin: brainstorm Dependencies/Assumptions.)
- **`schema_version: u32` field on every journal record** (starts at 1). (Origin: brainstorm R11.)
- **Big-bang single PR.** (Origin: brainstorm Key Decisions.)

---

## Implementation Units

### U1. Define the FSM types + `EngineEvent` schema in `vortix-core`

**Goal:** Establish the state enum, event enum, error enum, and supporting types.

**Requirements:** R1, R2, R3, R4, R5, R7

**Dependencies:** Plans #001–#004 complete.

**Files (new):**
- `crates/vortix-core/src/engine/state.rs`: `enum Connection { Disconnected { last_failure: Option<FailureReason> }, Connecting { profile_id, started_at, attempt, retry_budget_remaining }, Connected { profile_id, since, health: ConnectionHealth, details }, Reconnecting { profile_id, started_at, attempt, retry_budget_remaining, last_error }, Disconnecting { profile_id, started_at } }`. `enum ConnectionHealth { Healthy, Degraded { reason: DegradedReason }, Unknown }`. `enum FailureReason { RetryBudgetExhausted, HandshakeFailed, ConfigInvalid, NoNetworkLink, ProfileGone, ... }`.
- `crates/vortix-core/src/engine/event.rs`: `enum EngineEvent` with 15 variants per brainstorm R7 (`ConnectAttemptStarted, ConnectAttemptFailed, TunnelUp, TunnelDown, HandshakeStale, ConnectionHealthChanged, IpChanged, KillswitchEngaged, KillswitchDisengaged, RetryScheduled, RetryBudgetExhausted, NetworkLinkLost, NetworkLinkRestored, ProfileRenamed, ProfileDeletionRequested`). Each carries appropriate fields (timestamps, profile_ids, error details). `#[non_exhaustive]`. Serde-serializable.
- `crates/vortix-core/src/engine/input.rs`: `enum Input { UserCommand(UserCommand), Tick, NetworkLinkChanged(LinkState), TelemetryReport(TelemetryUpdate), ProfileChanged(ProfileChange), TunnelStatusObserved(TunnelStatusObservation) }`. `enum UserCommand { Connect { profile_id }, Disconnect, Reconnect, ... }`.
- `crates/vortix-core/src/engine/mod.rs`: re-export the above, declare the `Engine` struct (impl in U2).
- `crates/vortix-core/src/engine/error.rs`: `EngineError` via `thiserror`.

**Files (modifications):**
- `crates/vortix-core/src/lib.rs`: `pub mod engine;`.
- `crates/vortix-core/src/state/connection.rs` (relocated from `crates/vortix/src/state/connection.rs` in earlier plans): preserved as the historical type for back-compat; the new FSM uses the types in `vortix-core::engine::state`. **Decision:** rename or merge to avoid duplication — recommend renaming the old `ConnectionState` enum to `LegacyConnectionState` and marking deprecated, OR removing it entirely (verify no other code depends on it after plans #001–#004). Lean toward full removal; ce-work decides.

**Approach:**
- Inherit `DetailedConnectionInfo` from `crates/vortix-core/src/state/connection.rs` (preserved from today's 175-line file). It's used inside `Connected { details: DetailedConnectionInfo }`.
- All event payloads serde-serializable for JSONL persistence.

**Patterns to follow:**
- Today's `ConnectionState` enum at `src/state/connection.rs` (4 variants) is the starting shape; this evolves to 5 variants + `health` field.
- `thiserror` for `EngineError`.

**Test scenarios:**
- *Test expectation: types only; behavioral tests in U2/U3.*
- Verification: types compile; serde round-trips a sample event through `serde_json` correctly.

**Verification:** Types compile in `vortix-core`. `EngineEvent` serde-serializes to JSON.

---

### U2. Implement the FSM (`Engine`) with `handle(input)` method

**Goal:** The state-transition function.

**Requirements:** R5, R6, R8

**Dependencies:** U1

**Files (new):**
- `crates/vortix-core/src/engine/fsm.rs`: `Engine` struct + `impl Engine { async fn handle(&mut self, input: Input) -> Vec<EngineEvent> }`. Holds `state: Connection`, `runner: CommandRunner`, `platform: Platform`, `tunnel: Option<TunnelKind>` (active tunnel; None when Disconnected), `retry_budget_remaining: Duration`, `settings: EngineSettings` (the retry config from plan #006's Settings later).

**Approach:**
- `handle(input)` matches on `(state, input)` pairs:
  - `(Disconnected, UserCommand::Connect { profile_id })` → load profile via `ProfileStore` (plan #006), build TunnelKind via `tunnel_for(&profile)` (plan #004), transition to `Connecting`, invoke `tunnel.up(...)` async, emit `ConnectAttemptStarted` + result events.
  - `(Connecting, Tick)` → if `retry_budget_remaining` exhausted → `Disconnected { last_failure: RetryBudgetExhausted }`.
  - `(Connected { .. }, TelemetryReport)` → update `health`; possibly emit `ConnectionHealthChanged`.
  - `(Connected { .. }, NetworkLinkChanged(Lost))` → `Reconnecting { attempt: 1, retry_budget_remaining: settings.retry_budget }`.
  - ...all state-transition pairs enumerated per brainstorm F1-F4.
- Effects (subprocess invocations, killswitch.engage, dns.apply, journal.append) happen INSIDE `handle()` via `.await` on the injected ports. NOT returned as effects-as-data.
- The retry budget is decremented on each `Tick` while in `Connecting` or `Reconnecting`. Exponential backoff (2s, 4s, 8s, ...) capped by remaining budget.
- `Reconnecting → Reconnecting` transitions on retry events; `Reconnecting → Connected` on success; `Reconnecting → Disconnected { last_failure }` on budget exhaustion.

**Test scenarios:**
- `crates/vortix-core/tests/fsm.rs`:
  - **Happy path — connect succeeds (AE3):** Construct Engine with MockRunner scripting `wg-quick up` → success, MockTunnel → returns valid handle. Feed `UserCommand::Connect { profile_id }`. Assert events `[ConnectAttemptStarted, TunnelUp]`; state is `Connected { health: Unknown }`.
  - **Edge case — initial health is Unknown:** After successful up, state is `Connected { health: Unknown }`, NOT Healthy. (Covers brainstorm AE1.)
  - **Edge case — rename-safe reconnect (AE2):** Engine in `Reconnecting { profile_id: H1 }`. Feed `ProfileRenamed { id: H1, old, new }`. Assert state's display_name updated; profile_id unchanged; retry continues.
  - **Error path — retry budget exhaustion (AE4):** Engine in `Connecting`. Mock `wg-quick up` → always `Timeout`. Use `tokio::time::pause()` to advance clock past 300s. Assert final state `Disconnected { last_failure: RetryBudgetExhausted { .. } }`. Assert events include `RetryBudgetExhausted` and `ConnectAttemptFailed`.
  - **Integration — scanner correction:** Engine in `Disconnected`. Feed `TunnelStatusObserved(Active { interface: "utun3", ... })`. Engine treats as input, transitions to `Connected` with that interface (the scanner-as-input pattern; per brainstorm R18).

**Verification:** FSM tests pass. State transitions match brainstorm Key Flows F1-F4.

---

### U3. Implement journal writer + broadcast channel

**Goal:** Persist events to disk and fan them out to subscribers.

**Requirements:** R10, R11, R12, R13, R14, R16, R17

**Dependencies:** U1, U2

**Files (new):**
- `crates/vortix-core/src/journal/mod.rs`: `JournalConfig { disk: bool, retention_days: u32, retention_count: u32, journal_dir: PathBuf }`. `Journal` struct holding the broadcast sender and an mpsc to the writer task.
- `crates/vortix-core/src/journal/writer.rs`: the `tokio::spawn`'d writer task. Drains the mpsc, writes to the current session file (`<journal_dir>/<ISO>-<pid>.jsonl`), flushes per-event.
- `crates/vortix-core/src/journal/retention.rs`: prune logic. Called once at startup. Deletes files older than `retention_days` or beyond `retention_count`.

**Files (modifications):**
- `crates/vortix-core/src/engine/fsm.rs`: `Engine::handle` emits events to the journal via `journal.append(event).await` (mpsc send) and via `journal.broadcast(event)` (broadcast send, lossy).
- `crates/vortix-core/Cargo.toml`: add `time = { workspace = true, features = ["formatting", "macros"] }` for RFC3339 timestamps; `directories = { workspace = true }` for XDG path resolution (deps already in workspace dep set via plan #006).

**Approach:**
- Session-file path: at journal construction, resolve `${XDG_DATA_HOME}/vortix/sessions/<ISO8601-no-colons>-<pid>.jsonl` via the `directories` crate. Create the sessions directory if absent.
- Writer task body: `loop { while let Some(event) = mpsc_rx.recv().await { let line = serde_json::to_string(&Record { schema_version: 1, timestamp: now_rfc3339(), event })?; file.write_all(line.as_bytes()).await?; file.write_all(b"\n").await?; file.flush().await?; } }`.
- Retention pass: run synchronously at journal construction. Walk `sessions/`, parse timestamps from filenames, delete files older than `retention_days` AND beyond `retention_count` most-recent. Emit `JournalRetentionApplied { deleted }` event as the first event of the new session.
- Broadcast capacity: 1024. Slow subscribers get `Lagged(N)` errors; the engine continues unaffected.
- `[journal] disk = false` mode: writer task is not spawned; events flow only on broadcast + an in-memory ring buffer (sized to 1000 events) accessible via `journal.tail(N)` for `vortix bug-report`.

**Test scenarios:**
- `crates/vortix-core/tests/journal.rs`:
  - **Happy path (AE5):** Construct journal with `disk: true`, temp directory. Append 5 events. Read the file; assert 5 lines, each parseable JSON with `schema_version: 1`.
  - **Edge case — retention (AE9):** Pre-populate sessions/ with 35 files. Construct journal; assert oldest 5 deleted; first event of new session is `JournalRetentionApplied { deleted: 5 }`.
  - **Edge case — disk: false (AE8):** Construct with `disk: false`. Append events. Assert no file created. `journal.tail(10)` returns the events from memory.
  - **Edge case — broadcast Lagged (AE6):** Construct journal. Subscribe via broadcast. Append 2000 events without polling the subscriber. Subscriber polls; receives `Lagged(N)` error. Subscriber then calls `journal.tail(50)` to re-sync. Disk file still has all 2000 events.
  - **Concurrency — multiple subscribers:** Two subscribers, each at their own pace. Slow one lags; fast one keeps up. Disk file consistent.

**Verification:** Journal tests pass. Retention prunes correctly. Disk-disabled mode works without file creation.

---

### U4. Implement `EngineHandle` + `LocalHandle` (Phase A of idea 4)

**Goal:** The clone-able Command/Query/Subscribe API consumed by every surface.

**Requirements:** Brainstorm R23-R30

**Dependencies:** U1, U2, U3

**Files (new):**
- `crates/vortix-core/src/engine/handle.rs`: `enum EngineHandle { Local(LocalHandle) }`, `enum_dispatch`, `#[non_exhaustive]`. `struct LocalHandle { command_tx: mpsc::Sender<EngineMessage>, broadcast_rx_factory: ... }`.
- `crates/vortix-core/src/engine/commands.rs`: `enum EngineCommand { Connect { profile_id }, Disconnect, Reconnect, ImportProfile { source }, DeleteProfile { profile_id }, RenameProfile { profile_id, new_name } }`. `enum EngineQuery { Snapshot, ListProfiles, GetProfile { profile_id }, JournalTail { count } }`. Response types per query.
- `crates/vortix-core/src/engine/actor.rs`: the engine actor task. `tokio::spawn`'d; owns the `Engine` (FSM), `Journal`, and runs the `loop { recv command/query; engine.handle(input); reply via oneshot }` pattern.

**Approach:**
- `LocalHandle::new(engine: Engine, journal: Journal) -> EngineHandle` spawns the actor task; returns a handle that wraps the mpsc sender + a broadcast receiver factory.
- `EngineHandle::execute(cmd: EngineCommand) -> Result<CommandAck, EngineError>`: sends `(EngineMessage::Command(cmd), oneshot_reply_tx)` over mpsc; awaits oneshot.
- `EngineHandle::query(q: EngineQuery) -> Result<QueryResponse, EngineError>`: similar, separate enum branch.
- `EngineHandle::subscribe() -> EngineSubscription { snapshot, receiver }`: returns the current snapshot + a new broadcast receiver from the engine's broadcast sender.
- `EngineHandle::for_test()`: constructs `Engine` with `MockRunner + MockTunnel + Platform::for_test()`, a temp-dir Journal, spawns the actor, returns the handle.

**Test scenarios:**
- `crates/vortix-core/tests/engine_handle.rs`:
  - **Happy path (AE10):** Construct `EngineHandle::for_test()`. Call `execute(Connect { profile_id }).await`. Assert receives ack; subscribe and observe `TunnelUp` event.
  - **Concurrent clones:** Clone the handle twice; both call `query(Snapshot)` concurrently; both get the same snapshot.
  - **Subscription with lag (AE12):** Subscribe. Don't poll for 5 seconds while events fire. Poll; receive `Lagged`. Call `query(Snapshot)` to re-sync.

**Verification:** Handle tests pass. Clone semantics work. Subscription + snapshot round-trip works.

---

### U5. Restructure `App` to use `EngineHandle`; remove `Deref`

**Goal:** Migrate the TUI off direct engine access.

**Requirements:** Brainstorm R26, R27

**Dependencies:** U4

**Files (modifications):**
- `crates/vortix/src/app/mod.rs`:
  - Remove `pub engine: VpnEngine` field.
  - Remove `impl Deref for App` and `impl DerefMut for App`.
  - Add `engine_handle: EngineHandle` and `tui_state: TuiState` fields.
  - `App::new(config, config_dir) -> App`: constructs the engine, journal, handle; stores `engine_handle`.
  - `App::new_test()`: uses `EngineHandle::for_test()`.
- `crates/vortix/src/tui/state.rs` (was `src/state/ui.rs` after plan #001): grows to include the *projection* of engine state. Holds `connection: Connection` (the current snapshot), `profiles: Vec<ProfileSummary>`, `latest_events: VecDeque<EngineEvent>` (for activity log display), plus all existing TUI fields (focus, scroll, overlays).
- `crates/vortix/src/app/update.rs`: today's TEA-style update function. Add handlers for `EngineEvent` arrivals — they update `TuiState` projection. Subscribe to events in `App::run` and feed into the update loop.
- `crates/vortix/src/app/connection.rs`: today's connection-action handlers. Replace direct engine method calls with `engine_handle.execute(EngineCommand::Connect { ... }).await` (wrapped in `tokio::runtime::Handle::current().block_on(...)` from the TUI thread since the TUI's main loop is sync via crossterm).
- `crates/vortix/src/app/profile.rs`: same — profile operations go through the handle.
- All other `src/app/*` files: any remaining `app.engine.foo()` → `app.engine_handle.execute(...).await` or `app.engine_handle.query(...).await`.

**Approach:**
- TUI subscription pattern: in `App::run`, before entering the main loop, call `let subscription = app.engine_handle.subscribe();` and store the broadcast receiver. In the main event-loop iteration, after handling crossterm events, drain pending engine events via `subscription.receiver.try_recv()` until empty; each event flows through `update::apply_engine_event(&mut tui_state, event)`.
- `Lagged` handling: on `Lagged(N)`, call `engine_handle.query(EngineQuery::Snapshot).await` to re-sync; clear `latest_events`.
- This is the largest behavior-adjacent unit. Many small mechanical edits across `app/`. Use `cargo build -p vortix` to surface every broken callsite.

**Test scenarios:**
- `crates/vortix/src/app/tests.rs` (the existing test file): update to use `EngineHandle::for_test()` instead of `App::new_test()` returning a vortix-specific shape.
- New tests in `crates/vortix/src/app/tests.rs`:
  - **App-as-view (AE11):** Construct App via `App::new_test()`. Verify the App struct has only `engine_handle` and `tui_state` fields (compile-time check via destructuring). `grep -r 'impl Deref' crates/vortix/src/` returns zero matches.
  - **TUI re-sync after Lagged (AE12):** Use a custom MockEngine that emits 2000 events quickly. App lags; observe `Lagged`; observe re-sync via Snapshot.
  - **Connection-action flow:** TUI receives `KeyEvent` for "connect"; App dispatches `EngineCommand::Connect { ... }` via handle; subscribe observes `TunnelUp`; TUI renders Connected state.

**Verification:** `grep -r 'impl Deref' crates/vortix/src/` returns zero matches. TUI tests pass. Manual smoke: vortix launches, TUI renders, connect/disconnect works identically to pre-PR.

---

### U6. Adapt CLI commands to use `EngineHandle`

**Goal:** Migrate CLI dispatch off direct engine access.

**Requirements:** Brainstorm R28

**Dependencies:** U4

**Files (modifications):**
- `crates/vortix/src/cli/commands.rs`: each subcommand (`up`, `down`, `status`, `list`, `import`, `delete`, `rename`, ...) constructs a `LocalHandle`, sends one command/query, prints result, exits.
- `crates/vortix/src/cli/output.rs`: the JSON envelope (the `{ok, command, data, error, next_actions}` envelope per plan grounding) reads from the `EngineHandle`'s `QueryResponse` values.
- `crates/vortix/src/main.rs`: For CLI invocations, construct handle, run command, exit. For TUI invocations (default mode), construct App with handle, run TUI event loop.

**Approach:**
- CLI commands are inherently transient (one command per invocation). The handle is constructed, used once, dropped. The engine actor's `tokio::spawn` is scoped to the duration of the CLI invocation — exits when the handle drops.
- Some queries (`vortix status`) want a one-shot snapshot; others (`vortix watch`) want a live stream. v1 only ships one-shot semantics; live `watch` is a TUI feature.

**Test scenarios:**
- `crates/vortix/tests/cli_integration.rs` (existing): tests pass without modification — CLI external behavior unchanged.
- New: `crates/vortix/src/cli/tests/handle_dispatch.rs`:
  - **`vortix list` test:** Use `EngineHandle::for_test()` with scripted ListProfiles response. Run the CLI handler. Assert output JSON matches expected.

**Verification:** All CLI integration tests pass unchanged. CLI commands take the same args, exit with the same codes, produce the same JSON envelope as before.

---

### U7. Migrate telemetry to a separate actor that subscribes to events + dedup "IP unchanged" once-per-session

**Goal:** Deliver v0.1.7 ROADMAP item 4 (dedup) and re-architect telemetry as an event subscriber.

**Requirements:** R19, R20

**Dependencies:** U3, U4

**Files (modifications):**
- `crates/vortix/src/core/telemetry.rs` (or relocated to `crates/vortix-core/src/telemetry.rs`): becomes a `tokio::spawn`'d actor task. Holds a broadcast subscription + an mpsc sender into the journal. State: `ip_unchanged_warned_this_session: bool`.
- Telemetry loop body: periodic tick (10s default), gather metrics (rx/tx bytes via `platform.network_stats`, ping latency via `runner.run("ping", ...)`, IP via the future `ureq`-based probe but for now via curl-through-runner). Emit metric events (`RxBytes`, `TxBytes`, `PingLatency`, `IpChanged`, `IpUnchangedNoted`). The `IpUnchangedNoted` event fires ONLY if `ip_unchanged_warned_this_session == false`; sets the flag.

**Approach:**
- Telemetry's curl→runner→ureq evolution noted in plan #002 stays — telemetry actor uses `CommandRunner` to invoke curl until the follow-up ureq PR retires curl.
- Telemetry subscribes to `EngineEvent` to observe state transitions for context (e.g., "Connected → start ticking" / "Disconnected → stop ticking").

**Test scenarios:**
- `crates/vortix-core/tests/telemetry.rs`:
  - **Dedup happy path (AE7):** Spawn telemetry actor with mocked dependencies. Tick 20 times while connected; current IP unchanged each tick. Assert `IpUnchangedNoted` emitted exactly once.
  - **IP change:** Tick 5 times; on tick 3, mocked IP changes. Assert `IpChanged { from, to }` emitted on tick 3, no warnings.
  - **Telemetry stops on Disconnected:** Tick while connected; emit `Disconnected` event via broadcast. Assert telemetry stops querying within one tick.

**Verification:** Telemetry tests pass. The 30s "IP unchanged" warning spam is fixed.

---

### U8. Add `vortix bug-report` journal attachment

**Goal:** `vortix bug-report` includes the current session's journal in the bundle.

**Requirements:** R15

**Dependencies:** U3

**Files (modifications):**
- `crates/vortix/src/cli/report.rs` (the existing bug-report code): query the journal path (via `Journal::current_session_path()`); attach the file to the bug-report payload (or display it for the user to copy).

**Test scenarios:**
- `crates/vortix/src/cli/tests/bug_report.rs`:
  - **Happy path:** With `disk: true`, create a session with 10 events. Run `vortix bug-report` (dry-run mode). Assert the bundle contains the session's JSONL content.
  - **Edge case — disk disabled:** With `disk: false`, run bug-report. Assert the in-memory ring buffer is exported instead.

**Verification:** Bug reports include diagnostic context.

---

## Verification Strategy

- `cargo build --workspace --all-targets --locked` succeeds.
- `cargo test --workspace --all-targets` passes — all existing tests + new FSM tests + handle tests + journal tests + telemetry tests.
- `cargo xtask check-subprocess` and `cargo xtask check-platform-leak` and `cargo xtask check-protocol-leak` (all three lints from prior plans) still pass.
- `grep -r 'impl Deref' crates/vortix/src/` returns zero matches.
- Manual smoke test on maintainer's machine: connect WG, observe identical behavior. Connect OVPN, observe identical behavior. Disconnect mid-connect (during Reconnecting), verify clean state. Kill Wi-Fi while connected, observe Reconnecting + retry budget + eventual Disconnected with `last_failure: RetryBudgetExhausted`.
- Verify v0.1.7 ROADMAP promises:
  - Quality indicator shows "Measuring…" initially, then "EXCELLENT/GOOD/DEGRADED" once telemetry arrives.
  - Rename profile mid-connection; reconnect succeeds via stable pubkey identity.
  - Delete profile while connecting; engine blocks with clear message.
  - "IP unchanged" warning fires once per session, not every 30s.
- `vortix bug-report` produces a bundle including the session JSONL.

---

## Risks & Mitigations

- **Largest behavior change in the migration.** Many subtle behaviors (retry logic, scanner correction, telemetry dedup) get rewritten. Mitigation: per-flow tests covering brainstorm Acceptance Examples AE1-AE13; explicit Execution note that these behaviors must match v0.1.7 ROADMAP promises (tests should fail if they regress).
- **TUI rendering rewrite is non-trivial.** Today's `app.foo` direct access becomes `tui_state.foo` derived from events. Mitigation: incremental migration unit (U5) with per-callsite verification via compile.
- **Journal disk I/O latency** could affect engine throughput. Mitigation: non-lossy mpsc with unbounded buffer; writer task is async and never blocks the engine actor. Worst case: journal lags behind engine; events still in mpsc buffer.
- **`tokio::time::pause()` may not interact cleanly with all engine code paths.** Mitigation: where tests use paused time, document explicitly; manual integration tests use real time.
- **JSONL atomic-write assumption.** Linux/macOS atomic-write boundary is `PIPE_BUF` (4096 bytes). Events larger than this would risk partial writes interleaving. Mitigation: assert per-event JSON serialized size < 4096 in tests; emit a warning event if exceeded.
- **Schema migration from old `ConnectionState` to new `Connection` enum.** Where do existing TUI projections sit? Mitigation: U5 explicitly migrates `TuiState` to consume the new `Connection` enum; the old enum is removed.

---

## Scope Boundaries

- **Daemon process Phase B (`vortixd`, IPC, install story)** — out of scope. Defer to brainstorm `2026-05-24-daemon-engine-handle-requirements.md`.
- **Lifecycle hooks execution** (v0.3.0) — out of scope. Subscribes to events when the feature lands.
- **Audit log durable persistence beyond JSONL** — out of scope. JSONL with `schema_version` is the foundation; richer machinery ships with v1.0 audit.
- **Profile delete-while-connecting enforcement** — emits `ProfileDeletionRequested` event; actual gating lives in `ProfileStore` (plan #006).
- **Schema migration tooling for journal evolution** — out of scope. `schema_version: 1` ships; migration code lands when v2 first ships.
- **TUI visual changes for the new states** — Mostly out of scope. Reconnecting state requires a UI indicator; basic indicator added in U5; full design polish defers to ROADMAP v0.1.8 work.
- **Schema version > 1** — out of scope.
- **`Failed`, `WaitingForNetwork`, additional states** — out of scope. 5-state set is final for v1.

### Deferred to Follow-Up Work

- v0.3.0 lifecycle hooks: subscribe to filtered events.
- v1.0 audit log: a dedicated subscriber writing to a tamper-evident store.
- Daemon Phase B: brainstormed; not planned.
- TUI v0.1.8 polish for the new Reconnecting/Degraded states.

---

## Outstanding Questions

### Resolve Before Planning

(None.)

### Deferred to Implementation

- Exact mpsc channel capacity vs unbounded — recommend unbounded for the engine's command channel (back-pressure on the engine itself is wrong); broadcast stays bounded at 1024.
- Whether the `Engine` actor uses a single `tokio::select!` loop or separate tasks for different inputs. Recommend single `select!` for now.
- Per-event JSON payload field set — populated in U1; minor adjustments expected during implementation.
- Whether `tokio::time::pause()` works for all retry-budget timing tests on macOS. Verify; if not, use a custom-injectable clock trait.
- Whether `JournalRetentionApplied` should be the *first* event of the new session or precede the new session's open. Mechanical.
- Per-protocol stable identity for OpenVPN (cert fingerprint hash) — verify during implementation.
- Whether `App::run`'s tokio runtime should be `current_thread` (smaller, simpler) or `multi_thread` (already adopted in plan #002 main.rs). Stay with `multi_thread`.
