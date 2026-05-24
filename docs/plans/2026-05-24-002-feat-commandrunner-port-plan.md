---
date: 2026-05-24
title: "feat: Route every subprocess through a CommandRunner port"
status: active
type: feat
origin: docs/brainstorms/2026-05-24-commandrunner-port-requirements.md
prerequisite: docs/plans/2026-05-24-001-refactor-cargo-workspace-split-plan.md
---

# feat: Route every subprocess through a CommandRunner port

## Summary

Introduce one async `CommandRunner` trait in `vortix-core::ports::process` with two `enum_dispatch` variants (`Real(RealRunner)` for production, `Mock(MockRunner)` for tests) living in `vortix-process`. Route every existing subprocess callsite (~20 sites across engine, core, platform, cli, app, utils) through it in a single big-bang PR. Add a CI lint (the `xtask check-subprocess` stub scaffolded by plan #001 becomes functional here) that fails the build when `std::process::Command::new` or `tokio::process::Command::new` appears outside the runner module. Adopts `tokio` and `tracing` as new top-level deps; structured `tracing` events for every subprocess invocation seed audit logging (consumed by idea 3's event journal later). Drops `Command::new("date")` at the existing utils callsite in favor of the `time` crate. **OpenVPN telemetry's `curl` HTTP probes are migrated *through* the runner in this PR but `curl` itself is retired in a separate follow-up PR (`feat(telemetry): replace curl shell-out with ureq`).**

---

## Problem Frame

Every subprocess in vortix today calls `std::process::Command::new(...)` inline at the call site. The set: `wg-quick`, `wg`, `openvpn`, `kill`, `pkill`, `ip`, `route`, `ps`, `curl`, `ping`, `resolvconf`, `which`, `netstat`, `date`. They live across `src/engine/connection.rs` (669 lines), `src/engine/mod.rs` (525 lines), `src/core/{network_monitor,telemetry,scanner}.rs`, `src/utils.rs` (lines 37–639), `src/cli/report.rs` (575+), `src/app/connection.rs`, and the platform-OS files (now under `crates/vortix-platform-{macos,linux}/` per plan #001).

Two compounding pains:

1. **Connection flows are untestable in CI.** Exercising the engine's connect path needs `wg-quick`, root, and a working network interface. None of those exist in CI. Result: the engine's mutation paths — the parts that matter when a bug ships — are hand-tested only on the maintainer's laptop. v0.1.7 "Dependable" promises (retry cap, rename-safe reconnect, deduped warnings) all live in untestable code.
2. **Observability is structurally absent.** No shared seam means no place to attach structured logging, no place to write audit records, no place to insert a dry-run interceptor, no place to enforce privilege policy. Audit logging (v1.0), lifecycle hooks (v0.3.0), agent-friendly dry-run, and security review must each either invent their own seam or accept that vortix cannot offer it.

This PR is the foundational refactor that unlocks every downstream architectural move (ideas 3, 5, 6, 7) by making subprocess calls a typed, mock-friendly, observable system boundary.

---

## System-Wide Impact

- **End users:** Zero observable change. Same subprocess invocations, same connection latency, same telemetry, same kill switch.
- **Contributors writing tests:** New ability to write a connect-flow test in ~20 lines using `MockRunner::with_script(...)` + `tokio::test`. No root required. No real `wg`/`openvpn` required. CI exercises engine paths that have been hand-tested only.
- **Future audit-log subscriber (v1.0, idea 3):** Subscribes to one `tracing` target (`vortix::process`) and gets every subprocess invocation as a structured event without modifying RealRunner.
- **Future daemon `vortixd` (Phase B of idea 4):** Owns a single `RealRunner` instance; user-facing CLI/TUI no longer instantiate runners directly. Privilege-escalation UX (`sudo vortix up`) becomes daemon-resolved.
- **Future Tunnel impls (idea 5):** `WgTunnel::up(profile, plat, runner)` takes the runner as a dependency; protocol crates consume the trait without knowing whether the impl is Real or Mock.
- **Dependency footprint:** `tokio` (with `rt-multi-thread`, `process`, `time`, `macros`, `sync` features), `tracing`, `tracing-subscriber`, `enum_dispatch` enter `Cargo.toml`. Tokio enters the `vortix` binary transitively via `vortix-process`.
- **Privilege UX:** Unchanged — `sudo vortix up corp` still required for privileged operations today. The runner records the requirement and rejects mismatched calls with a typed error; auto-escalation deferred to daemon mode.

---

## Key Technical Decisions

- **Native AFIT (`async fn` in traits, stable since Rust 1.75) over the `async_trait` macro.** Vortix's MSRV is already 1.75. AFIT avoids per-call boxed-future allocation. Trade-off: AFIT traits aren't `dyn`-compatible. Mitigation: `enum_dispatch` over a closed-set enum provides static dispatch without `dyn`.
- **`enum_dispatch` over `enum CommandRunner { Real(RealRunner), Mock(MockRunner) }`,** not `Box<dyn CommandRunner>`. Same closed-set pattern as plan #001's workspace decisions and the future `TunnelKind` / `EngineHandle` / `KillswitchKind` enums. Adding a third variant (e.g., `Daemon(DaemonProxyRunner)` later for Phase B of idea 4) is additive.
- **`CommandSpec` covers OneShot and DetachedSpawn lifetimes** (per brainstorm R3). The `Supervised` lifetime — vortix as parent watching a long-running child like userspace WireGuard's `boringtun` — is **reserved** as a future `spawn_supervised(spec) -> SupervisedHandle` method on the trait, **not implemented** in this PR. The trait shape accommodates it cleanly when idea 4's daemon brings userspace-WG into scope.
- **`PrivilegeReq { None, Root }` on the spec, fail-fast model.** RealRunner checks the running uid against `requires_privilege`; rejects with `ProcessError::PrivilegeDenied` without executing if the requirement is unmet. Read-only ops (`status`, `list`, `ps`, `which`, `wg show`) carry `PrivilegeReq::None` and run unprivileged. Auto-sudo, pkexec, and `vortix install-daemon` are explicitly deferred. (Origin: brainstorm R6, F3.)
- **`ProcessError` via `thiserror`** aligned to the existing 0-6 semantic exit codes. Variants: `PrivilegeDenied`, `ProgramNotFound`, `Timeout`, `Killed`, `NonZeroExit`, `IoError`, `EnvelopeBuildFailed`. Each variant carries enough context to populate the JSON envelope's `next_actions`. (Origin: brainstorm R5.)
- **Big-bang migration.** All 20 callsites migrate together with the CI lint added in the same PR. Behavior is preserved per-callsite; the diff is mostly mechanical `Command::new("foo").args(...).output()?` → `runner.run(CommandSpec::oneshot("foo", args).privilege(Root)).await?` rewrites. (Origin: brainstorm R10, R12.)
- **`tracing` enters the workspace as a top-level dep.** A minimal `tracing-subscriber` configured in `crates/vortix/src/main.rs` (env-filter from `RUST_LOG`, compact format on TTY). No structured-log JSON output by default; that lands when idea 3's event journal subscribes to the `vortix::process` target.
- **Redaction-by-default in `tracing` events.** `CommandSpec` carries an optional `redact_in_audit: Vec<ArgIndex>` field. RealRunner emits the program name and arg list with redacted positions replaced by `***REDACTED***`. Today, no callsite uses this field (no secrets pass via args yet); idea 5's Tunnel impls and idea 7's SecretStore-aware code will populate it. (Origin: brainstorm Outstanding Question on redaction default — answer: redact when marked, not by default. The default is debug-info-by-default; secret callers mark explicitly.)
- **`MockRunner` invocation log + ordered expectations.** Tests build a `MockRunner::builder()` with `(matcher, scripted_outcome)` pairs. Calls not matching expectations panic with a clear diagnostic. Builder pattern (not a macro) for test ergonomics. (Origin: brainstorm R9.)
- **`Command::new("date")` at `crates/vortix/src/utils.rs:421` is replaced with the `time` crate** (existing dep). This is the one small behavior-adjacent cleanup in scope; flagged in the brainstorm R11 explicitly.
- **`curl` HTTP probes** (4 callsites in `core/telemetry.rs`) route through the runner in v1 with minimum-fuss mocks because they'll be deleted in the immediate follow-up `feat(telemetry): replace curl shell-out with ureq` PR. (Origin: brainstorm R10, R12 + Synthesis Call-out on curl deferral.)
- **`xtask check-subprocess` is functional in this PR.** The stub scaffolded by plan #001 becomes a working `rg`-driven lint. Allowlisted patterns: `std::process::exit(...)` (process termination, not execution); occurrences inside `crates/vortix-process/src/real.rs` (the runner module itself); explicit `#[allow]` comments on the same line with justification.

---

## Implementation Units

### U1. Define `CommandRunner` trait and supporting types in `vortix-core::ports::process`

**Goal:** Establish the trait, `CommandSpec`, `CommandOutcome`, `PrivilegeReq`, `ProcessError`, and `Kind` types in `vortix-core`. No implementation yet.

**Requirements:** R1, R3, R4, R5, R6

**Dependencies:** Plan #001 (workspace exists; `crates/vortix-core/` is the empty stub).

**Files:**
- Create `crates/vortix-core/src/ports/mod.rs` (the ports module; later ideas 5, 6 add `tunnel`, `killswitch`, etc., here).
- Create `crates/vortix-core/src/ports/process.rs` (the trait + types).
- Create `crates/vortix-core/src/lib.rs` (or modify the existing stub from plan #001) to `pub mod ports;`.
- Modify `crates/vortix-core/Cargo.toml` to add the small set of deps the types need: `serde = { workspace = true, features = ["derive"] }` for `Debug` / future serialization; `thiserror = "2"` for `ProcessError`. **Important:** `vortix-core` does NOT take a tokio dep — the trait uses `async fn` declarations (AFIT desugars to compiler-generated GATs, no runtime dep).

**Approach:**
- Trait shape (directional, not literal):
  - `trait CommandRunner { async fn run(&self, spec: CommandSpec) -> Result<CommandOutcome, ProcessError>; async fn spawn_detached(&self, spec: CommandSpec) -> Result<DetachedHandle, ProcessError>; }`
  - `spawn_detached` is the second method per brainstorm R1 (covering `openvpn --daemon`). A future `spawn_supervised` is mentioned in trait docs but not declared.
- `CommandSpec` fields: `program: String`, `args: Vec<String>`, `env: Option<HashMap<String, String>>` (merge into current env by default; explicit replace via a builder method), `cwd: Option<PathBuf>`, `stdin_bytes: Option<Vec<u8>>`, `timeout: Option<Duration>`, `requires_privilege: PrivilegeReq`, `kind: Kind`, `redact_in_audit: Vec<usize>` (arg indices). Provide a builder API: `CommandSpec::oneshot(program, args).privilege(Root).timeout(Duration::from_secs(30))`.
- `Kind { OneShot, DetachedSpawn }` enum.
- `PrivilegeReq { None, Root }` enum (per brainstorm R6; `Capability(CapName)` reserved for the Outstanding Question, defaulting to `Root` only for v1).
- `CommandOutcome` for OneShot: `stdout: Vec<u8>`, `stderr: Vec<u8>`, `exit_status: ExitStatusInfo` (a serde-friendly wrapper around `std::process::ExitStatus` since the std type isn't directly serializable), `duration: Duration`, `started_at: SystemTime`. For DetachedSpawn: a separate `DetachedHandle { pid: u32, spawned_at: SystemTime }`.
- `ProcessError` via `thiserror`: variants per brainstorm R5. Each variant carries the program name, args (redacted via `redact_in_audit`), and OS-error context where applicable.

**Patterns to follow:**
- rustup's `Process` abstraction (named in brainstorm) — methods are async; spec/outcome are typed.
- Existing `clap` derive style for option struct shape.
- `thiserror` for error enums (vortix's `color_eyre::Result` is binary-edge today; this PR introduces typed errors as the library convention).

**Test scenarios:**
- *Test expectation: none — types only; behavioral tests live in U3 (MockRunner) and U4+ (callsite migration tests). Type-level checks happen at compile time.*
- Verification: `cargo build -p vortix-core` succeeds.
- Verification: `cargo doc -p vortix-core` renders the trait with both methods documented.

**Verification:** Trait and types compile cleanly. `vortix-core`'s public API exports `CommandRunner`, `CommandSpec`, `CommandOutcome`, `DetachedHandle`, `PrivilegeReq`, `Kind`, `ProcessError`, `ExitStatusInfo`.

---

### U2. Implement `RealRunner` in `vortix-process`

**Goal:** The production implementation that actually invokes subprocesses via `tokio::process`.

**Requirements:** R1, R2, R4, R6, R7

**Dependencies:** U1

**Files:**
- Create `crates/vortix-process/src/lib.rs` (replacing plan #001's empty stub).
- Create `crates/vortix-process/src/real.rs` (the `RealRunner` impl).
- Create `crates/vortix-process/src/enum_dispatch.rs` (or inline in `lib.rs`): the `enum CommandRunner { Real(RealRunner), Mock(MockRunner) }` with `enum_dispatch` macro driving the trait impl.
- Modify `crates/vortix-process/Cargo.toml`:
  - `[dependencies] vortix-core = { path = "../vortix-core" }, tokio = { workspace = true, features = ["rt-multi-thread", "process", "time", "macros", "sync", "io-util"] }, tracing = { workspace = true }, enum_dispatch = { workspace = true }, libc = "0.2"`.

**Approach:**
- `RealRunner` is a unit struct (or carries a single `tracing::Span` field if span-context is wanted). Construction: `RealRunner::new()`.
- `RealRunner::run(spec)`:
  1. Privilege check: if `spec.requires_privilege == Root` and `unsafe { libc::geteuid() } != 0`, return `Err(ProcessError::PrivilegeDenied { program, next_actions })`.
  2. Emit `tracing::info!(target: "vortix::process", program = %spec.program, redacted_args = %redact(spec.args, &spec.redact_in_audit), requires_privilege = ?spec.requires_privilege, kind = ?spec.kind, "subprocess.start")`.
  3. Build `tokio::process::Command` from the spec.
  4. Apply `env` (merge or replace based on builder field), `cwd`, `stdin`. Set `Stdio::piped()` for stdout/stderr/stdin.
  5. Spawn; if `spec.timeout.is_some()`, wrap the `.wait_with_output()` future in `tokio::time::timeout`.
  6. On completion: emit `tracing::info!(target: "vortix::process", exit_status = ?status, duration_ms = %elapsed.as_millis(), "subprocess.end")` and return `Ok(CommandOutcome { ... })`.
  7. On error (timeout, IoError, kill-by-signal): map to the appropriate `ProcessError` variant and emit `tracing::warn!(target: "vortix::process", error = %err, "subprocess.failed")`.
- `RealRunner::spawn_detached(spec)`:
  1. Same privilege + tracing entry steps.
  2. `tokio::process::Command::new(...).spawn()?` and immediately retrieve the child's PID before dropping the `Child` handle. (Detached children survive `Child` drop on Unix; on Windows `Child::forget()` is needed — out of scope for this PR.)
  3. Return `Ok(DetachedHandle { pid, spawned_at })`.

**Patterns to follow:**
- rustup's `Process` impl (well-documented pattern: redacted args in tracing).
- vortix's existing `src/utils.rs::run_with_timeout` function — its timeout logic moves into RealRunner.

**Test scenarios:**
- *Tests are deferred to U3's MockRunner work plus the per-callsite migration units. RealRunner itself is hard to unit-test in CI without a real subprocess; one or two smoke tests exercising `which` (a globally-available program) and `false` (returns exit 1) provide enough coverage.*
- Test scenarios (in `crates/vortix-process/tests/real_runner_smoke.rs`):
  - **Happy path:** Run `CommandSpec::oneshot("echo", ["hello"]).privilege(None)`. Expect `stdout == b"hello\n"`, `exit_status.success() == true`, `duration > 0`.
  - **Edge case — timeout:** Run `CommandSpec::oneshot("sleep", ["5"]).timeout(Duration::from_millis(100))`. Expect `Err(ProcessError::Timeout { .. })`.
  - **Error path — program not found:** Run `CommandSpec::oneshot("vortix-no-such-program-xyz", []).privilege(None)`. Expect `Err(ProcessError::ProgramNotFound { .. })`.
  - **Error path — privilege denied:** Run `CommandSpec::oneshot("ls", []).privilege(Root)` as non-root user. Expect `Err(ProcessError::PrivilegeDenied { .. })` without `ls` having been invoked.
  - **DetachedSpawn happy path:** `spawn_detached(CommandSpec::oneshot("sleep", ["10"]))`; expect a valid PID returned. Verify the PID via `runner.run(CommandSpec::oneshot("kill", ["-0", &pid.to_string()]))` returns exit 0.

**Verification:** RealRunner smoke tests pass on macOS dev machine and Linux CI. `tracing` events appear in `RUST_LOG=vortix::process=debug cargo test` output.

---

### U3. Implement `MockRunner` in `vortix-process`

**Goal:** The test fixture that makes every downstream callsite testable.

**Requirements:** R1, R8, R9

**Dependencies:** U1, U2 (so the trait is settled)

**Files:**
- Create `crates/vortix-process/src/mock.rs` (the `MockRunner` impl).
- Modify `crates/vortix-process/src/lib.rs` to add the `Mock(MockRunner)` variant to `enum CommandRunner`.

**Approach:**
- `MockRunner` carries: `expectations: Arc<Mutex<VecDeque<Expectation>>>`, `invocations: Arc<Mutex<Vec<RecordedInvocation>>>`.
- `Expectation { matcher: SpecMatcher, scripted_outcome: ScriptedOutcome }` where:
  - `SpecMatcher` is an enum: `ExactProgram(String)`, `ProgramWithArgs(String, Vec<ArgMatcher>)`, `Any`, where `ArgMatcher = Exact(String) | Pattern(regex) | AnyArg`.
  - `ScriptedOutcome` is an enum: `Success { stdout, stderr, exit_code }`, `Failure(ProcessError)`, `Detached { pid }`.
- Builder API: `MockRunner::builder().expect(SpecMatcher::ProgramWithArgs("wg-quick", vec![Exact("up"), AnyArg])).respond(Success { stdout: vec![], stderr: vec![], exit_code: 0 }).build()`.
- `MockRunner::run(spec)` pops the next expectation, verifies the matcher against the spec, panics on mismatch (test failure with clear message), records the invocation, returns the scripted outcome.
- `MockRunner::spawn_detached(spec)` similar; only `ScriptedOutcome::Detached` is acceptable.
- Assertion helpers: `mock.invocations()` returns the full ordered record; `mock.assert_called_once_with(matcher)` shorthand; `mock.assert_no_remaining_expectations()` for end-of-test cleanup (call this in test `Drop` via a `#[must_use]` guard, or explicitly).
- Convenience: `MockRunner::with_default_success()` returns a runner that succeeds at any call (for tests that don't care about subprocess behavior).

**Patterns to follow:**
- `mockall` crate's API style (recognized Rust idiom), but lightweight hand-rolled.
- Existing `tokio::test` async test fixtures in vortix's `tests/` directory.

**Test scenarios (in `crates/vortix-process/tests/mock_runner.rs`):**
- **Happy path:** Build a MockRunner expecting `wg-quick up corp-iface` → success. Run the spec. Assert `mock.invocations().len() == 1` and the recorded invocation matches.
- **Edge case — empty expectations:** Build with no expectations. Call any spec. Expect a panic with message naming the unexpected call.
- **Edge case — wrong order:** Build expecting A then B. Call B first. Expect panic with diagnostic naming the expected vs actual call.
- **Error path:** Script `ScriptedOutcome::Failure(ProcessError::Timeout { .. })`. Run; expect `Err(...)` returned.
- **Integration scenario — multiple sequential calls:** Build expecting `wg-quick up` → success, then `wg show <iface>` → success with parsed stdout. Run both in sequence. Assert ordering preserved in `invocations()`.

**Verification:** Mock tests pass. `MockRunner::builder()` API is ergonomic enough to write a connect-flow test in <30 lines.

---

### U4. Migrate `src/engine/` callsites through the runner

**Goal:** Move the engine's subprocess calls (the largest cluster) onto the runner.

**Requirements:** R10

**Dependencies:** U1, U2, U3

**Files (modifications):**
- `crates/vortix/src/engine/connection.rs` (669 lines): migrate all `Command::new("wg-quick")`, `Command::new("kill")`, `Command::new("pkill")`, `Command::new("openvpn")` callsites (lines 238, 247, 260, 272, 457, 525, 589, plus the args/.output() chains for each).
- `crates/vortix/src/engine/mod.rs` (525 lines): migrate `Command::new("kill")` at line 393 and `Command::new("wg-quick")` at line 402.

**Approach:**
- Engine code constructs `CommandSpec`s using the builder. Per protocol:
  - WireGuard: `CommandSpec::oneshot("wg-quick", vec!["up".into(), iface.into()]).privilege(Root)`.
  - OpenVPN: `CommandSpec::oneshot("openvpn", openvpn_args).privilege(Root).kind(DetachedSpawn)` (today's openvpn uses `--daemon`; the runner's `spawn_detached` method handles it).
  - Kill operations: `CommandSpec::oneshot("kill", vec!["-9".into(), pid.to_string()]).privilege(Root)` for forced termination; `CommandSpec::oneshot("kill", vec!["-0".into(), pid.to_string()]).privilege(None)` for liveness checks.
- The engine holds a `runner: CommandRunner` (the enum) — passed in at construction. In this PR, `main.rs` constructs `CommandRunner::Real(RealRunner::new())` and threads it through. Idea 3's PR introduces the EngineHandle wrapping this.
- Add the `runner` field to `VpnEngine`. Update `VpnEngine::new(config, config_dir)` to take `runner: CommandRunner`. Update callers in `app/mod.rs` (`App::new` already calls `VpnEngine::new`).
- The `App::new_test()` helper (in `app/mod.rs:256`) constructs `VpnEngine::new_test()` — add a corresponding `VpnEngine::new_test()` that uses `CommandRunner::Mock(MockRunner::with_default_success())`.

**Patterns to follow:**
- Today's `src/engine/connection.rs` already groups WG and OVPN logic in match arms; preserve the grouping.
- The async nature: `engine/connection.rs` today is synchronous. Migration to async requires wrapping the runner calls in `tokio::runtime::Runtime::block_on(...)` calls UNLESS the entire engine moves to async in this PR. **Sub-decision:** the engine becomes async-aware in this PR (`async fn connect_wireguard`, `async fn connect_openvpn` instead of sync). The TUI's event loop wraps engine calls via `tokio::runtime::Runtime::block_on` from the main thread until idea 3's EngineHandle makes everything async natively. This is transitional shape; idea 3 cleans it up.

**Test scenarios (in `crates/vortix/src/engine/tests/connection_tests.rs`):**
- **Happy path — WireGuard connect:** MockRunner scripts `wg-quick up <iface>` → success. Call `engine.connect(profile)`. Assert resulting `ConnectionState::Connected { .. }`.
- **Happy path — OpenVPN detached spawn:** MockRunner scripts `openvpn --daemon ...` → DetachedSpawn returning pid 12345. Engine state holds the pid. Subsequent `kill -0` query → exit 0 → engine reports alive.
- **Error path — wg-quick exit 1:** MockRunner scripts `wg-quick up <iface>` → `NonZeroExit { code: 1, stderr: "Address already in use" }`. Engine transitions to disconnected with the error in state.
- **Error path — privilege denied:** Engine runs as non-root user; MockRunner records the call but `RealRunner` (in a separate integration test that doesn't use MockRunner) returns `PrivilegeDenied`. (For this MockRunner-based test: script `Failure(PrivilegeDenied { .. })`.)
- **Edge case — pkill kills lingering process:** Sequence: spawn openvpn, observe stale pid, runner-script for `pkill openvpn` → success, engine reports disconnected.

**Verification:** `cargo test -p vortix --lib engine::tests` passes. `rg 'Command::new' crates/vortix/src/engine/` returns zero matches.

---

### U5. Migrate `src/core/` callsites through the runner

**Goal:** Migrate network_monitor, telemetry (curl probes), and scanner.

**Requirements:** R10

**Dependencies:** U1, U2, U3, U4 (engine has runner threaded through)

**Files (modifications):**
- `crates/vortix/src/core/network_monitor.rs` (103 lines): `Command::new("route")` at line 23, `Command::new("ip")` at line 45 — both replaced with runner calls.
- `crates/vortix/src/core/telemetry.rs` (substantial; ~700 lines): all 4 `Command::new("curl")` callsites (lines 221, 313, 372, 409) and the `Command::new("ping")` (line 650) and `Command::new("curl")` at line 706 — replaced with runner calls. **Note: this PR routes curl through the runner with minimum-fuss mocks; the immediate follow-up retires curl for ureq.**
- `crates/vortix/src/core/scanner.rs` (556 lines): all `Command::new("ps")` calls (lines 94, 147), `Command::new("wg")` at line 180 — replaced.
- Add a `runner` parameter to the public functions in each module (or have them accept `&CommandRunner` via a struct holding the runner — e.g., `NetworkMonitor::new(runner: CommandRunner)`).

**Approach:**
- network_monitor and scanner functions today are free functions called from other modules; either wrap them in a struct holding the runner or pass the runner as an argument explicitly. Recommend: free functions taking `&CommandRunner` as the first arg (simpler refactor).
- telemetry today runs in a background thread polling the curl probes. The thread becomes a `tokio::spawn`'d task; the polling loop becomes `loop { tokio::time::sleep(...).await; runner.run(...).await; }`. This requires tokio runtime to be running; main.rs initializes it.

**Patterns to follow:**
- Match existing module structure: keep the parser logic (parsing `wg show` output, `ip route` output) verbatim — only the subprocess invocation changes.

**Test scenarios:**
- *Per-callsite migration: tests at the module level via MockRunner.*
- `crates/vortix/src/core/network_monitor.rs::tests`:
  - **Happy path:** Script `ip route show default` → returns parseable stdout. Assert parsed `default_gateway` matches expected.
  - **Error path:** Script `ip` → `ProgramNotFound`. Assert `network_monitor` returns a graceful "unknown" result.
- `crates/vortix/src/core/telemetry.rs::tests`:
  - **Happy path:** Script the IP-detection `curl` → returns IP string in stdout. Assert `current_ip()` returns parsed IP.
  - **Edge case — timeout:** Script `curl` → `Timeout`. Assert `current_ip()` returns `Err(...)` without crashing the telemetry loop.
- `crates/vortix/src/core/scanner.rs::tests`:
  - **Happy path — find active WG:** Script `ps -ax -o pid,command` → returns stdout listing a wg-quick process. Script `wg show <iface>` → returns peer info. Assert `scan()` returns an `ActiveSession` with the right interface name.
  - **Edge case — no active VPN:** Script `ps` → returns no wg/openvpn processes. Assert `scan()` returns empty.

**Verification:** Module-level tests pass. `rg 'Command::new' crates/vortix/src/core/` returns zero matches.

---

### U6. Migrate platform crate callsites through the runner

**Goal:** Migrate the `vortix-platform-{macos,linux}` crates (plan #001 relocated these from `src/platform/`).

**Requirements:** R10

**Dependencies:** U1, U2, U3

**Files (modifications):**
- `crates/vortix-platform-linux/src/firewall.rs` (~290 lines): the `IptablesFirewall::detect_backend()`, `engage()`, `disengage()` methods — all subprocess calls via `iptables` / `nft` / `which` go through the runner.
- `crates/vortix-platform-linux/src/dns.rs` (~105 lines): `resolvconf`, `systemd-resolve`, or similar — through the runner.
- `crates/vortix-platform-linux/src/interface.rs` (~89 lines): `ip` / `ip link` — through the runner.
- `crates/vortix-platform-linux/src/network.rs` (~17 lines): `cat /proc/net/dev` or similar; verify.
- `crates/vortix-platform-macos/src/firewall.rs` (~204 lines): `pfctl` operations — through the runner.
- `crates/vortix-platform-macos/src/dns.rs` (~86 lines): `scutil` / `networksetup` — through the runner.
- `crates/vortix-platform-macos/src/interface.rs` (~102 lines): `ifconfig` / `route` — through the runner.
- `crates/vortix-platform-macos/src/network.rs` (~66 lines): `netstat -ib` — through the runner.

**Files (modifications to the trait surface):**
- The existing informal traits at `crates/vortix/src/platform.rs` (per plan #001's transitional shape — see U3 of plan #001) take a `runner: &CommandRunner` parameter on each method, OR each impl holds an `Arc<CommandRunner>` field. Recommend: methods take the runner as an arg (avoids `Arc` clones and matches the future `Tunnel` trait shape from idea 5).
- Add `vortix-process = { path = "../vortix-process" }` to the platform crates' `Cargo.toml`.

**Approach:**
- The existing `IptablesFirewall::detect_backend()` uses `which iptables` / `which nft` probes — these go through the runner like everything else.
- Async migration: platform impl methods become `async`. Callers (the engine, which is now async per U4) await them naturally.
- The existing two-way path dep between platform crates and `vortix` (per plan #001's U3) is preserved; idea 6's PR cleans it up by moving the Firewall trait into `vortix-core`.

**Test scenarios:**
- `crates/vortix-platform-linux/tests/firewall_mock.rs`:
  - **Happy path:** Mock `which iptables` → exit 0; mock `iptables -L` → success. Assert `IptablesFirewall::detect_backend() == Iptables`.
  - **Backend fallback:** Mock `which iptables` → exit 1; mock `which nft` → exit 0. Assert backend == Nftables.
  - **No backend:** Both `which` calls fail. Assert `detect_backend()` returns `None` or an appropriate error.
  - **Engage:** Backend is iptables; mock all `iptables` rule-insertion calls succeed. Assert killswitch is engaged.
- Same shape for `macos/firewall.rs` with `pfctl` calls.

**Verification:** Platform crate tests pass on their respective OSes (or via cross-compile for sanity). `rg 'Command::new' crates/vortix-platform-{linux,macos}/src/` returns zero matches.

---

### U7. Migrate remaining callsites: `utils.rs`, `cli/report.rs`, `app/connection.rs`

**Goal:** Finish the migration with the smaller, scattered callsites.

**Requirements:** R10, R11

**Dependencies:** U1, U2, U3

**Files (modifications):**
- `crates/vortix/src/utils.rs`:
  - `run_with_timeout` helper at line 37 — REMOVED (functionality absorbed into `RealRunner` via the `timeout` field on `CommandSpec`).
  - `Command::new("date")` at line 421 — REPLACED with the `time` crate (`OffsetDateTime::now_local()`).
  - `Command::new("which")` at line 615 — through the runner.
  - `Command::new("resolvconf")` at line 636 — through the runner.
  - Internal helpers that call `run_with_timeout` need their bodies updated to use the runner.
- `crates/vortix/src/cli/report.rs`:
  - `Command::new(name)` at line 266 (the `<binary> --version` collection) — through the runner.
  - `Command::new(cmd)` at line 577 (`spawn` for bug-report diagnostic collection) — through the runner.
  - `Command::new(cmd)` at line 617 — through the runner.
  - These are diagnostic-collection calls; `PrivilegeReq::None`.
- `crates/vortix/src/app/connection.rs`:
  - Any remaining `Command::new` calls — through the runner.

**Approach:**
- `utils.rs` is a god-file; this PR replaces individual subprocess calls but does NOT split the file further. Splitting is deferred to idea 7's PR (which absorbs the config-related content) or a future cleanup PR.
- `cli/report.rs`'s diagnostic-collection calls run unprivileged; replacing them is mechanical.

**Test scenarios:**
- *Sparse — most behavior here is mechanical wrapping.*
- `crates/vortix/src/utils.rs::tests`:
  - **Happy path — time replacement:** Verify the new `time` crate-based timestamp helper returns a sensible RFC3339 string.
- `crates/vortix/src/cli/report.rs::tests`:
  - **Happy path — bug report diagnostic collection:** Mock the diagnostic subprocess calls (`uname`, `wg --version`, etc.) → success with deterministic stdout. Assert the bug report includes the captured info.

**Verification:** `rg 'Command::new' crates/vortix/src/utils.rs crates/vortix/src/cli/report.rs crates/vortix/src/app/connection.rs` returns zero matches. The `run_with_timeout` helper is removed (or marked deprecated and unused). `Command::new("date")` is gone.

---

### U8. Wire the runner through `main.rs` and configure `tracing-subscriber`

**Goal:** Construct the runner at program startup, thread it into the engine, and set up tracing output.

**Requirements:** R1, R7

**Dependencies:** U1, U2, U3, U4 (engine consumes the runner)

**Files (modifications):**
- `crates/vortix/src/main.rs`:
  - Add `#[tokio::main]` attribute to `main()` (or use `tokio::runtime::Runtime::new().block_on(async_main())` if `#[tokio::main]` is too invasive given the existing color_eyre/panic-hook setup).
  - Initialize `tracing-subscriber` early in `main()`: env-filter from `RUST_LOG`, format layer producing compact output on TTY and JSON on non-TTY (gated by `IsTerminal::is_terminal(&stdout())`). Defer JSON to idea 3's PR if it's substantial; for v1, simple compact format is fine.
  - Construct `CommandRunner::Real(RealRunner::new())` once, pass to `App::new(config, config_dir, runner)`.
- `crates/vortix/src/app/mod.rs`:
  - `App::new` accepts `runner: CommandRunner` and threads it to `VpnEngine::new(config, config_dir, runner)`.
  - `App::new_test()` constructs `CommandRunner::Mock(MockRunner::with_default_success())`.

**Files (additions to dependencies):**
- `crates/vortix/Cargo.toml`:
  - Add `vortix-process = { path = "../vortix-process" }` to `[dependencies]`.
  - Add `tokio = { workspace = true, features = ["rt-multi-thread", "macros"] }` for the runtime + `#[tokio::main]`.
  - Add `tracing = { workspace = true }, tracing-subscriber = { workspace = true, features = ["env-filter", "fmt"] }`.

**Approach:**
- The existing panic-hook + color_eyre dance (currently at the top of `main()`) stays; `tracing-subscriber` initialization comes after color_eyre install but before any vortix code runs.
- Tokio runtime: prefer `#[tokio::main(flavor = "multi_thread", worker_threads = 2)]` — small fixed pool sufficient for vortix's load (one telemetry task, one connect task, occasional CLI ops).

**Test scenarios:**
- *Test expectation: smoke only — exercising main() is integration-tested via the existing `tests/cli_integration.rs`.*
- Existing `tests/cli_integration.rs` tests pass with no modifications (they exercise the binary, which now uses the runner internally; output behavior unchanged).
- New: `tests/runner_integration.rs` with one test that exercises `vortix list --json` (which scans for profiles, a runner-mediated subprocess on macOS) and asserts the output structure.

**Verification:** Binary builds and runs. `RUST_LOG=vortix::process=debug vortix --help` emits tracing events for any subprocess invocation. `vortix list` works identically to pre-PR behavior on the maintainer's machine.

---

### U9. Implement `xtask check-subprocess` CI lint

**Goal:** Replace plan #001's `xtask check-subprocess` stub with a functional `rg`-driven lint.

**Requirements:** R12, R13

**Dependencies:** U1–U8 (all migration units complete; the lint enforces the end state)

**Files (modifications):**
- `crates/xtask/src/main.rs` (or `crates/xtask/src/subprocess_check.rs` if split): implement the `CheckSubprocess` subcommand:
  1. Run `rg --no-heading -n '\b(std::process|tokio::process)::Command::new\b' crates/` (or use the `ignore` crate to walk crates/ directly).
  2. Filter out matches inside `crates/vortix-process/src/real.rs` (the one legitimate use).
  3. Filter out lines with `// xtask:allow-subprocess` comments (explicit allowlist for legitimate exceptions with justification).
  4. Filter out `std::process::exit` matches (allowed — that's termination, not execution).
  5. Print any remaining matches with file:line:context. Exit code 1 if any matches; 0 otherwise.
  6. Also check `crates/xtask/` and `tests/` to prevent CI lint dodging via test-only `Command::new`.

**Files (new):**
- `.github/workflows/ci.yml` — add a step: `cargo xtask check-subprocess`. Fails the workflow on lint failure.

**Files (modifications):**
- `CONTRIBUTING.md` — add a brief note: "If you must invoke a subprocess directly (not through `CommandRunner`), add `// xtask:allow-subprocess: <reason>` to the same line. The CI lint will accept it."

**Approach:**
- Use the `ignore` crate (already a transitive dep via something) to walk the workspace, respecting `.gitignore`. Or use `std::process::Command` to invoke `rg` (note: the xtask itself can call `Command::new` because `xtask` is excluded from the lint target — but this is a recursion smell. Prefer `ignore`.)
- The `ignore` crate is small and well-maintained.

**Test scenarios:**
- `crates/xtask/tests/subprocess_check_tests.rs`:
  - **Happy path:** Run against a fixture directory with no `Command::new` calls outside an allowlisted file. Expect exit 0.
  - **Edge case — allowlisted file:** Fixture has `Command::new` inside `vortix-process/src/real.rs`. Expect exit 0.
  - **Edge case — annotated allow:** Fixture has `Command::new` with `// xtask:allow-subprocess: legitimate use` on the same line. Expect exit 0.
  - **Error path — uncovered call:** Fixture has `Command::new` in a random file with no annotation. Expect exit 1 with the file path in stderr.

**Verification:** `cargo xtask check-subprocess` exits 0 on the post-migration workspace. Introducing a deliberate `Command::new("test")` in any crate causes the next CI run to fail with the expected error message.

---

### U10. Update idea 1's brainstorm addendum + post-PR docs

**Goal:** Reflect the final migration in documentation.

**Requirements:** Reflects brainstorm Outstanding Question resolution + plan #001's R19.

**Dependencies:** U1–U9 (all migration done)

**Files (modifications):**
- `docs/brainstorms/2026-05-24-commandrunner-port-requirements.md`: Mark the Outstanding Question on `PrivilegeReq` variants as resolved (`Root` only for v1; `Capability(CapName)` deferred). Mark the redaction default as resolved (redact when marked explicitly; default is debug-info).
- `CONTRIBUTING.md`: Document the `CommandRunner` convention and the `xtask check-subprocess` lint.
- `README.md`: Add a brief "Testing" subsection noting that engine flows can be tested via `MockRunner` — example snippet.

**Test scenarios:**
- *Test expectation: none — documentation.*

**Verification:** Docs reflect the final design. Brainstorm doc's Outstanding Questions section is updated.

---

## Verification Strategy

End-to-end checks after all units land:

- `cargo build --workspace --all-targets --locked` succeeds.
- `cargo test --workspace --all-targets` passes — all existing tests + new MockRunner-driven tests for engine, core, platform.
- `cargo xtask check-subprocess` exits 0.
- `rg 'std::process::Command::new\|tokio::process::Command::new' crates/ | rg -v 'crates/vortix-process/src/real.rs'` returns zero results.
- Manual smoke test on maintainer's machine: connect to existing WG profile, observe identical behavior (latency, telemetry, kill switch).
- `RUST_LOG=vortix::process=info vortix up corp` emits tracing events for every subprocess invocation; no secrets appear in the output (no callsite uses `redact_in_audit` yet, so this just verifies the redaction infrastructure compiles).
- Engine state-machine correctness regressions covered by new MockRunner-driven tests are protected in CI.

---

## Risks & Mitigations

- **Async migration of the engine touches every callsite that calls engine methods.** TUI's event loop is synchronous (crossterm-based); it must block on async engine calls. Mitigation: wrap engine calls in `tokio::runtime::Handle::current().block_on(...)` from the TUI thread; idea 3's EngineHandle / actor-mailbox properly decouples this. Document this as transitional.
- **Tokio runtime startup adds binary startup latency.** Today's vortix has no async runtime; introducing `#[tokio::main]` adds tens of milliseconds. Acceptable — well within human-perceptible thresholds. If profiling shows it matters, switch to `current_thread` flavor for CLI invocations.
- **`enum_dispatch` + AFIT interaction may have rough edges.** Worst case: hand-rolled match-arm dispatch with explicit method-by-method forwarding. Mitigation: U1's verification includes building a small test program that exercises the enum's `CommandRunner` impl via both variants.
- **CI lint false positives.** Comments like `// example: Command::new("foo")` in doc strings could trip the lint. Mitigation: use `rg`'s `-g '!**/*.md'` to exclude docs; alternatively use `tree-sitter`-based parsing (overkill).
- **DetachedSpawn PID lifetime on macOS.** Detached children survive `Child` drop on Unix, but the PID space is not guaranteed unique forever (PID reuse). For `kill -0 <pid>` liveness checks, this is a known limitation accepted by today's code; not made worse by this refactor.
- **Telemetry curl→runner→ureq churn.** This PR routes curl through runner; immediate follow-up retires curl. Mocks written for curl in this PR are deleted in the follow-up. Mitigation: write minimum-fuss mocks for telemetry curl (scripted exact-match outcomes), not elaborate ones.

---

## Scope Boundaries

- **Replacing `curl` with `ureq`** — deferred to immediate follow-up PR `feat(telemetry): replace curl shell-out with ureq`. This PR routes curl through the runner with minimum-fuss mocks.
- **Splitting `crates/vortix/src/utils.rs`** — out of scope. The god-file relocates intact in plan #001 and remains intact here (with subprocess calls retargeted).
- **Supervised long-running processes** (`spawn_supervised` method, boringtun/wireguard-go support) — deferred to when idea 4's daemon brings userspace WG into scope. Trait shape accommodates the method.
- **`pkexec` / polkit GUI escalation, setuid privilege-separated helpers** — v1.0+ work. Idea 4 Phase B brainstorm covers them.
- **Audit log persistence** — `RealRunner` emits `tracing` events; idea 3's event journal subscribes to them and persists. Not in this PR.
- **`Dry-run` mode** — `CommandSpec.redact_in_audit` reserved; dry-run interceptor lands with idea 10/25 Plan/Apply work (deferred from the original ideation).
- **Replacing other shell-outs in the binary** (e.g., `open` crate for browser launching, which currently uses subprocess invocation under the hood) — out of scope. The `open` crate's subprocess use is its problem.
- **MSRV bump or tool-version bump** — out of scope.

### Deferred to Follow-Up Work

- `feat(telemetry): replace curl shell-out with ureq` — immediate follow-up PR retiring the 4 curl callsites in `core/telemetry.rs` in favor of the `ureq` crate. Removes the curl mocks added in this PR.
- Audit-log integration: when idea 3's event journal lands, add a subscriber that captures `vortix::process` tracing events to the journal.
- Capability-based privilege (`PrivilegeReq::Capability(CAP_NET_ADMIN)` on Linux) — added when the Linux capability ports (idea 6) demand it.

---

## Outstanding Questions

### Resolve Before Planning

(None — all material decisions resolved in the brainstorm.)

### Deferred to Implementation

- Exact builder API surface for `CommandSpec::oneshot()` vs `CommandSpec::detached()` — fluent style vs constructor variants. Mechanical; ce-work picks.
- Whether `RealRunner` should use `tokio::task::spawn_blocking` for any operations (probably not — `tokio::process` is async-native). Verify at implementation time.
- How to gate the tokio runtime's flavor: `current_thread` for CLI invocations (lower memory, fewer threads) vs `multi_thread` for daemon mode. v1: `multi_thread(2)`; daemon (idea 4 Phase B) tunes later.
- Whether `MockRunner::with_default_success()` should also auto-record invocations or stay invocation-recording-by-default. Mechanical preference.
- Exact format for `tracing-subscriber`'s output: `tracing_subscriber::fmt::format::Compact` vs `Pretty`. Verify rendered output during implementation.
- Whether to add a `vortix --debug-subprocess` CLI flag that elevates `RUST_LOG` automatically for the duration of a CLI invocation. Nice-to-have; defer if scope expanding.
- Exact wording of `ProcessError`'s `next_actions` arrays. Mechanical wording; align with idea 4 Phase A's structured error patterns.
- Whether to use `tokio::sync::Semaphore` or per-callsite serialization to prevent concurrent runner invocations stepping on each other (probably no — engine flows are inherently single-active-connection). Verify at implementation time.
- Exact set of `[workspace.dependencies]` to add: `tokio`, `tracing`, `tracing-subscriber`, `enum_dispatch`, `thiserror` versions. Recommend latest stable; ce-work picks.
