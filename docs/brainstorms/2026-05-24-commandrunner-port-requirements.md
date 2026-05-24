---
date: 2026-05-24
topic: commandrunner-port
---

# CommandRunner / Process Port

## Summary

Introduce one async `CommandRunner` trait that every subprocess in vortix flows through, with two `enum_dispatch` variants (`RealRunner` for production, `MockRunner` for tests), a `CommandSpec`/`CommandOutcome` data shape covering one-shot and detached spawn, and a CI lint that prevents new `Command::new` callsites outside the runner module. This is the foundational refactor that makes connection flows unit-testable without root or real `wg`/`openvpn`, and it seeds structured observability for the rest of the architectural migration (FSM + event journal, daemon, Tunnel trait, capability ports).

---

## Problem Frame

Every subprocess in vortix today calls `std::process::Command::new(...)` inline at the call site. The callsites live across `src/engine/connection.rs`, `src/engine/mod.rs`, `src/core/{network_monitor,telemetry,scanner}.rs`, `src/utils.rs`, `src/cli/report.rs`, `src/platform/{linux,macos}/*`, and a few other places. The set of programs invoked includes `wg-quick`, `wg`, `openvpn`, `kill`, `pkill`, `ip`, `route`, `ps`, `curl`, `ping`, `resolvconf`, `which`, and (oddly) `date`.

Two pains stack on top of each other and compound:

**Connection flows are effectively untested in CI.** A test that exercises `engine::connection::connect_wireguard` needs `wg-quick` installed, root privilege, and a working network interface. CI does not have those. The result is that `app/tests.rs` covers TUI mechanics but the engine's mutation paths — the parts that *matter* when a bug ships — are exercised only by hand, only on the maintainer's laptop, and only against the maintainer's environment. The roadmap's strongest correctness commitments (v0.1.7 retry cap, rename-safe reconnect, deduped warnings) all live in code paths that this gap leaves untested.

**Observability is structurally absent.** When a subprocess is invoked inline with no shared seam, there is no place to attach structured logging, no place to write audit records, no place to insert a dry-run interceptor, and no place to enforce policy (privilege requirements, timeouts, allowed-binary lists). Every roadmap item that wants any of those — audit logging, lifecycle hooks, agent-native dry-run, security review — must either invent its own seam or accept that vortix cannot offer it. The 26 KB `config.rs` and 35 KB `utils.rs` both contain subprocess code that contributes to the god-file pain because there is nowhere else to put generic process-handling helpers.

The bug shape that motivates urgency: a regression in the connect path (wrong arg ordering, missing env var, exit-code handling drift) ships to a user and is discovered when they cannot connect to their corporate VPN. There is no failing test in CI because there could not be one.

---

## Actors

- A1. **Contributor writing a new feature** — wants to write a unit test that exercises an engine path without setting up a real WireGuard environment.
- A2. **Contributor refactoring an existing flow** — wants to know what subprocess invocations the existing flow makes and what their expected outcomes are, without having to grep callsites.
- A3. **CI** — runs `cargo test` in an environment with no root, no real VPN binaries, and no network. Must be able to exercise the engine.
- A4. **Future audit-log subscriber (idea 3 of 7)** — wants a structured record of every subprocess invocation with start/end timestamps, program, args (with secrets redacted), exit, and the requesting state-machine transition.
- A5. **Future daemon `vortixd` (idea 4 of 7)** — owns the `RealRunner` instance and runs it as root; user-facing CLI/TUI never holds a `RealRunner` directly in this future state.
- A6. **Agent invoking vortix as a tool** — wants structured `next_actions` when an op fails (e.g., privilege denial) and eventually wants a dry-run mode that prints what would happen without executing.

---

## Key Flows

- F1. **Contributor writes a test for a connect path**
  - **Trigger:** Contributor adds a new test in `engine/connection.rs::tests` for "connect fails cleanly when `wg-quick up` exits non-zero."
  - **Actors:** A1, A3
  - **Steps:**
    1. Test constructs a `MockRunner` with a scripted response: `wg-quick up <iface>` returns exit 1 with stderr `"Address already in use"`.
    2. Test passes the `MockRunner` to the connect path.
    3. Connect path invokes the runner; receives the scripted outcome.
    4. Test asserts the engine transitioned to `Failed` with the expected error class.
    5. Test verifies via the `MockRunner` invocation log that exactly one call was made, with the expected program and args.
  - **Outcome:** The test passes in CI with no root, no `wg`, no network. The contributor did not have to mock anything beyond scripting one `CommandSpec → CommandOutcome` pair.
  - **Covered by:** R1, R2, R3, R7, R8

- F2. **Subprocess invocation in production**
  - **Trigger:** Engine's connect path needs to run `wg-quick up <iface>`.
  - **Actors:** A2, A4
  - **Steps:**
    1. Engine constructs a `CommandSpec { program: "wg-quick", args: ["up", iface], requires_privilege: PrivilegeReq::Root, kind: Kind::OneShot, ... }`.
    2. Engine calls `runner.run(spec).await`.
    3. `RealRunner` checks current uid against `requires_privilege`; if mismatch, returns `Err(ProcessError::PrivilegeDenied { next_actions: [...] })` without executing.
    4. Otherwise `RealRunner` emits a `tracing` span ("subprocess.start"), executes via `tokio::process::Command`, waits for completion or timeout, emits "subprocess.end" with exit + duration.
    5. Engine receives `Ok(CommandOutcome { stdout, stderr, exit_status, duration })` and continues.
  - **Outcome:** The subprocess ran with structured observability and policy enforcement around it.
  - **Covered by:** R1, R4, R5, R10

- F3. **Privilege denial UX**
  - **Trigger:** User runs `vortix up corp` as a non-root user; daemon mode not installed.
  - **Actors:** A6
  - **Steps:**
    1. CLI dispatches to engine connect path.
    2. `RealRunner` rejects the first privileged subprocess with `ProcessError::PrivilegeDenied`.
    3. Engine surfaces the error through the CLI's JSON envelope with structured `next_actions`: `[{"action": "rerun_as_root", "hint": "sudo vortix up corp"}, {"action": "install_daemon", "hint": "see https://… (recommended for repeated use)"}]`.
    4. Exit code is the semantic "privilege required" code (one of the existing 0-6 set).
  - **Outcome:** User and agent both get an actionable response. No silent failure, no fragile auto-sudo prompt.
  - **Covered by:** R5, R6

---

## Requirements

**The trait and data types**

- R1. Define one trait `CommandRunner` with an async `run` method (and an explicit `spawn_detached` method) modeled on rustup's `Process` abstraction. Use native AFIT (Rust 1.75+; vortix's MSRV is already 1.75). The trait is not `dyn`-compatible by construction.
- R2. Define `enum CommandRunner { Real(RealRunner), Mock(MockRunner) }` (or equivalent via `enum_dispatch`) so that callers hold a single concrete type without `Box<dyn>` or generics threading. The variant set is closed by design — third-party variants are not a use case.
- R3. Define `CommandSpec` carrying at minimum: `program`, `args`, optional `env`, optional `cwd`, optional `stdin_bytes`, optional `timeout`, `requires_privilege: PrivilegeReq`, `kind: Kind { OneShot, DetachedSpawn }`. Future extensions reserved: `redact_in_audit: Vec<ArgIndex>` for secrets, `dry_run: bool`.
- R4. Define `CommandOutcome` for `OneShot`: `stdout: Vec<u8>`, `stderr: Vec<u8>`, `exit_status`, `duration`, `started_at`. For `DetachedSpawn`: `pid`, `spawned_at`, plus a way to check liveness later (which itself goes through the runner as a separate `OneShot` invocation of `kill -0`).
- R5. Define `ProcessError` as a `thiserror` enum with at least these variants: `PrivilegeDenied`, `ProgramNotFound`, `Timeout`, `Killed`, `NonZeroExit`, `IoError`. Each variant carries enough context to populate the JSON envelope's `next_actions` field.

**Privilege model**

- R6. `RealRunner` does not auto-escalate. When `spec.requires_privilege == Root` and the process is not effective-uid 0, return `ProcessError::PrivilegeDenied` without executing the program. Read-only ops (`status`, `list`, `wg show`, `ps`, `which`, `route get`, IP probes) set `requires_privilege: None` and run unprivileged.

**Observability**

- R7. `RealRunner` emits structured `tracing` events for every invocation: at minimum a start event (program, redacted args, requires_privilege, spec.kind) and an end event (exit_status, duration). These are the seed of audit logging; durable persistence is deferred to idea 3's event journal.
- R8. `MockRunner` records every invocation it received in an ordered log accessible to tests, and exposes assertion helpers (e.g., `assert_called_once_with(matcher)`, `assert_no_remaining_expectations()`).

**Testing surface**

- R9. `MockRunner` is constructed from an ordered list of expectations: `(matcher, scripted_outcome)`. Matchers can match on program, args (exact or pattern), env subset, and `requires_privilege`. Calls not matching any expectation cause the test to fail with a clear diagnostic.

**Migration scope (big-bang)**

- R10. **Every existing subprocess callsite in `src/` is migrated to flow through the runner in a single PR.** The set must cover all callsites the codebase scan identified: `src/engine/connection.rs`, `src/engine/mod.rs`, `src/core/network_monitor.rs`, `src/core/telemetry.rs` (including the four `curl` probe sites), `src/core/scanner.rs`, `src/utils.rs`, `src/cli/report.rs`, `src/app/connection.rs`, `src/platform/linux/{dns,interface,firewall}.rs`, `src/platform/macos/network.rs`. No callsite may be partially migrated.
- R11. The PR removes the `Command::new("date")` callsite at `src/utils.rs:421` and replaces it with the `time` crate (existing dep) rather than routing through the runner.

**CI enforcement**

- R12. The same PR adds a CI check (via `xtask check-subprocess` or a GitHub Actions step running `rg`) that fails the build if `std::process::Command::new` or `tokio::process::Command::new` appears anywhere in `src/` outside the runner module's allow-listed file(s). The lint must explicitly allow `std::process::exit(...)` (process termination, not subprocess execution).
- R13. The lint covers the entire `src/` tree, not only the runner module. Test code that legitimately needs raw subprocess access (e.g., spawning a helper binary) requires an explicit `#[allow]`-equivalent comment and a justification on the same line.

---

## Acceptance Examples

- AE1. **Covers R1, R6.** Given a `RealRunner` and a `CommandSpec` with `requires_privilege: Root`, when the current process is not effective-uid 0, then `runner.run(spec).await` returns `Err(ProcessError::PrivilegeDenied)` without invoking the program, and `which` confirms the program file was not stat'd.

- AE2. **Covers R2, R9.** Given a `MockRunner` constructed with an expectation matching `wg-quick up <any>` and a scripted outcome of exit 1 with stderr "Address already in use", when the connect path runs, then the engine receives that exact `CommandOutcome` and the `MockRunner`'s invocation log shows exactly one call with `program: "wg-quick"` and `args: ["up", _]`.

- AE3. **Covers R3, R4.** Given a `CommandSpec` with `kind: DetachedSpawn` (e.g., `openvpn --daemon --config corp.ovpn`), when the runner is invoked, then the returned `CommandOutcome::Detached { pid, spawned_at }` carries a valid pid that survives the call returning, and a subsequent `kill -0 <pid>` invocation through the runner returns exit 0 while the process is alive.

- AE4. **Covers R5.** When a privileged op fails with `ProcessError::PrivilegeDenied`, then the CLI's JSON envelope `next_actions` field contains both an "rerun_as_root" hint and an "install_daemon" hint (in that order), and the process exits with the semantic privilege-required exit code.

- AE5. **Covers R12, R13.** When a contributor opens a PR that adds `std::process::Command::new("ls")` inside `src/core/foo.rs`, then CI fails with a clear error pointing at the file and line and naming the `CommandRunner` trait as the required path; when the contributor moves the same call into the runner module's allow-listed file, CI passes.

- AE6. **Covers R7.** When `RealRunner` executes any subprocess, then a `tracing` event with target `vortix::process` and fields `program`, `redacted_args`, `requires_privilege`, `kind` is emitted at start, and a paired event with `exit_status` and `duration` is emitted at end.

- AE7. **Covers R10.** When the migration PR lands, then `rg 'Command::new' src/` outside the runner module returns zero matches.

---

## Success Criteria

- A new test exercising an engine state transition that depends on subprocess outcomes runs in CI with no root, no real VPN binaries, and no network — and a contributor can write such a test in one file, with one `MockRunner` builder, in under 20 lines of test setup.
- A future audit-log subscriber (idea 3 of 7) can begin capturing every subprocess invocation by subscribing to one `tracing` target — no further changes to `RealRunner` required.
- A future `vortixd` daemon (idea 4 of 7) owns a single `RealRunner` instance; the user-facing CLI/TUI hold no `RealRunner` and never invoke a `std::process::Command::new` directly. The architectural path from "library that ships a binary" to "daemon + thin clients" does not require revisiting this trait.
- The connect-path bugs covered by v0.1.7's "Dependable" milestone (retry cap, rename-safe reconnect, deduped "IP unchanged" warning) become testable in CI as a side effect of this refactor.

---

## Scope Boundaries

- **Supervised long-running processes** (`boringtun`, `wireguard-go` userspace tunnels where vortix is the parent process watching stdout/stderr and restarting on exit) are out of scope. The trait is designed so a `spawn_supervised(spec) -> SupervisedHandle` method can be added cleanly later. The expected home for this is idea 4's daemon.
- **`pkexec` / polkit GUI escalation** and **setuid privilege-separated helpers** (`vortix-priv`) are out of scope. Both are valid v1.0+ work as additional `RealRunner`-variant adapters behind the same trait, not changes to this PR.
- **Retiring `curl` in favor of `ureq`** is out of scope for this PR. The four `curl` HTTP-probe callsites in `src/core/telemetry.rs` route through the runner in v1; a separate, smaller follow-up PR (`feat(telemetry): replace curl shell-out with ureq`) replaces them.
- **Durable audit-log persistence** is out of scope. This PR emits `tracing` spans; idea 3's event journal subscribes to those spans and persists them.
- **`Dry-run` mode** is out of scope as a runtime feature for v1. The `CommandSpec` reserves the field; the actual interceptor lands with idea 10/25's Plan/Apply work.
- **Test fakes for the `Tunnel` trait (idea 5)** are out of scope. The `Tunnel` trait will consume the runner; mock fixtures for individual tunnel kinds belong to that PR.
- **Replacing `Command::new("date")`** is in scope only for the one callsite at `src/utils.rs:421`; no other date/time work is included.

---

## Key Decisions

- **Native AFIT over `async_trait`.** Rust 1.75 MSRV is already met (Cargo.toml line 5). AFIT avoids boxed-future allocation and macro overhead; the trade-off (no `dyn` compatibility) is acceptable because `enum_dispatch` provides cleaner static dispatch.
- **`enum_dispatch` over `Box<dyn CommandRunner>`.** The variant set is closed (`Real`, `Mock`, future `Pkexec`, future `Daemon-IPC`). Static dispatch is faster, simpler, and consistent with idea 5's `TunnelKind` pattern.
- **Tokio adopted now, not deferred.** Vortix currently has no async runtime, but ideas 3 and 4 force tokio's adoption later. Anchoring it here pays off immediately for the existing `openvpn --daemon` spawn-and-track pattern (which today juggles `kill -0` polling in tight loops) and avoids a second architectural disruption later.
- **Fail-fast privilege model, not auto-escalation.** `RealRunner` records the requirement and rejects when uid mismatches; it does not attempt sudo/pkexec inline. The long-term privilege solution is the daemon (idea 4), modeled on NordVPN/Mullvad/Tailscale. This PR's job is to make privilege a typed, observable, testable concept — not to solve escalation UX.
- **Big-bang migration in one PR.** All ~20 subprocess callsites migrate together, with the CI lint added in the same PR. Trade-off: one large review vs many small ones. Chosen because a partial migration creates a window where the lint cannot be enforced and contributors can keep adding raw `Command::new` calls.
- **`tracing` as the observability layer.** Vortix does not currently use `tracing`; this PR introduces it as a dependency. Existing `eprintln!`/`color_eyre` reporting in the binary edge is unchanged.
- **`curl` routed through the runner in v1, retired in a follow-up.** Keeps scope tight; mocks for telemetry's curl callsites are minimum-fuss because they will be deleted in the follow-up `ureq` PR.

---

## Dependencies / Assumptions

- **Vortix's MSRV remains 1.75.** Native AFIT requires it. Bumping MSRV is not part of this work.
- **`tokio` enters the dependency tree as a top-level dep.** Feature flags scoped to what the runner uses (`rt-multi-thread`, `process`, `time`, `macros`); other crates touched by the migration get tokio transitively, which is fine because ideas 3 and 4 will use it more deeply.
- **`tracing` and `tracing-subscriber`** enter the dep tree. A minimal subscriber configured in `main.rs` honors `RUST_LOG`; later work tightens this.
- **`enum_dispatch` (crate)** enters the dep tree. Pure-macro; tiny.
- **No new external binary dependencies are introduced.** Routing through the runner does not change which external programs vortix calls; it only changes who calls them.
- **`tokio::process::Child` PID lifetime is the assumption that lets `DetachedSpawn` work.** Detached children survive their parent's `Child` handle being dropped, which is what `openvpn --daemon` relies on. Verified in tokio docs.
- **Test environment is single-threaded for `MockRunner` assertions.** Default `#[tokio::test]` is sufficient; multi-threaded test contexts that share a `MockRunner` need to wrap it in a `Mutex` (documented but not provided).

---

## Outstanding Questions

### Resolve Before Planning

- [Affects R3, R5][User decision] Final list of `PrivilegeReq` variants — is `Root` sufficient for v1, or do we need `Capability(CapName)` (e.g., `CAP_NET_ADMIN`) on Linux from day one? Default: `Root` only; capabilities deferred until the Linux platform adapter (idea 6) asks for them.
- [Affects R7][User decision] Should `tracing` event fields include the *unredacted* args by default (developer machine) and require explicit redaction (production), or be redacted by default? Default: redacted by default; debug build can opt in via env var.

### Deferred to Planning

- [Affects R10][Technical] Exact migration ordering inside the single PR — engine first, then platform adapters, then telemetry, then cli/report, then utils — or alphabetical by file. Mechanical; planner picks.
- [Affects R12][Technical] Whether the CI lint is implemented as `xtask check-subprocess` (Rust binary, runs everywhere) or a GitHub Actions step (faster CI but no local check). `xtask` is preferred per the workspace direction (idea 2) but cargo workspace doesn't exist yet at the time of this PR.
- [Affects R2][Needs research] Whether `enum_dispatch` plays cleanly with AFIT, or whether a hand-coded `enum CommandRunner` with explicit match arms is safer. Verify before locking in.
- [Affects R8, R9][Technical] Builder API surface for `MockRunner` — what idioms feel right in vortix's test style. Look at `app/tests.rs` patterns first.
- [Affects R3][Technical] Whether `CommandSpec::env` should be a "merge into current env" map or a "replace entire env" map. WireGuard scripts that source `/etc/wireguard/<iface>.conf` may rely on full env; defaults to merge.
- [Affects R7][Technical] Choice of `tracing-subscriber` config in `main.rs` — pretty layer for TTY, JSON layer when stdout is piped. Mechanical; planner picks.
