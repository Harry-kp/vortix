---
date: 2026-06-02
topic: openvpn-interactive-auth
origin_issue: https://github.com/Harry-kp/vortix/issues/191
---

# OpenVPN interactive mid-connect auth (2FA challenge + key passphrase)

## Summary

Activate the reserved `Connection::AwaitingUserInput` state (plan 008 U2) for OpenVPN profiles that require interactive input mid-connect — both server-issued 2FA challenges (static-challenge inline OTP and dynamic CRV1 challenge-response) and encrypted private-key passphrases. The OpenVPN supervisor changes from daemonized log-polling to a foreground child supervised over a per-tunnel management socket; the TUI surfaces a new mid-connect Prompt overlay, and `vortix connect` re-prompts on the controlling tty. Reconnects must preserve the server-issued `auth-token` so users don't re-MFA on every link flap.

---

## Problem Frame

OpenVPN today is spawned with `--daemon`, forks/detaches, and is observed by polling its log file for the success marker (`Initialization Sequence Completed`) or one of seven known error patterns (see `crates/vortix/src/vortix_protocol_openvpn/tunnel.rs` lines 23–35). There is no live channel — no stdin handle, no management socket — between vortix and the running daemon.

When a profile requires interactive input that the server prompts for *after* the initial username/password exchange, OpenVPN cannot complete the handshake. The two real-world cases:

1. **Dynamic CRV1 challenge** — server returns `>PASSWORD:Verification Failed: 'Auth' ['CHALLENGE: <text>']`. Without a management socket, the daemon hangs in `>HOLD:Waiting for hold release` and never logs the success marker. The connect-timeout path eventually fires and we return a generic timeout error — the user-reported "TUI crashes" in issue #191 is the visible symptom.
2. **Encrypted private-key passphrase** — server-independent. OpenVPN cannot decrypt the .key embedded in or referenced by the .ovpn without the passphrase. Same end state — silent hang followed by timeout.

The static-challenge path (server pre-declares it accepts inline OTP in the auth file) is technically reachable today by hand-crafting the auth file's second line as `SCRV1:base64(password):base64(otp)`, but vortix has no UI surface to collect the OTP and no parser flag to know when to use this format. So in practice all three modes fail.

The fix is architectural: the OpenVPN child must be foregrounded and supervised over a management socket so the runtime can both *observe* prompts and *respond* to them. The `AwaitingUserInput` FSM state, `PromptKind::{TwoFactorCode, Passphrase, Generic}`, sigil (`?`), and Connection-Details hint scaffolding all already exist (plan 008 U2) — they were reserved for this issue and currently have no producer.

---

## Actors

- **A1. End-user with an MFA-protected OpenVPN profile.** Has a corporate or commercial VPN that requires a TOTP / SMS code or a Duo / Okta dynamic challenge. Today the connect attempt silently hangs and they cannot use vortix for this profile.
- **A2. End-user with a passphrase-protected .ovpn profile.** Exported their certificate bundle with a key passphrase for at-rest security. Same end state as A1 — silent hang.
- **A3. CLI user running `vortix connect <profile>` from a terminal.** Expects to type the code at the same prompt they typed username/password into. Today the binary exits with a generic timeout.

---

## Key Flows

- **F1. Connect with dynamic CRV1 challenge (issue #191 primary path).**
  - **Trigger:** A1 selects an MFA profile and presses Enter (TUI) or runs `vortix connect <profile>` (CLI).
  - **Steps:** Existing auth overlay collects username + password and writes the auth file. OpenVPN spawns in foreground with `--management <socket> unix --management-hold --management-query-passwords`. After username/password is consumed, the server returns CRV1. The supervisor parses the `>PASSWORD:Verification Failed: 'Auth' ['CHALLENGE: <text>']` line, emits an FSM event, the runtime transitions to `AwaitingUserInput { prompt_kind: TwoFactorCode }`. TUI shows the mid-connect Prompt overlay; CLI re-prompts on the controlling tty. User types the code; runtime writes `password 'Auth' "CRV1::<state-id>::<code>"` to the socket. Server accepts; `>STATE:CONNECTED` arrives; FSM transitions to `Connected`.
  - **Outcome:** Connection establishes. The sigil `?` is visible during the wait state; the existing Press-[Enter]-to-provide hint surfaces in Connection Details.
  - **Covered by:** R1, R2, R4, R5, R7, R10, R11

- **F2. Connect with static-challenge profile (inline OTP).**
  - **Trigger:** A1 selects a static-challenge profile.
  - **Steps:** Same first-pass auth as F1. The supervisor sees `>PASSWORD:Need 'Auth' username/password SC:1,<prompt-text>` *before* sending credentials. FSM transitions to `AwaitingUserInput { prompt_kind: TwoFactorCode }` immediately after the username/password overlay closes; runtime sends `username 'Auth' <user>` and `password 'Auth' "SCRV1:base64(password):base64(code)"` together.
  - **Outcome:** Same as F1. The user experience is identical regardless of which challenge mode the server uses — the supervisor's parser distinguishes; the overlay does not.
  - **Covered by:** R1, R2, R3, R4, R5, R7, R10

- **F3. Connect with passphrase-protected private key.**
  - **Trigger:** A2 selects a profile whose key requires a passphrase.
  - **Steps:** Supervisor sees `>PASSWORD:Need 'Private Key' password`. FSM transitions to `AwaitingUserInput { prompt_kind: Passphrase }`. Overlay labels the field "Private key passphrase" (versus "2FA code" for F1/F2). Runtime writes `password 'Private Key' <passphrase>` to the socket. Continues to the auth phase if username/password is also required.
  - **Outcome:** Profiles with encrypted keys now connect. `PromptKind::Passphrase` scaffolding activates.
  - **Covered by:** R1, R2, R6, R7, R10

- **F4. Reconnect after link flap on an MFA profile.**
  - **Trigger:** A1's network drops briefly; the existing reconnect path attempts to bring the tunnel back without user involvement.
  - **Steps:** OpenVPN client has cached the server-issued `auth-token`. The reconnect path signals the existing child (SIGUSR1 / management `signal SIGUSR1`) rather than tearing it down and respawning. OpenVPN re-authenticates using the token; no `>PASSWORD:` event fires; `AwaitingUserInput` is not entered.
  - **Outcome:** User does not re-MFA on link flap. Without this constraint, every reconnect would re-prompt — a regression for MFA users.
  - **Covered by:** R8

- **F5. User cancels the mid-connect prompt.**
  - **Trigger:** Prompt overlay is showing; user presses Esc / chooses Cancel.
  - **Steps:** Runtime sends `signal SIGTERM` over the management socket, child exits cleanly, FSM transitions to `Disconnected { last_failure: Some(UserCancelled) }`. Socket file and any auth artifacts are cleaned up.
  - **Outcome:** No orphaned openvpn child; subsequent connect attempts on the same profile start clean.
  - **Covered by:** R9, R11

- **F6. CLI run on a non-interactive tty (piped / cron).**
  - **Trigger:** A3 runs `vortix connect <mfa-profile>` from a non-tty context (no controlling terminal, or stdin redirected).
  - **Steps:** Engine transitions to `AwaitingUserInput`. The CLI prompt helper detects non-interactive stdin and exits non-zero with a message naming the prompt kind and pointing to the TUI or to a future `--otp` flag. Child is torn down cleanly.
  - **Outcome:** Loud, actionable failure instead of an indefinite hang.
  - **Covered by:** R12

---

## Requirements

**Supervisor architecture**

- R1. OpenVPN runs in the foreground (no `--daemon`). The vortix runtime owns the child for the tunnel's full lifecycle, including reconnects, and is responsible for signal-based shutdown and orphan cleanup on crash.
- R2. Each tunnel has a dedicated Unix domain management socket path keyed off the profile's sanitized name (e.g. `<run_dir>/<safe_name>.mgmt.sock`). The supervisor parses the standard OpenVPN management protocol (`>STATE:`, `>HOLD:`, `>PASSWORD:`, `>NEED-OK:`, `>LOG:`, etc.) and translates relevant lines into FSM events. Readiness is signalled by `>STATE:CONNECTED`; log-file polling for the success marker is no longer required (the log file remains for diagnostics).
- R3. The static-challenge path is not a separate code path. The supervisor distinguishes static-challenge from dynamic CRV1 by parsing the `SC:1,<prompt>` suffix on the `>PASSWORD:Need 'Auth'` line versus the `CHALLENGE: <text>` payload on a CRV1 verification-failed line. Both flow through the same `AwaitingUserInput` transition.

**Prompt surfaces**

- R4. The runtime emits an FSM event that transitions `Connecting` → `AwaitingUserInput { profile_id, prompt_id, prompt_kind, since }` whenever the supervisor parses a 2FA challenge, a static-challenge request, or a private-key passphrase request. `prompt_id` is unique per prompt instance so responses cannot be misrouted.
- R5. The TUI renders a new Mid-Connect Prompt overlay when any tunnel is in `AwaitingUserInput`. The overlay shows: the profile name, a label derived from `prompt_kind` ("2FA code", "Private key passphrase", or the `Generic { label }` text), a single masked text input, a Submit / Cancel pair, and the elapsed wait time. The overlay reuses the existing auth-overlay layout primitives.
- R6. The existing sigil (`?`), header banner, sidebar marker, footer hint, and Connection-Details "Press [Enter] to provide …" line (already shipped in plan 008 U2) all fire correctly for both `TwoFactorCode` and `Passphrase` prompt kinds.
- R7. Submitting the prompt overlay writes the response over the management socket using the OpenVPN management protocol's `password '<realm>' <value>` form, with `<realm>` set to `Auth` for credentials/challenges and `Private Key` for passphrases. The response includes the static-challenge `SCRV1:` envelope when the supervisor identified the prompt as static-challenge.

**Reconnect & token survival**

- R8. The reconnect path for an MFA profile preserves the running openvpn child and triggers internal re-auth (e.g. via management `signal SIGUSR1`). The supervisor must not tear down and respawn the child on transient link failures for tunnels that have received an `auth-token` from the server. (A child that has not yet received an auth-token may still be torn down on hard failures.)

**Lifecycle**

- R9. User-cancel from the Prompt overlay (Esc or the Cancel control) transitions the FSM to `Disconnected { last_failure: Some(...) }` and the supervisor shuts the child down cleanly. The socket file is removed.
- R10. The FSM holds in `AwaitingUserInput` until the user submits, cancels, or a wait-state timeout fires. The timeout is distinct from the existing connect-timeout: it begins when `AwaitingUserInput` is entered and pauses the connect-timeout for its duration so a slow human typing a code does not register as a connect failure. Default timeout: 120 seconds (tunable in planning).
- R11. Multi-tunnel: when more than one tunnel is in `AwaitingUserInput` concurrently, each owns its own management socket and `prompt_id`. The overlay surfaces prompts one at a time, sequenced by `since`; submissions are routed by `prompt_id`. The existing sidebar `?` sigil marks every waiting tunnel.

**CLI parity**

- R12. `vortix connect <profile>` blocks while the engine is in `AwaitingUserInput`, reads the response from the controlling tty using a masked prompt, and writes it back to the engine. If stdin is not a tty (piped, cron, no controlling terminal), the CLI exits non-zero with an error that names the prompt kind and refers the user to the TUI; the supervisor cleans up the child before exit.

---

## Scope boundaries

**In this shipment**
- OpenVPN 2FA / MFA challenge — both static-challenge (inline SCRV1) and dynamic CRV1.
- Encrypted private-key passphrase prompt.
- Foreground supervised openvpn with per-tunnel management socket; multi-tunnel parity.
- TUI mid-connect Prompt overlay + CLI tty re-prompt.
- `auth-token` survival on reconnect (non-regression constraint).

**Deferred for later**
- **Push-based MFA (Duo Push, Okta Verify Push, etc.).** Same transport but the UX is a wait-state with spinner and Cancel, not a text field. Deserves its own brainstorm because the prompt surface diverges meaningfully — challenge text contains "push" but rendering a text input there confuses the user.
- **PKCS#11 / smartcard / hardware-token PIN prompts.** Rare; defer until requested.
- **HTTP proxy authentication mid-handshake.** Rare; defer until requested.
- **WireGuard interactive auth.** Protocol does not have a challenge concept; no work needed.

**Outside this work's identity**
- Replacing the auth file flow for username/password. The auth file remains the primary mechanism for credentials; the management interface supplements it for mid-connect prompts and challenge responses.
- Persisting OTP codes. 2FA codes are single-use by definition; "remember this code" is meaningless.
- Adding `--otp` style preflight flags to the CLI. The interactive prompt is the canonical surface; a flag could be a follow-up but is not required to close #191.

---

## Dependencies / Assumptions

- **Assumption A1: Most enterprise OpenVPN MFA servers send a CRV1 challenge over the management interface.** The supervisor must implement the CRV1 parsing path. Static-challenge support is included because it shares the same transport at zero marginal cost.
- **Assumption A2: The Unix domain socket can be owned/read by the unprivileged TUI process while openvpn runs as root.** Verify in planning — may need a sudo-wrapper that chowns the socket post-bind, or alternatively the management socket lives in a directory the user already has write access to, or the supervisor proxies all socket I/O through the daemon process. Resolution belongs in planning, not here.
- **Assumption A3: `--management-hold` correctly serialises with `--auth-user-pass <file>`.** OpenVPN's docs imply the auth file is consumed during the held state and the management interface drives the post-auth challenge phase. Manual-testing scenario needed.
- **Dependency D1: `vortix_process::run_to_output` is `--daemon`-oriented (it returns `Output` after the subprocess exits).** The new supervisor needs a long-lived spawn primitive that returns a `Child` handle and a means to read from a Unix socket concurrently with the child's stdout/stderr. Either extend `vortix_process` or build a small supervisor inside `vortix_protocol_openvpn`. xtask boundary checks (`vortix_protocol_*` must not import from process layer except through declared ports) apply.
- **Constraint C1: All `wg-quick` / `wg` / `openvpn` subprocess invocations live under `vortix_protocol_*`.** The new management-socket supervisor stays in `vortix_protocol_openvpn/`. No `// xtask:allow-protocol-leak` annotations are introduced.

---

## Success criteria

- A profile that previously hung at the CHALLENGE prompt (the #191 repro) connects successfully through the TUI within the wait-timeout window.
- The same profile connects successfully through `vortix connect` on an interactive tty.
- A passphrase-protected profile that previously hung connects after the user types the passphrase.
- A connected MFA tunnel survives a brief network flap (≥3 seconds) without re-prompting for the OTP.
- Multi-tunnel: two MFA profiles brought up in sequence each surface their own prompt; cancelling one leaves the other in its own `AwaitingUserInput` state without cross-talk.
- Non-tty `vortix connect` on an MFA profile exits non-zero with a message naming the prompt kind, and no orphan openvpn child remains.
- Existing single-factor and cert-only OpenVPN profiles continue to connect with no observable regression in timing, log output, or kill-switch semantics.

---

## Manual-testing scenarios (to add in `docs/manual-testing/`)

- Connect to a dynamic-CRV1 MFA server (e.g., a self-hosted OpenVPN with a custom `auth-user-pass-verify` script that issues CRV1). Verify the prompt appears, the code is accepted, and `>STATE:CONNECTED` lands within 5s of submission.
- Connect to a static-challenge MFA server. Verify the prompt appears *before* the first auth attempt completes and the inline SCRV1 envelope is accepted on the first try.
- Connect with a passphrase-encrypted .ovpn. Verify the prompt labels the field as "Private key passphrase".
- Connect, idle for 2 minutes, briefly disable Wi-Fi for 10 seconds, re-enable. Verify no `?` sigil appears and the tunnel reconnects silently (auth-token reuse).
- Bring up two MFA profiles back-to-back. Verify each shows its own prompt; cancelling profile A does not affect profile B's wait state.
- `vortix connect <mfa-profile> < /dev/null` from a script. Verify non-zero exit, clear error message, no orphan openvpn process.

---

## Resolve before planning

The following are unresolved decisions surfaced by the 2026-06-02 ce-doc-review pass (cross-persona agreement from coherence, feasibility, product-lens, design, security, scope-guardian, and adversarial reviewers). Each is a planning-blocker — picking the wrong path on any of these turns the implementation plan into rework. Decide here, not in planning.

### RBP1. Verify the #191 reporter's server type before locking Approach B

The doc concedes static-challenge is reachable today with a ~50 LOC change (auth-overlay OTP field + SCRV1 envelope on line 2 of the auth file + parser flag for `static-challenge` directive). Approach B was selected because the issue prose "sounds more like dynamic CRV1" — but this is inference, not evidence. Static-challenge is the more common enterprise MFA pattern (no server-side scripting required). If the reporter's server is static-challenge, Approach A closes #191 with a fraction of the code and **leaves the supervisor rewrite as a future, evidence-driven decision** when dynamic CRV1 is genuinely required.

- **Action:** Capture a `openvpn --verb 4` log excerpt (or `auth-user-pass-verify` script snippet, or screenshot of the CHALLENGE prompt) from the #191 reporter. Inspect the `>PASSWORD:` line format: `SC:1,<prompt>` suffix → static-challenge → Approach A is sufficient. `Verification Failed: 'Auth' ['CHALLENGE: …']` → dynamic CRV1 → Approach B is justified.
- **Until resolved:** Do not start planning. The architecture choice is conditional on this evidence.

### RBP2. Specify how `details.interface` is determined in the supervised model

R2 demotes the log file to "diagnostics" and makes `>STATE:CONNECTED` the readiness signal — but the kernel interface name (which the 2026-06-01 state-authority contract requires to be byte-comparable with `route get`) is extracted today exclusively from `OVPN_IFACE_ANCHORS` log lines via `parse_kernel_interface` in `crates/vortix/src/vortix_protocol_openvpn/tunnel.rs:216–245`. The management protocol's `>STATE:` line carries tun-id/local-ip/remote-ip but is not guaranteed to produce the exact form the firewall and primary-election code compare against. Two outcomes possible: (a) supervisor still scrapes the log → architecture has two ingestion paths, not one; (b) supervisor derives from `>STATE:` → regression risk on the "always Split tunnel" bug the state-authority work just fixed.

- **Action:** Name the authoritative source for `interface_name` in the new model. Options: keep log scraping for iface extraction and use `>STATE:` only for readiness; derive iface from `>STATE:` and document the macOS `utunN` mapping; query the kernel directly (`route get` after `>STATE:CONNECTED`).
- **Until resolved:** R2's "log file is no longer required" wording is incorrect and should be reworded.

### RBP3. Remove A2 — there is no privilege boundary today

`RealRunner::check_privilege` requires the caller to already be euid 0; every user-facing hint in the codebase tells users to run `sudo vortix up`. The TUI, the runtime, and openvpn all live in the same root process today. A2's three deferred options ("sudo-wrapper chowns socket / user-writable dir / proxy via daemon") are solving a non-problem in the current architecture and would consume planning cycles to no end. The privilege concern only becomes real after the daemon-engine split (`docs/brainstorms/2026-05-24-daemon-engine-handle-requirements.md`), which is not in scope here.

- **Action:** Replace A2 with a single sentence: *"The management socket is created at mode 0600 owned root:root in the existing run_dir. The supervisor, openvpn, and TUI share the root process; no cross-privilege IPC is introduced."* Add a note that daemon-engine split, if and when it lands, will re-open this question and require the supervisor to move to the daemon side.

### RBP4. Defer R8 (auth-token survival) to its own brainstorm

R8 is described as a "non-regression constraint" but is in fact a new capability the existing code does not have. The current FSM `try_reconnect` is hardcoded `try_disconnect(); try_connect()` (`fsm.rs:341–349`); `TunnelCapabilities.supports_reconnect_without_disconnect` exists as a flag but no code path consults it. Satisfying R8 requires either a new `Tunnel::reconnect_in_place` port method or a new FSM transition that bypasses `try_disconnect` — both are load-bearing changes that touch the state-authority contract (R1, R5 of `2026-06-01-multi-tunnel-state-authority-requirements.md`) and the reconnect-driver code in `vpn_runtime/connection.rs:254`. Bundling this with the prompt UI shipment couples two large, independently testable work items.

- **Action:** Move R8, F4, and manual-testing scenario 4 to a separate follow-up brainstorm titled "OpenVPN auth-token survival across reconnects." For this shipment, the existing tear-down/respawn reconnect model stays — MFA users re-prompt on link flap, which is the same UX as every other re-auth flow today. Not a regression; not great UX; deferable.
- **Update:** Revise the F4 success criterion accordingly: "an MFA tunnel that reconnects after a flap re-enters `AwaitingUserInput` with a fresh prompt" instead of "no re-prompt."

### RBP5. Define `FailureReason::UserCancelled` (or pick an existing variant)

F5 names `Disconnected { last_failure: Some(UserCancelled) }` but the `FailureReason` enum in `crates/vortix/src/vortix_core/engine/state.rs` has no such variant. The 8 existing variants are `RetryBudgetExhausted`, `HandshakeFailed`, `AuthFailed`, `ConfigInvalid`, `Timeout`, `NoNetworkLink`, `ProfileGone`, `Other`. Adding `UserCancelled` extends the journal's wire format — verify whether existing replayers handle a new variant gracefully (the enum is `#[non_exhaustive]`, so additions are forward-compatible at the type level, but the schema-version bump policy needs a call).

- **Action:** Either (a) add `UserCancelled` to the enum and document it in this requirements doc, or (b) reuse `Other { reason: "user cancelled prompt" }` and update R9/F5 accordingly. Pick one before planning.

### RBP6. Define a clear identity boundary for the supervisor

A foreground supervised openvpn child with a per-tunnel management socket, signal-based shutdown, and (per RBP4 deferral) tear-down/respawn reconnects drifts the product persona toward NetworkManager-shaped VPN orchestration. The repo's stated discipline (CLAUDE.md, density principle, state-authority work) is "TUI over kernel truth." Without a deliberate carve-out, every future OpenVPN feature (push MFA, PKCS#11, HTTP proxy auth, session liveness) will reasonably ask "why not put it in the supervisor?" and the answer will be ad-hoc.

- **Action:** Add an Identity statement to the Summary or Scope section naming what the supervisor is allowed to know and decide. Suggested boundary: *the supervisor owns prompt I/O, child lifecycle, and management-protocol parsing. It does NOT own routing decisions, primary election, kill-switch state, firewall rules, or session health observation — those remain kernel-truth-derived.*

### RBP7. Specify input-mode collision handling for the new overlay

`App.input_mode` is a flat enum, not a stack — 7 overlay variants already exist (AuthPrompt, ConfirmDefaultRouteTakeover, ConfirmRouteOverlap, ConfirmDisconnectAll, ConfirmDelete, Import, Rename). The two-overlay sequence in F2 (AuthPrompt closes → mid-connect overlay opens) and the multi-tunnel queue in R11 have no specified focus/handoff/collision semantics. Without rules, an in-flight overlay (e.g., a ConfirmRouteOverlap dialog open when a second tunnel's AwaitingUserInput event fires) will silently clobber or be clobbered.

- **Action:** State the collision policy in R5: when `AwaitingUserInput` fires while another input_mode is active, the new prompt (a) interrupts, (b) queues behind it, or (c) is dropped to a notification. Suggested default: queue behind active confirmation overlays (which are user-initiated and short-lived); interrupt nothing. Then specify the multi-tunnel queue behavior in R11: serve prompts FIFO by `since` with a "1 of N" indicator in the overlay header.

---

## Deferred / FYI items (do not block planning)

These were raised by reviewers but do not block planning. Track them, address opportunistically:

- Overlay UX details — server-rejection feedback when an OTP is wrong (re-enter AwaitingUserInput vs surface inline error), retry attempts visible to the user, numeric-vs-alphanumeric input filter per `PromptKind`, paste/clipboard policy (especially for `Passphrase`), `--json` CLI mode interaction with the masked tty prompt, wait-state timeout expiry UX
- 120s wait-state timeout vs real-world TOTP rotation (30s windows + skew → ~60–90s validity) — pick a number grounded in code lifetime, not arbitrary
- Security: management-socket creation mode (0600 from open via O_EXCL pattern, mirror `secret_file.rs`), auth-token must never be persisted to disk or logged in tracing spans, prompt-id is a routing key not an auth token
- Identity drift cumulative cost — if subsequent OpenVPN features (push MFA, PKCS#11) each add supervisor surface, revisit RBP6
- Daemon-engine split (`docs/brainstorms/2026-05-24-daemon-engine-handle-requirements.md`) will re-open the privilege question; the supervisor will need to move to the daemon side at that point — note as a known follow-up
