---
date: 2026-06-02
type: feat
origin: docs/brainstorms/2026-06-02-openvpn-interactive-auth-requirements.md
origin_issue: https://github.com/Harry-kp/vortix/issues/191
status: pre-approach-b-infrastructure
---

# feat: OpenVPN static-challenge — Approach B infrastructure (issue #191)

## ⚠️ Approach A is broken on OpenVPN 2.7 — confirmed 2026-06-02

This branch was originally scoped as Approach A: write the static-challenge OTP into the auth file as an SCRV1 envelope (`SCRV1:base64(password):base64(otp)` on line 2), let openvpn consume it via `--auth-user-pass <file>`, no daemon-mode changes. After implementation (U0–U6) shipped to a local test profile, the U0 manual spike was finally run against a real openvpn binary + the reporter's server config. **OpenVPN 2.7 does not consult the SCRV1 envelope in the auth file**: it prompts stdin for the OTP *before* the file is ever read.

Evidence (collected via `/tmp/vortix-debug-ovpn.sh` on 2026-06-02 against the user's `ovpn-totp.ovpn` profile, `OpenVPN 2.7.0 aarch64-apple-darwin24.6.0`, three zombie connect attempts left in the process table):

- The parameter dump showed `username = '[UNDEF]'` even though `--auth-user-pass <SCRV1-file>` was passed — the file had not been read.
- The next stdout line was `CHALLENGE: Enter TOTP code`, emitted at us=289606 (sub-second into startup), *before* any `Resolving remote` / `TCP/UDP link` / `TLS handshake` log lines that would mark the network-auth phase.
- The process then blocked reading stdin. No `--daemon` fork occurred, no `Initialization Sequence Completed` line appeared, no `.pid` / `.log` files were created.
- Repeating with the canonical 2-line `<user>\n<password>\n` auth file produced identical output (same prompt, same hang).

The OpenVPN man page now confirms: *"The challenge string in t will be passed to the management interface (or be shown on the user's terminal) before the username and password are entered."* The auth-user-pass file is read *after* the interactive prompt, and there is no documented path in OpenVPN 2.7 for the SCRV1 envelope to come from anywhere other than the management interface or stdin.

**The conclusion is unambiguous: Approach A — as originally specified — cannot close #191 on OpenVPN 2.7.** The fix the issue actually needs is Approach B (foreground supervised child + management socket), which the brainstorm's own adversarial reviewer flagged ("foregrounded supervised child reverses a deliberate architectural choice documented in code — without refuting the original reason"). The Pre-merge Gate (now satisfied as a "no, escalate to Approach B" outcome) prevented a fix-that-isn't from landing as a #191 closer.

## What this branch ships now

Despite Approach A being broken end-to-end, the eight commits on this branch contain reusable infrastructure for Approach B. Treat the branch as **a foundational stack**, not a user-visible fix. None of these change runtime behavior for profiles without a `static-challenge` directive — non-MFA OpenVPN, WireGuard, and the existing auth overlay are byte-for-byte unchanged.

| Surface | Status | Survives Approach B? |
|---|---|---|
| `static-challenge` directive parser (U1) | ✅ working, fully tested | Yes — Approach B needs the same flag to decide whether to capture the OTP |
| `base64` STANDARD-engine SCRV1 envelope helpers (U2) | ✅ working, fully tested | Yes — Approach B sends SCRV1 over the management socket, same envelope format |
| Startup stale-SCRV1 scrubber (U6) | ✅ working, fully tested | Yes — Approach B may still write transient files; the scrub is a safety net |
| TUI 3-field auth overlay + tab cycle + always-mask + collapsed spacing (U3) | ✅ working visually | **Probably no** — Approach B's design is a separate Mid-Connect Prompt overlay tied to the `AwaitingUserInput` FSM state, fired *after* openvpn emits the challenge. U3's pre-spawn overlay would be deleted. The auth-overlay extension is the largest single piece of throwaway code on this branch. |
| CLI masked OTP prompt + RawModeGuard (U4) | ✅ working as a UX surface | Yes — Approach B's CLI still needs an interactive prompt; the helper is independent of *when* it fires |
| Manual-testing rows 76–83 (U5) | Reframe needed | Most rows describe the Approach A success path; they won't pass. Update to "pending Approach B" or move to that future plan. |
| Connect-path overlay fires for static-challenge + saved creds (commit `68465bf`) | Behavior survives | Yes — Approach B needs the same "always show prompt for MFA profiles" gate |
| Post-submit gate bypass (`connect_profile_after_auth`, commit `9c10940`) | Behavior survives | Yes — same submit-loop concern applies to Approach B's flow |
| SCRV1-to-transient-sibling pattern + `OvpnTunnel.scrv1_auth_path` (commit `9d2c09c`) | Currently unused | Likely deleted under Approach B — the management socket sends SCRV1 in-band, no file needed |

## Recommended next steps

1. **Do NOT close issue #191 with this branch.** Approach A confirmed broken on OpenVPN 2.7; merging without a working user-visible fix would be misleading.
2. **Update issue #191** with the OpenVPN 2.7 diagnostic output (above) so the next investigation starts from this evidence.
3. **Open a new brainstorm** for Approach B with the OpenVPN 2.7 finding as a load-bearing input: management socket is the *only* viable transport on modern openvpn; there is no longer a "static-challenge via file" alternative to weigh against it.
4. **Decide whether to merge this branch as-is.** Two options:
   - **Merge as Approach B infrastructure.** Keep the parser + SCRV1 helpers + CLI prompt + overlay scaffolding. Approach B picks up the pieces it needs and rewrites the rest. The TUI 3-field overlay would be marked as `#[allow(dead_code)]` or deleted in the Approach B PR.
   - **Discard the branch.** Cherry-pick only the parser (U1) and SCRV1 helpers (U2) into a tiny prep PR; let Approach B start from there. Cleaner history, less Approach B mental load.

The author's recommendation is to merge as infrastructure (option a). The auth-overlay extension is the only piece that genuinely won't survive; everything else accelerates Approach B by 1–2 days at the cost of a small `dead_code` allowance until Approach B's first PR lands.

---

---

## Problem Frame

OpenVPN profiles whose server uses inline static-challenge MFA (most enterprise TOTP / SMS setups that avoid server-side auth-user-pass-verify scripting) hang at connect today because vortix has no UI surface to capture the second factor and no awareness of the directive that signals it. The hang manifests as the TUI crash described in #191 — the connect-timeout eventually fires and the FSM transitions through a path the renderer doesn't expect.

The fix is mechanical: the OpenVPN auth file supports the SCRV1 envelope on line 2 (the format `SCRV1:base64(password):base64(otp)` is consumed natively by `openvpn --auth-user-pass <file>` when the client's `static-challenge` directive in the .ovpn matches what the server expects). vortix's gap is purely in detection (parser doesn't know about the directive) and capture (no UI/CLI surface for the OTP).

A separate hazard: in `--daemon` mode, when openvpn cannot resolve credentials (no auth file, missing OTP, malformed SCRV1) it silently falls back to interactive prompts on stdin (which is detached). The result is an indefinite hang ending in connect-timeout — the exact failure mode the reporter described. U0 verifies that the SCRV1-via-auth-file path bypasses this fallback against a real openvpn binary before any UI work begins.

---

## Scope Boundaries

**In this plan**
- Detect `static-challenge "<prompt>" <echo>` in .ovpn configs.
- Extend the TUI auth overlay to capture an OTP field when the profile declares static-challenge.
- Extend `vortix connect` to interactively prompt for the OTP on the controlling tty when the profile declares static-challenge.
- Write the auth file in SCRV1 format when an OTP is supplied; preserve today's plain `username\npassword\n` format otherwise.
- The OTP is never persisted; "save credentials" continues to save only username + password.
- Restore the canonical auth file to plain-text after every connect attempt (success or failure) so stale SCRV1 lines never persist on disk.
- Detect-and-rewrite any stale SCRV1 line found in a saved auth file on app startup (safety net for the crash window).

### Deferred for later (origin scope, not this plan)
- **Dynamic CRV1 challenge support.** Requires the management-socket supervisor (origin's Approach B). Activate the reserved `AwaitingUserInput` FSM slot at that time. Gated on capturing evidence from the #191 reporter (or a separate report) that the server is dynamic CRV1.
- **Encrypted private-key passphrase prompt.** Same management-socket architecture; same gating.
- **Push-based MFA (Duo Push, Okta Verify Push).** Different UX shape (spinner + Cancel, not text field). Own brainstorm.
- **auth-token survival across reconnects.** Requires an FSM contract change (Tunnel::reconnect_in_place or equivalent). Own brainstorm.
- **Multi-tunnel concurrent prompt sequencing.** No multi-tunnel work here — each connect captures its own OTP up front before the next connect begins.

### Outside this work's identity
- Persisting OTPs. Single-use by definition.
- Management-socket IPC, foreground-supervised openvpn, signal-based reconnect. All belong to the deferred Approach B work.

### Deferred to follow-up work (plan-local)
- A manual-testing entry for the static-challenge happy path. Added in U5; if real-world testing reveals server-side variance (different prompt phrasings, echo=0 vs echo=1 servers), follow-ups land as their own rows.

---

## Key Technical Decisions

- **Auth file SCRV1 envelope is the canonical surface.** OpenVPN's static-challenge protocol accepts the SCRV1 envelope on line 2 of `--auth-user-pass <file>`; no live channel needed. U0 verifies this works for `--daemon` mode against a real openvpn binary before any UI work proceeds.
- **OTP capture happens before openvpn spawns, not after.** No FSM changes; `Connection::AwaitingUserInput` remains a reserved slot for the future supervisor work. The auth overlay (existing `InputMode::AuthPrompt`) gains a conditional OTP field; the CLI gains an interactive masked prompt at connect time.
- **OTP is always masked, regardless of the server's `echo` flag.** OpenVPN's `echo=1` means the *server permits* echo, not that the client must show. Most enterprise MFA setups use `echo=1` for layout reasons but still treat the value as sensitive on screen. The Password field is always masked; the OTP field is the same — masked everywhere. The echo flag is parsed but used only as informational metadata (currently no UI uses it; reserved for a future paste-policy or layout-hint decision).
- **The parser surfaces `static_challenge: Option<StaticChallenge>` on `OvpnParsedProfile`** carrying the prompt text and echo flag. Presence of the field is what triggers OTP capture; absence preserves today's flow byte-for-byte. Reached via parse-on-demand at the AuthPrompt construction site — no caching on `Profile`, no second byte-scanner — symmetric with how `openvpn_config_needs_auth` reads the config at use-time today.
- **`write_openvpn_auth_file` gains an `otp: Option<&str>` parameter.** When `Some(otp)` is passed, line 2 is the SCRV1 envelope; otherwise line 2 is the plain password (unchanged). Six in-tree call sites must be updated (two production + four test); all but the connect path pass `None`.
- **Canonical auth file is rewritten in-place for the connect window, then restored.** The connect handler writes the SCRV1 envelope to the canonical `<profile>.auth` path, spawns openvpn (which loads the file synchronously before forking in daemon mode), then restores plain-text line 2 immediately after `run_to_output` returns. The restore runs on both success and failure paths. U6 adds a startup-time safety net that detects and rewrites any stale SCRV1 line found on disk (covers the rare crash-during-connect window).
- **`base64` crate dependency added at the vortix-crate level.** SCRV1 needs base64 encoding; the `base64` crate (0.22.x) is the de facto Rust standard and is small. Hand-rolling base64 is rejected — the spec is fiddly and the crate's `STANDARD` engine is byte-exact with what OpenVPN's parser expects. The SCRV1 writer must use the standard RFC 4648 alphabet explicitly via `base64::engine::general_purpose::STANDARD` (NOT `URL_SAFE`, which substitutes `-` and `_` for `+` and `/` and would silently produce wrong-password auth failures for passwords whose standard encoding contains those characters).
- **CLI masked input is hand-rolled, not `rpassword`.** A ~25 LOC helper using `crossterm`'s raw mode (already in the workspace) preserves zero-new-deps for the CLI surface and avoids pulling `rpassword`'s broader cross-platform surface for a single field. Non-tty stdin exits non-zero with an actionable message naming the prompt kind.
- **Logging constraint applied to U3, U4, and U6.** No log message, tracing span field, or error message may contain the OTP value, the SCRV1 envelope string, or any base64-encoded segment derived from the password. Restore-failure logs emit only the error kind (e.g., `"AUTH: SCRV1 restore failed: permission denied"`).

---

## Implementation Units

### U0. Spike: verify `openvpn --daemon --auth-user-pass <file>` accepts SCRV1 on line 2

- **Goal:** Prove the architectural premise before any code is written. Confirm that a 2-line auth file with `SCRV1:base64(pw):base64(otp)` on line 2 is consumed correctly by `openvpn --daemon`, against a real openvpn binary, with the existing argv that vortix builds in `build_ovpn_args` (`crates/vortix/src/vortix_protocol_openvpn/tunnel.rs:325-356`). If the spike reveals that additional client-side flags are required (`--auth-retry interact`, a client-side `--static-challenge` flag, or an embedded `<static-challenge>...</static-challenge>` block in the .ovpn), document them and feed the result into U1's parser scope and the tunnel argv.
- **Requirements:** Validates the load-bearing assumption in Summary and Problem Frame. If the spike fails, this plan halts and the team escalates.
- **Dependencies:** none
- **Files:** none (paper spike; outcomes recorded in plan and PR description)
- **Approach:**
  - Stand up a minimal test server with `static-challenge "Test code" 1` configured (or use a known internal MFA server with permission).
  - Hand-craft an auth file: line 1 `<username>`, line 2 `SCRV1:base64(<password>):base64(<otp>)` (use the standard RFC 4648 alphabet).
  - Invoke `openvpn` with the same argv vortix uses today (`--config <profile> --daemon --writepid <pid> --log <log> --verb 3 --auth-user-pass <crafted-file>`).
  - Confirm `Initialization Sequence Completed` appears in the log within the connect-timeout window without any stdin interaction.
  - If the daemon emits `>PASSWORD:Need 'Auth'` to the management socket or stdin, or hangs waiting for input → additional flags are required → document them.
- **Test scenarios:** none (manual spike).
- **Verification:** A written paragraph in the PR description naming the openvpn version tested, the exact argv used, the auth-file contents (with credentials redacted), and the observed log line that confirmed success. If the spike requires new flags, U1's "Patterns to follow" section is updated and `build_ovpn_args` gets a corresponding modification in a small additional unit (insert as U0.5 in plan revision if needed).

### U1. Detect `static-challenge` directive in the OpenVPN parser

- **Goal:** Surface the static-challenge prompt and echo flag on `OvpnParsedProfile` so downstream UI/CLI can decide whether to capture an OTP.
- **Requirements:** Closes #191's detection gap. Underpins U3 and U4.
- **Dependencies:** U0
- **Files:**
  - `crates/vortix/src/vortix_protocol_openvpn/parser.rs` (modify — add struct, parse arm, quote-aware extractor)
  - `crates/vortix/src/vortix_protocol_openvpn/parser.rs` `#[cfg(test)] mod tests` (modify — add coverage)
- **Approach:**
  - Add a small `StaticChallenge { prompt: String, echo: bool }` struct.
  - Add `pub static_challenge: Option<StaticChallenge>` to `OvpnParsedProfile`.
  - In `parse_ovpn_conf`, add a match arm for the `static-challenge` directive. Because the existing tokenizer uses `line.split_whitespace()` and the prompt is typically a double-quoted multi-word string (e.g., `static-challenge "Enter authenticator code" 1`), the match arm must NOT consume tokens via the existing iterator. Instead, re-slice the original `line` after the `static-challenge ` prefix: find the first `"`, find the matching closing `"` (handling `\"` escapes), extract the prompt, then parse the trailing token as the echo bit.
  - Fallback for unquoted single-token prompts: if the post-directive remainder doesn't start with `"`, split off the next whitespace-delimited token as the prompt, then the next as the echo.
  - Warn-and-skip when the directive is malformed (no prompt, unparseable echo); preserve today's `warn!(line = %line, ...)` pattern.
  - Do NOT bump `interactive_auth` to true on the presence of static-challenge — that flag's contract is unchanged.
- **Patterns to follow:** existing `match directive { ... }` block in `parse_ovpn_conf` (parser.rs:126). Existing `warn!(line = %line, ...)` pattern for malformed directives. The quote-aware extractor is new; keep it as a small private helper inside the module.
- **Test scenarios:**
  - Happy path quoted multi-word: `static-challenge "Enter authenticator code" 1` → `Some(StaticChallenge { prompt: "Enter authenticator code", echo: true })`.
  - Happy path echo=0: `static-challenge "OTP" 0` → `Some(... echo: false)`.
  - Unquoted single-word prompt: `static-challenge Code 1` → `Some(... prompt: "Code", echo: true)`.
  - Prompt with embedded escaped quote: `static-challenge "Type \"code\" here" 1` → `Some(... prompt: "Type \"code\" here", echo: true)`.
  - Prompt with apostrophe: `static-challenge "Enter user's TOTP" 1` → parses correctly.
  - Empty quoted prompt: `static-challenge "" 1` → warn-and-skip (treat as malformed).
  - Malformed echo bit: `static-challenge "OTP" 2` → echo defaults to `false`, prompt retained, warn logged.
  - Extra whitespace: `static-challenge   "OTP"   1  ` → parses correctly.
  - Absent directive: profile without `static-challenge` → `None`.
  - Commented out: `# static-challenge "OTP" 1` → `None`.
  - Coexists with `auth-user-pass`: profile with both → both fields set on the parsed profile.
- **Verification:** All unit tests pass; existing `detects_interactive_auth` test continues to pass; no regression on `OvpnParsedProfile::default()` callers.

### U2. Extend `write_openvpn_auth_file` to emit SCRV1 envelope when an OTP is supplied

- **Goal:** Produce auth files in OpenVPN's static-challenge wire format when the caller supplies an OTP; preserve plain-text line-2 format otherwise.
- **Requirements:** Closes #191's capture-to-disk gap. The auth file is openvpn's only consumption surface in Approach A.
- **Dependencies:** U0
- **Files:**
  - `crates/vortix/Cargo.toml` (modify — add `base64 = "0.22"` to `[dependencies]`)
  - `crates/vortix/src/utils.rs` (modify — extend `write_openvpn_auth_file` signature both cfg arms; add `use base64::engine::{Engine, general_purpose::STANDARD as BASE64};` at module top)
  - `crates/vortix/src/utils.rs` `#[cfg(test)] mod tests` (modify — add SCRV1 coverage; update existing `test_write_read_openvpn_auth_file` at line 1136 and `test_auth_file_permissions` at line 1156 to pass `None`)
  - `crates/vortix/src/app/profile.rs` (modify — call site at line 166 passes `None`)
  - `crates/vortix/src/app/update.rs` (modify — call site at line 670 passes OTP when present; see U3)
  - `crates/vortix/src/app/tests.rs` (modify — call sites at lines 1051 and 1213 pass `None`)
- **Approach:**
  - New signature: `write_openvpn_auth_file(profile_name: &str, username: &str, password: &str, otp: Option<&str>) -> io::Result<PathBuf>`.
  - When `otp` is `Some(code)` AND `!code.is_empty()`, line 2 becomes `format!("SCRV1:{}:{}\n", BASE64.encode(password), BASE64.encode(code))` using the standard-alphabet engine pinned above.
  - When `otp` is `None` OR `Some("")`, line 2 remains `format!("{password}\n")` — byte-identical to today. Empty OTP is treated as `None` to avoid producing `SCRV1:cA==:` which openvpn would reject.
  - The `write_secret_file` chmod 600 path (unix) and the non-unix fallback both call the same formatter.
- **Patterns to follow:** existing `write_secret_file` invocation (utils.rs:322); test scaffolding in `test_write_read_openvpn_auth_file` (utils.rs:1136).
- **Test scenarios:**
  - Backward compatibility: `write_openvpn_auth_file(name, "u", "p", None)` produces `"u\np\n"` byte-for-byte. Existing `test_write_read_openvpn_auth_file` continues to pass.
  - SCRV1 happy path: `write_openvpn_auth_file(name, "u", "p", Some("123456"))` produces `"u\nSCRV1:cA==:MTIzNDU2\n"`. Verify by decoding back through `base64::engine::general_purpose::STANDARD`.
  - Standard-vs-URL-SAFE regression check: use a password byte sequence whose standard base64 encoding contains `+` or `/` (e.g., 3-byte input `[0xFB, 0xFF, 0xFF]` encodes to `+///`). Verify the encoded output contains `+`/`/`, not `-`/`_`. Catches accidental engine swaps.
  - Special-char password: password containing `:`, `+`, `/`, `=` round-trips correctly through SCRV1.
  - Empty OTP: `Some("")` → file content equals the `None` case (no SCRV1 envelope).
  - File permissions preserved: SCRV1 path still produces a 0600-mode file on unix.
- **Verification:** Unit tests pass; `cargo clippy --all-targets -- -D warnings` clean across the workspace; all six call sites compile.

### U3. TUI: capture OTP in the auth overlay when the profile declares static-challenge

- **Goal:** When the focused profile's `OvpnParsedProfile.static_challenge` is `Some(_)`, the auth overlay shows a third field for the OTP (labelled with the directive's prompt text, always masked). Submit writes the auth file with SCRV1 for the connect path and plain for the save path; after the connect attempt returns (success or failure), the auth file is restored to plain text.
- **Requirements:** Closes the TUI surface of #191. Reuses existing `InputMode::AuthPrompt` and existing tab-cycling code rather than introducing a new overlay.
- **Dependencies:** U0, U1, U2
- **Files:**
  - `crates/vortix/src/app/state.rs` (modify — extend `AuthField` enum with `Otp`; extend `InputMode::AuthPrompt` variant to carry `otp: String`, `otp_cursor: usize`, `static_challenge_prompt: Option<String>`)
  - `crates/vortix/src/app/update.rs` (modify — AuthPrompt construction site near line 398; populate `static_challenge_prompt` by **parse-on-demand**: when the focused profile is OpenVPN, read its config file and run `parse_ovpn_conf`, then surface `static_challenge.as_ref().map(|sc| sc.prompt.clone())`. Always initialize `otp: String::new()` and `otp_cursor: 0` so re-opening the overlay never inherits prior state.)
  - `crates/vortix/src/app/input.rs` (modify — tab cycling at line 461; include `Otp` in the rotation; character/backspace handling mirrors Password; `Enter` from any field submits when required fields are non-empty)
  - `crates/vortix/src/ui/overlays/auth.rs` (modify — render a third field row when `static_challenge_prompt.is_some()`; use the prompt text verbatim as the label; always mask the input regardless of echo)
  - `crates/vortix/src/ui/dashboard/mod.rs` (modify — pass the new state fields through to the overlay renderer; line 239 region)
  - `crates/vortix/src/ui/overlays/auth.rs` snapshot tests (add — verify the four-control layout at 80x24)
- **Approach:**
  - **Discoverability surface.** A static-challenge profile does NOT get a sidebar badge or a different overlay title — the labeled OTP field appearing at overlay-open IS the discoverability signal. This keeps the sidebar density clean per CLAUDE.md and matches the brainstorm's "user pressed Connect → overlay appears" mental model. Add a comment in `update.rs` near the construction site stating this is the intended discoverability surface.
  - **Field order:** Username → Password → OTP (label = directive prompt, always masked) → Save checkbox. Tab cycles through all four; Shift-Tab reverses.
  - **Layout at 80x24.** Today's auth overlay allocates 50% of terminal height (12 rows at 80x24, 10 inner after borders) and uses 9 content lines (blank/Profile/blank/Username-label/Username-input/blank/Password-label/Password-input/blank/checkbox). Adding the OTP row in the same pattern overflows. The three-field variant must **collapse the inter-field blank separators** (Username + Password + OTP packed without blank rows between input rows), keeping the overall content height inside the existing 10-row inner area. Snapshot tests at 80x24 verify no clipping.
  - **Submit handler — two-call structure.** The handler at `update.rs:670` is rewritten so that when `save=true` AND `otp.is_some()`, it issues TWO distinct `write_openvpn_auth_file` calls in this order: (1) `write_openvpn_auth_file(name, user, pass, None)` for the saved-credentials path so the canonical file persists plain-text creds even if the second write fails, then (2) `write_openvpn_auth_file(name, user, pass, Some(&otp))` to install the SCRV1 envelope just before the connect attempt. After `connect_profile` returns (success or failure), the handler unconditionally calls `write_openvpn_auth_file(name, user, pass, None)` a third time to restore plain text. When `save=false` AND `otp.is_some()`, the handler writes SCRV1 directly, runs connect, then deletes the auth file via `delete_openvpn_auth_file` (no plain-text restore — the user didn't ask to save). When `otp.is_none()`, behavior is byte-identical to today (one write call with the saved-or-not flag).
  - **Empty-OTP guard.** Submit with `static_challenge_prompt.is_some()` AND `otp.trim().is_empty()` → show a toast `"OTP required"`, do not change `input_mode`, do not write the auth file. Mirrors today's empty-username handling.
  - **OTP trim on submit.** Trim leading/trailing whitespace before passing to `write_openvpn_auth_file` (covers paste-with-newline).
  - **Logging.** No log message or tracing span field may contain the OTP, the SCRV1 envelope, or any base64-encoded segment derived from the password. The existing `AUTH: Saved credentials for '<profile>'` log line stays unchanged; an `AUTH: SCRV1 restore failed: <error-kind>` line is acceptable (kind only, never content).
- **Patterns to follow:** existing `AuthField` tab cycling in `app/input.rs:461–467`; existing masked-input rendering in `ui/overlays/auth.rs` for the password field; `delete_openvpn_auth_file` (utils.rs:359).
- **Test scenarios:**
  - Snapshot: profile without static-challenge → today's layout (no OTP field). Existing snapshot tests should not need updating.
  - Snapshot: profile with `static_challenge { prompt: "Enter code", echo: false }` at 80x24 → renders four controls (Username, Password, "Enter code" (masked), Save), collapsed spacing, no clipping.
  - Snapshot: profile with `echo: true` → OTP field STILL renders masked (the echo flag is informational only).
  - Tab cycling: Username → Password → Otp → SaveCheckbox → Username. Shift-Tab reverses.
  - Submit with empty OTP on a static-challenge profile → toast "OTP required", input_mode unchanged.
  - Submit with whitespace-only OTP (`"  "`) → same as empty.
  - Submit with OTP filled, save=true → first two writes (None then SCRV1) precede `connect_profile`; after connect returns, a third write (None) restores plain text. Three writes total.
  - Submit with OTP filled, save=false → one SCRV1 write, then `connect_profile`, then `delete_openvpn_auth_file`. No file persists.
  - **Wrong-OTP path:** mock `connect_profile` to simulate an AUTH_FAILED return. Verify the auth file on disk is plain text afterward (read line 2 — must not start with `SCRV1:`).
  - **Esc disposal:** with OTP partially typed, press Esc → input_mode replaced with Normal, no auth file modified.
- **Verification:** TUI snapshot tests pass; `cargo test -p vortix` passes; manual smoke (per U5) connects to a static-challenge profile.

### U4. CLI: interactive masked OTP prompt at connect when profile declares static-challenge

- **Goal:** `vortix connect <profile>` prompts for the OTP on the controlling tty when the parsed profile carries `static_challenge`. Non-tty stdin exits non-zero with an actionable message naming the prompt kind. Username/password come from the saved auth file as today; only the OTP is captured at connect-time. The auth file is restored to plain text after the connect attempt (success or failure).
- **Requirements:** Closes the CLI surface of #191; per the brainstorm CLI parity scope, the user opted for an interactive masked prompt over a `--otp` flag.
- **Dependencies:** U0, U1, U2
- **Files:**
  - `crates/vortix/src/cli/commands.rs` (modify — `connect` command handler; insert OTP prompt branch when parsed profile carries `static_challenge` AND saved credentials exist)
  - `crates/vortix/src/cli/commands.rs` (modify — new private helper `prompt_masked_otp(prompt: &str) -> io::Result<String>` returning `Err` when stdin is not a tty)
  - `crates/vortix/src/cli/commands.rs` tests (modify — exercise the tty-detect path and the restore-on-failure path)
- **Approach:**
  - **Connect path.** Load and parse the .ovpn config. If `static_challenge.is_some()`, branch:
    - If saved credentials do not exist (`read_openvpn_saved_auth().is_none()`), exit with exit code 1 and the message: `"Profile '<name>' requires 2FA ('<prompt>'). Save username/password first via the TUI (Auth Manager → set credentials), then re-run; the OTP will be prompted at each connect."` (Note: a `vortix auth set` subcommand is mentioned in the brainstorm but does not exist today; the error refers users to the TUI Auth Manager which does exist. If `vortix auth set` ships later, the message updates.)
    - If saved credentials exist, call `prompt_masked_otp(&prompt)`. On non-tty stdin, the helper returns `Err`; the connect path catches that and exits with exit code 1 and the message: `"Profile '<name>' requires 2FA but stdin is not a tty. Run the TUI instead, or invoke from an interactive terminal."`
    - Trim the OTP. Read the saved username+password via `read_openvpn_saved_auth`. Write `write_openvpn_auth_file(name, user, pass, Some(&otp))`.
    - Invoke the existing connect path (`connect_and_wait` / equivalent). After it returns — on success, failure, or timeout — unconditionally restore via `write_openvpn_auth_file(name, user, pass, None)`. Restore failure is logged at warn level (kind only) and does not block.
  - **Masked input helper.** Use `crossterm::terminal::enable_raw_mode` / `disable_raw_mode`. Read char-by-char from stdin. Echo `*` on each typed character (mask is unconditional; see DEC-2 — `echo` flag is informational only). Handle backspace (cursor.saturating_sub(1), redraw `*`), Ctrl-C (cancel → return `Err`), Enter (submit → return `Ok(trim(input))`). The helper drops raw mode on every exit path including panic via a guard struct so an interrupted CLI doesn't leave the user's terminal in raw mode.
  - **Ctrl-C during connect.** The CLI process catches SIGINT (existing handler if present; if not, add a small one) and runs the plain-text restore before exiting. Mirrors the post-connect restore but on the interrupt path.
- **Patterns to follow:** existing tty-detection pattern in `cli/report.rs:445` (`Skip interactive prompt if stdin is not a terminal`); existing `read_openvpn_saved_auth` / `write_openvpn_auth_file` / `delete_openvpn_auth_file` helpers.
- **Test scenarios:**
  - Mocked tty + supplied OTP → `prompt_masked_otp` returns `Ok("123456")`; `write_openvpn_auth_file` is called with `Some("123456")`.
  - Non-tty stdin (pipe from `/dev/null`) → `prompt_masked_otp` returns `Err`; CLI exits with code 1 and the message names "2FA" and "tty". Test via subprocess.
  - Static-challenge profile without saved credentials → CLI exits with code 1 and the message names the prompt text and points to the TUI Auth Manager. No auth file write occurs.
  - Echo flag is ignored — mask character is always `*`, regardless of `static_challenge.echo` value. Asserted via the test seam.
  - **Wrong-OTP path:** mock the connect call to return AUTH_FAILED. Assert the auth file on disk is plain text afterward.
  - **Ctrl-C mid-connect:** simulate SIGINT while connect is in flight. Assert restore runs and the auth file is plain text.
  - **Post-connect restore on success:** after a successful connect, assert the auth file is plain text.
- **Verification:** `cargo test -p vortix --lib` passes; non-tty subprocess test exits non-zero; manual smoke per U5 connects via `vortix connect <mfa-profile>`.

### U5. Manual-testing entries

- **Goal:** Document the static-challenge happy paths and the failure modes (wrong OTP, non-tty CLI, save-credentials interaction) so the CI-parity test plan covers what unit tests cannot.
- **Requirements:** CLAUDE.md manual-testing convention.
- **Dependencies:** U1–U4 (U6 is a follow-on safety net, not gated on this row set)
- **Files:**
  - `docs/manual-testing/backlog.md` (modify — add rows)
- **Approach:** Append rows to the existing table:
  - "Connect to a static-challenge OpenVPN profile (echo=0) via TUI" — setup: profile with `static-challenge "Enter code" 0`, saved username+password; action: connect, type OTP into masked third field; pass signal: tunnel reaches Connected within 30s, no error toast, auth file on disk is plain text after connect.
  - "Connect to a static-challenge profile via `vortix connect`" — setup: same profile + interactive tty; action: run `vortix connect <name>`, type OTP at the masked prompt; pass signal: process exits 0 within 30s, tunnel reaches Connected, auth file on disk is plain text after connect.
  - "Wrong OTP (TUI)" — setup: same profile, saved creds; action: connect, type a deliberately wrong OTP; pass signal: clear error toast appears (mentioning auth failure), auth file on disk is plain text afterward (line 2 has no `SCRV1:` prefix).
  - "Wrong OTP (CLI)" — setup: same profile + tty; action: `vortix connect <name>`, type wrong OTP; pass signal: process exits non-zero with an auth-failure message, auth file is plain afterward.
  - "Connect with `vortix connect <name> < /dev/null` on a static-challenge profile" — setup: same profile; action: pipe /dev/null to stdin; pass signal: non-zero exit, message names 2FA + tty, auth file on disk untouched.
  - "Ctrl-C mid-connect (CLI)" — setup: same profile + tty; action: type OTP, press Enter, immediately Ctrl-C during connect window; pass signal: process exits, auth file restored to plain text.
  - "Connect to a non-MFA OpenVPN profile (regression check)" — setup: any pre-existing OpenVPN profile without static-challenge; action: connect; pass signal: behavior identical to v0.3.1, two-field overlay, no perf change.
  - "Stale SCRV1 cleanup on startup" — setup: hand-corrupt an auth file by writing `SCRV1:cA==:MTIzNDU2` to line 2; action: start vortix; pass signal: auth file is rewritten to plain text (line 2 has no `SCRV1:` prefix) before the dashboard renders.
- **Test scenarios:** none (documentation).
- **Verification:** Each row, when executed by hand, produces the named pass signal.

### U6. Startup-time stale SCRV1 cleanup

- **Goal:** Detect any saved auth file whose line 2 starts with `SCRV1:` at vortix startup and rewrite it to a plain-text marker so the next connect attempt re-prompts for credentials rather than feeding stale SCRV1 to openvpn. Safety net for the rare case where vortix crashes (SIGKILL, panic mid-restore, system-level OOM) during the connect window and leaves an SCRV1 envelope on disk.
- **Requirements:** Closes the residual crash-window concern (PF-2 / R3 in the brainstorm doc-review). Without this, a crash during the SCRV1 connect window leaves a profile uncuckable until the user manually deletes the auth file.
- **Dependencies:** U2
- **Files:**
  - `crates/vortix/src/utils.rs` (modify — add `pub fn scrub_stale_scrv1_auth_files()` that scans the `OPENVPN_AUTH_DIR` for `*.auth` files and, for any whose line 2 starts with `SCRV1:`, deletes the file via `delete_openvpn_auth_file`. Deletion rather than rewrite-to-plain because we cannot recover the original plain password from the SCRV1 envelope — the user must re-enter credentials.)
  - `crates/vortix/src/app/mod.rs` or wherever `App::new` lives (modify — invoke `scrub_stale_scrv1_auth_files` once during app startup, before the dashboard renders)
  - `crates/vortix/src/cli/commands.rs` (modify — invoke the same function at the top of every CLI entry point that reads or writes auth files; cheap, ms-scale scan)
  - `crates/vortix/src/utils.rs` `#[cfg(test)] mod tests` (modify — add a test that seeds a stale SCRV1 file in a temp dir, runs the scrub, verifies deletion)
- **Approach:**
  - Read each file in the auth dir. For files whose line 2 matches the prefix `SCRV1:`, log at warn level (`"AUTH: stale SCRV1 in <profile>.auth — clearing"` — no envelope content), then call `delete_openvpn_auth_file`.
  - Plain-text auth files are left untouched.
  - On startup the scan runs synchronously; with N profiles the cost is N small file reads — negligible.
- **Patterns to follow:** existing `delete_openvpn_auth_file` (utils.rs:359); existing tracing patterns at warn level in this module.
- **Test scenarios:**
  - Seed a temp auth dir with three files: one plain (`user\npass\n`), one SCRV1 (`user\nSCRV1:cA==:MTIzNDU2\n`), one empty. Run the scrub. Assert: plain file untouched, SCRV1 file deleted, empty file untouched.
  - Run scrub on a non-existent auth dir → no error.
  - Verify the warn log message contains the profile name but NOT the SCRV1 envelope content.
- **Verification:** `cargo test -p vortix --lib` passes; manual smoke per U5's "Stale SCRV1 cleanup on startup" row.

---

## System-Wide Impact

- **No FSM changes.** `Connection::AwaitingUserInput` and `PromptKind` remain reserved-but-unused. The brainstorm's Approach B is the path that activates them.
- **No process-layer changes.** OpenVPN continues to run as `--daemon` with log-poll readiness. The state-authority interface-anchor contract from 2026-06-01 is untouched.
- **No multi-tunnel changes.** Each connect captures its own OTP up front in single-flight; multi-tunnel concurrent prompt sequencing remains deferred to Approach B.
- **One new workspace dependency:** `base64 = "0.22"` on the `vortix` crate. Minimal supply-chain impact; permanent (future plans inherit it).
- **`write_openvpn_auth_file` signature change.** Six in-tree call sites updated: two production (`app/profile.rs:166`, `app/update.rs:670`) and four test (`app/tests.rs` near lines 1051 and 1213, `utils.rs` test module near lines 1139 and 1161). All but the connect path pass `None` for the new `otp` parameter.
- **`read_openvpn_saved_auth` is unchanged.** The save path always writes plain-text line 2. The connect path writes SCRV1 transiently and restores plain-text on every exit path (success / failure / Ctrl-C). U6 catches the rare crash-window residue at startup. Invariant for `read_openvpn_saved_auth` callers: line 2 is plain text in steady state.
- **Startup adds an O(N) auth-dir scan** where N is the number of OpenVPN profiles with saved credentials. Cost is microseconds per profile; not a measurable change.

---

## Risks & Open Questions

- **R1 — Server-side variance in static-challenge prompt text and echo flag.** The OpenVPN spec allows the server-side `static-challenge` directive to specify any prompt and any echo bit. U1's parser surfaces the prompt verbatim and U3/U4 render it verbatim. Echo flag is parsed but always overridden to masked rendering (DEC-2). Variance is absorbed cleanly.
- **R2 — User pastes an OTP with leading/trailing whitespace.** Trim on submit in both TUI (U3) and CLI (U4) handlers, tested in U3/U4 scenarios.
- **R3 — Crash window between SCRV1 write and plain-text restore.** Mitigated by U6 (startup-time stale-SCRV1 detection + cleanup). On crash, the next vortix start clears the residue; the user re-enters credentials, which is the correct UX. The rare race where another concurrent vortix process reads the file during the SCRV1 window remains theoretical — single-user single-instance is the documented assumption (per the secret-stack work).
- **R4 — The original Approach B may still be needed for dynamic CRV1 servers.** Reusable surfaces from this plan if Approach B ships later: U1 parser flag (the `static_challenge` field), U2 SCRV1 writer (still needed for static-challenge profiles in a unified flow), U4 masked-input helper (the CLI surface is independent of FSM model). NOT reusable: U3's AuthPrompt overlay extension — Approach B requires a separate Mid-Connect Prompt overlay (per origin R5) bound to `AwaitingUserInput`, not to the pre-spawn `InputMode::AuthPrompt`. If/when Approach B ships, U3 may be deleted or retained as a static-challenge-only fast path.

---

## Deferred to follow-up work

These were in scope at brainstorm time and are deliberately not addressed here. Each becomes its own brainstorm + plan when warranted:

- Dynamic CRV1 challenge support (origin Approach B; foreground supervisor + management socket; activates `AwaitingUserInput`).
- Encrypted private-key passphrase prompt (same architecture as dynamic CRV1).
- `auth-token` survival across reconnects (FSM contract change).
- Push-based MFA UX (spinner + Cancel, not text field).
- Multi-tunnel concurrent prompt sequencing.
- The remaining RBPs from the brainstorm doc-review (RBP2 iface-authority, RBP5 `FailureReason::UserCancelled`, RBP6 identity statement, RBP7 input-mode collision policy) — all relate to Approach B's architecture and have no surface in Approach A.
- OTP-string zeroization (`zeroize` crate, single-use lifetime). Currently captured as plain `String`; threat model is single-user TUI on owner's machine, where chmod-600 + short OTP lifetime is the operative boundary. If the secret-stack work adopts `Secret<Vec<u8>>` as a typed envelope, fold the OTP into it then.
- Threat-model documentation that SCRV1's base64 encoding is a wire-format requirement (not encryption) and provides zero confidentiality beyond the chmod-600 file mode. Worth a one-paragraph note in the security overview when one exists.

---

## Requirements traceability

- Origin R1, R2, R3 (foreground supervisor / management socket / static-vs-CRV1 unification): **not addressed** — superseded by Approach A's auth-file rewrite.
- Origin R4 (FSM event into AwaitingUserInput): **not addressed** — Approach A does not enter AwaitingUserInput; captured pre-spawn.
- Origin R5 (Mid-Connect Prompt overlay): **not addressed** — the existing auth overlay is extended instead. The reserved sigil/header/sidebar/footer scaffolding stays unused.
- Origin R6 (sigil etc. fire for `Passphrase` and `TwoFactorCode`): **not addressed** — no FSM transition, no sigil fires.
- Origin R7 (write response over management socket): **not addressed** — response is the SCRV1 envelope written to the auth file pre-spawn.
- Origin R8 (auth-token survival): **deferred to follow-up.**
- Origin R9 (user-cancel transition): **partially addressed** — Esc on the auth overlay returns to the dashboard (no FSM transition needed because no AwaitingUserInput is entered). The brainstorm's `FailureReason::UserCancelled` variant remains undefined; that work belongs to Approach B.
- Origin R10 (wait-state timeout): **not addressed** — no wait state; the user types the OTP before openvpn spawns.
- Origin R11 (multi-tunnel): **deferred to follow-up.**
- Origin R12 (CLI parity): **closed by U4** — interactive masked tty prompt; non-tty exits non-zero with a 2FA-naming message.
- Origin F1 (connect with dynamic CRV1): **not addressed** — gated on the Pre-merge gate above.
- Origin F2 (connect with static-challenge): **closed by U0+U1+U2+U3+U4.**
- Origin F3 (connect with passphrase): **deferred to follow-up.**
- Origin F4 (reconnect with auth-token): **deferred to follow-up.**
- Origin F5 (user cancel): **partially addressed** — Esc-from-overlay is the cancel path; matches today's overlay cancel semantics.
- Origin F6 (CLI non-tty): **closed by U4.**
