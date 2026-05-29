---
title: "feat: behavioral test automation harness (Phase 1)"
type: feat
status: active
date: 2026-05-29
origin: docs/brainstorms/2026-05-29-test-automation-requirements.md
---

# feat: behavioral test automation harness (Phase 1)

## Summary

Automate ~55 behavioral checks from the manual test plan in `docs/manual-testing/multi-connection.md` — kernel routing, killswitch behavior, DNS scoping, CLI exit codes, JSON shape, PersistedState migration, daemon UID gate, security spot-checks. Extends the existing `tests/integration/` netns harness (Docker container + `ip netns` namespaces on a GitHub Actions runner) — no paid infrastructure, no DigitalOcean dependency. Tests run in two tiers: a fast subset (Rust integration tests, no privileged container) on every PR push, and a heavy subset (netns + real `wg-quick` + real `iptables-restore`) nightly + on `workflow_dispatch`. Phase 1 only; Phase 2 (TUI snapshots, perf) and Phase 3 (provider matrix, multi-version upgrade testing, bug-to-test policy) remain in the brainstorm as deferred scope.

---

## Problem Frame

See [origin §Problem](../brainstorms/2026-05-29-test-automation-requirements.md). Vortix's 114-check manual plan currently runs only at release time, creating release-burden + skip-under-pressure risk. The U9 iptables-nft regression caught in PR #1 (commit `b5dbfc6`) is recent concrete evidence that the netns integration pattern catches regressions the unit-test layer can't. Phase 1 extends that pattern across the highest-value behavioral checks.

---

## Requirements

Sourced from [origin §Goals](../brainstorms/2026-05-29-test-automation-requirements.md):

| ID | Requirement |
|----|-------------|
| R1 | Automate ≥ 50% of the 114-check manual plan — ~55 checks land in Phase 1. |
| R2 | Shift regression detection from release-time to PR-time. Bugs introduced today surface within minutes of PR push, not weeks later. |
| R3 | Keep CI infrastructure free. No paid external infra dependencies. Pure GitHub Actions + privileged Docker + `ip netns`. |
| R4 | Per-PR feedback ≤ 5 minutes on the fast subset. Heavy netns-real subset runs nightly + on `release` tag + `workflow_dispatch`. |
| R5 | Generate a coverage table mapping each of the 114 manual checks to `automated: <test-file-path>` or `manual: <reason>` so reviewers know what's protected. |
| R6 | No coverage regression on existing tests. Existing 731 Rust tests + 2 integration shell tests continue to pass on every PR. |

---

## Key Technical Decisions

### D-1. Coverage table format: sidecar annotations in `multi-connection.md`

Each `- [ ]` check in `docs/manual-testing/multi-connection.md` gets an inline annotation in HTML-comment-or-italic form: `- [ ] Check description **·** _automated: `tests/integration/killswitch.sh`_` or `- [ ] Check description **·** _manual: real consumer hardware_`. Single source of truth; reviewers see "what's tested" and "why this is still manual" side-by-side with the check itself.

Alternative considered: separate `docs/manual-testing/coverage.md`. Rejected — requires keeping two files in sync; the manual plan is the natural anchor.

### D-2. Tier split: fast Rust integration tests vs heavy netns-real shell tests

**Fast tier (~30 checks, runs per-PR via existing `test.yml`):**
- All assertions doable inside `cargo test` — CLI exit codes, JSON shape, file state, FSM event observation, PersistedState migration
- Targets: `crates/vortix/tests/cli_integration.rs`, `crates/vortix/tests/integration.rs`, new `crates/vortix/tests/json_v2.rs`, new `crates/vortix/tests/persisted_state_migration.rs`
- Wall-clock per PR: ≤ 5 minutes

**Heavy tier (~25 checks, runs nightly + on-demand via existing `integration-tests.yml`):**
- All assertions requiring privileged container + real `wg-quick` / `openvpn` / `iptables-restore` — multi-tunnel routing, killswitch traffic blocking, DNS scoping, daemon UID gate, security spot-checks
- Targets: extensions to existing `tests/integration/*.sh` + new `tests/integration/multi_tunnel.sh`, `tests/integration/dns_scoping.sh`, `tests/integration/security.sh`
- Wall-clock per nightly run: ≤ 15 minutes

### D-3. Multi-tunnel netns topology: peer-per-namespace, not single-host

For multi-tunnel tests, each "VPN server" runs in its own namespace; the client namespace has multiple WG interfaces (one per tunnel), each peering with the matching server namespace. This mirrors how a real multi-tunnel deployment routes packets — every tunnel has its own real-kernel WG interface with real keys, real handshake, real routing rules. Avoids the trap of "single-host shortcut" tests that wouldn't catch real-world multi-tunnel issues.

Diagram (directional, not implementation):

```
┌──────────────┐    ┌────────────────────┐    ┌──────────────┐
│ vortix-test-a│    │ vortix-test-client │    │ vortix-test-b│
│   WG server  │◄───┤  wg-a + wg-b ifs    ├───►│   WG server  │
│   10.99.99.1 │    │                    │    │  10.99.98.1  │
└──────────────┘    └────────────────────┘    └──────────────┘
```

### D-4. Defer cross-cutting policy (bug-to-test PR template, coverage trend tracking, flake registry)

Brainstorm Phase 1 listed these as "cross-cutting practices." They're workflow/policy changes, not test code. Defer to a follow-up brainstorm focused specifically on contributor workflow; this plan stays focused on test artifacts that exist as files in the repo.

### D-5. Defer Daemon UID-gate adversarial test until a second user can be provisioned in the container

The Dockerfile currently runs as the default container user. Adding a second user + the test orchestration (run-as-A, attempt-from-B) is a small but distinct piece of infrastructure work. Deferred to Phase 1B (after the core behavioral tests land) to keep this plan's PR-set focused.

---

## Output Structure

New files this plan adds; existing files modified per unit `**Files:**` lists.

```
crates/vortix/tests/
├── cli_grammar.rs                  (NEW — CLI exit codes + flag combos)
├── json_v2_envelope.rs             (NEW — JSON shape per status state)
├── persisted_state_migration.rs    (NEW — V1→V2 migration assertions)
└── journal_events.rs               (NEW — event-shape round-trip + PrimaryTunnelChanged emission)

tests/integration/
├── multi_tunnel.sh                 (NEW — 2-WG happy path + route inspection)
├── multi_tunnel_killswitch.sh      (NEW — multi-tunnel killswitch + atomicity probe)
├── dns_scoping.sh                  (NEW — WG primary DNS preserved; secondary DNS stripped)
├── ovpn_pull_filter.sh             (NEW — OVPN secondary spawn cmdline inspection)
├── security.sh                     (NEW — auth file perms, symlink refusal, ps aux scan)
├── setup-netns.sh                  (MODIFY — support N namespaces parametrically)
├── teardown-netns.sh               (MODIFY — clean up N namespaces)
├── fixtures/wg-c.conf              (NEW — third WG config for N=3 tests)
└── README.md                       (MODIFY — document the new tests + the harness extension)

docs/manual-testing/
└── multi-connection.md             (MODIFY — sidecar coverage annotations per check)

.github/workflows/
└── integration-tests.yml           (MODIFY — add invocations of the new .sh scripts)
```

---

## Implementation Units

Grouped by phase. Units within a phase can land in any order; phases are dependency-ordered.

### Phase A — Harness foundation

### U1. Extend `tests/integration/` for N-namespace multi-tunnel setup

**Goal:** Parameterize the existing `setup-netns.sh` / `teardown-netns.sh` to support N WG-server namespaces (currently fixed at A + B), so multi-tunnel scenarios are expressible.

**Requirements:** R3, R6

**Dependencies:** none

**Files:**
- Modify: `tests/integration/setup-netns.sh`
- Modify: `tests/integration/teardown-netns.sh`
- Create: `tests/integration/fixtures/wg-c.conf` (third WG config; mirror `wg-b.conf` shape with distinct keys + subnet 10.99.97.0/24)
- Modify: `tests/integration/README.md` (document the N-namespace parameter)

**Approach:**
- `setup-netns.sh N` creates namespaces `vortix-test-a` ... `vortix-test-<N-letter>` plus `vortix-test-client`, with veth pairs to each server namespace
- Existing `wg_happy_path.sh` continues to work (calls `setup-netns.sh 2` implicitly via default)
- `teardown-netns.sh` enumerates and cleans all namespaces matching `vortix-test-*`
- New WG configs use disjoint /24 subnets so routing tests can verify correct interface selection

**Patterns to follow:** Existing `tests/integration/setup-netns.sh` and `wg-b.conf` shape.

**Test scenarios:**
- After change, `bash tests/integration/setup-netns.sh` (default N=2) produces the same namespaces as today; `wg_happy_path.sh` + `killswitch.sh` both still pass
- `bash tests/integration/setup-netns.sh 3` produces three server namespaces plus the client; `ip netns list` shows them; teardown removes them cleanly
- N values outside [2, 5] error out cleanly with a usage message

**Verification:** Existing integration tests pass unchanged; new N=3 setup completes in ≤ 10 seconds.

---

### Phase B — Multi-tunnel real-firewall tests

### U2. Multi-tunnel happy-path integration test

**Goal:** Drive vortix against two real WG servers in netns; assert kernel routing decisions match the expected primary/secondary topology; clean teardown.

**Requirements:** R1, R2, R3 (covers multi-connection plan SC1-SC3, partially SC6)

**Dependencies:** U1

**Files:**
- Create: `tests/integration/multi_tunnel.sh`
- Modify: `.github/workflows/integration-tests.yml` (add invocation)

**Approach:**
- `setup-netns.sh 2` provisions the two-server topology
- Bring up `wg-a` (primary, 0.0.0.0/0) and `wg-b` (secondary, 10.99.98.0/24) in the client namespace via vortix
- Assert via `ip route get <dest>`:
  - Default-route destination → goes through `wg-a` interface
  - Destination in 10.99.98.0/24 → goes through `wg-b` interface
  - Destination outside both → blocked by killswitch (if enabled)
- Disconnect primary; verify auto-promote fires (registry's `pending_default_route_claimant` exposes the promotion decision via the daemon socket or via journal scan)
- Reconnect primary; verify role inverts back

**Patterns to follow:** `tests/integration/wg_happy_path.sh` for vortix-CLI-in-netns driving pattern; `tests/integration/killswitch.sh` for kernel-state assertion pattern.

**Test scenarios:**
- Both tunnels connect in <30 seconds; sidebar (via `vortix status --json`) reports `connections: [<wg-a>, <wg-b>]`, `primary: "wg-a"`
- `ip route get 1.1.1.1` shows `dev wg-a` (default route through primary)
- `ip route get 10.99.98.50` shows `dev wg-b` (declared subnet through secondary)
- Disconnect wg-a → `vortix status --json` shows `primary: null` (or auto-promoted secondary, per registry behavior)
- Clean teardown: namespaces destroyed, no orphan WG interfaces

**Verification:** Test passes in ≤ 90 seconds wall-clock. Catches any regression in multi-tunnel routing decision.

---

### U3. Multi-tunnel killswitch + atomicity integration test

**Goal:** Extend the existing single-tunnel `killswitch.sh` to N≥2 tunnels. Verify the synthesized `iptables-restore` ruleset matches expectations; verify atomicity by continuously curling during a tunnel transition.

**Requirements:** R1, R2 (covers SC5, SC6 atomicity)

**Dependencies:** U1

**Files:**
- Create: `tests/integration/multi_tunnel_killswitch.sh`
- Modify: `.github/workflows/integration-tests.yml` (add invocation)

**Approach:**
- Set up 2-tunnel topology; engage `vortix killswitch always`
- Inspect `iptables-save` output; assert it contains:
  - `:OUTPUT DROP [0:0]` (default-deny policy from U9)
  - `-A OUTPUT -o wg-a -j ACCEPT` (primary interface allow)
  - `-A OUTPUT -o wg-b -j ACCEPT` (secondary interface allow)
  - RFC1918 carve-out reflecting wg-b's declared 10.99.98.0/24 (i.e., 10/8 is NOT in the allow list)
- Continuous-probe test: from client namespace, run a background `while true; do ping -c 1 -W 1 10.99.0.99 || echo BLOCKED; sleep 0.1; done` for 5 seconds. Kill wg-a externally (`ip netns exec vortix-test-client wg-quick down wg-a`) mid-loop. Assert the probe shows BLOCKED for every iteration after the kill (no leak window).

**Patterns to follow:** `tests/integration/killswitch.sh` for the killswitch + iptables assertion pattern; the `continuous probe via background while loop` pattern is novel to this test.

**Test scenarios:**
- Killswitch engaged with 2 tunnels → `iptables-save | grep -c "j ACCEPT"` shows expected per-tunnel rules
- RFC1918 subtraction visible: `iptables-save` does NOT contain `-A OUTPUT -d 10.0.0.0/8 -j ACCEPT` when wg-b declares 10.99.98.0/24 (subset of 10/8)
- Atomicity probe: continuous-curl over 5 seconds during external wg-a-down shows no transient ACCEPT for non-tunnel traffic
- Disconnect wg-a → killswitch re-synthesises ruleset; only wg-b's rules remain

**Verification:** Test passes in ≤ 60 seconds. The atomicity probe is the key regression catcher — any flush-then-rebuild change would surface as a "leaked-during-transition" failure.

---

### U4. DNS scoping integration test

**Goal:** Verify WG secondary tunnels have DNS stripped from their temp config (per multi-tunnel plan U13); verify `/etc/resolv.conf` reflects only the primary's DNS.

**Requirements:** R1, R2 (covers multi-connection R13)

**Dependencies:** U1

**Files:**
- Create: `tests/integration/dns_scoping.sh`
- Modify: `tests/integration/fixtures/wg-a.conf` (ensure `DNS = 1.1.1.1` present in [Interface])
- Modify: `tests/integration/fixtures/wg-b.conf` (ensure `DNS = 8.8.8.8` present — should be stripped when wg-b becomes secondary)
- Modify: `.github/workflows/integration-tests.yml` (add invocation)

**Approach:**
- Set up 2-tunnel topology
- Connect wg-a (primary, with DNS=1.1.1.1); connect wg-b (secondary, with DNS=8.8.8.8)
- Assert `/etc/resolv.conf` contains `1.1.1.1` (primary's DNS, applied)
- Assert `/etc/resolv.conf` does NOT contain `8.8.8.8` (secondary's DNS, suppressed)
- Locate wg-b's temp config (under `${TMPDIR}/vortix-*/wg-*.conf`); assert it has NO `DNS = ` line
- Disconnect primary; auto-promote moves wg-b → primary. Note: per multi-tunnel plan U13 documented behavior, vortix does NOT rewrite an active tunnel's config; wg-b's DNS stays suppressed until reconnect. Assert this — `/etc/resolv.conf` does NOT add 8.8.8.8 mid-session.
- Reconnect wg-b explicitly → vortix re-renders the temp config now WITH DNS (it's primary now); `/etc/resolv.conf` shows 8.8.8.8

**Patterns to follow:** `tests/integration/wg_happy_path.sh` for the lifecycle pattern.

**Test scenarios:**
- Primary up with DNS → `/etc/resolv.conf` contains primary's DNS
- Secondary up with DNS → temp config DNS line stripped; `/etc/resolv.conf` unchanged
- Auto-promote without reconnect → secondary's DNS stays suppressed (documented behavior, R13)
- Explicit reconnect after promotion → temp config now contains DNS; `/etc/resolv.conf` updates
- Disconnect all → `/etc/resolv.conf` reverts to system default

**Verification:** Test passes in ≤ 60 seconds. Catches any DNS-write code path that bypasses the secondary-strip logic.

---

### Phase C — Subprocess correctness

### U5. OVPN secondary `--pull-filter` integration test

**Goal:** When an OVPN tunnel is brought up as a secondary, verify the launched `openvpn` process cmdline contains the `--pull-filter ignore "dhcp-option DNS"` flag (per multi-tunnel plan U14).

**Requirements:** R1, R2 (covers R13 for OVPN)

**Dependencies:** U1

**Files:**
- Create: `tests/integration/ovpn_pull_filter.sh`
- Create: `tests/integration/fixtures/ovpn-server.conf` (minimal OVPN server config for the test peer)
- Create: `tests/integration/fixtures/ovpn-client.ovpn` (matching client profile)
- Modify: `tests/integration/setup-netns.sh` (extend to support OVPN servers if not already covered by U1's parametrisation)
- Modify: `.github/workflows/integration-tests.yml` (add invocation)

**Approach:**
- Spawn an OVPN server in a netns (or use an inline mock OVPN responder if a real server is too heavy for the harness)
- Bring up a WG primary tunnel first; then bring up the OVPN tunnel as a secondary
- Use `ps auxf | grep openvpn` to capture the running `openvpn` process cmdline
- Assert the cmdline contains `--pull-filter` and `dhcp-option DNS`

**Patterns to follow:** `ps aux` cmdline inspection is a new pattern; mirror the shell idiom used in `tests/integration/wg_happy_path.sh`.

**Test scenarios:**
- WG primary + OVPN secondary → `openvpn` process cmdline includes `--pull-filter ignore "dhcp-option DNS"`
- OVPN as primary (no WG) → cmdline does NOT include the filter (DNS pull is desired for primary)
- OVPN 2.3.x detection (mock by setting a version-check stub) → vortix refuses to add OVPN as secondary; cmdline never launched
- Clean teardown: OVPN process exits, no lingering subprocesses

**Verification:** Test passes in ≤ 90 seconds. Catches any regression where vortix forgets to add the `--pull-filter` arg for secondaries.

---

### U9. Auto-promote FSM event observability test

**Goal:** When the primary tunnel disconnects externally, verify the registry emits a `PrimaryTunnelChanged { reason: PriorPrimaryDisconnected }` journal event with the right `from` / `to` / `via_interface` fields.

**Requirements:** R1, R2 (covers multi-connection R7, R-journal-events)

**Dependencies:** none (this is a Rust integration test; no netns needed if using `MockTunnel`)

**Files:**
- Create: `crates/vortix/tests/journal_events.rs`

**Approach:**
- Construct a `TunnelRegistry<MockTunnel>` with two tunnels — one declaring 0/0 (primary), one declaring 10.0.0.0/8 (secondary)
- Connect both; verify `PrimaryTunnelChanged { reason: InitialConnect }` event was emitted
- Externally disconnect the primary (simulate via `MockTunnel.set_down()` or `registry.disconnect(primary_id)`)
- Tick the registry; assert the next event is `PrimaryTunnelChanged { from: Some(primary_id), to: Some(secondary_id), reason: PriorPrimaryDisconnected }`
- For the secondary's via_interface, assert it matches the secondary's `MockTunnel.interface_name()`

**Patterns to follow:** Existing unit tests in `crates/vortix/src/vortix_core/engine/registry.rs` (in-module tests; this U9 lifts them into a workspace-level integration test).

**Test scenarios:**
- Initial connect → `InitialConnect` event with correct profile_id
- Primary disconnect with eligible secondary → `PriorPrimaryDisconnected` event with correct `from`/`to`
- Primary disconnect with NO eligible secondary → `PrimaryTunnelChanged { from: Some(_), to: None, reason: PriorPrimaryDisconnected }` (no-primary boundary)
- External route change detection (simulate via `RouteTable::default_route_interface()` returning a different interface) → `ExternalRouteChange` event
- Connect after a no-primary state → `InitialConnect` event again (boundary crossing)

**Verification:** Test passes in ≤ 5 seconds. Catches any registry change that breaks the auto-promote event contract that the TUI's banner depends on.

---

### Phase D — CLI / contract tests

### U6. CLI grammar + exit codes

**Goal:** Exhaustively test the `vortix up / down / reconnect / status` CLI grammar — every flag combination, every exit code, every hint-text variant.

**Requirements:** R1, R2 (covers multi-connection R6, SC8)

**Dependencies:** none (pure CLI tests via `assert_cmd` or process spawn)

**Files:**
- Create: `crates/vortix/tests/cli_grammar.rs`
- Extend: `crates/vortix/tests/cli_integration.rs` (if existing tests overlap)

**Approach:**
- Use `std::process::Command` or `assert_cmd` to spawn `target/debug/vortix <args>` in test
- Test cases driven by a table of (args, expected_exit_code, expected_stdout_pattern, expected_stderr_pattern)
- Cover: `up <profile>`, `up <profile> --yes`, `up <nonexistent>` (exit 3), `up <conflict-profile>` (exit 4 — requires test setup with prior active tunnel), `down`, `down <profile>`, `down --all`, `down <profile> --all` (clap conflict → exit 2), `reconnect`, `reconnect <profile>`, `status`, `status --json`, `status --brief`, `status --watch` (run for 3 seconds, capture stream)

**Patterns to follow:** Existing `crates/vortix/tests/cli_integration.rs` test shape (if present).

**Test scenarios:**
- `vortix up nonexistent` → exit 3, stderr contains "not found" + the profile name
- `vortix down corp` with corp not active → exit 0 (idempotent), stdout/json reflects "already disconnected"
- `vortix down corp --all` → clap rejects (`conflicts_with`), exit code is clap's default for arg conflict (2)
- `vortix status --json` with 0 tunnels active → `data.connections: []`, `data.primary: null`, `schema_version: 2`
- `vortix status --json --brief` → single-line JSON or summarized form (verify the chosen shape)
- `vortix reconnect personal` with personal connected → cycles tunnel; exit 0

**Verification:** Test passes in ≤ 30 seconds (cargo test runtime). Catches any regression in CLI exit code or hint text contract.

---

### U7. JSON v2 envelope shape

**Goal:** Verify the JSON output of `vortix status --json` matches the v2 envelope contract across every state (0 tunnels, 1 primary, N tunnels, no primary with active secondaries).

**Requirements:** R1, R2 (covers multi-connection R6, U21 JSON v2)

**Dependencies:** none (pure JSON shape test; uses the existing `CliResponse` struct + `serde_json`)

**Files:**
- Create: `crates/vortix/tests/json_v2_envelope.rs`

**Approach:**
- Construct synthetic `StatusData` values for each state (0 tunnels, 1 primary, 2 mixed, 3 secondaries no primary)
- Serialize via the existing `cli::output::print_success` path (or its underlying serde shape)
- Assert top-level fields: `schema_version: 2`, `data.connections: [...]`, `data.primary: <id|null>`, `data.connection: <entry|null>` (back-compat)
- Assert v1-compat behaviour: `data.connection` is set to the primary's entry when primary exists; null otherwise

**Patterns to follow:** Existing `crates/vortix/src/cli/output.rs` `CliResponse` envelope shape; serde-json round-trip tests.

**Test scenarios:**
- 0 active → `connections: []`, `primary: null`, `connection: null`
- 1 primary → `connections: [<entry>]`, `primary: "<id>"`, `connection: <entry>` (back-compat)
- 2 mixed (1 primary + 1 secondary) → `connections: [<primary>, <secondary>]`, `primary: "<id>"`, `connection: <primary's entry>`
- 3 secondaries no primary (synthetic) → `connections: [<a>, <b>, <c>]`, `primary: null`, `connection: null`
- Schema version always `2`; deserialise + reserialise round-trip is stable
- Each `ConnectionEntry` has the expected fields (`profile`, `state`, `interface`, `endpoint`, `since`, `latency_ms`)

**Verification:** Test passes in ≤ 5 seconds. Catches any accidental break of the JSON v1-compat or v2 envelope contract that downstream JSON consumers depend on.

---

### U8. PersistedState V1→V2 migration

**Goal:** Verify the killswitch persisted state file migrates cleanly from V1 (pre-multi-tunnel single-tunnel shape) to V2 (multi-tunnel shape with `active_tunnels: Vec<PersistedTunnelInfo>`).

**Requirements:** R1, R2 (covers multi-connection U11)

**Dependencies:** none (pure file-state test)

**Files:**
- Create: `crates/vortix/tests/persisted_state_migration.rs`

**Approach:**
- Write a synthetic V1 file to a tempdir (`{ interface: "wg0", server_ip: "1.2.3.4", ... }` — the v0.3.x shape)
- Call the existing `load_state(&path)` function (or its public equivalent)
- Assert the loaded state has `schema_version: 2`, `active_tunnels: [{interface: "wg0", ...}]`, and the legacy fields are correctly mapped
- Assert the state is then persisted back as V2 (subsequent load reads V2 cleanly)
- Phantom-interface validation: write a V2 state pointing at an interface that doesn't exist (e.g., `wg-nonexistent`); load it; assert vortix drops the phantom entry and logs a warning

**Patterns to follow:** Existing tests in `crates/vortix/src/core/killswitch.rs` (in-module tests covering serialization round-trip).

**Test scenarios:**
- V1 file with single tunnel → V2 reload preserves all fields; subsequent reads see V2 shape
- V1 file with empty/missing fields → V2 reload fills defaults via serde-default
- Corrupt file (random bytes) → load returns None with a parse-error log; no crash
- V2 file with phantom interface → loaded but the phantom entry is dropped; warning logged
- Round-trip stability: V2 → save → load → save → load produces byte-identical or semantically-identical state

**Verification:** Test passes in ≤ 3 seconds. Catches any migration code regression that would silently break upgraders from v0.3.x to v0.4.x.

---

### Phase E — Security spot-checks

### U10. Auth file perms + symlink attack + ps aux credential leak

**Goal:** Three security spot-checks bundled (small surface each): verify auth file permissions, symlink-attack refusal, and credential non-leak via `ps aux`.

**Requirements:** R1, R2 (covers multi-connection security spot-checks section)

**Dependencies:** U1

**Files:**
- Create: `tests/integration/security.sh`
- Modify: `.github/workflows/integration-tests.yml` (add invocation)

**Approach:**
- Section 1: bring up an OVPN tunnel with auth (username + password); assert `~/.config/vortix/<profile>.auth` exists with mode 0600 and owned by the calling user (not root)
- Section 2: replace `~/.config/vortix/<profile>.auth` with a symlink to `/etc/shadow` (simulating attacker); attempt to update the auth via vortix; assert the write fails (O_NOFOLLOW refuses to follow the symlink); `/etc/shadow` is unchanged
- Section 3: while OVPN is running, `ps auxf | grep openvpn | grep <password>` must return 0 lines (password not in process cmdline)

**Patterns to follow:** Existing `tests/integration/wg_happy_path.sh` for vortix-in-netns; `ls -la` + `stat -c '%a %U'` for file mode/owner assertions.

**Test scenarios:**
- Auth file mode is 0600 (octal); owner is the test user, not root
- Symlink attack: vortix refuses to write through the symlink; `/etc/shadow` content unchanged after attempted write
- `ps aux` over the running OVPN process: no password in cmdline
- After tunnel down: auth file may persist (cached for next connect) but mode/owner still correct
- After explicit `vortix clear-auth <profile>`: auth file is unlinked

**Verification:** Test passes in ≤ 30 seconds. Catches any regression in `write_secret_file` semantics (TOCTOU mitigation) or credential exposure via cmdline.

---

### Phase F — Integration + visibility

### U11. Coverage table — annotate `multi-connection.md` with automation status

**Goal:** Each of the 114 checks in `docs/manual-testing/multi-connection.md` gets a sidecar annotation showing whether it's automated (with file path) or stays manual (with reason).

**Requirements:** R5

**Dependencies:** U2 through U10 (the annotations reference the test file paths from those units)

**Files:**
- Modify: `docs/manual-testing/multi-connection.md` (add annotations per check)
- Modify: `docs/manual-testing/README.md` (document the annotation convention)

**Approach:**
- For each check, append ` **·** _automated: <test-file-path>_` or ` **·** _manual: <reason>_`
- "Automated" entries reference the new test file or test name added by U2-U10
- "Manual" reasons fall into a small set: `real consumer hardware`, `screen reader`, `terminal rendering`, `real third-party provider`, `release-time only`, `perf benchmark`, `requires Phase 2 / 3 work`
- Coverage summary added at the bottom of the file: `Total checks: 114 / Automated: ~55 / Manual residual: ~59 (broken down by reason)`

**Patterns to follow:** Existing `- [ ]` checkbox format in `multi-connection.md`; sidebar-annotation pattern using italic + middle-dot is novel to this repo but readable in both rendered Markdown and raw text.

**Test scenarios:** Test expectation: none — documentation-only change. Verification is manual review that each annotation accurately reflects the corresponding test file's coverage.

**Verification:** Coverage summary at the bottom shows ≥ 50% automation (target R1).

---

### U12. CI workflow integration

**Goal:** Wire the new `tests/integration/*.sh` scripts into `.github/workflows/integration-tests.yml` so they run nightly + on `workflow_dispatch`. Verify the fast-tier Rust tests run via the existing `test.yml`.

**Requirements:** R2, R4

**Dependencies:** U2 through U10 (the workflow invokes the scripts those units created)

**Files:**
- Modify: `.github/workflows/integration-tests.yml`

**Approach:**
- Extend the existing single-invocation `docker run` step to invoke all the new `.sh` scripts in sequence
- Each script has its own setup/teardown (per-test namespaces); no shared mutable state between scripts
- Total runtime budget: ≤ 15 minutes for the full heavy-tier batch (one test scenario each ~30-90 seconds + Docker build + teardown overhead)
- New Rust tests in `crates/vortix/tests/*.rs` run automatically via the existing `test.yml` (cargo test --workspace picks them up); no workflow change needed for the fast tier

**Patterns to follow:** Existing `integration-tests.yml` `docker run` step shape.

**Test scenarios:**
- After merge, nightly cron runs all new integration scripts in sequence; total wall-clock ≤ 15 minutes
- `gh workflow run integration-tests.yml --ref <branch>` triggers the full batch on-demand
- A deliberate test failure (touch one of the .sh scripts to break it) makes the workflow run fail; the failed script is named in the run output

**Verification:** Nightly run after merge passes all new tests; subsequent runs continue passing.

---

## Scope Boundaries

### Deferred to follow-up work (Phase 2 / 3 of the brainstorm)

- **TUI snapshot rendering tests** (insta-cmd or similar visual-diff harness) — deferred per brainstorm Phase 2.
- **Performance / scale regression detection** (N=10 tunnels, killswitch refresh latency benchmark) — deferred per brainstorm Phase 2.
- **OVPN 2.3.x rejection path with a real old binary** — deferred per brainstorm Phase 2; covered partially in U5 via version-check stub.
- **Full failure-mode injection** (network drop mid-handshake, disk full, OOM) — deferred per brainstorm Phase 2.
- **Multi-version upgrade ladder testing** (v0.3.0 → v0.3.1 → v0.4.0 → v0.5.x state migration) — deferred per brainstorm Phase 3.
- **Real third-party VPN provider compatibility matrix** (Mullvad, ProtonVPN, IVPN configs) — deferred per brainstorm Phase 3; pre-release manual smoke covers the gap until then.
- **Daemon UID gate adversarial test with a real second user in the Docker container** — deferred per D-5; Phase 1B once core behavioral tests are stable.
- **Bug-to-test PR template + flake registry + coverage trend tracking** — cross-cutting workflow policies, deferred per D-4.

### Outside this plan's identity

- **Cross-platform fidelity on real consumer hardware** (a user's actual M-series MacBook with their specific terminal/font setup, distro-specific Linux quirks) — stays manual indefinitely; no automation mechanism exists.
- **Screen-reader accessibility validation** (VoiceOver / Orca) — stays manual; no automation hook.
- **Real-world adversarial network conditions** (ISP-level interference, geoblocking) — caught by beta-user feedback, not testable in CI.
- **End-user telemetry / crash reporting infrastructure** — separate product decision; not test infrastructure.

---

## Verification Strategy

**Per-PR verification (fast tier, runs via existing `test.yml`):**
1. `cargo test --workspace` passes — includes the new Rust integration tests (U6, U7, U8, U9)
2. No regression on the existing 731 Rust tests

**Nightly verification (heavy tier, runs via `integration-tests.yml`):**
1. All new `.sh` scripts execute in sequence; each one logs `OK: <test name>` on success
2. Total wall-clock ≤ 15 minutes
3. Any script failing fails the workflow run; the specific script + the assertion that failed is named in the run output

**Coverage-table verification (manual, one-time after the plan lands):**
1. Walk through `docs/manual-testing/multi-connection.md`; every check has an annotation
2. Coverage summary at the bottom shows ≥ 50% automation
3. Each "automated" annotation points at a real file path that actually contains the assertion

**Wall-clock measurement (post-merge, R2 / R4 verification):**
1. Open a representative PR; measure time from push to all-checks-green
2. Compare against the pre-Phase-1 baseline (currently ~5 minutes for fast checks); target: stays ≤ 5 minutes (no regression)
3. Nightly runs complete in ≤ 15 minutes consistently across 5 consecutive nights

---

## System-Wide Impact

- **`tests/integration/` becomes the primary integration test fixture.** Future test additions follow the netns-parametric pattern from U1.
- **`docs/manual-testing/multi-connection.md` becomes a living coverage document.** Every new manual check that's later automated updates its annotation.
- **CI runtime budget grows.** Nightly + workflow_dispatch invocations of `integration-tests.yml` add ~15 min/run. Free on public-repo GitHub Actions.
- **No production code changes.** Test additions only; no runtime behavior changes in `crates/vortix/src/`.
- **Boundary checks (`cargo xtask check-*-leak`) continue to pass** — test files in `crates/vortix/tests/` and `tests/integration/` are outside the boundary scope.

---

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Netns harness flakes under CI load (privileged container + multiple namespaces racing) | Med | Med | Each test logs `ip route show`, `iptables-save`, `ps aux` on failure. Make state observability the first-class debug surface. |
| OVPN test (U5) requires a real OVPN server in netns — may be heavier than expected to set up in Docker | Med | Low | If OVPN-in-netns proves flaky, U5 can fall back to a vortix-side process-spawn mock (intercept the subprocess invocation, assert the args, don't actually run openvpn). Documented in U5's approach. |
| Auto-promote test (U9) depends on `MockTunnel.set_down()` API existing in the test surface | Low | Low | If not exposed, add a `#[cfg(test)] pub fn` to the registry's test-utilities module. One-line change. |
| Coverage-table annotations drift from reality (test renamed; annotation not updated) | Med | Low | Add a CI lint check in Phase 2 (deferred): grep each "automated:" annotation's file path against actual repo file set; fail if any are stale. For Phase 1, manual review only. |
| Heavy-tier nightly takes longer than 15 min as more tests land | Low | Med | Each test reports its own runtime; sum visible in workflow output. If trending upward, split into parallel runs or invest in test parallelisation. Not a Phase 1 concern. |
| The user reports a bug not covered by the new tests | High | Low | Expected — Phase 1 covers ~55 of 114 checks. Bug becomes a new test case (see brainstorm cross-cutting practice "Bug-to-test policy" deferred to Phase 3 brainstorm). |
| The new Rust integration tests slow `cargo test --workspace` past the 5-min PR budget | Low | Med | The new tests are pure assertion + serde (no network, no subprocesses for U6/U7/U8/U9). Should add ≤ 5 seconds total. If they exceed, mark with `#[ignore]` and add a separate `cargo test --workspace -- --ignored` step. |

**Dependencies between units:**

```
U1 (harness foundation)
 ├─ U2 (multi-tunnel happy path)
 ├─ U3 (multi-tunnel killswitch)
 ├─ U4 (DNS scoping)
 ├─ U5 (OVPN --pull-filter)
 └─ U10 (security spot-checks)

(no U1 dependency — pure Rust tests):
 ├─ U6 (CLI grammar)
 ├─ U7 (JSON v2 envelope)
 ├─ U8 (PersistedState V1→V2)
 └─ U9 (auto-promote FSM events)

After U2-U10:
 └─ U11 (coverage table — references their file paths)

After U2-U10:
 └─ U12 (CI workflow integration — invokes their scripts)
```

U1 is the only hard prerequisite for the netns-based tests. U6-U9 (Rust-only) can ship in any order, in parallel with U1. U11 and U12 are last because they need the file paths from the earlier units.

---

## Open Questions

Resolvable at execution time, not blocking the plan:

1. **OVPN server harness shape (U5).** Real `openvpn` server in netns vs. process-spawn mock that intercepts the subprocess invocation. Decide at execution time based on Docker-container startup time + observed flakiness. Documented in U5's Approach.
2. **Auto-promote event observability surface (U9).** Read events via the journal file path, or via a daemon socket subscription, or via a `#[cfg(test)]` registry accessor? Implementer decides based on what's least invasive at the time.
3. **Annotation format readability in rendered Markdown (U11).** The proposed ` **·** _automated: <path>_` pattern works in GitHub-rendered Markdown; verify visually after the first batch of annotations. Iterate on format if it's noisy.
4. **Naming conventions for new test files.** `crates/vortix/tests/cli_grammar.rs` vs `crates/vortix/tests/cli_grammar_integration.rs` — match existing repo conventions when starting (whichever pattern `cli_integration.rs` set).
