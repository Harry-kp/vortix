# Manual Test Plan — Multi-tunnel VPN connections

Plan: [`docs/plans/2026-05-28-001-feat-multi-connection-plan.md`](../plans/2026-05-28-001-feat-multi-connection-plan.md)
Brainstorm: [`docs/brainstorms/2026-05-28-multi-connection-requirements.md`](../brainstorms/2026-05-28-multi-connection-requirements.md)
Shipped in: v0.4.0 (pending)

Automated tests cover FSM, parsers, CIDR math, JSON shapes, wire-format serde, and UI render-builders with hand-rolled snapshots. The list below is everything that can only be validated by a human running the binary against real kernels, real WG/OVPN daemons, and real terminals. Run on both macOS and Linux unless flagged otherwise.

## Coverage map (Phase 1 automation status)

Per-category map of what's automated vs still requires manual verification. Automated test paths are repo-relative. See [`docs/plans/2026-05-29-002-feat-behavioral-test-automation-plan.md`](../plans/2026-05-29-002-feat-behavioral-test-automation-plan.md) for the automation plan.

| Category | Status | Where covered / why manual |
|---|---|---|
| Setup prerequisites | n/a | Environment config; not test material |
| Single-tunnel regression | **automated (partial)** | `tests/integration/wg_happy_path.sh` covers connect/disconnect lifecycle; CLI behavior covered by `crates/vortix/tests/cli_integration.rs` (37 tests). Residual: real OVPN auth flow + telemetry chart manual |
| Multi-tunnel happy paths | **manual** | Needs netns-multi-tunnel harness (Phase 1 plan U1+U2 — deferred) |
| Conflict detection (registry) | **automated** | `crates/vortix/src/vortix_core/engine/registry.rs` — `conflict_when_existing_primary_holds_default_route`, `conflict_against_pending_default_route_claimant`, `split_slash_one_pair_*`, `slash_two_quartet_*`, `force_true_bypasses_*` |
| CLI conflict path | **automated (partial)** | Registry-side covered above; CLI exit-code mapping needs `vortix up <conflict-profile>` integration test (Phase 1 U6 deferred to netns harness) |
| Auto-promote banner (D-3) | **partial — feature gap** | Registry promotion logic covered (`disconnect_primary_promotes_secondary_with_zero_slash_zero`); event variant defined and serde-tested in `engine/event.rs`; **but the `PrimaryTunnelChanged` event is never emitted in production code** — wiring gap, not a test gap. The 10s banner UX is manual until wired |
| Multi-tunnel disconnect flow | **manual** | TUI keybinding behavior (`d`/`D`/`Tab`/`c`/`u`); needs TUI snapshot harness (Phase 2 deferred) |
| CLI down / reconnect grammar | **automated** | `crates/vortix/tests/cli_integration.rs` — `clap_parses_down_with_profile_arg`, `clap_parses_down_all_flag`, `clap_rejects_down_profile_with_all_flag`, `clap_parses_reconnect_with_profile_arg`, `clap_parses_reconnect_no_args`, `clap_parses_up_yes_*` (plan 002 U6-narrow) |
| Killswitch v2 — real firewall | **automated (single-tunnel) / manual (multi)** | `tests/integration/killswitch.sh` covers single-tunnel default-DROP behavior. Multi-tunnel `iptables-restore` ruleset + atomicity probe needs Phase 1 U3 (deferred to netns harness) |
| DNS scoping (R13) | **partial** | WG temp-config DNS-strip logic unit-tested in `crates/vortix/src/vortix_protocol_wireguard/tunnel.rs`. End-to-end `/etc/resolv.conf` assertion + OVPN `--pull-filter` needs Phase 1 U4+U5 (deferred to netns harness) |
| fwmark warning (D-1) | **manual** | TUI rendering; predicate is unit-testable but the warning text is not. Phase 2 TUI snapshot harness |
| Sidebar / header / Connection Details visual | **automated (render builders) / manual (visual fidelity)** | `crates/vortix/src/ui/dashboard/{sidebar,header,connection_details,security}.rs` — ratatui `TestBackend` snapshot tests cover render logic. Visual fidelity at user terminal widths + screen readers stays manual |
| JSON v2 envelope (U21) | **automated** | `crates/vortix/tests/json_v2_envelope.rs` — 7 tests covering schema_version pinning, empty/single/multi/no-primary states, back-compat `data.connection` field, optional-field null serialization, serde round-trip (plan 002 U7) |
| Daemon (D1-D3) + IPC | **automated (partial)** | `crates/vortix/src/daemon/server.rs` and `mod.rs` cover socket bind, frame round-trip, UID-gate logic. Adversarial cross-UID attempt + daemon-sweep tests are manual until netns harness (Phase 1 U10 deferred) |
| PersistedState V2 migration (U11) | **automated** | `crates/vortix/src/core/killswitch.rs` — `v2_persisted_state_round_trips`, `v1_file_deserializes_with_serde_defaults`, `v1_with_no_interface_coerces_*`, `v2_file_with_schema_version_field_deserializes`, `persisted_state_corrupted_mode_fails`, `persisted_state_empty_json_fails`, `unknown_future_schema_falls_back_to_v1_coercion`, `v0_3_x_v1_reader_tolerates_v2_file` (8 tests) |
| V2 → V1 downgrade | **manual** | Needs real v0.3.x binary install; release-time pre-ship check |
| Failure modes / negative paths | **partial** | Bad config syntax + missing files covered in protocol-parser unit tests. Disk-full / OOM / network-drop mid-handshake = Phase 2 fault-injection layer |
| Security spot-checks | **partial** | `write_secret_file` TOCTOU mitigation tested in `crates/vortix/src/vortix_core/secret_file.rs`; symlink attack + ps aux credential scan + real-file-mode assertions need netns harness (Phase 1 U10 deferred) |
| Cross-platform parity | **manual** | Real consumer hardware (M-series MacBook, distro-specific Linux); inherently human. CI matrix (`Test (macos-latest)`, `Test (ubuntu-latest)`, `Test (fedora-41)`) catches 80%; long-tail stays manual |
| Performance / scale | **manual / deferred** | N=10 tunnels TUI render budget; killswitch refresh latency. Phase 2 perf workflow |
| Journal observability (U23) | **partial — feature gap** | Event variants defined and serde-tested in `engine/event.rs`. Production emission of `PrimaryTunnelChanged` / `ConnectAttemptBlockedByConflict` is **not yet wired** — same gap as auto-promote |

**Status legend:**
- **automated** = fully covered; no human verification needed pre-release
- **automated (partial)** = primary path covered; some edge cases still manual
- **partial** = unit-level covered; integration / behavioral end-to-end manual
- **partial — feature gap** = test variants exist but production wiring is missing (separate fix needed)
- **manual** = stays human; no automation feasible or value
- **manual / deferred** = automatable but waiting for Phase 2/3 infrastructure

**Phase 1 plan tracks the remaining gaps:** [`docs/plans/2026-05-29-002-feat-behavioral-test-automation-plan.md`](../plans/2026-05-29-002-feat-behavioral-test-automation-plan.md) — units U1-U5, U10, U12 add the netns multi-tunnel harness needed to convert the "manual" rows above into automated coverage.

## Setup prerequisites

- [ ] Two real WireGuard profiles available (`corp` = 0.0.0.0/0, `lab` = 10.0.0.0/8 only)
- [ ] One real OpenVPN profile (`.ovpn`) with username+password auth (OVPN 2.4+)
- [ ] An OVPN profile against OpenVPN 2.3.x for the version-rejection path (optional — only if you have an old install lying around)
- [ ] `sudo` available — most paths require root
- [ ] A second user account on the host for the daemon UID-gate adversarial check

## Single-tunnel regression — must keep working

- [ ] Existing single-WG flow: `sudo vortix up corp` → connects, sidebar shows `● corp`, header shows `Exit: <ip>`
- [ ] Existing single-OVPN flow with auth prompt: TUI asks for username/password, connects
- [ ] `sudo vortix down` (no args, 1 active) disconnects the one tunnel — old script muscle memory preserved
- [ ] `sudo vortix reconnect` (no args, 1 active) cycles that tunnel
- [ ] Killswitch Auto / AlwaysOn / Off cycle via `s` key — single-tunnel rules apply correctly
- [ ] Telemetry chart populates (latency / packet loss) within ~10s of connect
- [ ] Profile rename / delete still works
- [ ] Existing v0.3.x JSON consumer (parsing `data.connection`) still gets correct shape for single primary

## Multi-tunnel — happy paths

- [ ] Connect `corp` (0/0) then `lab` (10/8) — both show `●` in sidebar; header shows primary `corp` + `Tunnels [●corp ●lab]`
- [ ] After both connect: `ip route show` (Linux) / `netstat -rn` (macOS) confirms `corp` owns default; `lab` owns 10/8 only
- [ ] `curl https://api.ipify.org` returns `corp`'s exit IP (default-route through `corp`)
- [ ] `curl https://10.x.y.z/whatever` routes via `lab` (verify with `ip route get 10.x.y.z`)
- [ ] Connect 3 tunnels — Tunnels strip in header truncates with `+N`; primary stays at position 0
- [ ] Connect 6+ tunnels on a narrow terminal (resize to ~60 cols) — overflow ladder degrades through Tier 1 → Tier 2 → Tier 3 (dot-row) gracefully; never wraps

## Conflict detection (registry)

- [ ] Connect `corp` (0/0), then `Enter` on a second 0/0 profile (e.g. `personal`) — `ConfirmDefaultRouteTakeover` overlay fires with from/to names; `Y` promotes `personal`, demotes `corp` to Addressable-suppressed; `N` cancels
- [ ] Connect `lab` (10/8), then `Enter` on a profile claiming `10.5.0.0/16` (overlap subset) — `ConfirmRouteOverlap` overlay fires; CIDRs are listed; `Y` connects with force; `N` cancels
- [ ] Race: `Enter` on `corp` (still Connecting), then immediately `Enter` on `personal` (also 0/0) — overlay cites `corp` as the in-flight claimant (SC12)

## CLI conflict path

- [ ] `sudo vortix up <0/0-profile>` with another 0/0 already up → exits **4** (StateConflict); stderr hint mentions `--yes`
- [ ] `sudo vortix up <0/0-profile> --yes` with conflict → no prompt, second connects, primary inverts
- [ ] `echo $?` after each call matches the documented exit codes (0/3/4/5/6)
- [ ] `vortix up <nonexistent>` → exits **3** (NotFound)

## Auto-promote banner (D-3)

- [ ] With `corp` (0/0) and `lab` (10/8) up, manually `sudo wg-quick down corp` outside Vortix — within one Tick (~1s), TUI shows `Promoted 'lab' to primary because 'corp' disconnected — [u] to revert (10s)`; header updates
- [ ] Press `[u]` within 10s — `corp` reconnects; `lab` demotes if still eligible
- [ ] Wait >10s, banner auto-dismisses; `[u]` after dismissal does nothing; manual `vortix up corp` re-fires the takeover overlay
- [ ] No banner fires if there is no eligible secondary to promote
- [ ] No banner on Reconnecting transitions (only Connected → Disconnected triggers)

## Multi-tunnel disconnect flow

- [ ] `d` on Connected secondary row → that one disconnects; primary unaffected
- [ ] `d` on Connected primary row → it disconnects; auto-promote should fire if eligible secondary exists
- [ ] `Shift+D` with N≥2 active → "Disconnect all N tunnels?" confirm dialog renders; `Y` disconnects all
- [ ] `Shift+D` with N≤1 → identical to `d` (no confirm)
- [ ] `Enter` on a Connected secondary → that secondary disconnects (uniform-disconnect rule)
- [ ] `c` on a Connecting row's Connection Details panel → cancels the in-flight connect; sidebar clears `◐`
- [ ] `Tab` while Connection Details focused with N>1 active → focus cycles through active tunnels; wraps at end

## CLI down / reconnect grammar

- [ ] `sudo vortix down` (no args, N>1 active) → all disconnect; JSON `data.disconnected` lists all names
- [ ] `sudo vortix down --all` (N>1) → same as above
- [ ] `sudo vortix down corp` (`corp` among N active) → only `corp` disconnects; others stay
- [ ] `sudo vortix down corp` (`corp` not active) → exits **0** (idempotent)
- [ ] `sudo vortix reconnect` (N>1) → all Connected tunnels cycle
- [ ] `sudo vortix reconnect lab` → only `lab` cycles

## Killswitch v2 — real firewall

- [ ] **Linux:** `sudo iptables-save | grep -E 'OUTPUT|vortix'` after `vortix up corp lab` shows expected per-tunnel ACCEPT rules + RFC1918 minus `lab`'s 10/8
- [ ] **Linux:** `sudo ip6tables-save` populated only if a tunnel has an IPv6 server IP
- [ ] **macOS:** `sudo pfctl -s rules` after `vortix up corp lab` shows pass-out rules per interface + RFC1918 minus 10/8
- [ ] **Atomicity:** while `corp`+`lab` are up, kill `corp` externally (`sudo wg-quick down corp`); during the brief Tick window, run `curl --max-time 2 https://example.com` from a background loop — verify no traffic leak window (continuous block or continuous pass through `lab`, never both)
- [ ] Kill all VPNs externally — within one Tick, Vortix detects, killswitch holds (Auto mode) — `ping 8.8.8.8` should fail
- [ ] Toggle to `s → Off` → traffic passes; toggle back to AlwaysOn → blocks until next connect
- [ ] Quit Vortix (`q`) with active tunnels — tunnels remain; killswitch state file persists; relaunch — Vortix re-attaches without dropping tunnels

## DNS scoping (R13)

- [ ] **WG:** Connect `corp` (carries `DNS = 1.1.1.1`) then `lab` (also carries DNS) — `cat /etc/resolv.conf` shows ONLY `corp`'s DNS (`lab`'s stripped). Verify `lab`'s temp config in `${TMPDIR}/vortix-*/wg-*.conf` has no `DNS =` line
- [ ] **WG:** Disconnect `corp`; auto-promote moves `lab` to primary; `lab`'s DNS still suppressed (it was already up as secondary — registry does NOT rewrite an active tunnel's config; documented as expected. Reconnect `lab` to apply its DNS as primary)
- [ ] **OVPN:** Connect a secondary OVPN — verify the launched process command-line includes `--pull-filter ignore "dhcp-option DNS"` (use `ps aux | grep openvpn`)
- [ ] **OVPN 2.3.x:** Attempt to add a SECOND OVPN tunnel with v2.3 installed — Vortix should refuse with "OpenVPN 2.4+ required" before connect; single-tunnel OVPN still works on 2.3.x
- [ ] **WG temp-config sweep:** Kill Vortix mid-connect (Ctrl+C the daemon process); confirm temp WG config left behind in `${TMPDIR}/vortix-<session>/`; restart Vortix — startup sweep deletes the orphan

## fwmark warning (D-1)

- [ ] Connect a WG profile WITH `FwMark = 51820` in `[Interface]` — Connection Details shows no warning
- [ ] Connect a WG profile WITHOUT `FwMark` as a SECONDARY (primary already up) — Connection Details shows `⚠ Fwmark hijack risk: add 'FwMark = 51820' to your WG config. See docs/multi-tunnel-fwmark.md`
- [ ] Same secondary as the only/primary tunnel → warning does NOT fire (single-tunnel case has no hijack risk)
- [ ] Sidebar badge for fwmark-at-risk row shows the `●!` risk annotation (when U17's predicate wires it — current code keeps the hook even if predicate is conservative; verify visually)

## Sidebar / header / Connection Details visual checks

- [ ] Empty profile catalog → sidebar shows "No profiles" empty-state
- [ ] 10+ profiles loaded — sidebar scroll works with `j` / `k`; selection wraps at edges
- [ ] Resize terminal to 50 / 60 / 80 / 100 / 120 cols — header line never wraps; tunnels strip degrades through ladder tiers
- [ ] Resize to 80x12 (very short) — sidebar truncates rows cleanly; no panic
- [ ] Switch theme / no-color (set `NO_COLOR=1`) — badges render via Unicode shape only; bold / dim still readable
- [ ] Screen reader (VoiceOver / Orca) — sidebar row text is announceable (no purely-color signals)
- [ ] Open Connection Details for a Connecting row → compact transitional summary renders
- [ ] Open Connection Details for AwaitingUserInput row (OVPN with 2FA prompt) → `⚠ Press [Enter]...` hint appears
- [ ] Connection Details Role line for primary → `Primary (0.0.0.0/0)`; for `lab` → `Secondary (10.0.0.0/8)`; for ex-primary after demotion → `Addressable (0.0.0.0/0, suppressed)`
- [ ] Security Guard with 0 tunnels → `EXPOSED`; with primary present → `PROTECTED`; with secondaries-only (no primary) → `PARTIAL` + KS-mode-aware Killswitch bullet
- [ ] Security Guard IPv6 line — always shows `⚠ IPv6: Not enforced (v4-only killswitch)` (honest) on a host that doesn't actually have v6 leak detection
- [ ] Sigil legend at panel bottom: `Legend: ✓ pass · ⚠ at risk · ─ not applicable`

## JSON v2 envelope (U21)

- [ ] `vortix status --json` with 0 active → `connections: []`, `primary: null`, `connection: null`, `schema_version: 2`
- [ ] `vortix status --json` with 1 primary → `connections: [<corp>]`, `primary: "corp"`, `connection: <corp>` (back-compat)
- [ ] `vortix status --json` with 2 (1 primary, 1 secondary) → `connections: [<corp>, <lab>]`, `primary: "corp"`, `connection: <corp>`
- [ ] `vortix status --json` with 3 secondaries no primary (synthetic — disconnect the 0/0) → `primary: null`, `connection: null`
- [ ] A v1 reader script (`jq '.data.connection.profile'`) still works for the single-primary case
- [ ] `vortix status --watch --json` streams NDJSON, one envelope per tick, `schema_version` stays 2 across the stream

## Daemon (D1-D3) + IPC

- [ ] **D1 happy path:** `sudo vortix daemon &` → socket appears at `${XDG_RUNTIME_DIR}/vortix.sock` (Linux) or `${TMPDIR}/vortix.sock` (macOS); `ls -la` shows mode 0600 owned by the daemon UID
- [ ] **D3 bypass:** with no daemon running, `vortix status` falls back to direct scanner — exit 0, full status; no socket-connection error in stderr
- [ ] **D3 bypass:** with daemon running but stopped mid-call, `vortix status --no-daemon` ignores the live socket and goes direct
- [ ] **D2 UID gate:** run `sudo vortix daemon &` as root, then as a non-root user run `vortix status` — request is denied at the daemon (check daemon stderr for the UID-mismatch log line); CLI falls back to direct read (D3) so the user still gets output
- [ ] **D2 UID gate adversarial:** as a *different non-root user* attempt to `socat - UNIX-CONNECT:/path/to/vortix.sock` — connection accepted by the kernel but the daemon closes after the first frame with a UID-mismatch error
- [ ] **U22 wire-break:** with a v0.3.x `vortix` binary on PATH, try `vortix status --json` against a v2 daemon socket — should fail cleanly (structured error), not silently mis-parse. Same for v2 client vs v1 daemon
- [ ] **U22 multi-tunnel through daemon:** if a future CLI flag routes writes through the daemon, verify `vortix up <conflict-profile>` returns exit 4 with identical hint text whether daemon is up or not
- [ ] Send `SIGTERM` to the daemon — socket unlinks cleanly; in-flight tunnels stay up (kernel state untouched)
- [ ] Restart Vortix daemon → re-attaches to existing tunnels via scanner discovery (no double-connect)

## PersistedState V2 migration (U11)

- [ ] On a host with v0.3.x installed and connected (so v1 `killswitch-state.json` exists), upgrade to this PR — first launch reads v1, writes v2 promptly; killswitch state preserved (no disarmed window beyond one boot)
- [ ] Synthesize a v1 file by hand (the v0.3.x shape: `{ interface, server_ip, ... }`) → Vortix loads it, fills in V2 defaults via serde, persists as V2
- [ ] Corrupt the state file (random bytes) → Vortix logs the parse error, treats as no-state, killswitch disarmed (documented soft-fail); no crash
- [ ] Phantom interface: kill a tunnel externally, write a v2 state pointing at the now-gone interface, restart — startup validation drops phantom; killswitch doesn't try to enable rules referencing it

## V2 → V1 downgrade (MIGRATION.md)

- [ ] Connect with this PR, then revert binary to v0.3.x and launch — follow `docs/MIGRATION.md` steps; verify v0.3.x runs (it may need to `rm ~/.config/vortix/killswitch-state.json` per the migration doc)
- [ ] Journal JSONL written by V2 (with `PrimaryTunnelChanged` events) — v0.3.x replay tools skip unknown variants without erroring (`#[non_exhaustive]` guarantee)

## Failure modes / negative paths

- [ ] `sudo vortix up corp` while `corp`'s WG config has a syntax error → tunnel fails fast with a parser error; sidebar shows `✗`; retry with `Enter` works after fix
- [ ] Network drops mid-connect → FSM retries per existing retry budget; banner / log entries readable
- [ ] OVPN auth fails (wrong password) → `✗` with reason; auth overlay can re-prompt
- [ ] Profile deleted while connected → registry handles the missing config gracefully; tunnel disconnects on next Tick
- [ ] Out-of-disk during `secret_file` write (simulate with `mount -o remount,size=1` or a small ramdisk) → graceful error, no half-written auth file, no kernel state changes
- [ ] Profile config readable only by root, ran as non-root → permission error surfaced; doesn't leak path

## Security spot-checks

- [ ] `~/.config/vortix/*.auth` files have mode 0600, owned by the invoking user (not root, even if vortix ran with sudo)
- [ ] Symlink attack against `~/.config/vortix/foo.auth` (replace with a symlink to `/etc/shadow` between calls) → `write_secret_file` refuses (`O_NOFOLLOW`)
- [ ] `ps aux | grep openvpn` does NOT show username/password on the command line
- [ ] `/tmp/vortix-*/` temp WG configs are mode 0600 and unlinked on tunnel down
- [ ] Daemon socket survives a `chmod 0644` attack? It shouldn't — Vortix re-binds with 0600 on startup

## Cross-platform parity

- [ ] macOS (Apple Silicon)
- [ ] macOS (Intel) — if available
- [ ] Linux (`iptables` host)
- [ ] Linux (`nftables` host — the fallback path matters)
- [ ] Windows (NG per origin — should not crash; multi-tunnel features may be stubbed)

## Performance / scale

- [ ] 10 active tunnels — TUI render stays responsive (<16ms frame budget); no obvious lag on `Tab` / sidebar nav
- [ ] Killswitch ruleset rewrite latency at N=5 — measure `sudo time pfctl -f -` / `iptables-restore` round-trip; should be sub-100ms
- [ ] 50 profiles loaded (synthesize empty `.conf` files) — sidebar scroll and search work; no perceptible lag

## Journal observability (U23)

- [ ] After a multi-tunnel session with auto-promote, `tail -f ~/.local/share/vortix/journal.jsonl | jq '.event'` shows `PrimaryTunnelChanged` and (where applicable) `ConnectAttemptBlockedByConflict` envelopes with the documented fields
- [ ] `event.reason` values appear as `initial_connect` / `prior_primary_disconnected` / `external_route_change` for the right transitions
