# Manual Test Backlog — Multi-tunnel VPN

Pre-release human-verification checks. Categories below stay manual either because automation isn't feasible (real consumer hardware, screen readers, terminal rendering) or because the netns harness for end-to-end behavioral testing hasn't been built yet (tracked in [`docs/plans/2026-05-29-002-feat-behavioral-test-automation-plan.md`](../plans/2026-05-29-002-feat-behavioral-test-automation-plan.md)).

If a check below becomes covered by an automated test, **delete it from this file** — don't annotate. This doc is a residual backlog, not a coverage report.

## Setup prerequisites

- [ ] Two real WireGuard profiles available (`corp` = 0.0.0.0/0, `lab` = 10.0.0.0/8 only)
- [ ] One real OpenVPN profile (`.ovpn`) with username+password auth (OVPN 2.4+)
- [ ] An OVPN profile against OpenVPN 2.3.x for the version-rejection path (optional)
- [ ] `sudo` available — most paths require root
- [ ] A second user account on the host for the daemon UID-gate adversarial check

## Multi-tunnel happy paths

> Why manual: netns multi-tunnel harness not yet built (plan 002 U1+U2).

- [ ] Connect `corp` (0/0) then `lab` (10/8) — both show `●` in sidebar; header shows primary `corp` + `Tunnels [●corp ●lab]`
- [ ] After both connect: `ip route show` (Linux) / `netstat -rn` (macOS) confirms `corp` owns default; `lab` owns 10/8 only
- [ ] `curl https://api.ipify.org` returns `corp`'s exit IP (default-route through `corp`)
- [ ] `curl https://10.x.y.z/whatever` routes via `lab` (verify with `ip route get 10.x.y.z`)
- [ ] Connect 3 tunnels — Tunnels strip in header truncates with `+N`; primary stays at position 0
- [ ] Connect 6+ tunnels on a narrow terminal (resize to ~60 cols) — overflow ladder degrades through Tier 1 → Tier 2 → Tier 3 (dot-row) gracefully; never wraps

## Auto-promote banner

> Why manual: the `PrimaryTunnelChanged` journal-event variant is defined and serde-tested but **never constructed in production code** — feature wiring gap separate from test gap. UX validation requires the wiring to land first.

- [ ] With `corp` (0/0) and `lab` (10/8) up, manually `sudo wg-quick down corp` outside Vortix — within one Tick (~1s), TUI shows `Promoted 'lab' to primary because 'corp' disconnected — [u] to revert (10s)`; header updates
- [ ] Press `[u]` within 10s — `corp` reconnects; `lab` demotes if still eligible
- [ ] Wait >10s, banner auto-dismisses; `[u]` after dismissal does nothing; manual `vortix up corp` re-fires the takeover overlay
- [ ] No banner fires if there is no eligible secondary to promote
- [ ] No banner on Reconnecting transitions (only Connected → Disconnected triggers)

## Multi-tunnel disconnect flow

> Why manual: TUI keybinding behavior; needs ratatui-based snapshot harness (Phase 2 deferred).

- [ ] `d` on Connected secondary row → that one disconnects; primary unaffected
- [ ] `d` on Connected primary row → it disconnects; auto-promote fires if eligible secondary exists
- [ ] `Shift+D` with N≥2 active → "Disconnect all N tunnels?" confirm dialog renders; `Y` disconnects all
- [ ] `Shift+D` with N≤1 → identical to `d` (no confirm)
- [ ] `Enter` on a Connected secondary → that secondary disconnects (uniform-disconnect rule)
- [ ] `c` on a Connecting row's Connection Details panel → cancels the in-flight connect; sidebar clears `◐`
- [ ] `Tab` while Connection Details focused with N>1 active → focus cycles through active tunnels; wraps at end

## Killswitch v2 — real firewall (multi-tunnel)

> Why manual: single-tunnel covered by `tests/integration/killswitch.sh`; multi-tunnel netns harness not yet built (plan 002 U3).

- [ ] **Linux:** `sudo iptables-save | grep -E 'OUTPUT|vortix'` after `vortix up corp lab` shows expected per-tunnel ACCEPT rules + RFC1918 minus `lab`'s 10/8
- [ ] **Linux:** `sudo ip6tables-save` populated only if a tunnel has an IPv6 server IP
- [ ] **macOS:** `sudo pfctl -s rules` after `vortix up corp lab` shows pass-out rules per interface + RFC1918 minus 10/8
- [ ] **Atomicity:** while `corp`+`lab` are up, kill `corp` externally (`sudo wg-quick down corp`); during the brief Tick window, run `curl --max-time 2 https://example.com` from a background loop — verify no traffic leak window
- [ ] Kill all VPNs externally — within one Tick, Vortix detects, killswitch holds (Auto mode) — `ping 8.8.8.8` should fail
- [ ] Toggle to `s → Off` → traffic passes; toggle back to AlwaysOn → blocks until next connect
- [ ] Quit Vortix (`q`) with active tunnels — tunnels remain; killswitch state file persists; relaunch — Vortix re-attaches without dropping tunnels

## DNS scoping

> Why manual: end-to-end `/etc/resolv.conf` + `--pull-filter` assertion needs netns harness with real WG + OVPN servers (plan 002 U4+U5).

- [ ] **WG:** Connect `corp` (carries `DNS = 1.1.1.1`) then `lab` (also carries DNS) — `cat /etc/resolv.conf` shows ONLY `corp`'s DNS. Verify `lab`'s temp config in `${TMPDIR}/vortix-*/wg-*.conf` has no `DNS =` line
- [ ] **WG:** Disconnect `corp`; auto-promote moves `lab` to primary; `lab`'s DNS still suppressed (documented behavior — registry does NOT rewrite an active tunnel's config). Reconnect `lab` to apply its DNS as primary
- [ ] **OVPN:** Connect a secondary OVPN — verify the launched process command-line includes `--pull-filter ignore "dhcp-option DNS"` (`ps aux | grep openvpn`)
- [ ] **OVPN 2.3.x:** Attempt to add a SECOND OVPN tunnel with v2.3 installed — Vortix should refuse with "OpenVPN 2.4+ required"
- [ ] **WG temp-config sweep:** Kill Vortix mid-connect (Ctrl+C the daemon); confirm temp WG config left in `${TMPDIR}/vortix-<session>/`; restart Vortix — startup sweep deletes the orphan

## fwmark warning

> Why manual: TUI rendering of the warning line; predicate is unit-testable but visible text needs the ratatui snapshot harness (Phase 2).

- [ ] Connect a WG profile WITH `FwMark = 51820` in `[Interface]` — Connection Details shows no warning
- [ ] Connect a WG profile WITHOUT `FwMark` as a SECONDARY → Connection Details shows `⚠ Fwmark hijack risk: add 'FwMark = 51820' to your WG config. See docs/multi-tunnel-fwmark.md`
- [ ] Same secondary as the only/primary tunnel → warning does NOT fire
- [ ] Sidebar badge for fwmark-at-risk row shows the `●!` risk annotation

## TUI visual checks

> Why manual: terminal rendering fidelity at various widths, color/no-color modes, screen reader behavior — inherently human.

- [ ] Empty profile catalog → sidebar shows "No profiles" empty-state
- [ ] 10+ profiles loaded — sidebar scroll works with `j` / `k`; selection wraps at edges
- [ ] Resize terminal to 50 / 60 / 80 / 100 / 120 cols — header line never wraps; tunnels strip degrades through ladder tiers
- [ ] Resize to 80x12 (very short) — sidebar truncates rows cleanly; no panic
- [ ] Switch theme / no-color (set `NO_COLOR=1`) — badges render via Unicode shape only; bold / dim still readable
- [ ] Screen reader (VoiceOver / Orca) — sidebar row text is announceable (no purely-color signals)
- [ ] Open Connection Details for AwaitingUserInput row (OVPN with 2FA prompt) → `⚠ Press [Enter]...` hint appears
- [ ] Connection Details Role line for ex-primary after demotion → `Addressable (0.0.0.0/0, suppressed)`
- [ ] Security Guard with 0 tunnels → `EXPOSED`; with secondaries-only → `PARTIAL` + KS-mode-aware Killswitch bullet
- [ ] Security Guard IPv6 line — `⚠ IPv6: Not enforced (v4-only killswitch)` (honest)

## Daemon adversarial

> Why manual: requires a second OS user in the test environment; netns harness with two-user setup not yet built (plan 002 U10).

- [ ] **D1 happy path:** `sudo vortix daemon &` → socket at `${XDG_RUNTIME_DIR}/vortix.sock` / `${TMPDIR}/vortix.sock`; `ls -la` shows mode 0600
- [ ] **D3 bypass:** with no daemon running, `vortix status` falls back to direct scanner — exit 0, full status
- [ ] **D2 UID gate adversarial:** as a *different non-root user* attempt to `socat - UNIX-CONNECT:/path/to/vortix.sock` — connection accepted but daemon closes after the first frame with a UID-mismatch error
- [ ] **U22 wire-break:** with a v0.3.x `vortix` binary on PATH, try `vortix status --json` against a v2 daemon socket — fails cleanly (structured error), not silent mis-parse
- [ ] Send `SIGTERM` to the daemon — socket unlinks cleanly; in-flight tunnels stay up (kernel state untouched)
- [ ] Restart daemon → re-attaches to existing tunnels via scanner discovery (no double-connect)

## V2 → V1 downgrade

> Why manual: requires installing an actual v0.3.x binary; release-time pre-ship check only.

- [ ] Connect with this version, then revert binary to v0.3.x and launch — follow `docs/MIGRATION.md` steps; verify v0.3.x runs
- [ ] Journal JSONL written by V2 — v0.3.x replay tools skip unknown variants without erroring (`#[non_exhaustive]` guarantee)

## Failure modes (real-world)

> Why manual: disk-full / OOM / network-drop mid-handshake fault injection not yet built (Phase 2 deferred).

- [ ] Network drops mid-connect → FSM retries per existing retry budget; banner / log entries readable
- [ ] OVPN auth fails (wrong password) → `✗` with reason; auth overlay can re-prompt
- [ ] Profile deleted while connected → registry handles the missing config gracefully; tunnel disconnects on next Tick
- [ ] Out-of-disk during `secret_file` write (simulate with `mount -o remount,size=1` or a small ramdisk) → graceful error, no half-written auth file
- [ ] Profile config readable only by root, ran as non-root → permission error surfaced; doesn't leak path

## Security spot-checks (real filesystem)

> Why manual: needs a real Linux filesystem with controlled symlink + uid setup; netns harness deferred (plan 002 U10).

- [ ] `~/.config/vortix/*.auth` files have mode 0600, owned by the invoking user (not root, even if vortix ran with sudo)
- [ ] Symlink attack against `~/.config/vortix/foo.auth` (replace with a symlink to `/etc/shadow` between calls) → `write_secret_file` refuses (`O_NOFOLLOW`)
- [ ] `ps aux | grep openvpn` does NOT show username/password on the command line
- [ ] `/tmp/vortix-*/` temp WG configs are mode 0600 and unlinked on tunnel down

## Cross-platform parity

> Why manual: CI runners ≠ real consumer hardware. Inherently human.

- [ ] macOS (Apple Silicon) — full smoke through Multi-tunnel happy paths
- [ ] macOS (Intel) — if available; same smoke
- [ ] Linux (iptables host) — full smoke
- [ ] Linux (nftables host — the fallback path matters) — full smoke
- [ ] Windows (NG per origin — should not crash; multi-tunnel features may be stubbed)

## Performance / scale

> Why manual: perf benchmarks have different signal + cadence than per-PR tests; Phase 2 perf workflow deferred.

- [ ] 10 active tunnels — TUI render stays responsive (<16ms frame budget); no obvious lag on `Tab` / sidebar nav
- [ ] Killswitch ruleset rewrite latency at N=5 — `sudo time pfctl -f -` / `iptables-restore` round-trip should be sub-100ms
- [ ] 50 profiles loaded (synthesize empty `.conf` files) — sidebar scroll and search work; no perceptible lag

## Journal observability (post-wiring)

> Why manual: `PrimaryTunnelChanged` / `ConnectAttemptBlockedByConflict` event emission is not yet wired in production code (feature gap). Once wired, this section may become automatable.

- [ ] After a multi-tunnel session with auto-promote, `tail -f ~/.local/share/vortix/journal.jsonl | jq '.event'` shows `PrimaryTunnelChanged` and `ConnectAttemptBlockedByConflict` envelopes with the documented fields
- [ ] `event.reason` values appear as `initial_connect` / `prior_primary_disconnected` / `external_route_change` for the right transitions
