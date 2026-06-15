# Manual Test Backlog

Pre-release human-verification checks. Every row here is something that CI can't catch and a human has to confirm before shipping.

**Convention:** Append rows when a new feature ships with a manual check. **Delete rows** when an automated test starts covering the check — never annotate "now automated"; the row goes away.

| # | Check | Steps | Why manual |
|---|---|---|---|
| 1 | Two real WG profiles available for multi-tunnel testing | Have `corp` (0/0) and `lab` (10/8) configs ready | Environment setup; can't be automated |
| 2 | Real OpenVPN profile with username+password auth (OVPN 2.4+) | Have `.ovpn` file with auth-user-pass directive | Environment setup |
| 3 | OVPN 2.3.x binary available for version-rejection path | `apt install openvpn=2.3.*` or equivalent | Test fixture; requires installing old binary |
| 4 | Second OS user account for daemon UID-gate adversarial test | `useradd vortix-adversary` | Test fixture; cross-UID setup |
| 5 | Multi-tunnel routing: corp owns default, lab owns 10/8 | `vortix up corp; vortix up lab; ip route get 1.1.1.1` shows `dev wg-corp`; `ip route get 10.x.y.z` shows `dev wg-lab` | Multi-tunnel netns harness not built (plan 002 U1+U2) |
| 6 | Multi-tunnel real-internet exit IP differs per tunnel | `curl https://api.ipify.org` via corp returns IP A; same via lab returns IP B (when lab is primary) | Requires real public IPs; netns can't fake this |
| 7 | 3+ tunnels overflow ladder in header degrades cleanly | Connect 6 tunnels on a 60-col terminal; verify Tier 1 → Tier 2 → Tier 3 (dot-row) transitions; never wraps | TUI rendering; needs ratatui snapshot harness (Phase 2) |
| 8 | _(removed — auto-promote feature retired; primary changes are silent, user manages manually)_ | — | — |
| 9 | _(removed — see #8)_ | — | — |
| 10 | _(removed — see #8)_ | — | — |
| 11 | Multi-tunnel disconnect via `d` key disconnects single tunnel | Connect 2 tunnels; focus secondary in sidebar; press `d`; only that one disconnects | TUI keybinding; needs snapshot harness |
| 12 | `Shift+D` with N≥2 fires "Disconnect all N?" confirm dialog | Connect 3 tunnels; press `Shift+D`; verify dialog renders; Y disconnects all | Same as #11 |
| 13 | `Tab` cycles Connection Details focus across active tunnels | 2 tunnels up; focus Connection Details; press `Tab`; focus advances; wraps at end | Same as #11 |
| 14 | `c` cancels an in-flight Connecting state | Connect a slow tunnel; while Connecting (`◐`), focus Details + press `c`; sidebar clears | Same as #11 |
| 15 | Multi-tunnel iptables ruleset has per-tunnel ACCEPT + RFC1918 carve | After `vortix up corp lab`: `sudo iptables-save` shows `-A OUTPUT -o wg-corp/wg-lab -j ACCEPT` + no `-d 10.0.0.0/8` (carved by lab's 10/8 declaration) | Multi-tunnel netns harness deferred (plan 002 U3) |
| 16 | Atomicity probe: no traffic leak window during tunnel transition | While corp+lab up, run continuous `curl 10.99.0.99 --max-time 2` loop; externally kill corp; assert no BLOCKED → ACCEPT → BLOCKED gap | Same as #15 |
| 17 | macOS pf ruleset has per-tunnel pass-out rules + RFC1918 carve | macOS only: `sudo pfctl -s rules` shows per-interface pass-outs + RFC1918 carve | Same as #15; macOS-only |
| 18 | WG secondary's `DNS = ...` stripped from temp config | Connect corp (with `DNS=1.1.1.1`) + lab (with `DNS=8.8.8.8` as secondary). Verify `/etc/resolv.conf` has only 1.1.1.1; lab's temp WG config in `${TMPDIR}/vortix-*/` has no `DNS=` line | DNS-scoping netns harness deferred (plan 002 U4) |
| 19 | OVPN secondary launched with `--pull-filter ignore "dhcp-option DNS"` | Connect WG primary; connect OVPN as secondary; `ps aux \| grep openvpn` shows the filter arg | OVPN netns harness deferred (plan 002 U5) |
| 20 | OVPN 2.3.x as secondary is rejected with "OpenVPN 2.4+ required" | With OVPN 2.3 installed: connect any primary; attempt OVPN 2.3 as secondary; vortix refuses before connect attempt | Needs real OVPN 2.3 binary install |
| 21 | fwmark hijack warning shows on Connection Details for WG without `FwMark` | Connect WG without `FwMark = ...` as secondary; Connection Details shows `⚠ Fwmark hijack risk...` line | TUI rendering |
| 22 | fwmark warning DOES NOT show when secondary has `FwMark = 51820` | Same as #21 but with FwMark set; no warning line | TUI rendering |
| 23 | fwmark warning DOES NOT show when single tunnel (not secondary) | Connect just the WG-without-FwMark profile alone; no warning | TUI rendering |
| 24 | Sidebar empty-state renders correctly | Start vortix with no profiles imported; sidebar shows "No profiles" message | TUI rendering |
| 25 | Sidebar scroll with 10+ profiles works | Import 15 profiles; `j`/`k` scroll the list; selection wraps at edges | TUI rendering |
| 26 | Header degrades at 50 / 60 / 80 / 100 / 120 columns | Resize terminal to each width; header never wraps; tunnels strip uses the right Tier | TUI rendering at variable widths |
| 27 | Sidebar truncates rows cleanly at 80x12 | Resize to 80x12; sidebar still renders without panic; rows truncated with ellipsis | TUI rendering |
| 28 | `NO_COLOR=1` renders badges via Unicode shape only | `NO_COLOR=1 vortix`; status badges (`●` etc.) still distinguishable by shape, not just color | TUI rendering + accessibility |
| 29 | VoiceOver / Orca announces sidebar rows | macOS VoiceOver or Linux Orca enabled; sidebar row text is announced; no purely-color signals required for comprehension | Screen-reader accessibility; no automation hook |
| 30 | AwaitingUserInput hint renders on Connection Details | OVPN with 2FA prompt — Connection Details shows `⚠ Press [Enter] to provide 2FA code/passphrase/input` | TUI rendering |
| 31 | Demoted ex-primary Role shows `Addressable (0.0.0.0/0, suppressed)` | Connect 2× 0/0 profiles; one takes over; the demoted one shows the suppressed role in Connection Details | TUI rendering |
| 32 | Security Guard shows `EXPOSED` with 0 tunnels | No tunnels up; Security panel headline = `EXPOSED` | TUI rendering |
| 33 | Security Guard shows `PARTIAL` with secondaries-only | Connect tunnels that don't claim 0/0; Security panel = `PARTIAL` + KS-mode-aware Killswitch bullet | TUI rendering |
| 34 | _(retired — replaced by rows 89–99 covering the v0.4.2 dual-stack Real IP / Exit IP redesign)_ | — | — |
| 35 | Daemon socket created at expected path with mode 0600 | `sudo vortix daemon &`; verify socket at `${XDG_RUNTIME_DIR}/vortix.sock` (Linux) or `${TMPDIR}/vortix.sock` (macOS); `ls -la` shows mode 0600 | Real-fs assertion; daemon test harness deferred |
| 36 | Read-only CLI ops bypass daemon when socket absent | Stop daemon; run `vortix status`; falls back to direct scanner with exit 0 | Same as #35 |
| 37 | Cross-UID adversarial: different non-root user can't talk to daemon | Run daemon as user A; as user B attempt `socat - UNIX-CONNECT:/path/to/vortix.sock`; daemon closes after first frame with UID-mismatch error | Needs two-user setup; deferred (plan 002 U10) |
| 38 | Wire-format compatibility: v0.3.x client → v2 daemon socket fails cleanly | Old vortix binary on PATH; `vortix status --json` against running v2 daemon; structured error, not silent mis-parse | Needs real v0.3.x binary install |
| 39 | SIGTERM to daemon cleans up socket; tunnels persist | `kill -TERM <daemon-pid>`; socket unlinks; active tunnels stay up; `wg show` confirms | Real-fs + signal handling; needs daemon test harness |
| 40 | Daemon restart re-attaches to existing tunnels (no double-connect) | Start daemon; up a tunnel; SIGTERM; start new daemon; no second wg-quick fires; tunnel still up | Same as #39 |
| 41 | V2 → V1 downgrade: v0.3.x reads V2 journal without erroring | Connect with current binary; revert to v0.3.x; `journalctl` replay tools skip unknown variants per `#[non_exhaustive]` | Needs real v0.3.x binary; release-time only |
| 42 | V2 → V1 downgrade: clean shutdown + v0.3.x cold start works | Per `docs/MIGRATION.md` 5-step procedure; v0.3.x launches successfully | Same as #41 |
| 43 | Network drop mid-handshake → FSM retries per budget | Use `tc qdisc add dev <iface> root netem loss 100%` mid-handshake; vortix retries; log entries readable | Fault injection deferred (Phase 2) |
| 44 | OVPN auth fails with wrong password → `✗` + re-prompt available | Connect with wrong password; sidebar shows `✗`; auth overlay can re-open | Real OVPN server needed |
| 45 | Profile deleted while connected → tunnel disconnects on next Tick | Active tunnel; delete profile file; within ~1s tunnel goes down + sidebar updates | Real-fs + state coherence; partial automation possible |
| 46 | Out-of-disk during secret_file write → graceful error | `mount -o remount,size=1` or ramdisk to fill /tmp; attempt `vortix auth save`; error returned; no half-written auth file | Fault injection deferred (Phase 2) |
| 47 | Profile config readable only by root, run as non-root → permission error | `chmod 0400 ~/.config/vortix/foo.conf`; `vortix up foo` as non-root; error surfaced; no path leak in stderr | Real-fs perms test; netns harness deferred |
| 48 | Auth file has mode 0600 and is owned by invoking user (not root via sudo) | `sudo vortix up <ovpn-profile>`; enter password; `ls -la ~/.config/vortix/foo.auth` shows mode 0600 + user (not root) | Real-fs setup needed (plan 002 U10) |
| 49 | Symlink attack on auth file is refused (O_NOFOLLOW) | Replace `~/.config/vortix/foo.auth` with symlink to `/etc/shadow`; `vortix up` triggers auth re-save; write refused; `/etc/shadow` unchanged | Real-fs + attacker setup needed |
| 50 | `ps aux` does not leak OVPN credentials in command line | While OVPN running: `ps auxf \| grep openvpn \| grep <password>` returns 0 lines | Real-process scan; partial automation possible |
| 51 | `/tmp/vortix-*/` temp WG configs are mode 0600 + unlinked on tunnel down | While WG connected: `ls -la ${TMPDIR}/vortix-*/`; mode 0600; after `vortix down`: directory gone | Real-fs assertion |
| 52 | macOS Apple Silicon smoke: full multi-tunnel happy path | Run multi-tunnel scenarios on an M-series MacBook | Cross-platform: real consumer hardware |
| 53 | macOS Intel smoke (if available) | Same as #52 on an Intel Mac | Cross-platform: real consumer hardware |
| 54 | Linux iptables host smoke | Run on a host where `iptables` is the actual backend (not iptables-nft) | Cross-platform: requires distro-specific install |
| 55 | Linux nftables host smoke | Run on a host where `nft` is the only backend | Cross-platform: requires distro-specific install |
| 56 | Windows: vortix does not crash (NG features stubbed) | `vortix --version`; `vortix list`; no panic on profile import; multi-tunnel features may be stubbed | Cross-platform: Windows |
| 57 | 10 active tunnels: TUI render budget under 16ms/frame | Connect 10 tunnels; observe TUI doesn't lag on `Tab` / sidebar nav | Perf benchmark cadence (Phase 2) |
| 58 | Killswitch ruleset rewrite latency sub-100ms at N=5 | `sudo time pfctl -f -` / `iptables-restore` round-trip during a 5-tunnel transition | Perf benchmark cadence (Phase 2) |
| 59 | 50 profiles loaded: sidebar scroll + search responsive | Synthesize 50 empty `.conf` files; verify no perceptible TUI lag | Perf benchmark cadence (Phase 2) |
| 60 | _(removed — auto-promote feature retired)_ | — | — |
| 61 | Journal shows `ConnectAttemptBlockedByConflict` on overlay-cancelled connect | Trigger conflict overlay; cancel it; journal entry appears | Same as #60 |
| 62 | `vpn-only` engages firewall immediately while VPN is up | `vortix up corp`; `vortix killswitch vpn-only`; `iptables -L OUTPUT -n` head shows `policy DROP`; before the P5d-era fix this silently produced "Armed" with no enforcement | Regression check for the `vpn-only` (`AlwaysOn`) semantic change (commit `34f07e3`) |
| 63 | `vpn-only` keeps blocking through a VPN drop → reconnect cycle | With `vpn-only` engaged and corp up, externally `wg-quick down corp`; verify `iptables -L OUTPUT -n` still shows `policy DROP` between drop and reconnect; no ICMP escapes during the gap | Canonical Linux killswitch invariant |
| 64 | Per-profile concurrent retry: two profiles failing in parallel each retry independently | Connect two profiles with bad endpoints simultaneously; `tail -f ~/.local/share/vortix/journal.jsonl \| jq '.event'` shows separate `ConnectAttemptFailed`/`RetryScheduled` entries per ProfileId with their own attempt counters; neither overwrites the other | Per-profile retry HashMap correctness; can't be observed via TUI single-slot view |
| 65 | D-4 auto-adopt of externally-started tunnel — authoritative iface case | Start the TUI (no profile connected); in another terminal run `wg-quick up corp` (or single `openvpn --config ...` outside vortix); within ~1 scanner tick the sidebar shows corp Connected, registry has the entry with `interface_authoritative=true` (no muted-dot, sidebar `*` if it owns kernel default route), killswitch slice includes corp's interface. WG on macOS is authoritative via `/var/run/wireguard/<name>.name`; Linux is always authoritative; OpenVPN on macOS is authoritative only when lsof Method A succeeds | Cross-process registry adoption from kernel state |
| 66 | CLI `vortix down A` while TUI tracks A+B does not clobber B's killswitch slice | TUI open with corp+lab Connected and AlwaysOn engaged; in another terminal `vortix down corp`; `cat ~/.config/vortix/killswitch.toml` still lists lab's interface + server_ips; firewall keeps lab's ACCEPT rule | Bug 1 regression check (commit `8e7181f`) |
| 67 | Security Guard panel fits cleanly at 80×24 with no compaction drops | Resize the terminal to exactly 80×24; connect a primary VPN; verify the Security Guard panel shows both section words (`Identity`, `Defense`), all rows (Real IP, Exit IP, Location, DNS, Killswitch, Encryption, IPv6 — 7 content rows after the split-rows redesign), and the `Updated …` footer with no rows dropped or truncated mid-word. Pay particular attention to whether `compact_to_fit` is dropping the Location or IPv6 row at the bottom |
| 68 | Security Guard panel alarm states pull the eye correctly | Trigger DNS leak (e.g. set system DNS to a non-VPN server while connected); confirm only the DNS row uses bright `✗` + bold and gains a sub-line; other rows stay muted. Repeat for Auto + dropped VPN — only the Killswitch row goes loud with `press r to reconnect` sub-line | TUI rendering — visual hierarchy regression check |
| 69 | WireGuard on macOS reports the real `utunN` device | macOS only: `vortix up <wg-profile>`; Connection Details `VPN IP` line shows `@ utunN` (not `@ wg-corp` or basename). Confirm byte-for-byte equality with `route -n get 8.8.8.8` interface output. Plan 2026-06-01-001 U2 contract — protocol layer routes through `Interface::resolve_wireguard_interface` port | Real macOS kernel + wg-quick behavior; can't be simulated |
| 70 | Multi-OpenVPN primary-election byte-comparable with kernel | macOS only: connect ovpn-cert (full-tunnel); connect a SECOND ovpn profile via Shift+B (takeover overlay → Both). Verify sidebar `*` and header CONNECTED-name reflect whichever tunnel's routes win `route -n get 8.8.8.8`. Repeat in reverse order (split first, then primary). Both registry entries must store byte-for-byte real `utunN` from the log scrape, NOT colliding with the lowest-numbered utun. Plan 2026-06-01-001 scenarios #3 + #12 regression | Multi-PID iface attribution that automated tests can't verify without real openvpn processes |
| 71 | OpenVPN log-parse failure leaves no synthetic iface in registry | Force a failure of `parse_kernel_interface` (e.g. tail an `.ovpn` log mid-handshake before the daemon writes the device-open line); vortix surfaces `TunnelError::DaemonExited` mentioning "kernel interface"; no entry in the registry has `interface = "openvpn-<name>"` after the failure. Plan 2026-06-01-001 U1 — no synthetic fallback. | Real `OpenVPN` log timing; flaky to automate |
| 72 | Scanner does NOT promote Connecting → Connected pre-protocol-success | Connect a slow OpenVPN profile (insert artificial `--connect-retry-max 99 --connect-retry 1` and a wrong remote that times out slowly). While scanner sees the openvpn process running, registry must stay in `Connecting` state (badge `◐`, not `●`) until the connect-timeout fires (`handle_connection_timeout`) — never jumps directly to Connected via scanner. Plan 2026-06-01-001 U4 regression — scanner-promotion removal | Race-window observation; the bug it prevents is silent corruption, not a crash |
| 73 | Externally-adopted OpenVPN on macOS multi-tunnel shows unauthoritative badge | macOS only: connect ovpn-cert through vortix. In another terminal, manually `openvpn --config ovpn-auth.ovpn --daemon ...`. Scanner adopts the external tunnel within ~1 tick. Sidebar shows it with the muted/dim `●` (not the bright SUCCESS green), Connection Details `VPN IP` line shows `@ <iface> (external)`, NO asterisk (`recompute_primary` excludes it), `vortix status --json` `data.primary` does NOT name this profile. Plan 2026-06-01-001 R4 + U6. | Multi-OpenVPN per-PID iface ambiguity that automated tests can't simulate |
| 74 | Real IP cache survives startup-with-VPN-up race | Connect a profile via vortix; quit vortix while it's connected (or kill its process); externally verify the kernel tunnel is still up (`route -n get 8.8.8.8` shows utunN). Re-launch vortix. The Security Guard `Real IP` row must show `detecting…` (NOT the VPN's exit IP — that would be the pre-fix bug). Now disconnect the tunnel through vortix; within ~1 telemetry tick the `Real IP` row populates with your actual ISP IP. Reconnect — `Real IP` stays frozen at the cached value, `Exit IP` shows the VPN's exit IP. Plan: real-IP gate requires scanner to have ticked AND kernel session count == 0 AND no Connected registry entries. | Race window observation that automated tests cover but only real launch-time timing on real kernel exercises end-to-end |
| 75 | Real IP persists across vortix restarts via `real-ip.cache` | Sequence: (a) launch vortix with no VPN up — wait for `Real IP` row to populate from telemetry (verify `~/.config/vortix/real-ip.cache` exists with mode 600 and contains your ISP IP). (b) Connect a profile; verify `Real IP` row stays at your ISP IP (NOT the VPN's exit IP). (c) Quit vortix while connected. (d) Re-launch vortix while the kernel tunnel is still up — `Real IP` row must populate IMMEDIATELY from the cache (no `detecting…` placeholder) and show your ISP IP, not the VPN's exit IP. This is the load-from-disk path. (e) Move networks (different wifi) while vortix is closed, re-launch; cache is stale until you disconnect once, then auto-refreshes. | End-to-end cache persistence; covers the launch-with-VPN-up case that telemetry alone cannot solve |
| 76 | **HISTORICAL — Approach A SCRV1-via-auth-file premise failed** | Run on 2026-06-02 against OpenVPN 2.7.0 + `ovpn-totp.ovpn` (server `209.38.218.39:1196`). Result: openvpn emits `CHALLENGE: Enter TOTP code` to stdout at us=289606 with `username = '[UNDEF]'` still in the parameter dump — proving the `--auth-user-pass` file is NOT read before the static-challenge prompt fires. The SCRV1 envelope on line 2 was never consulted; openvpn blocks on stdin waiting for the OTP and never daemonizes. Conclusion: Approach A cannot close #191 on modern openvpn. See `docs/plans/2026-06-02-001-feat-openvpn-static-challenge-plan.md` "Approach A is broken on OpenVPN 2.7" section. Row retained as the diagnostic artifact for the Approach B brainstorm. | The U0 spike outcome that retired Approach A |
| 77 | Non-MFA OpenVPN regression after the static-challenge wiring | Setup: a pre-existing OpenVPN profile WITHOUT `static-challenge` directive (e.g. `ovpn-auth`). Action: connect via TUI and via `vortix up`. Pass: behavior is identical to v0.3.1 — two-field auth overlay only, no OTP prompt, auth file contains `user\npass\n` after connect, connect timing and log output unchanged. | Regression guard for the most-trafficked OpenVPN path — the static-challenge code path is gated on the parser flag, so non-MFA profiles must be byte-for-byte untouched |
| 78 | Stale SCRV1 cleanup on vortix startup | Setup: any OpenVPN profile with saved credentials, vortix not running. Action: hand-corrupt the auth file with `printf 'user\nSCRV1:cA==:MTIzNDU2\n' \| sudo tee ~/.config/vortix/auth/<profile>.auth`. Start vortix (TUI or any CLI subcommand). Pass: the file no longer exists (`stat ~/.config/vortix/auth/<profile>.auth` returns no such file), a warn-level tracing event mentioning the profile name appears in stderr when `RUST_LOG=vortix::utils=warn`. Next connect attempt re-prompts for credentials cleanly. | U6 safety net — applies whether or not Approach B is later implemented |
| 79 | _(reserved — Approach B happy-path rows belong to the next plan)_ | — | — |
| 80 | _(reserved — Approach B happy-path rows belong to the next plan)_ | — | — |
| 81 | _(reserved — Approach B happy-path rows belong to the next plan)_ | — | — |
| 82 | _(reserved — Approach B happy-path rows belong to the next plan)_ | — | — |
| 83 | _(reserved — Approach B happy-path rows belong to the next plan)_ | — | — |
| 84 | Fresh resolved-native distro connects WG-with-DNS without resolvconf shim | On a clean Omarchy / Arch + `systemd-resolved` host with NO `systemd-resolvconf` or `openresolv` installed (`pacman -Qi systemd-resolvconf` errors), import a WG profile containing `DNS = 1.1.1.1` (use `scripts/test-profiles/wg-full.conf`). Connect via TUI or `vortix up wg-full`. Pass: dep-check does NOT raise `Missing dependencies: resolvconf (systemd)`; tunnel comes Connected; `resolvectl status wg-full` shows `DNS Servers: 1.1.1.1` and `Default Route: yes`. Issue #190 acceptance signal. See "Linux test environments for rows 84–88" below for a 5-min Colima/Lima setup on macOS. | Headline #190 verification; needs a fresh systemd-resolved host without the shim |
| 85 | Default Fedora Workstation connects WG-with-DNS without openresolv | Fedora 39+ default install (resolved is the default since F33), `openresolv` NOT installed (`dnf list installed openresolv` empty). Same WG profile + connect as #84. Pass: same observations as #84. | Confirms the path works across the two major resolved-shipping distros |
| 86 | Multi-tunnel on resolved registers per-link DNS for both, primary owns catchall | On a resolved host, connect `wg-full` (primary, `DNS = 1.1.1.1`) and `wg-split` (secondary, `DNS = 1.0.0.1`). Pass: `resolvectl status` lists BOTH interfaces with their respective DNS servers; only `wg-full` shows `Default Route: yes`; `wg-split` shows the DNS but no default route. Verify `resolvectl query -i wg-split google.com` resolves via the secondary's DNS. | R3 acceptance; needs real resolved + two distinct profiles |
| 87 | Fail-open path: resolvectl failure mid-connect leaves tunnel up | On a resolved host with a WG profile that has `DNS = …`, set up a script that does `sudo systemctl stop systemd-resolved` AFTER you press connect but BEFORE the connect-success path fires (or block `resolvectl` via a permissions trick — `sudo chmod -x $(which resolvectl)` then restore after). Connect. Pass: `wg-quick up` succeeds, the tunnel reaches Connected, sidebar shows the normal connected sigil, `journalctl -u vortix` (or stderr with `RUST_LOG=vortix::tunnel::wireguard=warn`) contains the `resolvectl set_link_dns failed` warn line, tunnel still routes packets. R5 acceptance — fail-open posture. | Failure-window timing on real resolved; can't be simulated by unit tests |
| 88 | Resolved auto-clears link state on `vortix down` (no explicit revert call needed) | On a resolved host with a WG tunnel up under the new path, run `resolvectl status wg-full` and capture the DNS / Default Route lines. Disconnect: `vortix down wg-full`. Pass: `resolvectl status` no longer lists the iface (or `resolvectl status wg-full` returns "link not found"). No residual per-link DNS registration. R6 acceptance — verifies the "no explicit revert" decision empirically. If this FAILS, add `resolvectl revert <iface>` to `WgTunnel::down()` as a follow-up. | Verifies resolved's documented auto-cleanup on `ip link delete`; behaviour varies subtly across systemd versions |
| 89 | Identity collapses to single `Real IP` / `Exit IP` rows when host has NO IPv6 | Host has NO IPv6 (`curl -6 -s --max-time 5 https://ifconfig.co/ip` times out). Disconnect any VPN; open TUI. Identity section shows `Real IP` / `Exit IP` labels (NOT `Real IPv4` / `Real IPv6`). No `Real IPv6` or `Exit IPv6` rows render. #227 acceptance: no v6 connectivity → labels stay v4-only-friendly. | TUI rendering — needs v6-less host |
| 90 | `Real IPv6` populates from disk cache on launch-with-VPN-up | Sequence: (a) launch vortix with no VPN; wait for telemetry to write `~/.config/vortix/real-ipv6.cache`. (b) `vortix up wg-full` (or any tunnel that doesn't carry v6). (c) Quit vortix. (d) Relaunch vortix WHILE the VPN is still up. Pass: Identity section renders explicit `Real IPv4` / `Real IPv6` / `Exit IPv4` / `Exit IPv6` rows immediately; `Real IPv6` shows the cached value (not `checking…`). Validates the parallel-to-v4 disk-cache fix. | Real-fs cache survival across vortix restarts |
| 91 | `Exit IPv6` reads ✓ on a tunnel that actually carries v6 | Use the `wg-v6` flavor from `scripts/test-infra.sh up wg-v6` (dual-stack server: `Address = 10.99.99.1/24, fd00:99:99::1/64` + `ip6tables MASQUERADE`). Host has IPv6. Record `REAL_V6` pre-connect via `curl -6 ifconfig.co/ip`. Connect `wg-v6`. Re-run `curl -6 ifconfig.co/ip`. Pass: returns a DIFFERENT v6 (server's DO-assigned v6); TUI `Exit IPv6` row reads the new address with green `✓` (no alarm sub-line). #227 acceptance — confirms ground-truth IP comparison, not AllowedIPs introspection. | TUI rendering — needs v6-capable WG server (wg-v6 droplet) |
| 92 | `Exit IPv6` reads ✗ leaking when `public_ipv6 == real_ipv6` while VPN up | Host has IPv6. Record `REAL_V6` pre-connect. Connect any v4-only WG/OpenVPN profile (`wg-full`, `wg-split`, `ovpn-cert`, etc.). Re-run `curl -6 ifconfig.co/ip` — still returns `REAL_V6` because tunnel doesn't carry v6. TUI `Exit IPv6` row reads `REAL_V6` with red `✗` + sub-line `v6 exposed — matches real IPv6`. Banner demotes to PARTIAL. This is the reporter's literal scenario from #227. | TUI rendering — real v6 leak; any v4-only tunnel works |
| 93 | `Exit IPv4 / Exit IPv6` both render `split-route — no exit` in split-only topology | Host has IPv6. Connect `wg-split` (AllowedIPs `10.8.0.0/24` only — no default route, no `::/0`). Pass: both `Exit IPv4` and `Exit IPv6` rows read `split-route — no exit` with `─` sigil. No ✗ alarm on v6 (split-only ≠ leak — user didn't ask for protection). Verdict banner reads PARTIAL. | TUI rendering — split-only consistency |
| 94 | v6 rows flip correctly across connect → disconnect cycles | Host has IPv6. Connect `wg-v6`: `Exit IPv6` ✓. `vortix down wg-v6` → telemetry re-probes; `Exit IPv6` should now match `Real IPv6` (both = your real v6, ✓ since no expectation of protection). `vortix up wg-v6` again → `Exit IPv6` returns to the masked value within ~1 telemetry tick. No stale-state hangover. | TUI rendering — state transitions over time |
| 95 | `Real IPv6` reads `checking…` when launched mid-connection without cache | Sequence: (a) delete `~/.config/vortix/real-ipv6.cache` if present. (b) Connect a v4-only WG profile via `vortix up wg-full` (outside the TUI, via CLI). (c) Launch vortix TUI fresh. Pass: `Real IPv6` row reads `checking…` with `─` sigil (we can't safely cache while VPN is up unless no tunnel carries v6 per AllowedIPs introspection). After disconnect, the row populates and the cache file appears. | TUI rendering — pending-state UX |
| 96 | DNS row reads ✓ Protected when configured resolver = answering recursor | Connect any tunnel that pushes a public-resolver DNS (`wg-full` pushes `DNS = 1.1.1.1`). TUI DNS row reads `1.1.1.1 · Cloudflare ✓` (no sub-line). Verify with `dig +short txt o-o.myaddr.l.google.com` on the host — the returned IP should be a Cloudflare anycast (1.1.1.0/24, 1.0.0.0/24, 2606:4700::/32, or 2400:cb00::/32). Vortix's recursor-IP probe runs the same query and classifies it as same-provider. | Recursor-IP probe baseline (recursor matches configured DNS provider) |
| 97 | DNS row reads ✗ leaking when recursor is a different provider | Use the `wg-dns-leak` flavor from `scripts/test-infra.sh up wg-dns-leak` — server pushes `DNS = 9.9.9.9` (Quad9) but `iptables -t nat ... DNAT --to-destination 208.67.222.222` silently hijacks every tunnel UDP/53 packet to OpenDNS. Connect, wait one telemetry tick. Pass: DNS row reads `9.9.9.9 · Quad9 ✗` + sub-line `leaking — queries answered by 208.67.x.x, not configured 9.9.9.9` (or recursor 2620:119::/40). Verdict banner demotes to PARTIAL. Validates the recursor-IP echo probe catches MitM-style DNS hijacks. | Recursor-IP probe positive — needs the wg-dns-leak droplet |
| 98 | DNS row stays ✓ when configured = v4 anycast and recursor returns same provider's v6 | Connect `wg-v6` (full-tunnel dual-stack, pushes `DNS = 1.1.1.1, 2606:4700:4700::1111`). On many setups Google's auth server sees Cloudflare's recursor via its v6 backbone — the TXT response carries a Cloudflare v6 anycast IP (e.g. `2400:cb00:71:1024::6816:7bd5`). Pass: DNS row stays ✓; the v4-configured + v6-recursor cross-family match works because the provider table covers both Cloudflare's v4 anycast (1.1.1.0/24) and v6 anycast (2606:4700::/32, 2400:cb00::/32, 2803:f800::/32). Regression guard against the false-positive we hit during testing. | Provider-table v6 coverage regression |
| 99 | DNS row reads Unknown (✓ no alarm) when no primary tunnel owns default route | Topology: no tunnel up, OR only split-only tunnels (no primary). Pass: DNS row sigil is ✓ green, no sub-line. The leak probe never runs because there's no expectation of DNS protection without a primary tunnel (mirrors v6's split-only handling). Disconnecting all tunnels should also clear any stale `Leaking` state within one tick. | UX safety — no false alarms in EXPOSED / split-only |
| 100 | DNS row reads ✓ ProbeFailed when the recursor probe times out | Sequence: (a) Connect any primary tunnel. (b) Block outbound UDP/53 to break the probe (`sudo pfctl -e -f /etc/pf-test.conf` with a `block out proto udp to any port 53` rule on macOS, or `iptables -A OUTPUT -p udp --dport 53 -j DROP` on Linux). (c) Wait for next telemetry tick. Pass: DNS row sigil is `─` (NotApplicable, gray); no alarm sub-line. The 3s UDP timeout returns `ProbeFailed`, which renders informationally — no false alarm when the probe can't reach Google's authoritative server. | Probe failure-mode safety |

## Linux test environments for rows 84–88

The systemd-resolved DNS-integration path is Linux-only — `#[cfg(target_os = "linux")]` compiles it out on macOS / Windows hosts. To exercise rows 84–88 from a macOS development box, spin up a VM with a real Linux kernel + systemd-resolved. Lima (used under the hood by Colima) gives you that in ~1 minute.

```bash
# Already have Colima? You almost certainly have limactl too.
which limactl  # if missing: brew install lima

# Fedora 41 ships systemd-resolved on by default — perfect for row 85.
# Arch (closer to the Omarchy reporter's setup, row 84) is also available
# via `template://archlinux`. Pick one.
limactl start --name=vortix-resolved template://fedora
limactl shell vortix-resolved
```

Inside the VM:

```bash
# Sanity-check resolved is the resolver and resolvectl is on PATH.
sudo systemctl is-active systemd-resolved   # → active
resolvectl --version                         # → systemd 25x (…)

# For row 84's Arch-flavoured setup, also confirm the shim is absent:
#   dnf list installed openresolv systemd-resolvconf 2>/dev/null   # must be empty

# Build vortix from the feature branch.
sudo dnf install -y wireguard-tools cargo git iptables-services
git clone https://github.com/Harry-kp/vortix.git
cd vortix
git checkout feat/systemd-resolved-dns   # or main, post-merge
cargo install --path crates/vortix

# Copy a WG profile in. From your Mac:
#   limactl copy scripts/test-profiles/wg-full.conf  vortix-resolved:/tmp/wg-full.conf
#   limactl copy scripts/test-profiles/wg-split.conf vortix-resolved:/tmp/wg-split.conf
mkdir -p ~/.config/vortix/profiles
cp /tmp/wg-full.conf  ~/.config/vortix/profiles/
cp /tmp/wg-split.conf ~/.config/vortix/profiles/

# Run the scenario. Note that the cargo-installed binary lives under the
# invoking user's home; sudo's secure_path won't see it without a full path.
sudo "$(which vortix)" up wg-full
resolvectl status wg-full     # row 84/85 pass signal
```

For row 87's fail-open scenario, the cleanest reproduction is the `chmod -x` trick — it lets `wg-quick up` succeed (resolved is still running, just `resolvectl` can't be executed by vortix), so you observe the post-`wg-quick up` failure path specifically.

For row 88's cleanup verification, capture `resolvectl status wg-full` BEFORE `vortix down`, run the down, capture again. Diff should show the link's DNS / Default Route entries gone.

Cleanup when done:

```bash
limactl stop vortix-resolved && limactl delete vortix-resolved
```

The VM is disposable — rerun the whole sequence on a fresh VM if anything gets into a weird state.

## How to add a row

1. Pick the next sequential `#`.
2. Write the **Check** in one line — what you're verifying.
3. Write **Steps** as the literal commands or actions to perform.
4. Write **Why manual** as a short tag — match an existing tag when possible so reviewers can scan related rows together (`TUI rendering`, `Cross-platform: ...`, `Real-fs ...`, `Feature wiring gap`, `Perf benchmark cadence`, `Fault injection deferred`, etc.).

## How to remove a row

When an automated test now covers the check, delete the row. Don't annotate "now covered" — the row is the source of truth for "needs human attention." Mention the deletion in the test's commit message so the link survives in git history.
