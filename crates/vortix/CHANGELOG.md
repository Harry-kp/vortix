# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.5.1] - 2026-09-26

### Fixed

- **WireGuard split tunnels with hundreds of routes work again.** A profile carrying GitHub's published ranges (about 340 routes, 6 KB on one `AllowedIPs` line) was refused at import, and a slightly smaller one failed to connect with "no handshake" and was left running where Vortix could not see it. Profiles may now hold up to 1024 routes in total. ([#331](https://github.com/Harry-kp/vortix/pull/331))
- **Connecting either finishes or leaves nothing behind.** A connect that runs out of time, or a dashboard quit while connecting, now rolls back fully; before, it could leave half a tunnel running that `vortix down` refused to remove. ([#334](https://github.com/Harry-kp/vortix/pull/334))
- **Large WireGuard profiles connect and disconnect in seconds.** On macOS a 337-route profile took 23 s to connect and 26 s to disconnect, and 1024 routes could do neither; it is now 4 s and 1 s, and 1024 routes take 9 s and 3 s. ([#334](https://github.com/Harry-kp/vortix/pull/334))

### Changed

- **`vortix up --timeout` sets how long the connect itself may take**, not only how long the command waits, so a larger value now helps. A timed-out `up` says nothing was left running and how to wait longer. ([#334](https://github.com/Harry-kp/vortix/pull/334))

## [0.5.0] - 2026-09-25

### Upgrading from 0.4.3

The first `sudo vortix` after upgrading shows what to do, once, and lists only the steps your machine needs. In short:

- **If a VPN or the kill switch was on when you upgraded, restart your computer.** 0.4.3's tunnel and firewall rules can outlive it, and 0.5.0 cannot remove them; on a Mac they can keep blocking your internet. Best of all, before upgrading run `sudo vortix down` and `sudo vortix killswitch off` with 0.4.3.
- **Linux:** the kill switch now needs `nftables` (iptables support is gone).
- **Profiles that run scripts** (WireGuard `PreUp`/`PostUp`/`PreDown`/`PostDown`, OpenVPN `up`/`down`/`route-up` and similar) no longer connect. Move the commands to `[[hooks]]` in `settings.toml`.
- **`vortix daemon` is gone.** If you installed it as a service, remove the service.

Commands for each system are in [Upgrading from 0.4.3 to 0.5.0](https://github.com/Harry-kp/vortix/blob/main/docs/MIGRATION.md#upgrading-from-043-to-050).

### Highlights

- **Linux works end to end.** On Debian and Ubuntu, AppArmor stopped `wg-quick` reading Vortix's configs, so every WireGuard connect timed out; configs are now staged in `/etc/wireguard/vortix/`. Verified on Ubuntu, Fedora 44, Arch and CachyOS. ([#292](https://github.com/Harry-kp/vortix/pull/292))
- **Several VPNs at once behave correctly.** A full tunnel and a split tunnel run side by side. A second connect no longer drops the first tunnel's DNS. Switching brings the new tunnel up before stopping the old one, and a route conflict offers Switch or Cancel instead of an error. ([#296](https://github.com/Harry-kp/vortix/pull/296), [#300](https://github.com/Harry-kp/vortix/pull/300), [#303](https://github.com/Harry-kp/vortix/pull/303), [#307](https://github.com/Harry-kp/vortix/pull/307), [#327](https://github.com/Harry-kp/vortix/pull/327))
- **The kill switch fails closed and reports what the firewall is really doing.** On macOS it lives in its own pf anchor and never replaces your pf rules; on Linux it uses nftables. If the rules cannot be verified it says Degraded, never Off, and tells you how to fix it. ([#281](https://github.com/Harry-kp/vortix/pull/281), [#292](https://github.com/Harry-kp/vortix/pull/292), [#325](https://github.com/Harry-kp/vortix/pull/325))
- **See why an OpenVPN connection failed.** In the Logs panel, `f` now steps through each OpenVPN tunnel's own log, marked live or last session. ([#319](https://github.com/Harry-kp/vortix/pull/319))
- **Profile files can no longer run commands as root.** Script directives are refused with an explanation; automation moves to `[[hooks]]`, which run without root and cannot block a connect. ([#264](https://github.com/Harry-kp/vortix/pull/264))
- **A third smaller:** the macOS release binary is 4.1 MB, down from 6.1 MB. ([#284](https://github.com/Harry-kp/vortix/pull/284), [#305](https://github.com/Harry-kp/vortix/pull/305))

### Fixed

- **Disconnect and reconnect finish cleanly.** A disconnect no longer bounces back to Connected, Disconnect All no longer times out, and a reconnect on slower Linux hosts re-applies DNS instead of failing. ([#253](https://github.com/Harry-kp/vortix/pull/253), [#298](https://github.com/Harry-kp/vortix/pull/298), [#301](https://github.com/Harry-kp/vortix/pull/301), [#318](https://github.com/Harry-kp/vortix/pull/318))
- **Connecting and Disconnecting show in the header** long enough to read, instead of skipping straight to the result. ([#327](https://github.com/Harry-kp/vortix/pull/327))
- **Switching always leaves one tunnel.** Switching between two tunnels that carry the same networks works on Linux (it failed with "RTNETLINK answers: File exists"). When a server pushes a full-traffic route after connecting, Vortix now asks: Cancel disconnects the new tunnel, Switch stops the old one, and `vortix up` without `--yes` refuses with exit 4 and keeps the old tunnel. ([#327](https://github.com/Harry-kp/vortix/pull/327))
- **Switching between two tunnels on the same server keeps the new one working**, instead of leaving it Connected with no internet on macOS. ([#321](https://github.com/Harry-kp/vortix/pull/321))
- **Leftover routes and DNS from a tunnel that died while Vortix was closed** are removed the next time it starts. ([#318](https://github.com/Harry-kp/vortix/pull/318))
- **The exit IP and leak display are accurate.** Right after connecting it shows the VPN's address, and the false "matches the pre-VPN address" warning is gone. ([#307](https://github.com/Harry-kp/vortix/pull/307), [#321](https://github.com/Harry-kp/vortix/pull/321))
- **Credentials.** A wrong OpenVPN password is never saved, Ctrl+R shows the password while you type, Ctrl+U clears a field instead of typing a "u", and a saved-credential file Vortix refuses now says why. ([#284](https://github.com/Harry-kp/vortix/pull/284), [#321](https://github.com/Harry-kp/vortix/pull/321))
- **IPv6 and unusual gateways.** IPv6 VPN servers are pinned to the physical gateway, `redirect-gateway local` works, and IPv6 routes apply on macOS. ([#318](https://github.com/Harry-kp/vortix/pull/318))
- **Another WireGuard network on the machine** (Tailscale, a corporate mesh) no longer stops Vortix from starting, and the orphan warning lists only processes Vortix started. ([#303](https://github.com/Harry-kp/vortix/pull/303), [#320](https://github.com/Harry-kp/vortix/pull/320))
- **Files stay yours under `sudo`.** Every file Vortix writes is private and owned by you, including logs and session journals, which now live in `~/.config/vortix`. ([#292](https://github.com/Harry-kp/vortix/pull/292), [#318](https://github.com/Harry-kp/vortix/pull/318), [#321](https://github.com/Harry-kp/vortix/pull/321))
- **CLI.** `up --yes` really switches tunnels, a missing VPN tool exits 5 with the install command, and `status` without root says it cannot see WireGuard instead of claiming Disconnected. ([#321](https://github.com/Harry-kp/vortix/pull/321))
- **TUI.** Profile names are readable at 80×24, a VPN Vortix did not start shows as "UNMANAGED VPN" instead of DISCONNECTED, and large imports finish instead of timing out. ([#283](https://github.com/Harry-kp/vortix/pull/283), [#321](https://github.com/Harry-kp/vortix/pull/321))
- **Messages say what broke and what to do**, and claim only what happened: `release-killswitch` no longer says "Internet access restored" without checking. A second instance, or starting without a terminal, now exits with a clear sentence. ([#279](https://github.com/Harry-kp/vortix/pull/279), [#292](https://github.com/Harry-kp/vortix/pull/292))

### Changed

- **WireGuard shows Connected only after a real handshake** with the peer. The timeout and staleness are `wireguard_handshake_timeout_secs` and `wireguard_handshake_stale_secs` in `config.toml`; probe targets are `[engine].wireguard_health_targets` in `settings.toml`. ([#264](https://github.com/Harry-kp/vortix/pull/264))
- **Vortix writes every OpenVPN route itself.** Route directives it cannot apply safely, and TAP (`dev tap`) profiles, are refused. ([#307](https://github.com/Harry-kp/vortix/pull/307), [#318](https://github.com/Harry-kp/vortix/pull/318))
- **TUI keys.** In the sidebar `d` disconnects the selected profile and `D` all of them; a route conflict opens one Switch or Cancel dialog; `p` cycles seven color themes; `y` copies through the terminal (works over SSH). ([#279](https://github.com/Harry-kp/vortix/pull/279), [#282](https://github.com/Harry-kp/vortix/pull/282), [#300](https://github.com/Harry-kp/vortix/pull/300))
- **`vortix up` waits as long as the protocol needs** (about 22 s for WireGuard, 37 s for OpenVPN); `--timeout` still overrides it. ([#264](https://github.com/Harry-kp/vortix/pull/264))
- **`settings.toml` is read from the Vortix config directory**, the one `--config-dir` selects. ([#264](https://github.com/Harry-kp/vortix/pull/264))

### Removed

- **`vortix daemon`**, `vortix status --no-daemon` and `VORTIX_DAEMON_SOCKET`. The CLI and TUI run the engine themselves. ([#296](https://github.com/Harry-kp/vortix/pull/296), [#297](https://github.com/Harry-kp/vortix/pull/297))
- **The iptables kill-switch backend.** Linux needs `nft`; 0.4.3's iptables rules are removed when you turn the kill switch off. ([#307](https://github.com/Harry-kp/vortix/pull/307))

### Security

- Profile directives that could run commands as root are refused. ([#264](https://github.com/Harry-kp/vortix/pull/264))
- Vortix directories are no longer group-writable, which had let a group member replace a profile. ([#292](https://github.com/Harry-kp/vortix/pull/292))
- Bumped `rustls` 0.23.40 → 0.23.45 for [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285). ([#292](https://github.com/Harry-kp/vortix/pull/292))

## [0.4.3] - 2026-07-18

### Highlights

- **IPv6-disabled hosts get a clean refusal instead of a crash-dump** ([#242](https://github.com/Harry-kp/vortix/issues/242)). Connecting a WireGuard profile whose `Address` line declares an IPv6 entry used to fail mid-way inside `wg-quick` with a raw `RTNETLINK answers: Operation not supported` error and a retry loop. Both the TUI and CLI now refuse pre-flight with an actionable message: re-enable IPv6 via sysctl (or remove `ipv6.disable=1` from the kernel cmdline), or drop the IPv6 entry from the profile. The profile is never rewritten silently. ([#247](https://github.com/Harry-kp/vortix/pull/247))
- **CLI lifecycle hardening** ([#249](https://github.com/Harry-kp/vortix/pull/249)). `vortix up` is now truly idempotent, live tunnels are no longer flagged as "possible orphans" on every `down`, and concurrent `up`/`down`/`reconnect` invocations from multiple terminals serialize instead of racing.

### Fixed

- **`vortix up` is now truly idempotent.** Re-running `up` for an already-connected profile prints `Already connected` and exits 0 instead of re-spawning the tunnel. Previously a second `up` of an OpenVPN profile spawned a duplicate daemon whose `--writepid` clobbered the first's pidfile, leaving the original daemon untracked. ([#249](https://github.com/Harry-kp/vortix/pull/249))
- **No more spurious orphan warnings for live tunnels.** The startup orphan scan now excludes PIDs recorded in profile pidfiles (`run/<name>.pid`), so `vortix down` / `status` no longer flags the active session's own `openvpn` daemon as a "possible orphan from a previous session." ([#249](https://github.com/Harry-kp/vortix/pull/249))
- **Concurrent `up`/`down`/`reconnect` invocations are serialized** via a `flock` lifecycle lock in the config dir. Two terminals racing the same mutation now queue instead of interleaving; the second prints a one-line "waiting…" note. ([#249](https://github.com/Harry-kp/vortix/pull/249))
- **OpenVPN double-spawn guard** at the tunnel layer: `up()` refuses when the profile's pidfile records a live daemon (covers the mid-negotiation window the scanner can't see). ([#249](https://github.com/Harry-kp/vortix/pull/249))
- WireGuard connect on a Linux host with IPv6 disabled no longer fails mid-way inside `wg-quick` (see Highlights). Detection covers both disable mechanisms: sysctl `disable_ipv6=1` and the `ipv6.disable=1` boot param, verified against real kernels in both states. ([#242](https://github.com/Harry-kp/vortix/issues/242), [#247](https://github.com/Harry-kp/vortix/pull/247))
- Daemon socket now binds inside the Tokio runtime ([#233](https://github.com/Harry-kp/vortix/pull/233)).

### Security

- Bumped `crossbeam-epoch` 0.9.18 → 0.9.20 for [RUSTSEC-2026-0204](https://rustsec.org/advisories/RUSTSEC-2026-0204) (invalid pointer dereference in `fmt::Pointer`; reached via a build-tooling dependency chain, not vortix's runtime path).

### Changed

- README now documents the kill-switch **reboot boundary**: firewall rules do not survive an OS reboot, so `vpn-only` is unenforced between boot and the next vortix launch. Persistence across reboot is tracked in [#250](https://github.com/Harry-kp/vortix/issues/250). ([#249](https://github.com/Harry-kp/vortix/pull/249))
- The flip-panel widget now ships as the extracted [`ratatui-flip-panel`](https://crates.io/crates/ratatui-flip-panel) crate, consumed as a dependency. ([#232](https://github.com/Harry-kp/vortix/pull/232))

### Documentation

- README overhaul: install matrix, named competitor comparison, security model, contributing section. ([#230](https://github.com/Harry-kp/vortix/pull/230))
- Refreshed demo GIFs (hero + 4 scenario clips) and README cleanup. ([#236](https://github.com/Harry-kp/vortix/pull/236))
- X/Twitter handle badge. ([#244](https://github.com/Harry-kp/vortix/pull/244))

## [0.4.2] - 2026-06-16

### Highlights

- **No more false IPv6-leak alarms on dual-stack tunnels** ([#227](https://github.com/Harry-kp/vortix/issues/227)). IPv6 leak detection now uses ground-truth `real_ipv6 == public_ipv6` comparison (mirroring the v4 check) instead of introspecting the tunnel's declared `AllowedIPs`. The old check produced false positives on tunnels that declared `::/0` but where the kernel didn't actually route v6 through them — the reporter's exact scenario.
- **Real DNS leak detection.** The previous string-compare of pre- vs post-VPN resolver IPs was broken — it false-flagged the common case where both pre- and post-VPN DNS happened to be the same public resolver (e.g. you set Cloudflare and the VPN also pushed Cloudflare). v0.4.2 replaces it with a recursor-IP echo probe: vortix resolves `o-o.myaddr.l.google.com` TXT through your configured resolver and Google's authoritative server returns the IP of the recursor that actually walked the chain. Same mechanism dnsleaktest.com / ipleak.net use. Provider-aware match across Cloudflare / Google / Quad9 / OpenDNS v4 + v6 anycast ranges.
- **Dual-stack Identity rows.** When the host has IPv6, the Security Guard panel renders four explicit rows — `Real IPv4`, `Real IPv6`, `Exit IPv4`, `Exit IPv6` — each with its own ✓/✗ sigil. Collapses back to a single `Real IP` / `Exit IP` pair on v4-only hosts so users without v6 don't see jargon.
- **Sigil-colored value text.** Audit-row value text now inherits the sigil's color so every row reads as one visual unit — green ✓ throughout, red ✗ throughout, etc. Removes the prior visual split where the value was always white while only the sigil carried the verdict.

### Fixed

- IPv6 leak detection no longer reports `Leaking` when an IPv6-only tunnel correctly carries v6 traffic via `::/0` ([#227](https://github.com/Harry-kp/vortix/issues/227)). The `ipv6_traffic_is_leaking` AllowedIPs-introspection helper and the `Ipv6Status` enum are deleted; the panel now reads off the same ground-truth signal as the JSON envelope.
- DNS leak false positives on shared public resolvers (configured DNS and VPN-pushed DNS both pointing at `1.1.1.1` no longer alarms). DNS leak verdict is now path-of-recursion, not destination-IP equality.

### Added

- `Real IPv6` survives vortix restarts via a new `real-ipv6.cache` (parallel to `real-ip.cache`). Launching vortix with a VPN already up populates the row immediately instead of stalling on `checking…`. The cache also writes when the registry shows the active tunnel's AllowedIPs don't claim `::/0` — the safe one-sided half of the old config-introspection logic, now used only for caching, never for leak verdict.
- Security Guard `Exit IPv6` row carries a per-family alarm sub-line on leak (`v6 exposed — matches real IPv6`) so the user knows which family escaped.
- Historical test-infrastructure flavors (now consolidated in `scripts/vpn-lab.sh`):
  - `wg-v6` — dual-stack server (v4 + v6 `Address`, ip6_forward + ip6tables MASQUERADE on the egress interface, droplet provisioned with `--enable-ipv6`). Validates the `Exit IPv6 ✓ Protected` path.
  - `wg-dns-leak` — full-tunnel WG that silently DNATs every tunnel-side UDP/53 query to a different DNS provider than the one the client config claims. The same MitM pattern a hostile coffee-shop AP or ISP-side DNS hijacker uses, and exactly what the recursor-IP probe is designed to catch.

### Changed

- Help-overlay entries refreshed: `Identity → Real IPv4 / Real IPv6`, `Identity → Exit IPv4 / Exit IPv6`, `Identity → DNS` (now describes the recursor-IP echo probe and references dnsleaktest.com / ipleak.net as the inspiration).
- Log lines and the `Copy Public IP` clipboard action renamed to be explicit about IPv4 vs IPv6 (e.g. `NET: Real IPv4 detected`, `WARN: Public IPv4 changed`, `Copy Public IPv4`).
- Removed: `runtime.real_dns` field + `real-dns.cache` (dead after the recursor-IP rewrite), `runtime.ipv6_leak: bool` (replaced by ground-truth comparison), `Ipv6Status` enum + helpers, `cidr::ipv6_traffic_is_leaking` + its 8 unit tests, the `Defense → IPv6` standalone help entry.



## [0.4.1] - 2026-06-12

### Fixed

- **`cargo install vortix` now compiles on a clean cargo cache.** The `time` crate published version `0.3.48` on the same day v0.4.0 shipped, and it carries a fresh `error[E0119]: conflicting implementations of trait From<...>` build break. Without `--locked`, cargo's resolver was happily picking the broken `time 0.3.48` for every user typing the canonical `cargo install vortix` command. Capped our workspace `time` dep at `<0.3.48` so the resolver can't reach the broken version; the lockfile already pinned the working `0.3.47`. Drop the cap once upstream releases a clean `0.3.49+`.



## [0.4.0] - 2026-06-11

### Highlights

- **Run multiple VPNs at the same time.** Connect to several WireGuard / OpenVPN profiles concurrently; one owns the kernel default route (the *primary*), the rest are *split tunnels* reachable on their declared `AllowedIPs`.
- **Friendlier kill switch.** Modes are now `off`, `block-on-drop`, and `vpn-only` — the same words in the TUI, the CLI, and the JSON output. The `vpn-only` mode actually stays engaged whether the VPN is up or down (the v0.3.x `AlwaysOn` mode sat unarmed while the VPN was up, leaving a leak window between a drop and reconnect).
- **systemd-resolved-native DNS on Linux** ([#190](https://github.com/Harry-kp/vortix/issues/190)). On distros where resolved manages DNS (Arch / Omarchy, NixOS-with-resolved, default Fedora Workstation), vortix now registers per-link DNS via `resolvectl` directly — no `systemd-resolvconf` / `openresolv` shim package required.
- **OpenVPN inline 2FA / static-challenge** ([#191](https://github.com/Harry-kp/vortix/issues/191)). Profiles with `static-challenge "<prompt>" 1` now prompt for the TOTP/PIN at connect time and feed it via the OpenVPN management socket. TUI gets a 3-field form-style auth overlay; CLI prompts inline.
- **Polished Security Guard panel.** New `Identity` / `Defense` layout, calmer colour treatment, and the encryption row now grades your cipher (`modern AEAD`, `strong`, `deprecated`, or `INSECURE`) instead of just printing the name.

### Added

- Connect to multiple VPN profiles concurrently. Each gets its own retry budget and reconnect schedule.
- Auto-adopt: tunnels you started outside vortix (e.g. `wg-quick up corp` from another terminal) appear in the TUI within a second.
- Takeover overlay: when a second tunnel wants the default route, choose `[S]witch` (replace), `[B]oth` (keep both up, the new one becomes the exit), or `[N]o`.
- Auto-promote banner: if the primary drops and a secondary takes over, a one-line banner explains what happened and offers `[u]` to revert.
- Cipher strength annotation on the Security Guard `Encryption` row, with bright alarms for `INSECURE` ciphers (BF-CBC, DES, RC4, NULL, CAST5, IDEA, RC2).
- `vortix up <name> --yes` to skip the takeover prompt for scripts and CI.
- Multi-tunnel keybindings: `Shift+D` (disconnect every active tunnel with confirm), `c` (cancel an in-flight connect from Connection Details), `B` (Both from the takeover overlay), `u` (revert auto-promote).
- JSON status reports every connected tunnel in `data.connections[]` plus `data.primary`. The legacy `data.connection` field stays populated when only one tunnel is up (back-compat for v1 consumers).
- Sigil legend (`✓ ✗ ⚠ ─`) in the `?` help overlay.
- **OpenVPN inline 2FA / static-challenge support (#191).** Profiles declaring `static-challenge "<prompt>" 1` now prompt for the TOTP/PIN at connect time and feed it to the server via the OpenVPN management socket using the SCRV1 envelope. TUI shows a 3-field auth overlay; CLI `vortix up <profile>` adds a masked OTP prompt below the password. The static-challenge `0` (cleartext echo) variant is intentionally unsupported.
- Auth overlay redesigned as a form: fixed-width label column, single `▸` focus marker, `Up`/`Down` arrows now cycle between Username / Password / OTP / Save-checkbox in a circular loop (Tab/BackTab still work). Empty values render an em-dash placeholder; secrets mask to filled-circle dots.
- **systemd-resolved DNS integration on Linux (#190).** When `is_systemd_resolved()` is detected and `resolvectl` works, vortix calls `resolvectl dns <iface> <ips>` (and `resolvectl domain <iface> ~.` for primary tunnels) directly after `wg-quick up` succeeds. The connect path strips `DNS = …` from the wg-quick-fed temp config so wg-quick never tries its own resolvconf path. Result: a fresh Arch / Omarchy / NixOS-with-resolved / default-Fedora host now connects WG-with-DNS without needing the `systemd-resolvconf` or `openresolv` shim package — the historic "Missing dependencies: resolvconf (systemd)" wall is gone. Secondary tunnels also get per-link DNS registered (non-authoritative — DNS reachable on the link but doesn't claim the catchall), strictly better than v0.3.x's "strip-and-discard" behaviour.

### Changed

- **Breaking — CLI killswitch verbs.** `vortix killswitch off | block-on-drop | vpn-only` replaces `off | auto | always | always-on`. The old verbs are no longer accepted; the parser rejects them with `Use: off, block-on-drop, vpn-only`.
- **Breaking — JSON killswitch values.** `data.security.killswitch_mode` now emits `off` / `block-on-drop` / `vpn-only` instead of `off` / `auto` / `alwayson`. `data.security.killswitch_state` emits `Inactive` / `Watching` / `Blocking` instead of `disabled` / `armed` / `blocking`. Scripts parsing the old values need to switch.
- **Kill switch `vpn-only`** stays engaged whether the VPN is up or down. In v0.3.x the `AlwaysOn + Connected` combination resolved to `Armed` with no actual firewall enforcement, so a drop between checks could leak. Now: default-DROP egress + per-tunnel ACCEPT rules are in place at all times when this mode is selected.
- `vortix down` with no profile argument now disconnects every active tunnel (was single-tunnel only). `vortix down <name>` keeps the per-tunnel behaviour.
- `vortix reconnect` cycles every currently-connected tunnel.
- Telemetry switched from `reqwest` / `curl` / `ping` shell-outs to in-process HTTP (`ureq`) + raw-ICMP (`socket2`). Smaller binary, faster startup, no transient child processes.
- Interface and process lookups on Linux / macOS go through `libc` directly (`getifaddrs`, `sysctlbyname`, `kill`) instead of parsing `ip addr show` / `ifconfig` / `ps` output. Fewer locale-dependent parser bugs.
- Default OpenVPN connect timeout bumped from 20s → 35s to accommodate the static-challenge MFA flow (TLS + PAM + `PUSH_REPLY` can comfortably exceed 20s on geographically distant servers).
- **MSRV bumped from 1.75 to 1.85.** A transitive dep (`idna_adapter`) requires `edition2024`, which Rust 1.75 doesn't support. Distros shipping older Rust — notably Ubuntu 24.04's apt — will need `rustup` for source builds; `curl | sh` installer users get a prebuilt binary as before.
- **Missing-dependency error formatting.** When the WG dep-check fires, `wg` and `wg-quick` now report under a single label (`wireguard-tools`) and produce one install hint instead of duplicating the per-distro lines. Same for OpenVPN — gets a proper three-distro hint instead of falling through to the apt-or-dnf-only fallback. Vestigial `curl` binary check removed from startup (telemetry has been in-process HTTP since the `ureq`/`socket2` switch above).

### Fixed

- CLI's `vortix up <name>` now refuses pre-2.4 OpenVPN before attempting to connect (matches what the TUI already did in v0.3.x; pre-fix the CLI would proceed and could leak pushed DNS through the primary's resolver).
- TUI no longer freezes when connecting to OpenVPN — even on misbehaving / slow / broken servers. Four interacting bugs would each park the UI thread for seconds at a time on a connect; together they could lock the panel for 30+ seconds and queue keystrokes. Fixed by removing every synchronous subprocess call from the UI thread's connect-success path:
  - `openvpn --daemon` forks + detaches, but the daemonized grandchild inherited vortix's stdout/stderr pipes — `wait_with_output()` blocked forever waiting for pipe EOF that never came. Subprocesses can now declare themselves as daemonizing; the runner routes their stdio to `/dev/null` and uses `child.wait()` instead.
  - `openvpn --version` dependency probe ran synchronously on the UI thread with no timeout. A slow first-run probe (Gatekeeper / Spotlight / antivirus on macOS) froze the panel until it returned. The probe now has a 10-second cap.
  - `route get default` / `ip route show default` ran inline on the UI thread every time the registry's `recompute_primary` fired (which is every connect, every disconnect, and every scanner tick). Right after a VPN claims the default route, the macOS kernel takes up to 30 seconds to answer that query. The query now lives in the scanner's background thread; its result is fed into a registry-side cache that the UI thread reads instantly. Subprocess timeout is also bounded at 1 second as defense in depth.
  - `handle_connect_result` dropped its own success result as "stale" if the scanner had already adopted the tunnel as Connected by the time the connect thread reported back (~1s race window). The post-connect bookkeeping — `last_used` timestamp, kill-switch sync, `STATUS: Connected` log line — was silently skipped, leaving the UI in a half-connecting state. Now accepts `Connected{this profile}` as a non-stale arrival.
- TUI stays responsive on broken VPN servers. When a tunnel comes up but its server's routing is misconfigured (everything behind the VPN times out), the scanner and network-monitor threads were both probing the kernel's default-route every 1-2 seconds and each hitting their 1s timeout — burning two tokio runtime workers continuously and starving the scanner of cycles to do useful session work. The probe now shares a process-wide failure backoff: first 1-2 failures retry immediately, 3-5 cool down 5s, 6-10 cool down 15s, 10+ cap at 60s. Reset on any successful probe.
- Aggressive scroll-spam in the `v` config viewer no longer wedges the TUI. Two compounding causes: (1) every keystroke ran `content.lines().count()` for scroll bounds AND a full per-line re-parse + re-highlight for the render. On a multi-thousand-line `.ovpn` (typical when certs/keys are inlined), that was ~4N string-iterations per arrow-key. (2) Mouse wheels emit 30+ events per second; the event loop processed one event per render, so a fast scroll burst queued hundreds of events and the TUI ground through them long after the user stopped scrolling. Fix: a `CachedConfigView` is built once when the viewer opens (pre-counted line total + pre-highlighted `Vec<Line>`); the main event loop now drains every queued event into state before rendering, so a 100-event scroll burst lands in one render frame at the final position.
- New observability: any `Message` handler that holds the UI thread for more than 50ms emits a `tracing::warn` (silent by default; turn on with `RUST_LOG=vortix::app=warn`). Future regressions of this class surface immediately instead of being chased down with ad-hoc instrumentation.
- CLI → TUI handoff for OpenVPN tunnels (#191). When a profile was connected via `vortix up` and the TUI then opened, the sidebar sigil flashed grey (`external` — "not started by vortix") because the scanner couldn't authoritatively resolve the kernel interface from the running `openvpn` process. The scanner now reads the per-profile log file as Method 0 (platform-neutral, runs ahead of the lsof/ifconfig methods) and extracts the interface via the existing `parse_kernel_interface` parser. Vortix-started tunnels render with the correct owned sigil regardless of which entry point launched them.
- Manage-credentials save-only path no longer writes a plaintext-OTP `.scrv1.auth` bundle to disk. The `static_challenge_prompt` field is now explicitly cleared in the ManageAuth handler so the save path takes the username/password-only branch even for profiles that declare a static-challenge directive.
- **TUI rendering no longer scrambled by config-ownership notes** ([#222](https://github.com/Harry-kp/vortix/pull/222)). `fix_ownership()` was writing `Note: could not set ownership of …` directly to stderr via `eprintln!`, which corrupted ratatui's alternate-screen rendering when running as direct root (no sudo). Now routes through `tracing::debug!` (SUDO_UID-unset case — chown is structurally impossible, no operator action needed) or `tracing::warn!` (real chown failures), both via the existing tracing infrastructure.

### Removed

- The Security Guard panel no longer renders the sigil legend inline (moved to the `?` help overlay) or the `Real IP: <ip> (hidden)` sub-bullet (avoids leaking the real IP in screenshots of an otherwise-clean panel).
- Approach A dead code from the early static-challenge design (#191). An exploratory path tried to embed the SCRV1 envelope as a third line of the `--auth-user-pass` file, but OpenVPN 2.7 does not consult that file for static-challenge responses. Removed: the SCRV1 branch in `format_openvpn_auth_body`, the `otp: Option<&str>` parameter on `write_openvpn_auth_file`, the dead branch in `scrub_stale_scrv1_auth_files`, and 5 dead tests. The shipping flow drives the management socket exclusively.

## [0.3.1] - 2026-05-25

### Changed

- **Flattened to single crate.** Merged all 8 internal crates into the main `vortix` crate as modules. Enables `cargo install vortix` from crates.io. No functional changes.
- Internal modules marked `#[doc(hidden)]` to keep public API surface clean.

## [0.3.0] - 2026-05-24

### Architecture

- **Cargo workspace split.** Codebase restructured into 12 internal crates under `crates/` (vortix-core, vortix-process, vortix-config, vortix-platform-{linux,macos,windows}, vortix-protocol-{wireguard,openvpn}, xtask). Single published binary remains `vortix`.
- **Capability ports.** 7 trait-based ports (Tunnel, Killswitch, DNS, Interface, NetworkStats, RouteTable, CommandRunner) in `vortix-core` with per-OS implementations behind them. Adding new protocols or platforms is now mechanical.
- **Engine FSM.** Internal connection state is now a typed 5-variant state machine (`Disconnected`, `Connecting`, `Connected`, `Disconnecting`, `AwaitingUserInput`) with compile-time transition enforcement.
- **CI boundary lints.** Three `cargo xtask` lints enforce that `Command::new` only appears in `vortix-process`, `cfg(target_os)` only in platform crates, and protocol strings only in protocol crates.

### Added

- **Session journal.** Every session writes a JSONL event log to `${XDG_DATA_HOME}/vortix/sessions/*.jsonl` with 30-day / 30-file retention. Path surfaced via `vortix info`.
- **`vortix secrets {set,get,delete}`** -- Layered secret store backed by OS keyring (Keychain / Secret Service) with AES-256-GCM + argon2id on-disk fallback. Opt-in; existing `.auth` files keep working.
- **`vortix audit`** -- Per-process socket snapshot for VPN leak detection. `--pid <N>` filters to one process, `--vpn-only` to tunnel sockets, `--json` for structured output. Linux (`/proc/net`) + macOS (`lsof`) implementations.
- **`vortix daemon`** -- IPC server skeleton with Unix socket (mode 0600) and length-prefixed JSON framing. Engine routing through daemon completes in v0.3.x.
- **`vortix show --raw --inline-secrets`** -- Streams profile config to stdout with stored credentials appended as `# vortix-secret:<base64>` trailing comment.
- **CI integration tests.** Privileged Docker container with network namespaces running real `wg-quick` + killswitch engage/release end-to-end.
- **`settings.toml`** -- Figment-layered config (defaults -> system -> user -> env). Not required; runtime defaults match v0.2.x behavior.
- **JSON `schema_version`.** Every `--json` envelope now includes `"schema_version": 1`.
- **Windows stub crate.** `vortix-platform-windows` compiles on Windows; every port returns `PlatformUnsupported`.
- **Startup orphan scan.** Warn-only detection of leftover `wg-quick`/`openvpn` processes from previous runs.
- **Cold-start performance test.** CI ceiling on `vortix --version` startup time.

### Fixed

- **WireGuard shows Connected with no handshake on invalid server address** ([#31](https://github.com/Harry-kp/vortix/issues/31)). FSM now requires a real `TunnelUp` event before entering `Connected` state.
- **CLI hardening** ([#177](https://github.com/Harry-kp/vortix/issues/177)). Typed errors via `thiserror` at every port boundary, config value masking in output.

### Changed

- Profile sidecar backfill runs automatically at first launch. A `<name>.meta.toml` appears next to each `.conf`/`.ovpn`. Idempotent; v0.2.x ignores these files.
- Killswitch state and active VPN sessions survive the binary upgrade unchanged.

### Documentation

- `docs/MIGRATION.md` -- upgrade guide from v0.2.x
- `docs/v0.3.0-RELEASE-NOTES.md` -- full release notes
- `docs/v0.3.0-FAQ.md` -- common upgrade questions
- `docs/architecture-migration-v1.md` -- technical surface map
- `docs/RELEASE-PLAYBOOK-v0.3.0.md` -- maintainer runbook
- `SECURITY.md` updated with daemon authentication model
- 15 plan documents in `docs/plans/` (001-015)

### Not in v0.3.0 (deferred)

- No Windows binary (stub only, [#17](https://github.com/Harry-kp/vortix/issues/17))
- Daemon engine routing (skeleton only, [#16](https://github.com/Harry-kp/vortix/issues/16))
- Privilege separation / no-sudo ([#153](https://github.com/Harry-kp/vortix/issues/153))
- Lifecycle hooks (backed out after UX iteration, [#36](https://github.com/Harry-kp/vortix/issues/36))
