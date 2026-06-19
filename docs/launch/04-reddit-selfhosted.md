# Reddit /r/selfhosted

**Subreddit:** https://www.reddit.com/r/selfhosted/
**Subscribers:** ~600k
**Post type:** Text post (mandatory — link-only posts get removed)
**Best post time:** Weekday US morning (~14:00–17:00 UTC) catches the EU evening crowd too
**Flair:** Required — pick `Software Development` or `Guide`

---

## Title (300 char limit)

> Vortix — a self-hosted-friendly TUI for managing multiple WireGuard / OpenVPN tunnels from the terminal

Alternatives:
- `Built a TUI VPN client (Vortix) — multi-tunnel, kill switch, leak detection, no GUI required`
- `Vortix: terminal-only VPN manager for homelabs running headless servers`

**Convention notes:**
- /r/selfhosted users are skeptical of "AnotherClient #547". Lead with what's different.
- Self-hosters care about: no telemetry-back-home, headless-friendly, multi-instance, doesn't need a cloud account
- Mods enforce a "What it does / What it doesn't / Why I built it" structure for new tools

---

## Post body — follow the unofficial /r/selfhosted template

> ### What is Vortix?
>
> [FILL IN — 2–3 sentences positioning. Example:
> "Vortix is a terminal UI (TUI) for managing WireGuard and OpenVPN profiles on macOS and Linux. It's a CLIENT — connects to YOUR profiles, doesn't proxy through a third party — and runs entirely from the shell. No web UI, no cloud account, no telemetry phone-home."]
>
> ### Who is it for?
>
> - Self-hosters who SSH into a homelab and want to bring up a VPN there without leaving the terminal
> - Anyone juggling multiple VPN profiles (work + home + privacy) and tired of remembering which `wg-quick up X` is currently the default route
> - Headless server operators who want kill-switch + leak detection without installing a GUI client
>
> ### Highlights
>
> - **Multi-tunnel.** Run 2+ WireGuard or OpenVPN profiles at the same time. One is the primary (owns the kernel default route), others are split tunnels on their declared `AllowedIPs`.
> - **Headless-friendly.** Pure TUI (ratatui-based). Works over SSH. No X server, no DBus desktop integration required.
> - **Kill switch built in.** Three modes — off / block-on-drop / vpn-only — via PF on macOS, iptables or nftables on Linux. No external systemd unit or third-party firewall manager.
> - **Real-time telemetry.** Throughput, latency, jitter, packet loss, geo-IP, DNS leak, IPv6 leak.
> - **No phone-home.** No analytics, no error-reporting backend, no account.
>
> ### What it isn't
>
> - Not a VPN provider — Vortix doesn't host servers
> - Not a meta-client for commercial VPNs (Mullvad / NordVPN etc. all have their own clients)
> - Not a web UI / management dashboard — those exist (Headscale, WG-Easy); Vortix is the local client side
>
> ### Tech stack
>
> Rust, tokio, ratatui. Wraps native `wg-quick` / `openvpn` binaries — doesn't reimplement either. ~15 MB binary, <100 ms startup.
>
> ### Install
>
> ```
> # Any of these:
> curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Harry-kp/vortix/releases/latest/download/vortix-installer.sh | sh
> brew install Harry-kp/tap/vortix
> cargo install vortix
> sudo pacman -S vortix
> npm i -g @harry-kp/vortix
> ```
>
> ### Source + docs
>
> https://github.com/Harry-kp/vortix
>
> Author here — would love feedback from the homelab crowd. Especially interested if you're running a Headscale node or a self-hosted WG server and want to point a TUI client at it.

---

## Engagement tips

- /r/selfhosted users LOVE before/after screenshots. If you have a GIF / asciinema, embed in a comment after posting (Reddit doesn't allow inline media in text posts cleanly)
- Pre-empt the "what's the difference from [X]" question — homelabbers compare to: WG-Easy, Headscale, Tailscale, raw `wg-quick` scripts
- "Does it support [auth method]?" is common — answer the OpenVPN TOTP / static-challenge support up front

---

## Cross-post candidates

- /r/homelab (broader, less technical)
- /r/sysadmin (Mon-Fri only; weekend posts die)
- /r/privacy (privacy angle, sensitive audience)
