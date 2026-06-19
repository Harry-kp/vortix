# Reddit /r/WireGuard

**Subreddit:** https://www.reddit.com/r/WireGuard/
**Subscribers:** ~35k
**Post type:** Text post (description matters more than link)
**Best post time:** Weekday evening US (~22:00–01:00 UTC), reaches the homelab crowd

---

## Title (300 char limit)

> Vortix: a terminal UI that manages multiple WireGuard tunnels at the same time, with real-time telemetry

Alternatives:
- `Run multiple WireGuard profiles concurrently from a terminal UI (Vortix)`
- `Built a TUI for WireGuard — kill switch, leak detection, multi-tunnel — feedback welcome`

**Convention notes:**
- /r/WireGuard is small and friendly; technical depth + concrete use cases land well
- Members are sensitive to "VPN provider shilling" — emphasize this is a CLIENT, not a paid service
- Mention you're the author up front; mods are strict about disclosure

---

## Post body

> Hey /r/WireGuard — author here. I built Vortix, a Rust TUI for managing WireGuard (and OpenVPN) connections on macOS and Linux. Not a VPN provider, not a paid service — it's an OSS client that wraps `wg-quick` and surfaces what's actually happening on a single screen.
>
> ### Why I built it
>
> [FILL IN — Anchor it in a WireGuard-specific pain point. Examples:
> - "I have a corp WG profile + a homelab WG profile + a third for personal use. Running `wg-quick up corp; wg-quick up home` left me grepping `wg show` to see which one owned the default route."
> - "I kept hitting the `wg-quick: resolvconf not found` wall on Arch every time I imported a profile with `DNS = …`."]
>
> ### What it does specifically for WireGuard users
>
> - **Multi-tunnel.** Connect 2+ WG profiles concurrently. One owns the kernel default route (the primary), the rest are split tunnels reachable on their declared `AllowedIPs`. Takeover overlay when a second profile wants the default route.
> - **systemd-resolved native** (closes a long-standing pain point on Arch / Omarchy / NixOS-with-resolved): when resolved is the system resolver, Vortix registers per-link DNS via `resolvectl` directly — no `systemd-resolvconf` shim required.
> - **Kill switch with three modes**: `off`, `block-on-drop` (only blocks if VPN drops unexpectedly), `vpn-only` (always blocks non-tunnel egress). Per-tunnel ACCEPT rules — multi-tunnel-aware out of the box.
> - **Auto-adopt**: if you run `wg-quick up corp` from another terminal, Vortix's TUI picks it up within ~1 second.
> - **Telemetry**: throughput, latency, jitter, packet loss, exit IP, geo-IP, DNS leak, IPv6 leak — all live on one screen.
> - **Real `wg` underneath**: Vortix doesn't reimplement WireGuard. Kernel WG on Linux/BSD, wireguard-go on macOS via `wg-quick`.
>
> ### Install
>
> ```
> # Any of these:
> curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Harry-kp/vortix/releases/latest/download/vortix-installer.sh | sh
> brew install Harry-kp/tap/vortix
> cargo install vortix
> sudo pacman -S vortix     # Arch
> npm i -g @harry-kp/vortix
> ```
>
> ### Source
>
> https://github.com/Harry-kp/vortix
>
> Happy to answer WireGuard-specific questions — DNS scoping under multi-tunnel, kill-switch interaction with `wg-quick`'s PostUp hooks, why I picked `wg-quick` over native netlink wg setup, anything.

---

## Common questions to expect

- **"Why not just use `wg show` + scripts?"** — Honest answer: you can. Vortix is for when juggling >1 profile gets annoying, or when you want leak detection + telemetry in one place.
- **"Does it work with WireGuard-go on macOS?"** — Yes, via `wg-quick`'s userspace fallback.
- **"What about Windows?"** — Stubbed; the Windows WireGuard ecosystem is so good (official client) that there's no real gap to fill.
- **"Will you add [provider X]?"** — Vortix manages YOUR profiles; it's not a meta-client for VPN providers.
