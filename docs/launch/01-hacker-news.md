# Hacker News — Show HN

**Submission URL:** https://news.ycombinator.com/submit
**Type:** Show HN
**Best post time:** Tue–Thu, 13:00–16:00 UTC (8–11 AM EST), avoid weekends
**Submission cooldown:** Don't re-submit if it doesn't take off — HN penalizes resubmits

---

## Title (80 char limit, picks one — A/B in your head before posting)

> Show HN: Vortix – A terminal UI for WireGuard and OpenVPN, written in Rust

Alternatives to consider:
- `Show HN: Vortix – Multi-tunnel VPN TUI with kill switch and leak detection`
- `Show HN: I built a Rust TUI that runs WireGuard and OpenVPN side by side`

**HN convention notes:**
- No emojis, no "🚀", no marketing language
- "Show HN" prefix is mandatory for project launches
- Keep title factual; community downvotes hype

---

## Post body (text post — paste below the title field)

> Hi HN — I built Vortix, a terminal UI for managing WireGuard and OpenVPN connections. It runs on macOS and Linux, supports multiple simultaneous tunnels (one primary + N split tunnels), and surfaces real-time telemetry / DNS-leak / IPv6-leak detection without leaving the terminal.
>
> Why I built it: [FILL IN — 2–3 sentences. Concrete origin story works best. e.g. "I was juggling 3 VPN configs at work and Tunnelblick/NetworkManager-GUI kept hiding what was actually happening. I wanted to see throughput, latency, jitter, exit IP, leak status — all on one screen, in a shell, without a browser tab."]
>
> What's interesting technically:
> - [FILL IN — 1 bullet on a specific decision that nerds will appreciate. e.g. "Engine is a 5-variant FSM with compile-time transition enforcement; the TUI just reads snapshots."]
> - [FILL IN — 1 bullet on a hard problem you solved. e.g. "Multi-tunnel DNS scoping on Linux: each tunnel gets per-link DNS via resolvectl when systemd-resolved is the resolver, fallback to resolvconf otherwise."]
> - [FILL IN — 1 bullet on something deliberately NOT done. e.g. "Vortix doesn't reimplement WireGuard or OpenVPN — it orchestrates them. ~15MB binary, <100ms startup."]
>
> Install: `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Harry-kp/vortix/releases/latest/download/vortix-installer.sh | sh` (or `brew install Harry-kp/tap/vortix`, `cargo install vortix`, `npm i -g @harry-kp/vortix`)
>
> Source: https://github.com/Harry-kp/vortix
>
> Happy to answer questions about the design tradeoffs, the multi-tunnel state machine, or anything else.

---

## Engagement plan (first 2 hours = make-or-break)

- Be at your keyboard. Respond to every comment within 15 minutes for the first 90 min.
- Top-of-thread comments often ask "why not [X]?" — have honest, non-defensive answers ready for: WireGuard's native CLI, NetworkManager, Tunnelblick, Tailscale, Mullvad client.
- If someone reports a bug live, fix it within the thread or open an issue + link it back.
- **Do not** ask friends to upvote — HN's voting ring detection kills posts that do this.

---

## Things NOT to put in the post

- Pricing / "freemium" / "paid tier" language (Vortix is OSS, but mentioning OSS-licensing is unnecessary unless asked)
- Roadmap promises ("coming soon: X") — community wants what works today
- Comparison tables — let those come up in comments organically
- Multiple emoji or marketing speak; HN audience reacts negatively
