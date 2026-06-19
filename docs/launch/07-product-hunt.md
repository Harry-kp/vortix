# Product Hunt

**URL:** https://www.producthunt.com/posts/new
**Launch day rule:** PH listings go live for **24 hours** starting at 00:01 PST (08:01 UTC). All votes on launch day count.
**Best launch day:** Tuesday or Wednesday. Avoid Sunday (low traffic), Saturday (decent surprisingly), Monday (crowded launches).
**Account requirement:** Free PH account; "hunter" status helps but anyone can launch.

---

## Required fields

### Product name
> Vortix

### Tagline (60 char limit — the make-or-break field on PH)

Pick ONE — the tagline is your title:

> **Terminal UI for WireGuard and OpenVPN, written in Rust**  (53 chars) ← recommended
>
> Alternatives:
> - `A multi-tunnel VPN client that lives in your terminal`  (54 chars)
> - `WireGuard + OpenVPN, side by side, in your terminal`  (52 chars)
> - `Manage every VPN connection from one terminal screen`  (53 chars)

### Description (260 char limit — appears under the tagline on cards)

> [FILL IN — write 2 sentences that hook a non-technical PH browser.
>  Recommended angle:
>  "Vortix is a terminal interface for managing multiple WireGuard and OpenVPN connections at once. Real-time throughput, leak detection, and a built-in kill switch — all keyboard-driven, no GUI required."  (242 chars)]

### Topics (pick 3–5)

- Developer Tools
- Open Source
- Productivity
- Networking
- Privacy

### Gallery (recommend 3–6 visuals, in this order)

1. **Hero shot.** Full TUI with 2 tunnels connected, security guard panel visible, sparklines populated. PNG. Aspect ratio 16:9 (e.g. 1920x1080).
2. **Multi-tunnel takeover overlay.** Screenshot of the `[S]witch / [B]oth / [N]o` prompt — visually distinctive.
3. **Connection details panel.** Shows VPN IP, throughput sparkline, latency, jitter.
4. **Animated GIF.** 5–10 sec: connect → telemetry fills in → second profile connects → both visible. Loops cleanly.
5. **CLI mode screenshot.** `vortix status --json` output rendered in a JSON viewer or terminal — shows it's scriptable.
6. **Optional:** README screenshot showing supported install methods.

### Maker comment (post immediately when listing goes live — pinned at top)

> [FILL IN — Personal story. 4-6 sentences. Examples:
>
> "Hey PH! I built Vortix because I was juggling three VPN configs (work, homelab, personal) and every existing client either had a clunky tray icon I couldn't see throughput on, or required me to disconnect one to connect another.
>
> Vortix runs entirely in your terminal — connect multiple WireGuard or OpenVPN profiles concurrently, see real-time throughput / latency / leak status on one screen, with a built-in kill switch. It's MIT-licensed and runs on macOS and Linux.
>
> Would love feedback from anyone who's set up their own VPN, run a homelab, or just lives in the terminal. Especially curious what you'd want to see next — happy to answer any questions about the design tradeoffs."]

---

## Engagement plan (24-hour launch window)

- Be online for hours 0–4 (00:01–04:00 PST) and hours 12–18 (US workday) — that's where 80% of votes come from
- Reply to every comment within 30 minutes
- Share the PH link ONCE on Twitter / Mastodon / LinkedIn (PH-style posts don't go on HN)
- Don't ask for votes directly anywhere — PH detects vote rings and unlists products

---

## Things to prepare BEFORE launch day

- Crisp 30-sec demo GIF (loops, no audio needed)
- 2-line and 5-line elevator pitches memorized for live comments
- Stress-test the install flow ON EVERY documented install path (brew, cargo, npm, curl) — first-time users WILL try these
- A list of known competitors prepared mentally for the "how does this compare to X?" comment that always shows up

---

## Things PH audience reacts to (vs HN)

- More visual, less technical
- "I built this because..." stories work well
- Open-source positioning is a plus, not a wash
- Roadmap teasers ARE welcome here (unlike HN) — PH is forward-looking
