# Twitter / X + Mastodon (Fosstodon)

**Why both:** Twitter for reach, Fosstodon (https://fosstodon.org/) for the OSS / Linux / Rust crowd that's left X. They reinforce each other.

**Best post time:** Tue–Thu, 14:00–17:00 UTC (catches US workday + EU evening).

**Format:** Twitter has a 280-char hard cap; Mastodon (Fosstodon instance) has 500. Same content works on both with minor edits.

---

## Single post version (use this on Twitter as the lead, also works standalone on Mastodon)

> [FILL IN with light edits to fit 280 chars on Twitter]
>
> Just shipped Vortix v0.4 — a terminal UI for WireGuard and OpenVPN written in Rust.
>
> ✦ Run multiple VPN tunnels concurrently
> ✦ Real-time telemetry, leak detection, kill switch
> ✦ macOS + Linux
>
> Built it because I was tired of `wg show` + scripts.
>
> https://github.com/Harry-kp/vortix

**Character count check:** ~275 chars. Comfortable on both platforms.

---

## Thread version (Twitter — 4 tweets, post 30 sec apart so the thread chains properly)

### Tweet 1 (hook)

> [FILL IN — punchy lede. Examples:
> "I was juggling 3 WireGuard profiles. wg-quick + grep + counting routes manually. So I built a terminal UI for it.
>
> Meet Vortix — Rust TUI for WireGuard + OpenVPN. v0.4 just shipped 🧵"]

### Tweet 2 (what's interesting)

> Multi-tunnel by default. One profile owns the kernel default route (primary), the rest are split tunnels reachable on their declared AllowedIPs.
>
> Per-profile retry, auto-adopt of tunnels started outside the TUI, real-time throughput + latency + jitter + leak detection.

### Tweet 3 (technical credibility)

> Tech: Rust + tokio + ratatui. Wraps native wg-quick / openvpn — doesn't reimplement either. ~15MB binary, <100ms startup.
>
> Kill switch built-in: PF on macOS, iptables/nftables on Linux. Three modes: off / block-on-drop / vpn-only.

### Tweet 4 (close + CTA)

> Free, open source (MIT), no telemetry, no account.
>
> Install: `cargo install vortix` or `brew install Harry-kp/tap/vortix` (curl-installer / npm / Arch pacman also supported).
>
> Source: https://github.com/Harry-kp/vortix
>
> Feedback welcome 🙏

---

## Mastodon-specific tweaks

- Fosstodon community responds well to **Free / Libre / Open Source** framing — explicit "MIT-licensed, no telemetry, no account" tagline at the top
- Hashtags work better here than on X: `#Rust #Linux #OpenSource #VPN #WireGuard #OpenVPN #TUI`
- 500 chars per toot — combine tweets 1+2 into one toot for cleaner flow
- Don't repost-then-delete — Mastodon culture finds it spammy

**Suggested single Fosstodon toot (combining the thread):**

> Just shipped Vortix v0.4 — a terminal UI for managing WireGuard and OpenVPN connections, written in Rust.
>
> ✦ Multi-tunnel: run 2+ VPN profiles concurrently, one primary + N split tunnels
> ✦ Real-time telemetry: throughput, latency, jitter, leak detection
> ✦ Built-in kill switch (PF/iptables/nftables)
> ✦ Wraps native wg-quick/openvpn — doesn't reimplement either
> ✦ macOS + Linux, MIT-licensed, no telemetry
>
> https://github.com/Harry-kp/vortix
>
> #Rust #Linux #OpenSource #VPN #TUI

(~445 chars, within Fosstodon's 500-char limit)

---

## Engagement plan

- **First 90 minutes are critical** on Twitter — same as HN. Reply to every comment.
- **DON'T** quote-tweet your own post to "boost it" within the same hour — algorithm punishes it.
- After 24 hours, post a **followup tweet** with one specific user reaction / install screenshot / star count milestone. Stick it as a reply to your own thread, not a new top-level tweet.
- Cross-post on LinkedIn ONLY if your network is technical — otherwise the engagement skews wrong and LinkedIn's algorithm shows it to non-target audience.

---

## What NOT to do

- Don't @ influencers cold ("@dhh check this out!") — looks needy, rarely works
- Don't post the same content on Twitter and HN simultaneously — pick a primary, let it run for 4-6 hours, then signal-boost on social
- Don't pay for promoted-tweet boost; OSS tools never recoup it
