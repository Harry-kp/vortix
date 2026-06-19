# Lobste.rs

**URL:** https://lobste.rs/stories/new
**Account requirement:** Invite-only. If you don't have an invite, ask in a Rust / OSS community channel where someone has a Lobsters account — invites are commonly given to known OSS authors.
**Best post time:** Tue–Thu, 12:00–16:00 UTC. Avoid weekends.
**Tags:** `rust`, `release` (mandatory pick at least one — see tag list at /tags)

---

## Title (300 char limit, but Lobsters prefers brief)

> Vortix: a Rust TUI for managing multiple WireGuard and OpenVPN tunnels

Alternatives:
- `Show Lobsters: Vortix, a multi-tunnel VPN TUI in Rust`

**Convention notes:**
- Lobsters is small, technical, curated. Audience overlaps heavily with HN's senior-engineer tail.
- Self-promotion is allowed but capped — typically one launch + occasional follow-up. Don't spam release notes.
- The community values *technical depth* over breadth. A 3-sentence "what it does" gets fewer upvotes than a 3-paragraph "here's the interesting design problem."

---

## Submission type: URL post

> URL: https://github.com/Harry-kp/vortix
> Tags: `rust`, `release`, `show`
> Title: Vortix: a Rust TUI for managing multiple WireGuard and OpenVPN tunnels

---

## First comment (post immediately, as the author — this is where the engagement happens on Lobsters)

> Author here. A few design decisions I'd be curious to get feedback on:
>
> **1. State authority lives in a `TunnelRegistry`, not in the UI.**
> [FILL IN — 2–3 sentences. e.g.
> "Earlier versions had the TUI hold connection state directly, and the CLI maintained a parallel mirror. They drifted constantly. v0.4 centralizes everything in a `TunnelRegistry` — both surfaces read snapshots from it. The legacy single-tunnel `ConnectionState` enum still exists but only as a derived view for back-compat with single-tunnel-shaped reads."]
>
> **2. Capability ports + per-OS implementations behind traits.**
> [FILL IN — example:
> "7 traits in `vortix-core` (Tunnel, Killswitch, DnsResolver, Interface, NetworkStats, RouteTable, CommandRunner). Per-platform crates (`vortix-platform-{linux,macos,windows}`) implement them. Three xtask lints enforce that `Command::new` only appears in `vortix-process`, `cfg(target_os)` only in platform crates, and protocol strings only in protocol crates."]
>
> **3. systemd-resolved native DNS scoping.**
> [FILL IN — example:
> "wg-quick on Linux calls resolvconf to set DNS. On Arch / Omarchy / fresh-Fedora that's the Achilles heel — no resolvconf binary on PATH. v0.4 detects systemd-resolved + resolvectl and takes over per-link DNS itself, leaving wg-quick a DNS-stripped config. Multi-tunnel DNS becomes free: each link gets its own resolvectl entry, primary claims `~.`, secondaries are reachable but non-authoritative."]
>
> Happy to dig into any of these or the kill-switch / multi-tunnel atomicity stories if anyone's curious.

---

## What Lobsters tends to reward

- Honest discussion of tradeoffs (not "shipped this perfect thing")
- Genuinely interesting technical decisions, even if small
- Author responding to every comment within the day
- Posting once, no resurrection / "v0.4.1 bump" posts

## What Lobsters tends to punish

- Marketing language ("revolutionary", "the best", "finally a real")
- Self-link to commercial product / paywalled service
- Tag spamming (don't pick `show` AND `release` AND `rust` AND `linux` AND `unix` — pick 2-3 max)
