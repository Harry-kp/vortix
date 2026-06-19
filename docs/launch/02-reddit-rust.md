# Reddit /r/rust

**Subreddit:** https://www.reddit.com/r/rust/
**Subscribers:** ~330k as of 2026
**Post type:** Link post (to repo) OR Text post
**Best post time:** Tue–Thu morning EU time (~07:00–09:00 UTC) catches both EU and East-Coast US
**Flair:** Required — pick `🛠️ project`

---

## Title (300 char limit, picks one)

> Vortix: a Rust TUI for WireGuard and OpenVPN — multi-tunnel, real-time telemetry, leak detection

Alternatives:
- `[Project] Built a Rust TUI VPN client with multi-tunnel and a state-machine engine`
- `Vortix v0.4: Rust TUI managing multiple WireGuard / OpenVPN tunnels concurrently`

**/r/rust convention notes:**
- Square-bracket prefixes (`[Project]`, `[Crate]`) are common but not required if flair is set
- Avoid clickbait; community downvotes hype hard
- Show code or technical detail in the body, not just a marketing link

---

## Post body (text post — recommended over bare link)

> [FILL IN — Lede: 2–3 sentences. Why does a Rust dev care? What's the Rust angle? Examples:
> - "Built with tokio + ratatui. Plain Rust binary, ~15MB, <100ms startup."
> - "Workspace split: `vortix-core` is platform-agnostic, `vortix-platform-{linux,macos,windows}` behind capability ports."]
>
> ### What it does
>
> - Terminal UI that manages WireGuard and OpenVPN connections side by side
> - Multi-tunnel: one primary owns the kernel default route, secondaries are split tunnels on declared `AllowedIPs`
> - Real-time telemetry: throughput, latency, jitter, packet loss, geo-IP, DNS/IPv6 leak detection
> - Platform-native kill switch: PF on macOS, iptables/nftables on Linux
> - Cross-platform: macOS and Linux first-class, Windows stub
>
> ### Notable Rust-y bits
>
> - [FILL IN — Pick 2–3. Examples:
>   - "Engine FSM as a typed 5-variant state machine; compile-time transition enforcement, no can-this-happen branches."
>   - "Capability ports via traits + enum_dispatch; per-OS implementations behind them. Static dispatch, no `Box<dyn>`."
>   - "xtask-driven boundary lints: `cargo xtask check-platform-leak` ensures `cfg(target_os)` only appears in platform crates."
>   - "Async runtime is tokio with a sync wrapper for the TUI thread; subprocess execution goes through a `CommandRunner` port so the TUI never blocks."]
>
> ### Crate is on crates.io
>
> ```
> cargo install vortix
> ```
>
> ### Repo
>
> https://github.com/Harry-kp/vortix
>
> Feedback / code review / "why did you do X" comments welcome — happy to talk about the design tradeoffs.

---

## Things /r/rust audience pushes back on

- `unsafe` without a SAFETY comment — Vortix has a few libc calls; make sure they're well-commented
- Synchronous blocking on the UI thread — anticipate this; the answer is "we don't, here's how"
- Crate name collisions with niche existing crates — quick `cargo search vortix` shows we're clean
- "Why not just wrap [existing tool]?" — answer is the multi-tunnel + real-time telemetry story

---

## Cross-post candidates after this lands

- /r/rust_gamedev (no, irrelevant)
- /r/rust_networking (smaller but relevant) — wait 24h, then crosspost with note "crossposted from /r/rust"
