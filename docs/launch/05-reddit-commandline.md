# Reddit /r/commandline

**Subreddit:** https://www.reddit.com/r/commandline/
**Subscribers:** ~140k
**Post type:** Image/video link (asciinema or GIF) OR link to repo
**Best post time:** Weekday morning US (~13:00–15:00 UTC)
**Flair:** Required — `application` or `tool`

---

## Title (300 char limit)

> Vortix — TUI for WireGuard and OpenVPN, real-time telemetry, multi-tunnel, written in Rust

Alternatives:
- `[TUI] Vortix: manage multiple VPN tunnels from the terminal, with live throughput / latency / leak detection`
- `Built a ratatui-based VPN TUI — feedback welcome (Vortix)`

**Convention notes:**
- /r/commandline is heavily visual — a GIF or asciinema recording of the TUI in action does 10x the engagement of a text post
- Members appreciate technical detail about TUI choices (ratatui vs tui-rs, layout, keybindings, color handling)
- Don't title with "best ever" or hype — community is allergic to it

---

## Post body

> [PIN A GIF / asciinema FIRST. Vortix's strength here is visual.
>  Suggested capture:
>  1. `vortix` opens the TUI, sidebar shows 2-3 profiles
>  2. `vortix up <profile>` connects, dashboard fills in (throughput sparkline, latency, exit IP)
>  3. Connect a second profile — takeover overlay appears
>  4. Press `B` for "both", security guard panel updates
>  5. `vortix down` disconnects, telemetry shows the drop
>
>  ~45 sec total. asciinema.org/a/[XXX] OR https://github.com/.../assets/demo.gif]
>
> ### What it does
>
> Vortix is a terminal UI for managing WireGuard and OpenVPN connections. Runs on macOS and Linux. Multi-tunnel (1 primary + N split tunnels), live telemetry, kill switch, DNS / IPv6 leak detection. All keyboard-driven.
>
> ### TUI-specific details (the bits this sub will care about)
>
> - **ratatui** for rendering, **crossterm** for input. Single-threaded UI loop; all blocking work (subprocess execution, network probes) is pushed to background threads with mpsc channels back to the UI.
> - **Layout adapts to terminal width** at 50 / 60 / 80 / 100 / 120 columns. Below 80x24, header degrades through a sigil-ladder rather than wrapping. Tested in tmux splits, alacritty, ghostty, Terminal.app, foot, kitty.
> - **NO_COLOR is honored.** Status badges (`●`, `*`, `⚠`, `✓`, `✗`) carry information via Unicode shape, not just color — works fine in monochrome terminals and for color-blind users.
> - **VoiceOver / Orca-friendly.** No purely-color signals; sidebar rows are announced cleanly. Tested.
> - **Pure TUI, no inputs that drop you out of the terminal.** No browser auth flow, no QR codes, no OS notification popups — by design.
>
> ### Keybindings (sample)
>
> ```
> j/k     navigate profile list           Tab     cycle focus
> Enter   connect / disconnect            d       disconnect single tunnel
> Shift+D disconnect ALL tunnels          B       "both" on takeover overlay
> v       view profile config             ?       help overlay
> q       quit                            r       reconnect current
> ```
>
> ### Install
>
> ```
> curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Harry-kp/vortix/releases/latest/download/vortix-installer.sh | sh
> # or brew install Harry-kp/tap/vortix
> # or cargo install vortix
> # or sudo pacman -S vortix
> ```
>
> ### Source
>
> https://github.com/Harry-kp/vortix
>
> Built with ratatui — happy to talk about TUI design decisions (why no mouse support, the overflow ladder, the security-guard panel layout, etc).

---

## Common /r/commandline pushback to anticipate

- "Why ratatui not tview/bubbletea?" — Vortix is Rust; ratatui is the only serious answer in that ecosystem
- "Does it work in [obscure terminal]?" — Honest answer is "tested on the common ones, please file an issue"
- "Why no mouse?" — Pure keyboard-driven by design; mouse support adds layout complexity for marginal benefit
- "Color scheme?" — Honors NO_COLOR; no custom-theme system yet (room for issue/PR)
