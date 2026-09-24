# Context for Claude Code sessions
## VERY IMPORTANT: Read the STOPOVERENGINEERING.md

Hard-won knowledge from prior sessions. Read these before you ship anything.

## Before every push: run the full CI parity set

CI failed four times on a single PR because each push verified a different subset of what CI actually runs. The full command set lives in [`docs/ci-parity.md`](docs/ci-parity.md) — run it before every push, not a subset.

Common traps documented there (each cost one CI cycle):
- `-p vortix --lib` skips test code; `clippy::pedantic` is workspace-wide so test code gets pedantic lints too
- macOS host cannot validate Linux-cfg code paths (`vortix_platform_linux/*`, `daemon/server.rs` SO_PEERCRED block) and vice versa
- `cargo clippy` does NOT run rustdoc lints — only `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` exercises them
- `cargo fmt` (without `--all`) skips workspace members on rustfmt diffs

"Passes locally" is a claim that requires the full command output, not a verbal assertion.

## Architectural boundaries are enforced by xtask, not just convention

- `vortix_core/` must not import from `vortix_platform_*`, `vortix_protocol_*`, or the process layer
- `vortix_platform_*` must not import from `vortix_protocol_*` and vice versa
- Subprocess invocations of protocol binaries (`wg`, `wg-quick`, `openvpn`) belong in `vortix_protocol_*` only — anywhere else needs a `// xtask:allow-protocol-leak: <reason>` annotation

The three `cargo xtask check-*-leak` commands enforce this in CI. If you're tempted to add an import that crosses a boundary, stop and ask whether the abstraction should move instead.

## TUI density principle

User's explicit guidance from session memory: density via signaling, not duplication. Never auto-add UI panels per entity. When you add a TUI feature:
- Single-line summary signals beat multi-line panels
- Multi-tunnel views fit in the existing 6-row dashboard layout via overflow ladders, not new panels
- See `docs/manual-testing/multi-connection.md` for what "fits cleanly at 80×24" means in practice

## Build budget and test-target layout

Binary size, build time and the profile knobs behind them live in
[`docs/performance.md`](docs/performance.md); `scripts/bench-build.sh` re-measures the table.
Two rules from it that bite silently:

- `[profile.release]` sets `opt-level = "z"`. `panic = "abort"` is **not** set and must not be —
  `catch_unwind` carries panic isolation for tunnels, hooks, the control worker and background
  tasks.
- Integration tests live in `crates/vortix/tests/suite/` behind one `main.rs`. A file dropped in
  that directory with no `mod` line compiles into nothing and its tests stop running with no
  diagnostic. A suite that mutates process-global state or asserts wall-clock duration stays a
  top-level `tests/*.rs` instead.

## Manual testing convention

Automated tests cover FSM, parsers, CIDR math, JSON shapes, render builders. They cannot cover real kernels, real `wg-quick`/`openvpn` subprocesses, real terminals, real adversaries. The release gate lives in [`docs/manual-testing/P0.md`](docs/manual-testing/P0.md) — numbered workflows an agent can execute against a live TUI on macOS and Linux. When you ship a feature with observable runtime behavior, add a workflow only if no automated test can answer it, and write its pass signal as something visible in a captured frame.

## Connections: one engine, one planner

`src/control/` owns every VPN connection. One engine thread (`engine.rs`) holds
the tunnel list (`state.rs`), starts and stops protocol processes
(`tunnels.rs`), and after every change asks the pure planner (`plan.rs`) what
routes, DNS and firewall the host should carry, then applies the difference
(`net.rs`). The plan depends only on which tunnels are up and the kill switch
mode — never on the order of commands — so every path to the same tunnel set
lands on the same host state. The newest full tunnel owns the default route
and DNS; a switch brings the new tunnel up before stopping the ones it
conflicts with.

TUI and CLI send `control::Command`s and read `control::Snapshot`s; nothing
else touches routes, DNS or pf. The dashboard's `TunnelRegistry` is only a
render cache fed from the snapshot. New behaviour goes into the planner or a
state transition, with a test in `plan.rs`/`state.rs` — not into a caller.

## Kill switch semantics

One vocabulary, used identically on every surface — CLI input verb, CLI output, TUI panels, JSON envelope, log lines. Rust enum variants (`Off` / `Auto` / `AlwaysOn`) stay idiomatic for the language but never leak into output. The bridge between the enum and every user-visible string is the helper set on `vortix_core::state::killswitch` — `KillSwitchMode::display_name` (display), `cli_verb` / `from_cli_verb` (input parsing), `one_liner`, `behavior_lines`, and `KillSwitchState::display_status`.

| Rust enum    | Slug (CLI verb + display) | What it does                                                                                                                                                                                                  |
|--------------|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Off`        | **`off`**                 | No firewall rules. All traffic flows; real IP exposed if VPN drops.                                                                                                                                           |
| `Auto`       | **`block-on-drop`**       | Armed while a VPN is up; engages default-DROP egress only on an unexpected drop.                                                                                                                              |
| `AlwaysOn`   | **`vpn-only`**            | Firewall stays engaged whether VPN is up or down. Default-DROP OUTPUT policy + per-tunnel ACCEPT rules (`core::killswitch::enable_blocking_multi`) close the gap-between-drop-and-reconnect leak window. State always resolves to `Blocking`, never `Armed`. |

There are **no aliases**. `vortix killswitch auto` and `vortix killswitch always` are not accepted — the parser returns the "Use: off, block-on-drop, vpn-only" error. If you're touching killswitch I/O, route through the helpers; never hardcode a string.

The header bar uses short abbreviations of the same labels (`KS:Off` / `KS:Watch` / `KS:VPN-only` / `KS:DROPPED`) because of the 80-col budget. The display-name labels (`Off` / `Block on drop` / `VPN-only`) are the long-form rendering of the same three slugs — just title-cased for prose. Slug everywhere, prose only in the long-form Security Guard / `vortix killswitch` output.

## Background mode and the daemon were removed

Vortix runs as root directly. There is no helper, no daemon socket, no
`vortix setup`/`background`/`daemon` command. The privilege-separated tree is
preserved on the `archive/background-mode` branch. Do not re-introduce it
without a product decision.

## Planning artifacts

- `docs/brainstorms/<date>-<slug>-requirements.md` — what to build (origin doc)
- `docs/plans/<date>-<seq>-<type>-<slug>-plan.md` — how to build (implementation units)
- `docs/manual-testing/<slug>.md` — what to verify by hand after shipping

The `compound-engineering` skill set (`ce-brainstorm`, `ce-plan`, `ce-work`, `ce-doc-review`) drives this workflow. If you're starting from a fuzzy ask, run `ce-brainstorm` first.
