# Context for Claude Code sessions

Hard-won knowledge from prior sessions. Read these before you ship anything.

## Before every push: run the full CI parity set

CI failed four times on a single PR because each push verified a different subset of what CI actually runs. The full command set lives in [`docs/ci-parity.md`](docs/ci-parity.md) — run it before every push, not a subset.

Common traps documented there (each cost one CI cycle):
- `-p vortix --lib` skips test code; `clippy::pedantic` is workspace-wide so test code gets pedantic lints too
- macOS host cannot validate Linux-cfg code paths (`vortix_platform_linux/*`, `daemon/server.rs` SO_PEERCRED block) and vice versa
- `cargo clippy` does NOT run rustdoc lints — only `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps` exercises them
- `cargo fmt` (without `--all`) skips workspace members on rustfmt diffs

"Passes locally" is a claim that requires the full command output, not a verbal assertion.

## Dependency pins to leave alone

`crates/vortix/Cargo.toml` pins `rand = "0.8"` and `sha2 = "0.10"`. Dependabot will keep proposing bumps — DO NOT accept them naively:
- `aes-gcm 0.10` (in `vortix_config/secret_store.rs`) expects `rand_core 0.6`; `rand 0.10` ships `rand_core 0.10` and the two are not interchangeable
- The PR comment chain on #208/#209/#211 documents the breakage if you need receipts

If you bump, also rewrite `secret_store.rs`'s nonce generation against whatever rand_core version aes-gcm exposes that release.

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

## Manual testing convention

Automated tests cover FSM, parsers, CIDR math, JSON shapes, render builders. They cannot cover real kernels, real `wg-quick`/`openvpn` subprocesses, real terminals, real adversaries. Manual scenarios live in [`docs/manual-testing/backlog.md`](docs/manual-testing/backlog.md) — one table of rows ordered by risk. When you ship a feature with observable runtime behavior, add a row that names the scenario, the setup, and the pass/fail signal.

## Multi-tunnel: registry is the truth

The App layer's single source of truth for active VPN state is `App.registry: TunnelRegistry<TunnelKind>`. Every panel renderer (header, sidebar, Connection Details, Security Guard, footer) reads from `app.registry.snapshot_all` / `app.registry.snapshot(profile_id)` exclusively.

The legacy `ConnectionState` enum still exists in `crates/vortix/src/vpn_runtime/connection_state.rs` and is re-exported from `vpn_runtime`, but only as: (a) the CLI's blocking helpers' local single-tunnel view (one process, one tunnel), and (b) the return type of `App::legacy_state()` — a derived view from the registry primary for the few residual single-tunnel-shaped reads (kill-switch sync, delete-safety, scanner dispatch).

There is **no** `connection_state` field on `VpnRuntime`. Don't add one. Multi-tunnel-aware code reads registry snapshots; single-tunnel-shaped code calls `App::legacy_state()` and matches on the variant.

## Kill switch semantics

- **Off** — disabled, no firewall rules.
- **Auto** — armed while a VPN is up; engages default-DROP egress only on an unexpected drop.
- **AlwaysOn** — firewall stays engaged whether VPN is up or down. The default-DROP OUTPUT policy + per-tunnel ACCEPT rules (in `core::killswitch::enable_blocking_multi`) keep traffic from leaking in the gap between a drop and reconnection. State always resolves to `Blocking`, never `Armed`.

### Enum variants vs UI labels (don't get confused)

The enum variants `Off` / `Auto` / `AlwaysOn` are the **stable contract** — they appear in code matches, log lines, the CLI grammar (`vortix killswitch off|auto|always`), the JSON envelope (`{"mode": "..."}`), and `killswitch.toml`. **Never rename them.**

User-facing rendering uses friendlier labels via the helpers on `vortix_core::state::killswitch` (`KillSwitchMode::display_name`, `KillSwitchMode::one_liner`, `KillSwitchMode::behavior_lines`, `KillSwitchState::display_status`):

| Enum         | UI label          | Plain English                                          |
|--------------|-------------------|--------------------------------------------------------|
| `Off`        | `Off`             | All traffic flows; real IP exposed if VPN drops.       |
| `Auto`       | `Block on drop`   | Watch the VPN; block if it drops unexpectedly.         |
| `AlwaysOn`   | `VPN-only`        | Only VPN traffic permitted. No internet without a VPN. |

If you're touching killswitch rendering, route through those helpers — don't hardcode "Auto" or "Strict" in display strings. The header bar uses short abbreviations (`KS:Off` / `KS:Watch` / `KS:VPN-only` / `KS:DROPPED`); the Security Guard panel uses `display_name` + a status phrase; the CLI's human output uses `display_name` + `behavior_lines`. The module docs on `vortix_core/state/killswitch.rs` list the canonical mapping table.

## Planning artifacts

- `docs/brainstorms/<date>-<slug>-requirements.md` — what to build (origin doc)
- `docs/plans/<date>-<seq>-<type>-<slug>-plan.md` — how to build (implementation units)
- `docs/manual-testing/<slug>.md` — what to verify by hand after shipping

The `compound-engineering` skill set (`ce-brainstorm`, `ce-plan`, `ce-work`, `ce-doc-review`) drives this workflow. If you're starting from a fuzzy ask, run `ce-brainstorm` first.
