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

Automated tests cover FSM, parsers, CIDR math, JSON shapes, render builders. They cannot cover real kernels, real `wg-quick`/`openvpn` subprocesses, real terminals, real adversaries. Every feature with observable runtime behavior gets a manual test plan under [`docs/manual-testing/`](docs/manual-testing/) — see the README and `_template.md` there. New features add a new file and an entry in the index table.

## Planning artifacts

- `docs/brainstorms/<date>-<slug>-requirements.md` — what to build (origin doc)
- `docs/plans/<date>-<seq>-<type>-<slug>-plan.md` — how to build (implementation units)
- `docs/manual-testing/<slug>.md` — what to verify by hand after shipping

The `compound-engineering` skill set (`ce-brainstorm`, `ce-plan`, `ce-work`, `ce-doc-review`) drives this workflow. If you're starting from a fuzzy ask, run `ce-brainstorm` first.
