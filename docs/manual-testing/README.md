# Manual Testing Guides

Per-feature checklists of things that **only a human running the binary against real kernels, real WG/OVPN daemons, and real terminals** can validate. Automated tests (`cargo test`) cover FSM logic, parsers, CIDR math, JSON shapes, wire-format serde, and UI render builders with hand-rolled snapshots — but they can't cover real kernel routing, real firewall transitions, TUI visuals at different terminal sizes, daemon lifecycle, or cross-platform parity.

Use these guides:

- **Before merging** a feature PR — work top-to-bottom on the relevant guide, check items off
- **After upgrading** dependencies that touch subprocess / network / kernel surfaces (rand, sha2, libc, tokio)
- **For release smoke tests** — pull in every guide for the units shipped that release
- **When debugging** a regression — the checklist is also a map of the feature's observable surface

## Conventions

- One file per feature / plan, named after the plan slug (e.g. `multi-connection.md` for plan `001-feat-multi-connection`)
- Each file groups checks by **category** (Setup, Regression, Happy paths, Conflict / edge, Failure modes, Cross-platform, Security, Performance)
- Each check is a Markdown checkbox — copy the file into a PR or scratchpad to track progress
- Where a check requires a specific platform (Linux-only, macOS-only), flag it inline — most checks should run on both
- Where a check requires unusual setup (e.g. OVPN 2.3 binary, multi-UID daemon adversary), call it out in the "Setup prerequisites" section at the top of the guide

## How to add a new guide

1. Copy `_template.md` to `<feature-slug>.md`
2. Fill in the sections; delete categories that don't apply
3. Reference the guide from your PR's "Test plan" section: `See [docs/manual-testing/<feature>.md](docs/manual-testing/<feature>.md)`
4. After the feature ships, the guide stays — future regression sweeps and dependency upgrades use it again

## Index

| Guide | Plan | Shipped | Surface |
|---|---|---|---|
| [multi-connection.md](multi-connection.md) | [001-feat-multi-connection](../plans/2026-05-28-001-feat-multi-connection-plan.md) | v0.4.0 (pending) | TunnelRegistry, killswitch v2, DNS scoping, fwmark, multi-tunnel TUI, CLI grammar v2, daemon dispatch |

Add new rows above as guides land.
