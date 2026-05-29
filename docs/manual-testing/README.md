# Manual Testing

[`backlog.md`](backlog.md) is the single source of truth — a flat table of every manual check needed pre-release, with the steps to reproduce and one-line reason it can't be automated.

## Conventions

- **One file, append-only.** New features that ship with a manual check add rows to `backlog.md`. No per-feature files.
- **Delete to mark "done."** When an automated test starts covering a row, delete it. Don't annotate "now automated" — the row IS the residual.
- **Match existing "Why manual" tags** when possible (`TUI rendering`, `Cross-platform: ...`, `Real-fs setup`, `Feature wiring gap`, `Perf benchmark cadence`, `Fault injection deferred`). Easier to spot related rows.

## When to consult it

- **Before releases** — walk the backlog top-to-bottom; sign off in the release PR description.
- **After upgrading subprocess / kernel / firewall deps** (rand, sha2, libc, tokio, etc.) — re-run the relevant subset.
- **When debugging a regression** — the backlog is also a map of the product's observable surface.

## CI parity (automated test command set)

See [`docs/ci-parity.md`](../ci-parity.md). Run that command set locally before pushing; it catches everything `backlog.md` doesn't.
