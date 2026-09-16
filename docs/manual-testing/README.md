# Manual testing

[`P0.md`](P0.md) is the release gate: numbered workflows that must pass on macOS and Linux
before a release ships. Each one is written so an agent can execute it with no prior
knowledge of Vortix — literal commands, literal keystrokes, and a pass signal visible in a
captured frame or command output.

[`multi-connection.md`](multi-connection.md) holds the layout reference for what "fits
cleanly at 80×24" means in practice.

## What belongs here

Automated tests cover FSM, parsers, CIDR math, JSON shapes and render builders. They cannot
cover real kernels, real `wg-quick`/`openvpn` subprocesses, real terminals or real
adversaries. Only checks in that last group belong in `P0.md`. If a passing automated test
can answer the question, it is not a P0 workflow — see the coverage table at the end of
`P0.md` for what was handed back to the test suite and why.

## When to run it

- **Before every release** — walk `P0.md` top to bottom on both platforms and fill in the
  results log. Sign off in the release PR description.
- **When debugging a regression** — the gate is also a map of the product's observable surface.

## What this is not

Pre-push verification. See [`docs/ci-parity.md`](../ci-parity.md); run that command set
locally before pushing. It catches everything `P0.md` does not.
