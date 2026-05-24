---
plan_id: 2026-05-24-012
title: "feat: CI integration tests against real wg/openvpn binaries"
type: feat
status: completed
created: 2026-05-24
target_version: 0.4.0
target_branch: TBD (post v0.3.0 GA)
origin: docs/brainstorms/2026-05-24-architectural-completion-requirements.md
motivating_issue: 162
---

# feat: CI integration tests against real wg/openvpn binaries

> **Status: deferred.** This plan is a document-only artifact in PR
> #201. Execution happens in a future PR after v0.3.0 ships.

## Problem Frame

Issue #162 has been open since March. Vortix has 425+ unit tests but
zero integration tests that exercise real `wg-quick` or `openvpn`
binaries. Every release relies on a manual smoke pass (the new
`scripts/smoke-v0.3.0.sh` from plan 007 helps, but it's still manual).

The migration v1 makes integration tests easier: `MockRunner` and
`MockPlatform` exist, but the gap is the opposite — we don't run
against the *real* runner with real binaries on real network
interfaces.

## Summary

Add a GitHub Actions workflow that spins up a Docker matrix with
`wireguard-tools` and `openvpn` installed, runs a curated set of
integration tests against synthetic peer endpoints (loopback +
network namespaces), and gates the release on these passing.

## Scope Boundaries

**In scope:**
- New `.github/workflows/integration-tests.yml`
- Docker images for ubuntu-latest with `wireguard-tools`, `openvpn`,
  `iproute2` preinstalled
- Network namespace setup so tests can bring up a real interface
- Curated test set (10–20 tests) exercising:
  - WireGuard connect / disconnect lifecycle
  - OpenVPN connect / disconnect lifecycle
  - Killswitch engage / release with real firewall rules
  - Reconnect on transient failure
  - DNS resolution through the tunnel
- Matrix at minimum: Ubuntu 22.04, Ubuntu 24.04. macOS via runners
  optional (harder to set up wg-quick in CI).
- Tests gated as required-for-release in branch protection

**Deferred:**
- Real network egress testing (CI runners may not have it)
- Multiple distros beyond Ubuntu (Fedora, Arch — defer)
- Performance/throughput tests (separate concern)
- Real OpenVPN server setup — use a stub server in another netns
  instead

**Outside this product's identity:**
- Vortix tests internet-routing behavior — no, that's QA, not
  unit-or-integration

## Requirements

| ID | Requirement |
|----|-------------|
| R1 | A CI workflow runs the integration test set on every PR to main |
| R2 | Tests use real `wg-quick` and `openvpn` binaries, not mocks |
| R3 | A WireGuard tunnel is brought up between two network namespaces and verified |
| R4 | An OpenVPN tunnel is brought up against a stub server and verified |
| R5 | Killswitch tests verify real `iptables`/`nft` rules are applied |
| R6 | Failing integration tests block PR merge (branch protection rule) |

## Key Technical Decisions (deferred)

- **Network namespaces, not Docker containers, for tunnel endpoints.**
  Lighter weight; closer to how vortix runs in production.
- **Self-contained stub OpenVPN server in the test harness** — no
  external network dependencies.
- **Run in privileged Docker** — required for net namespace + iptables
  manipulation. CI runners already support this for `ubuntu-latest`.

## Open Design Questions

1. macOS integration tests — feasible? `wg-quick` on macOS uses
   `wireguard-go` which needs a different harness.
2. Cleanup guarantees — if a test fails partway, who cleans up the
   leftover interfaces / firewall rules?
3. Test isolation — one netns per test, or shared netns with
   per-test setup/teardown?
4. Should integration tests run on every commit, or only on PRs to
   main? (latency vs. coverage)

## Verification

- Workflow passes on a known-good main branch
- Workflow fails when introducing a regression (e.g., breaking
  killswitch rule generation)
- Total CI wall-clock for integration tests stays under 15 minutes
- No false positives across 10 consecutive runs on main

## What this plan unblocks

- Issue #162 (platform integration tests) — direct solve
- Higher release confidence — fewer manual smoke runs per release
- Refactor confidence — future architectural changes can be tested
  without full manual VPN smoke

## Estimated effort

3–4 weeks for the initial setup; ongoing maintenance as
distros/binaries change.
