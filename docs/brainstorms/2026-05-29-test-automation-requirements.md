---
title: Test automation strategy — from manual smoke to scale-ready QA
date: 2026-05-29
status: ready-for-plan
type: test-infrastructure
---

# Test automation strategy — from manual smoke to scale-ready QA

## Problem

Vortix's manual test plan in `docs/manual-testing/multi-connection.md` lists 114 checks across 21 categories — kernel routing, killswitch behavior, DNS scoping, TUI rendering, CLI exit codes, daemon UID gates, security spot-checks, cross-platform parity, performance/scale. Today, every release requires a human (the maintainer) to walk through this list manually. This already has cost:

- **Time burden per release.** ~110 checks at 30s-2min each = 1-3 hours of focused work per release, every release.
- **Skip risk under pressure.** When a fix needs to ship fast, checks get skipped. Regressions ship that the manual plan would have caught.
- **No regression-catching during development.** A bug introduced today doesn't surface until the next manual sweep (release time). The U9 iptables-nft regression caught in PR #1 is a recent concrete example — the integration test caught it because it's automated; the manual `docs/manual-testing/multi-connection.md` checks would have caught it only at release smoke.
- **Scale risk.** As vortix gains users, the cost of an undetected regression rises (more affected users, more support burden, larger trust impact for a privacy tool). The current manual-only approach scales linearly with release cadence; user impact scales with installed base. These curves diverge fast.

The brainstorm targets converting as much of the 114-check plan to automated coverage as is technically possible, leaving only the genuinely-unautomatable residual (real consumer hardware, screen readers, terminal rendering fidelity, real third-party VPN provider compatibility) for human work.

## Actors

| ID | Actor | Role |
|---|---|---|
| A1 | Maintainer | Currently runs all 114 checks manually pre-release. Wants the burden to scale sublinearly with feature velocity. |
| A2 | CI runner | Executes the automated subset on every PR and nightly. |
| A3 | Future contributor | Submits PRs to vortix. Should learn from CI feedback what they broke — not from a manual reviewer's "you missed this." |
| A4 | End user | Downstream consumer. Bears the cost of regressions that escape testing. The product promise (kill switch protects against leaks, multi-tunnel routing works as configured) is what testing protects. |

## Goals

1. **Automate ~95% of behavioral correctness checks** — anything testable without real consumer hardware, real internet exit IPs as the assertion target, or human perception (visual fidelity, screen reading). Phase 1 covers the highest-value 50% of the plan; Phases 2 and 3 cover the long tail.
2. **Shift regression detection from release-time to PR-time.** Bugs introduced today should surface within minutes of the PR push, not weeks later during release smoke.
3. **Keep CI infrastructure free.** GitHub Actions + `ip netns` + privileged Docker containers cover the technical needs without paid infrastructure (DigitalOcean, etc.). The remaining 5% gap doesn't justify the operational overhead of paid infra.
4. **Build a regression registry, not just a test suite.** Every user-reported bug should add a permanent test case before the fix ships. Coverage grows with the project's lived history, not just with intentional planning.
5. **Make "what's tested vs what isn't" visible.** A coverage table in the repo, kept current, so reviewers and contributors know which manual checks survived and which became automated.

## Non-goals

- **Replacing all human testing.** Cross-platform fidelity on real consumer hardware (a user's actual M3 MacBook with their specific terminal/font setup), screen-reader accessibility, and terminal-rendering quirks remain human work indefinitely. The goal is shrinking the human surface, not eliminating it.
- **Building a TUI visual-fidelity test framework from scratch.** Existing Rust unit tests with `ratatui::backend::TestBackend` snapshots already catch most TUI regressions. A more elaborate visual-diff framework (terminal screenshots, font rendering) is Phase 2 maybe-work; not a Phase 1 commitment.
- **Real-world VPN provider compatibility as continuous-integration concern.** Mullvad / ProtonVPN / IVPN config quirks belong in a pre-release smoke layer, run once per release against actual provider configs. CI tests synthetic peers in netns; provider quirks are a separate test layer.
- **Performance benchmarking infrastructure.** Perf tests have different signals (latency, throughput) and different cadence (pre-release, not per-PR). Build separately when scale warrants.
- **Real-world adversarial simulation** (network drops mid-handshake, ISP interference, geoblocking). Real product issues, but not catchable in a unit/integration test. Beta-user feedback handles this layer.

## Phased delivery

Three phases. Phase 1 lands as a single project; Phases 2 and 3 are tracked as scope, not commitments — they wait for Phase 1 to prove its value first.

### Phase 1: behavioral automation foundation (~55 checks)

Extends the existing `tests/integration/` netns harness pattern (Docker container with `ip netns` namespaces on a GitHub Actions runner). Covers the regressions most likely to fire on real changes.

**Pure-CI subset (~30 checks, runs per-PR):**
- All CLI grammar variants (`up`/`down`/`reconnect`/`status` with every flag combination)
- All CLI exit codes (0/3/4/5/6) with the right hint text
- JSON v2 envelope shape (every variant of `connections` / `primary` / `connection`)
- PersistedState V1→V2 migration (synthesize V1, observe V2)
- Conflict detection registry (unit + integration tests for every `Conflict` variant)
- Journal events (`PrimaryTunnelChanged`, `ConnectAttemptBlockedByConflict`) fire on correct transitions
- Auto-promote banner FSM logic (event-level, not visual)
- Failure modes that don't need network simulation (bad configs, missing files, file mode 0600 on auth/temp files)
- `ps aux` credential-leak check (spawn an OVPN process, assert no password in cmdline)

**Netns-real subset (~25 checks, runs nightly + on-demand):**
- Multi-tunnel happy path (2 WG servers in separate namespaces; client connects both; real `ip route get` validates routing; real `iptables-save` shows the synthesized ruleset)
- Killswitch v2 with N≥2 tunnels (real `iptables-restore` ruleset; real traffic blocking via `ping` from client netns)
- Killswitch atomicity (continuous-curl probe during external tunnel-down; no leak window)
- DNS scoping (WG primary with DNS; secondary's `DNS = ...` stripped from temp config; `/etc/resolv.conf` state asserted)
- OVPN secondary `--pull-filter` (real OVPN process; cmdline inspection)
- Daemon UID gate adversarial (two users on the runner; user B attempts to connect to user A's socket; SO_PEERCRED refusal observed)
- Symlink attack on auth file (replace `~/.config/vortix/foo.auth` with symlink to a sensitive path between vortix calls; `O_NOFOLLOW` refusal asserted)
- Temp-config orphan sweep (kill vortix mid-connect; restart; sweep removes orphan)

**Coverage table.** A generated `docs/manual-testing/coverage.md` (or sidecar metadata in `multi-connection.md` itself) lists each of the 114 checks with one of: `automated: <test-file-path>`, `manual: <reason>`, or `deferred: <phase>`.

### Phase 2: extension after Phase 1 proves itself

These items are real value but should wait until Phase 1's harness is stable and the regression-catch frequency proves the investment level.

- **TUI snapshot harness via `insta-cmd` or similar.** Catches rendering regressions across terminal widths. Substantial new tooling. Best ROI once Phase 1 is shipping.
- **fwmark warning rendering** (subset of TUI snapshot — defer until that harness exists).
- **OVPN 2.3.x rejection path** (DO container with explicitly-old OVPN binary; verify rejection fires before any tunnel work starts).
- **Failure mode injection layer** (network drops mid-handshake, disk full, OOM). Each requires a different fault-injection mechanism. Real value at scale; defer until Phase 1 covers the baseline.
- **Performance regression detection** (latency under load, killswitch refresh under N=10 concurrent transitions). Separate workflow, separate cadence (pre-release, not per-PR).

### Phase 3: scale-up QA practices

Triggered when user adoption signals make the additional investment worthwhile (e.g., first 1000 users, first 10 unique VPN provider configurations reported).

- **Multi-version upgrade testing** — automated ladder (v0.3.0 → v0.3.1 → v0.4.0 → v0.5.x), each step asserts state migrates cleanly. Catches the V1→V2 PersistedState issue + future schema bumps.
- **Real VPN provider compatibility matrix** — Mullvad + ProtonVPN + IVPN + Surfshark, each running per-release. Record each provider's exported config, replay in netns against a synthetic peer that emulates the provider's WG/OVPN-side behavior. Catches provider-specific config-syntax bugs.
- **Beta release channel.** Tag v0.x.y-beta releases via release-plz; users self-select. Surfaces real-world bugs before stable.
- **Crash reporting telemetry** (opt-in). Aggregate crash signatures. Convert each new crash signature into a regression test.

### Cross-cutting practices (apply at every phase)

- **Bug-to-test policy.** Every user-reported bug must add a regression test before the fix lands. PR template gains a checkbox: "If fixing a bug, what test is being added to catch it next time?"
- **Coverage trend tracking** — `cargo tarpaulin` or `cargo llvm-cov` line/branch coverage trend visible in PR comments. Trend, not absolute number; absolute coverage targets are anti-patterns for this kind of code.
- **Flake registry.** Every test flake gets logged with timestamp + commit. After N occurrences (e.g., 3 flakes in 7 days), the test is auto-quarantined and an issue is opened.

## Success criteria

1. **Phase 1 lands within 4-6 weeks of plan approval.** Single PR or small sequence of PRs against `main`, extending `tests/integration/` and adding new `crates/vortix/tests/*.rs` files. No paid infrastructure required.
2. **Phase 1 reduces release-time manual smoke from 1-3 hours to 15-30 minutes.** Verified by timing a release after Phase 1 lands. The manual residual covers only what genuinely can't be automated.
3. **At least one regression caught by Phase 1 within the first month.** Concrete proof the harness is doing its job. If month-1 catches zero regressions, the suite is over-fitted to known-good code paths and needs adversarial scenario expansion.
4. **`docs/manual-testing/coverage.md` is current and accurate.** Every entry in the manual plan maps to either an automated test file (with file path) or a documented reason for staying manual. No "TBD" entries.
5. **Per-PR feedback under 5 minutes** for the fast subset. Heavy subset (~25 netns-real tests) runs nightly + on `release` tag + on `workflow_dispatch`.
6. **CI cost remains $0** for Phase 1. No paid infra dependencies introduced.

## Dependencies / Assumptions

- **GitHub Actions privileged Docker containers** continue to support `ip netns` operations. Tested today via `tests/integration/setup-netns.sh`; assumed to remain available.
- **`wireguard-tools` and `openvpn` packages** remain installable in the Ubuntu 22.04 base image. Both are in `apt` mainline; safe assumption.
- **Existing integration harness pattern is the right foundation.** The U9 iptables-nft fix demonstrated this pattern catches real regressions. Phase 1 extends it; doesn't rewrite it.
- **Real third-party VPN provider testing** stays in a separate manual layer until Phase 3 scale signals justify automation. Mullvad / ProtonVPN config-replay is feasible but the engineering cost only pays back at scale.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Netns harness regressions are hard to debug (privileged container + netns + multiple subprocesses) | Med | Med | Each test logs `ip route show`, `iptables-save`, `ps aux`, `/etc/resolv.conf` on failure. Make state observability the first-class debugging surface. |
| Some "highly automatable" checks turn out to need real public IPs after implementation starts | Low | Low | Phase 1 is sized at ~55 checks; if 5-10 prove unautomatable, we land 45-50 instead and move them to Phase 2 / manual. No commitment to landing all 55. |
| Test flake rate compounds with test count (114 tests × 0.5% flake rate = 1 flake every 2 runs) | Med | Med | Flake registry from cross-cutting practices catches this. Quarantine flakes aggressively; don't accept "known flake" as a permanent state. |
| Maintenance burden of the harness exceeds value (more time fixing tests than they catch regressions) | Low | Med | Track test value: every regression caught = +1 in the test's "caught" counter. Tests that never catch anything in 6 months are candidates for deletion or rewrite. |
| Phase 1 catches zero regressions in month 1 — proves the test suite is over-fitted to known-good behavior | Low | Low | Section 3.3 of success criteria. If true, expand adversarial scenarios (unusual configs, race conditions, partial states) and treat as a learning signal. |
| Real third-party VPN provider regressions ship to users between releases | Med | High | Pre-release manual smoke against Mullvad + ProtonVPN configs (1 hour per release) covers this. Move to Phase 3 automation when adoption justifies. |

## Outstanding questions

Resolvable at plan time, not blocking the brainstorm.

1. **Coverage table location and shape.** A new file `docs/manual-testing/coverage.md` vs annotating each line in `multi-connection.md`. Annotation gives one-source-of-truth at a readability cost; separate file gives clean separation at a sync cost. Plan-time decision.
2. **Manual-residual file location.** A new `docs/manual-testing/real-vpn-providers.md` for the pre-release provider smoke, or fold into `multi-connection.md` under a "Manual residual" section? Plan-time decision.
3. **Bug-to-test PR template enforcement.** Soft (checklist with no enforcement) or hard (CI checks that a test was added when a `bug` label is on the PR)? Soft is easier; hard catches more. Plan-time decision based on workflow tolerance.
4. **Trend tracking tool.** `cargo tarpaulin` (more mature, Linux-only) vs `cargo llvm-cov` (newer, cross-platform). Codecov / Coveralls integration vs in-repo report. Plan-time decision.

## References

- Source manual checks: [`docs/manual-testing/multi-connection.md`](../manual-testing/multi-connection.md) — 114 checks across 21 categories.
- Existing integration pattern: [`tests/integration/`](../../tests/integration/) — Dockerfile, setup-netns, killswitch.sh, wg_happy_path.sh.
- Recent real regression caught by the existing pattern: [PR #1 commit `b5dbfc6`](https://github.com/harshit-chaudhary07/vortix/pull/1/commits/b5dbfc6) — U9 iptables-nft incompatibility surfaced because the integration test was hard-gated. Direct evidence Phase 1 has real value.
