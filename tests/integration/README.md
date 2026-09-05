# vortix integration test harness

This directory carries the **network-namespace-based integration test
harness** that drives the vortix binary against real `wg-quick`
invocations on a real Linux kernel.

## Why this exists

The workspace tests prove vortix's *logic*. They don't prove
that the engine cooperates correctly with the real WireGuard / OpenVPN
binaries on a real Linux kernel. Issue [#162](https://github.com/Harry-kp/vortix/issues/162)
has been open since March asking for exactly that gap to close.

## Architecture

```
┌─ Docker container (ubuntu:22.04, privileged) ────────────┐
│                                                          │
│  ┌─ netns "vortix-test-a" ─┐  ┌─ netns "vortix-test-b" ─┐│
│  │ 10.99.0.1/24 (server)   │──│ 10.99.0.2/24 (client)   ││
│  │ wg-quick up wg0         │  │ vortix-driven vortix up ││
│  └─────────────────────────┘  └─────────────────────────┘│
│                                                          │
└──────────────────────────────────────────────────────────┘
```

The setup script (`setup-netns.sh`) creates two network namespaces +
a veth pair between them. The teardown is idempotent — rerunning
either script is safe.

## What's wired in CI today

- `wg_happy_path.sh` — WireGuard connect → status → ping → disconnect
- `killswitch.sh` — verify owned dual-stack iptables chains, host-rule
  preservation, blocked egress, and clean release; it also invokes
  `nft_killswitch.sh` to exercise the native nft backend and failed atomic
  replacement
- `release_smoke.sh` — runs on macOS, off any kernel: proves the shipped
  release profile links and the binaries run, and holds a size budget. It
  needs no netns, no root, and no VPN tooling, so it is the one piece of
  macOS coverage the harness can offer

## What's not yet wired (scope-honest)

**OpenVPN has no automated integration coverage.** The harness images install
`openvpn` and the netns topology would support it, but no script drives it —
every kernel-level OpenVPN result this project has came from
`scripts/vpn-lab.sh` against a real server, recorded by hand in
`docs/manual-testing/backlog.md`. Treat that as the source of truth for
OpenVPN until a script lands here.

Failure-path coverage (auth-failed, unreachable peer, daemon-died-mid-session)
is also absent; the intent lives in TODO comments inside each test script.

## Running locally

Requires Docker + a Linux kernel (the test won't work on Docker
Desktop for macOS because `ip netns` doesn't work cleanly through the
VM boundary).

```sh
docker build -t vortix-integration tests/integration/
docker run --privileged --rm -v "$PWD:/workspace" -w /workspace vortix-integration \
    bash -c 'cargo build --release -p vortix && \
             bash tests/integration/setup-netns.sh && \
             bash tests/integration/wg_happy_path.sh && \
             bash tests/integration/killswitch.sh && \
             bash tests/integration/teardown-netns.sh'
```

## CI gate

`.github/workflows/integration-tests.yml` runs the netns scripts on both
`ubuntu-22.04` (iptables-nft compat) and `fedora-41` (native nft), plus
`release_smoke.sh` on `macos-latest`, for every PR and nightly. Failures
block merge.

## Notes on macOS

GitHub Actions macOS runners don't support `ip netns` or sandboxed
`wg-quick` easily, so kernel-level macOS parity — PF kill-switch,
`scutil` DNS, real utun tunnels — is still deferred and still needs
`docs/manual-testing/backlog.md`.

What is covered there is the profile itself. `release_smoke.sh` runs on
`macos-latest` and is the only job anywhere that executes a macOS release
binary: `cargo test` builds dev, and every netns suite is Linux-only, so a
release profile that miscompiled or failed to link would otherwise have
surfaced first at tag time. Run it locally against any build:

```sh
cargo build --release -p vortix --locked
VORTIX_SIZE_BUDGET_BYTES=7000000 bash tests/integration/release_smoke.sh
```
