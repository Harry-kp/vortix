# vortix integration test harness (plan 015 phase B / plan 012)

This directory carries the **network-namespace-based integration test
harness** that drives the v0.3.0 vortix binary against real
`wg-quick` and `openvpn` invocations.

## Why this exists

The 445+ workspace unit tests prove vortix's *logic*. They don't prove
that the engine cooperates correctly with the real WireGuard / OpenVPN
binaries on a real Linux kernel. Issue [#162](https://github.com/Harry-kp/vortix/issues/162)
has been open since March asking for exactly that gap to close.

## Architecture

```
┌─ Docker container (ubuntu:22.04, privileged) ────────────┐
│                                                          │
│  ┌─ netns "vortix-test-a" ──┐  ┌─ netns "vortix-test-b" ─┐│
│  │ 10.99.0.1/24 (server)   │──│ 10.99.0.2/24 (client)   ││
│  │ wg-quick up wg0         │  │ vortix-driven vortix up ││
│  │ openvpn --config server │  │                         ││
│  └─────────────────────────┘  └─────────────────────────┘│
│                                                          │
└──────────────────────────────────────────────────────────┘
```

The setup script (`setup-netns.sh`) creates two network namespaces +
a veth pair between them. The teardown is idempotent — rerunning
either script is safe.

## What's wired in CI today

- `wg_happy_path.sh` — WireGuard connect → status → ping → disconnect
- `ovpn_happy_path.sh` — OpenVPN connect → status → ping → disconnect
- `killswitch.sh` — engage iptables-based killswitch, verify blocked
  destinations are unreachable, release, verify restored

## What's not yet wired (scope-honest)

Plan 015 phase B ships the harness + one representative test per
protocol + the killswitch test. Failure-path coverage (auth-failed,
unreachable peer, daemon-died-mid-session) is documented as
follow-up and lives in TODO comments inside each test script.

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
             bash tests/integration/teardown-netns.sh'
```

## CI gate

`.github/workflows/integration-tests.yml` runs the above on every
PR to main + nightly. Failures block merge.

## Notes on macOS

GitHub Actions macOS runners don't support `ip netns` or sandboxed
`wg-quick` easily. macOS integration parity is on the deferred-work
list; phase B is Ubuntu-only.
