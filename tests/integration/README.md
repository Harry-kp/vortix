# Integration tests

Linux scripts that drive the real `vortix` binary against real `wg-quick` and nftables inside a
privileged container, plus one macOS release check.

| Script | What it proves |
|---|---|
| `wg_happy_path.sh` | WireGuard connect, status, ping and disconnect between two network namespaces |
| `killswitch.sh` | The nftables kill switch blocks traffic, leaves host rules alone and releases cleanly; runs `nft_killswitch.sh` for multi-tunnel dual-stack rules and a failed atomic replace |
| `p0_smoke.sh` | The release smoke scenarios that need neither the internet nor an OpenVPN server, run by `scripts/p0.sh` in the client namespace: S1 startup and privilege, S2 the CLI lifecycle, S3 the TUI and CLI agreeing, S9 the 80×24 layout |
| `release_smoke.sh` | The release build links, runs and holds its CLI contracts and size budget (macOS, no root) |

`setup-netns.sh` makes two namespaces joined by a veth pair (server `10.99.0.1`, client
`10.99.0.2`); `teardown-netns.sh` removes them, and both are safe to rerun. The images are
`Dockerfile` (Ubuntu 22.04), `Dockerfile.fedora` (Fedora 41) and `Dockerfile.arch`.

CI (`integration-tests.yml`) runs the netns scripts on Ubuntu 22.04 and Fedora 41, and
`release_smoke.sh` on `macos-latest`, for every PR that changes code and nightly.

Not covered: OpenVPN, DNS, the exit address and the kill switch smoke scenarios (S4–S8, S10),
which need an OpenVPN server or the internet and run live (see
[P0.md](../../docs/manual-testing/P0.md)), failure paths such as a rejected password or an
unreachable peer, and macOS kernel behaviour (pf, DNS, utun), which needs a real Mac.

## Running locally

Needs Docker on a Linux host; `ip netns` does not work through Docker Desktop on macOS. On an
Ubuntu 24.04 host, the host's AppArmor profile for `wg-quick` also confines the container's
`wg-quick` and refuses the fixtures ("Permission denied"). Unload it for the run with
`sudo apparmor_parser -R /etc/apparmor.d/wg-quick` and load it back after with `-a`.

```sh
docker build -t vortix-integration tests/integration/
docker run --privileged --rm -v "$PWD:/workspace" -w /workspace vortix-integration \
    bash -c 'cargo build --release -p vortix && \
             bash tests/integration/setup-netns.sh && \
             bash tests/integration/wg_happy_path.sh && \
             bash tests/integration/killswitch.sh && \
             bash tests/integration/p0_smoke.sh && \
             bash tests/integration/teardown-netns.sh'
```

A new user's install-to-uninstall journey on real Arch, CachyOS and Fedora machines is
`scripts/p0-vms.sh` (see [P0.md](../../docs/manual-testing/P0.md#distro-vms)).
