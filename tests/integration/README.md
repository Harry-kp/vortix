# Integration tests

Linux scripts that drive the real `vortix` binary against real `wg-quick` and nftables inside a
privileged container, plus one macOS release check.

| Script | What it proves |
|---|---|
| `wg_happy_path.sh` | WireGuard connect, status, ping and disconnect between two network namespaces |
| `killswitch.sh` | The nftables kill switch blocks traffic, leaves host rules alone and releases cleanly; runs `nft_killswitch.sh` for multi-tunnel dual-stack rules and a failed atomic replace |
| `release_smoke.sh` | The release build links, runs and holds its CLI contracts and size budget (macOS, no root) |
| `distro_ux_audit.sh <label> <binary>` | Manual: a fresh install as an ordinary user (umask, file ownership after sudo, missing tools, error wording), across distro images |

`setup-netns.sh` makes two namespaces joined by a veth pair (server `10.99.0.1`, client
`10.99.0.2`); `teardown-netns.sh` removes them, and both are safe to rerun. The images are
`Dockerfile` (Ubuntu 22.04), `Dockerfile.fedora` (Fedora 41) and `Dockerfile.arch`.

CI (`integration-tests.yml`) runs the netns scripts on Ubuntu 22.04 and Fedora 41, and
`release_smoke.sh` on `macos-latest`, for every PR that changes code and nightly.

Not covered: OpenVPN (no script drives it yet; it is tested live, see
[P0.md](../../docs/manual-testing/P0.md)), failure paths such as a rejected password or an
unreachable peer, and macOS kernel behaviour (pf, DNS, utun), which needs a real Mac.

## Running locally

Needs Docker on a Linux host; `ip netns` does not work through Docker Desktop on macOS.

```sh
docker build -t vortix-integration tests/integration/
docker run --privileged --rm -v "$PWD:/workspace" -w /workspace vortix-integration \
    bash -c 'cargo build --release -p vortix && \
             bash tests/integration/setup-netns.sh && \
             bash tests/integration/wg_happy_path.sh && \
             bash tests/integration/killswitch.sh && \
             bash tests/integration/teardown-netns.sh'
```
