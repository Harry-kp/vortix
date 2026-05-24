# vortix integration test harness (plan 015 phase B / plan 012).
#
# Privileged Ubuntu container with wireguard-tools + openvpn + iproute2 +
# iptables preinstalled. CI mounts the source tree, builds the binary
# inside, and runs the netns-based test scripts under `tests/integration/`.
#
# Why Ubuntu 22.04: matches the GitHub Actions `ubuntu-latest` runner
# kernel + iproute2 versions; older releases lack the `ip netns` features
# the harness uses.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_TERM_COLOR=always

# Layer 1: runtime + build tooling for vortix + the VPN binaries the
# integration tests drive.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential pkg-config libssl-dev \
        wireguard-tools openvpn iproute2 iptables nftables \
        iputils-ping sudo procps \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: Rust toolchain. Pin matches the workspace MSRV badge.
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.91.0 \
    && /root/.cargo/bin/rustup component add clippy rustfmt
ENV PATH="/root/.cargo/bin:${PATH}"

# Workdir is mounted from the repo at runtime; tests bind-mount the source
# tree into /workspace and run `cargo build` inside.
WORKDIR /workspace

# Default entrypoint is bash so the GH Actions step controls invocation.
CMD ["/bin/bash"]
