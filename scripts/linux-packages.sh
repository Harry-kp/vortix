#!/usr/bin/env bash
# Package a release's static musl binaries as .deb and .rpm (amd64, arm64).
#   scripts/linux-packages.sh <tag> <out-dir>     needs gh and nfpm
set -euo pipefail
cd "$(dirname "$0")/.."

tag=$1
out=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

for pair in x86_64:amd64 aarch64:arm64; do
    triple="${pair%%:*}-unknown-linux-musl"
    gh release download "$tag" --repo Harry-kp/vortix --pattern "vortix-$triple.tar.xz" --dir "$work"
    tar -xJf "$work/vortix-$triple.tar.xz" -C "$work"
    mkdir -p target/linux-package
    cp "$work/vortix-$triple/vortix" target/linux-package/vortix
    for packager in deb rpm; do
        VERSION="${tag#v}" ARCH="${pair##*:}" nfpm package --config scripts/nfpm.yaml --packager "$packager" --target "$out"
    done
done
ls -l "$out"
