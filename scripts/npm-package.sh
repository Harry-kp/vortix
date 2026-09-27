#!/usr/bin/env bash
# Build the @harry-kp/vortix npm package for a release: the release's macOS and
# static Linux binaries plus scripts/npm-launcher.js, with no install script.
#   scripts/npm-package.sh <tag> <out-dir>     needs gh, node and npm
set -euo pipefail
cd "$(dirname "$0")/.."

tag=$1
out=$2
pkg=$(mktemp -d)
trap 'rm -rf "$pkg"' EXIT

for target in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    mkdir -p "$pkg/vendor/$target"
    gh release download "$tag" --repo Harry-kp/vortix --pattern "vortix-$target.tar.xz" --output - |
        tar -xJ -C "$pkg/vendor/$target" --strip-components=1 "vortix-$target/vortix"
done
cp scripts/npm-launcher.js "$pkg/vortix.js"
cp README.md LICENSE "$pkg/"
VERSION=${tag#v} node -e '
const fs = require("node:fs");
fs.writeFileSync(process.argv[1], JSON.stringify({
  name: "@harry-kp/vortix",
  version: process.env.VERSION,
  description: "Terminal UI for WireGuard and OpenVPN with multi-tunnel control, real-time telemetry, and leak guarding",
  license: "MIT",
  repository: "https://github.com/Harry-kp/vortix",
  homepage: "https://github.com/Harry-kp/vortix",
  bin: { vortix: "vortix.js" },
  os: ["darwin", "linux"],
  cpu: ["x64", "arm64"],
  engines: { node: ">=14" },
}, null, 2) + "\n");
' "$pkg/package.json"
mkdir -p "$out"
npm pack --silent --pack-destination "$out" "$pkg"
