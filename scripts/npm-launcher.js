#!/usr/bin/env node
// `vortix` for the npm package: runs the binary shipped in this package for this
// OS and CPU. Nothing is downloaded at install or run time, so it works with
// install scripts disabled (npm 12 for global installs, pnpm, Bun, --ignore-scripts)
// and offline.
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const targets = {
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-musl",
  "linux-arm64": "aarch64-unknown-linux-musl",
};
const target = targets[`${process.platform}-${process.arch}`];
if (!target) {
  console.error(`vortix: no build for ${process.platform}-${process.arch}; see https://github.com/Harry-kp/vortix#quick-start`);
  process.exit(1);
}

const result = spawnSync(path.join(__dirname, "vendor", target, "vortix"), process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`vortix: ${result.error.message}`);
  process.exit(1);
}
if (result.signal) process.kill(process.pid, result.signal);
process.exit(result.status ?? 1);
