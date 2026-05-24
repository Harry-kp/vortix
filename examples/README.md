# vortix daemon — deployment examples (plan 015 phase D / plan 010)

Reference unit files for running `vortix daemon` as a system service.
Use these as starting points; review the `SECURITY.md` notes about
the v0.3.0 phase E auth posture before deploying.

- [`systemd/vortix-daemon.service`](systemd/vortix-daemon.service) — Linux
- [`launchd/com.vortix.daemon.plist`](launchd/com.vortix.daemon.plist) — macOS

## Quick local test

```sh
# Build vortix first
cargo build --release -p vortix

# Run the daemon in one terminal
./target/release/vortix daemon

# In another terminal, observe the socket
ls -la "${XDG_RUNTIME_DIR:-/tmp}/vortix.sock"
```

The frontend (TUI/CLI) checks `VORTIX_DAEMON_SOCKET` env var at
startup and routes through the daemon when set. v0.3.0 ships the
daemon skeleton + IPC contract; full engine routing through the
daemon is post-v0.3 hardening (see plan 015 phase D commit body for
the staged scope).
