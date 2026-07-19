# vortix daemon — deployment examples

**Preferred path: `sudo vortix service install`.** It generates these
artifacts with your binary path, your uid as the daemon's owner, and
your config dir baked in, then starts the service and enables it at
boot. `sudo vortix service uninstall` removes everything it installed.

The files here are *reference copies* of what the installer generates,
with `<PLACEHOLDER>` values, for people who manage units by hand or
need to adapt them (custom unit dirs, NixOS modules, etc.). If you
hand-install one, keep it in sync with the generated shape — the
`--socket /var/run/vortix.sock` argument and the `VORTIX_OWNER_UID` /
`VORTIX_CONFIG_DIR` environment are what let an unprivileged user
drive the root daemon (see SECURITY.md for the auth posture).

- [`systemd/vortix-daemon.service`](systemd/vortix-daemon.service) — Linux
- [`launchd/com.vortix.daemon.plist`](launchd/com.vortix.daemon.plist) — macOS

## Quick local test (no root, no service manager)

```sh
# Build vortix first
cargo build --release -p vortix

# Run the daemon in one terminal (binds your user default socket)
./target/release/vortix daemon

# In another terminal, observe the socket and route through it
ls -la "${XDG_RUNTIME_DIR:-/tmp}/vortix.sock"
vortix status --json
```

A user-owned daemon can serve reads and state, but tunnel bring-up
needs root — install the service (or run `sudo vortix daemon`) for
real connects.
