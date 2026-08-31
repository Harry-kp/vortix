# Vortix service templates

These files are packaging references for the passive daemon candidate and the
future Background-mode privilege boundary. Packages may stage them, but must
not enable or start them during a normal installation.

Linux/systemd:

- [`systemd/vortix-daemon.service`](systemd/vortix-daemon.service) — optional
  per-user passive candidate.
- [`systemd/vortix-daemon@.service`](systemd/vortix-daemon@.service) — inactive
  enrolled-owner system-service template; U13 creates an instance.
- [`systemd/vortix-helper.service`](systemd/vortix-helper.service) — inactive
  root helper template. The U11 helper rejects `--serve` until U12.

macOS/launchd:

- [`launchd/com.vortix.agent.plist`](launchd/com.vortix.agent.plist) — optional
  per-user passive candidate.
- [`launchd/com.vortix.daemon.plist`](launchd/com.vortix.daemon.plist) —
  disabled enrolled-owner template with a package-time user placeholder.
- [`launchd/com.vortix.helper.plist`](launchd/com.vortix.helper.plist) —
  disabled root-helper template.

The canonical trust model, fixed paths, package-channel classification, and
upgrade/uninstall order live in
[`docs/security/privileged-helper-threat-model.md`](../docs/security/privileged-helper-threat-model.md).

## Passive candidate smoke test

```sh
cargo build --release -p vortix
./target/release/vortix daemon
```

The ready line prints the effective socket. In another terminal, point a
read-only status query at it:

```sh
VORTIX_DAEMON_SOCKET=/path/from/ready/line ./target/release/vortix status
```

The candidate is unprivileged and observational. It does not own tunnels,
desired state, retries, firewall, DNS, or routes.
