# Using Vortix

Vortix exposes one VPN control engine through an interactive terminal dashboard, a blocking CLI, and versioned machine-readable output.

## Start the dashboard

```bash
sudo vortix
```

Root is required for tunnel, route, DNS, and firewall changes. Read-only commands such as `vortix list`, `vortix show`, and `vortix status` can run without it.

If another Vortix process already owns the lifecycle lock, use the running instance or close it before starting a second interactive instance.

## TUI keys

Press `?` at any time for the complete in-app reference. The most frequently used keys are:

### Global

| Key | Action |
|---|---|
| `1`–`9` | Quick-connect to profile N |
| `d` | Disconnect, cancel, or force-kill the focused tunnel according to its phase |
| `D` | Disconnect every active tunnel |
| `r` | Reconnect |
| `i` | Import a profile, directory, or URL |
| `K` | Cycle the kill-switch mode |
| `Tab` / `Shift-Tab` | Move between panels |
| `F1`–`F5` | Jump directly to a dashboard panel |
| `z` | Zoom the focused panel |
| `x` | Open the context action menu |
| `b` | Open bulk actions |
| `p` | Switch color theme |
| `/` | Search profiles |
| `?` | Open help |
| `q` | Quit |

### Profiles

| Key | Action |
|---|---|
| `j` / `↓`, `k` / `↑` | Move selection |
| `g` / `Home`, `G` / `End` | First or last profile |
| `c` / `Enter` | Connect or disconnect the selected profile |
| `R` | Rename |
| `v` | View configuration |
| `s` | Change sort order |
| `a` | Manage OpenVPN credentials |
| `A` | Clear saved OpenVPN credentials |
| `Delete` | Delete the selected profile |

The Connection Details panel follows the selected profile. When a tunnel is in flight, `c` cancels the connection attempt. The log panel uses `j` / `k` to scroll, `f` to filter, and `L` to clear the visible log.

## Profiles

Vortix recognizes WireGuard `.conf` and OpenVPN `.ovpn` / `.conf` files. Imports validate and copy the profile into the managed profile directory; keep source files outside that directory.

```bash
vortix import ./work.conf        # one local file
vortix import ./profiles/        # supported files in a directory
vortix import https://example.com/work.ovpn

vortix list
vortix list --sort last-used
vortix list --protocol wireguard
vortix list --names-only

vortix show work                # parsed, secrets masked
vortix show work --raw
vortix rename work work-eu
vortix delete work-eu --yes
```

WireGuard profile names must also be valid platform interface names. If an import reports that the name is too long or invalid, rename the source file and import it again.

## Connections

```bash
sudo vortix up work
sudo vortix up work --timeout 60
sudo vortix down work
sudo vortix down --all
sudo vortix reconnect work
```

Without a profile, `down` disconnects every active tunnel and `reconnect` cycles every connected tunnel. Both are idempotent at their terminal state.

### Multi-tunnel behavior

Multiple tunnels may be connected at once:

- The **primary** tunnel owns the kernel default route.
- A **split-route** tunnel carries only the destinations declared by its WireGuard `AllowedIPs` or OpenVPN route directives.
- Vortix rejects overlapping routes or default-route takeovers before connection unless an interactive user confirms the choice or a script passes `--yes`.
- Disconnecting one profile does not disconnect unrelated active profiles.

Use bypass flags only after reviewing the routes:

```bash
sudo vortix up second-vpn --yes
```

## Status and durable operations

```bash
vortix status
vortix status --brief
vortix status --watch
vortix status --operation op-0000000000000001-0000000000000001
```

If a blocking CLI command times out, its operation remains recorded for reconciliation. Query the operation ID reported by the command rather than immediately assuming the tunnel failed.

## Kill switch

The same three labels are used in CLI input, CLI output, JSON, and the TUI:

| Mode | Behavior |
|---|---|
| `off` | No firewall rules; normal traffic is allowed |
| `block-on-drop` | Blocks egress after an unexpected VPN drop |
| `vpn-only` | Keeps default-deny egress protection active with or without a connected VPN |

```bash
vortix killswitch
sudo vortix killswitch off
sudo vortix killswitch block-on-drop
sudo vortix killswitch vpn-only
sudo vortix release-kill-switch      # emergency firewall release
```

The OS may flush firewall state on reboot. Re-arm `vpn-only` after each boot.

## Diagnostics and system commands

```bash
vortix info
vortix report
vortix audit
vortix audit --pid 12345
vortix audit --vpn-only
vortix completions zsh > ~/.zfunc/_vortix
vortix update
```

`vortix audit` is a point-in-time process socket and route inspection tool. It does not continuously intercept traffic.

## JSON and automation

Every command supports `--json`. Successful and failed one-shot commands use a versioned envelope containing `schema_version`, `ok`, `command`, `data`, and `next_actions`. Watch commands emit one JSON object per line (NDJSON).

```bash
vortix list --json
vortix status --json
vortix status --watch --json
sudo vortix up work --json
```

Current status output is multi-tunnel aware:

- `data.connections` contains active and transitional tunnels.
- `data.primary` names the default-route owner, or is `null`.
- `data.connection` is retained for single-tunnel compatibility and is `null` when that shape would be ambiguous.

Stable exit categories allow scripts to distinguish usage errors, permission failures, state conflicts, missing dependencies, and timeouts. Run `vortix --help` for the current numeric mapping and `vortix <COMMAND> --help` for authoritative flags.

For file locations and settings, see [Configuration](configuration.md). For failure recovery, see [Troubleshooting](troubleshooting.md).
