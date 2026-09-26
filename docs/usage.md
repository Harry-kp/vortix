# Using Vortix

One engine drives the tunnels, routes, DNS and firewall; the dashboard (`sudo vortix`) and the
CLI (`vortix <command>`) are two ways to talk to it.

Every command takes `-j`/`--json` (see [JSON and exit codes](#json-and-exit-codes)),
`-q`/`--quiet` (errors only; the exit code says the rest), `-v`/`--verbose` (debug details) and
`-C`/`--config-dir <DIR>` (see [configuration](configuration.md#config-directory)).

## Root and the one-instance rule

Tunnel, route, DNS and firewall changes need root, so the dashboard and every command that
changes state need `sudo`. `list`, `show`, `status`, `info` and `killswitch` (without a mode)
work unprivileged; `status` without root says the state is unknown when it cannot see
WireGuard, rather than reporting Disconnected.

Only one Vortix process may change state at a time. While the dashboard is open, `up`, `down`,
`reconnect`, `killswitch <mode>`, `release-killswitch`, `import`, `delete` and `rename` exit
with code 4 and "Another Vortix process is managing VPN state". Quit the dashboard (`q`) first.

## Dashboard keys

`?` opens the in-app help, which is always current. The keys:

| Key | Action |
|---|---|
| `1`–`9` | Connect profile N from the list; on a connected profile, disconnect it |
| `c` / `Enter` | Connect or disconnect the focused profile; on a connect in progress, cancel it |
| `d` | Disconnect the focused tunnel, or cancel it if it is still connecting |
| `D` | Sidebar focused: disconnect every tunnel (asks `y`/`n` when two or more are up). Elsewhere: disconnect |
| `r` | Sidebar focused: reconnect the focused profile, or connect it if it is down. Elsewhere: reconnect |
| `y` | Copy the VPN IP through the terminal (works over SSH) |
| `i` | Import a file, directory or URL |
| `K` | Cycle the kill-switch mode |
| `j` `k` / `↓` `↑`, `g` `G`, `PgUp` `PgDn` | Move through the list |
| `Tab` / `Shift-Tab`, `F1`–`F5` | Move between panels (Profiles, Details, Chart, Security, Logs) |
| `z` | Zoom the focused panel |
| `f` | Flip the Chart, Details or Security panel to its other side; in the Logs panel, cycle the source |
| `x` / `b` | Action menu / bulk actions |
| `R` / `v` / `Del` | Rename / view config / delete the focused profile |
| `a` / `A` | Save / clear OpenVPN credentials |
| `s` / `/` / `p` | Sort / search / switch theme |
| `q` | Quit |

## Panels

### Connection Details: the Role line

| Role | Meaning |
|---|---|
| `Primary (0.0.0.0/0)`, `Primary (multi)` | Owns the default route: all traffic without a more specific route goes through it |
| `Split tunnel (10.200.0.0/24)`, `Split tunnel (multi)` | Carries only its own routes; everything else leaves as before |
| `Split tunnel (…, yielded)` | A full tunnel whose default route a newer full tunnel took, seen briefly during a switch |
| `Reconnecting via Primary` / `via Split tunnel` | Dropped unexpectedly; waiting for the next reconnect attempt |

`multi` means more than one route. The newest full tunnel is the primary.

A WireGuard tunnel that is not the primary, while another tunnel is, shows
`⚠ Fwmark hijack risk: add 'FwMark = 51820' to your WG config` until its profile has a `FwMark`
line. Without one, the tunnel's own encrypted traffic to its server can be routed through the
primary tunnel. Vortix only checks that the line exists, and reads the imported copy, so
re-import the profile after editing it.

### Security Guard

Checks whether traffic is actually protected instead of trusting that a tunnel is up. The first
line is the verdict:

| Verdict | Meaning |
|---|---|
| `PROTECTED` | A full tunnel is up, your real address is hidden, DNS goes through the tunnel, the kill switch is on and working, and the cipher is not broken |
| `PARTIAL` | A tunnel is up but one of those checks fails, or only split tunnels are up |
| `⚠ EXPOSED` | No tunnel is up: sites see your real address |

Each row ends in a mark: `✓` fine, `⚠` needs attention, `✗` a problem, `─` not applicable or
not measured yet.

| Row | Shows |
|---|---|
| Real IP / Real IPv4 / IPv6 | Your address without the VPN; `last known` when carried over from an earlier session |
| Exit IP / Exit IPv4 / IPv6 | The address sites see now. `real IPv4 exposed` (or `v6 exposed — matches real IPv6`) when it equals your real one; `split-route — no exit` when only split tunnels are up |
| Location | Where the exit address geolocates |
| DNS | The resolver in use. `Unverified`: the tunnel's resolvers could not be applied. `Not provided`: the profile sets none, so queries use your normal resolver |
| Killswitch | The mode, or `VPN dropped` (blocking after a drop; press `r` to reconnect), `Degraded` (the firewall rules could not be verified) or `off — not protecting` |
| Encryption | The cipher and its grade: `modern AEAD`, `strong`, `deprecated` or `INSECURE` |

The footer gives the age of the readings (`Updated 12s ago`); a reading too old to trust shows
`unavailable`. Addresses come from public IP lookup services (see [SECURITY.md](../SECURITY.md)).

### Logs

`f` cycles the level filter (Live, Err, Warn+, Info+), then the OpenVPN log of each active
OpenVPN tunnel, titled `<profile> · OpenVPN log · LIVE`; with none active, the last session of
the last one, `… · last session, ended HH:MM:SS`. `L` clears the view.

## Profiles

```bash
vortix import ./work.conf          # WireGuard .conf, OpenVPN .ovpn or .conf
vortix import ./profiles/          # every supported file in a directory
vortix import https://example.com/work.ovpn
vortix list                        # --sort, --reverse, --protocol, --names-only
vortix show work                   # parsed, secrets masked; --raw for the file
vortix rename work work-eu
vortix delete work-eu --yes
```

Import copies the profile into the config directory; later edits to the source file do not
apply until you import it again. A WireGuard profile name becomes the interface name, so it must be 1–15 characters of
letters, numbers, `_`, `.` or `-`. Profiles may hold up to 1024 routes. Profiles that run
commands (`PreUp`/`PostUp`/`PreDown`/`PostDown`, OpenVPN `up`/`down` and similar) are refused;
use [hooks](configuration.md#hooks) instead.

## Connecting

```bash
sudo vortix up work                # no profile: the last-used one
sudo vortix up work --timeout 60
sudo vortix down work              # no profile, or --all: every tunnel
sudo vortix reconnect work         # no profile: every tunnel; nothing up: the last-used one
```

`up` waits 22 s for WireGuard and 37 s for OpenVPN. `--timeout <seconds>` sets both the wait
and the time the connect may take. A connect that runs out of time is rolled back: nothing is
left running. `down` on a tunnel Vortix did not start exits 4 and leaves it alone.

OpenVPN profiles that need a username and password connect from the CLI only with saved
credentials: save them once in the dashboard (`a`). A one-time code (static challenge) is
asked for on the terminal.

### Several tunnels at once

- The newest full tunnel owns the default route and DNS; split tunnels carry only their routes.
- Connecting a tunnel that conflicts with a running one (both want all traffic, or both want
  the same networks) asks in the dashboard: `[Y] Switch` stops the old one, `[Esc] Cancel`
  keeps it. The CLI refuses with exit 4; `up --yes` switches.
- A conflict can also appear after connecting, when an OpenVPN server pushes a full route the
  profile did not declare. The dashboard asks then; Cancel disconnects the new tunnel.
- A switch between full tunnels brings the new one up before stopping the old one; tunnels that
  share split routes stop the old one first.
- Disconnecting one tunnel leaves the others alone.

## Status

```bash
vortix status                      # --brief, --watch, --interval <secs> (default 2)
```

## Kill switch

| Mode | Behaviour |
|---|---|
| `off` | No firewall rules |
| `block-on-drop` | Blocks traffic when a tunnel drops unexpectedly, until it reconnects |
| `vpn-only` | Blocks all traffic except through a tunnel, with or without one connected |

```bash
vortix killswitch                  # show the mode
sudo vortix killswitch vpn-only    # or off, block-on-drop
sudo vortix release-killswitch     # emergency: remove Vortix's rules and set the mode to off
```

The mode is saved and re-applied whenever Vortix next runs as root. A reboot clears the rules,
so between boot and that first run nothing is blocked. macOS uses a `pf` anchor of its own,
Linux an `nftables` table.

## Diagnostics

```bash
vortix info                        # config directory, files and counts
vortix report                      # a bug-report block with versions and system details
vortix audit                       # which process sockets use which interface (--pid, --vpn-only)
vortix completions zsh             # bash, zsh, fish, elvish, powershell
vortix update                      # runs `cargo install vortix --force`
```

`update` always uses Cargo. If you installed another way (Homebrew, pacman, npm, Nix), update
that way instead.

## JSON and exit codes

`--json` gives a versioned envelope: `schema_version`, `ok`, `command`, then `data` on success
(plus `next_actions` when there are any) or `error: {code, message, hint}` on failure.
`status --watch --json` prints one object per line. `report` and `completions` always print
plain text.

In `status --json`, `data.connections` lists every tunnel, `data.primary` names the one that owns
the default route (or `null`), and `data.connection` is the focused connected tunnel.

| Exit code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error |
| 2 | Needs root |
| 3 | Profile not found |
| 4 | State conflict (a conflicting tunnel, another Vortix running, a tunnel Vortix did not start) |
| 5 | Missing dependency (WireGuard tools, `openvpn`, or on Linux `resolvconf`/`systemd-resolved`) |
| 6 | Timeout |

See [Configuration](configuration.md) for files and settings, and
[Troubleshooting](troubleshooting.md) when something fails.
