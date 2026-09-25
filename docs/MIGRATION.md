# Upgrading Vortix

Vortix 0.4.4 and later show these steps once, in the dashboard, the first time
you run `sudo vortix` after upgrading. This page is the full version.

## Upgrading from 0.4.3 to 0.4.4

0.4.4 manages tunnels and the kill switch differently from 0.4.3. Anything
0.4.3 left running when you upgraded is invisible to 0.4.4's controls, so let
0.4.3 clean up first. Everything else (profiles, saved OpenVPN passwords, the
kill switch mode, file ownership) moves over by itself.

### Best: before you upgrade, with 0.4.3 still installed

```bash
sudo vortix down                 # disconnect every tunnel
sudo vortix killswitch off       # 0.4.3 removes its own firewall rules
```

Then upgrade, run `sudo vortix`, and set your kill switch mode again if you
want one. Nothing else is needed unless a section below applies to you.

**Why:** 0.4.4 can see a tunnel 0.4.3 started but cannot stop it (`vortix down`
reports it as "not started by Vortix"). On macOS, 0.4.3's kill switch replaced
the Mac's main firewall rules, and 0.4.4 only manages its own section of the
firewall, so after upgrading `vortix killswitch off` cannot lift 0.4.3's
block and the Mac stays offline.

### Already upgraded while a VPN or the kill switch was on

**Restart your computer once.** That ends any tunnel 0.4.3 left running, and
macOS reloads its stock firewall rules at boot. Skip this if nothing was on.

Cannot restart right now? Run these instead. Each is safe when there is
nothing to clear; replace `NAME` with the profile name `sudo vortix status`
shows as connected.

macOS:

```bash
sudo pfctl -f /etc/pf.conf            # restore the Mac's stock firewall rules
sudo pkill -f 'daemon vortix-'        # stop an OpenVPN tunnel 0.4.3 left running
sudo kill $(sudo lsof -t /var/run/wireguard/$(cat /var/run/wireguard/NAME.name).sock)   # WireGuard
```

Linux:

```bash
sudo vortix killswitch off            # remove 0.4.3's firewall rules
sudo pkill -f 'daemon vortix-'        # stop an OpenVPN tunnel 0.4.3 left running
sudo ip link del NAME                 # WireGuard
```

Then set your kill switch mode again if you use one.

### Linux: the kill switch needs nftables

0.4.4 dropped the iptables backend, so the kill switch cannot turn on without
`nft`. Check with `nft --version`; if it is missing:

| Distribution | Install |
|---|---|
| Ubuntu, Debian, Mint | `sudo apt install nftables` |
| Fedora, RHEL, Nobara | `sudo dnf install nftables` |
| Arch, CachyOS, EndeavourOS, Manjaro | `sudo pacman -S nftables` |

### Profiles that run scripts

WireGuard `PreUp`, `PostUp`, `PreDown`, `PostDown` and OpenVPN `up`, `down`,
`route-up` (and other script or plugin directives) are now refused, because
Vortix ran them as root. A profile with one of them will not connect until you
move the command into a hook; see
[Migrate profile scripts to lifecycle hooks](#migrate-profile-scripts-to-lifecycle-hooks).

### If you set up `vortix daemon` as a service

The command was removed. A service that still runs it fails and restarts every
few seconds.

| System | Remove it |
|---|---|
| Linux (systemd) | `sudo systemctl disable --now vortix-daemon` then `sudo rm /etc/systemd/system/vortix-daemon.service` |
| macOS (launchd) | `sudo launchctl bootout system/com.vortix.daemon` then `sudo rm /Library/LaunchDaemons/com.vortix.daemon.plist` |

### Going back to 0.4.3

0.4.3 cannot read settings that 0.4.4 writes (for example `theme` in
`config.toml`). Remove those lines, or the file, before downgrading.

---

# Migrating to Vortix v0.3.0

This release lands a large architectural refactor (28
commits). For users, the day-to-day surface barely changes. This document
covers what's automatic, what's optional, and how to roll back if you need
to.

## TL;DR

- **Upgrade is automatic.** Existing `.conf` and `.ovpn` profiles keep
  working. No flags to change. `vortix up <profile>`, `down`, `status`,
  `list`, `import`, `show` all behave exactly as before.
- **One new optional feature:** a JSON event journal, on by default.
- v0.3.0 also shipped a `vortix secrets` store and a `show --inline-secrets`
  flag; both were retired in v0.3.1. Auth credentials live in
  `auth/<profile>.auth` files or the TUI prompt.
- **One-line rollback** if you hit trouble: `cargo install vortix
  --version 0.2.2 --force`.

---

## What auto-migrates

The first time v0.3.0 runs, it walks `${XDG_CONFIG_HOME}/vortix/profiles/`
and creates a sibling `.meta.toml` next to each existing `.conf` /
`.ovpn`:

```
~/.config/vortix/profiles/
├── corp.conf
├── corp.meta.toml            ← new sidecar, generated automatically
├── home.ovpn
└── home.meta.toml            ← new sidecar
```

Each sidecar carries a stable `profile_id` assigned once during import or
migration, the original `display_name`, and the protocol.
v0.2.x ignores `.meta.toml` files entirely, so rollback is safe.

The migration is **idempotent** — it re-runs at every startup and creates
sidecars only for profiles that lack one. There is no explicit `vortix migrate`
command; if you need to re-trigger after fixing something (e.g., a permissions
issue), just restart vortix.

Older Vortix releases could leave a `.meta.toml` behind after deleting its
profile config. During the one-time archive phase, Vortix first saves the
active profile IDs plus a size and SHA-256 record for each config-less legacy
sidecar. It then moves those exact files into
`profiles/.vortix-legacy-sidecars-v1/` and atomically marks the phase complete.
If startup is interrupted, the next run revalidates the active catalog and
resumes from the durable record before moving anything else. The archived files
remain available to the invoking user for rollback and inspection, but no
longer participate in the active profile catalog. Active configs and their
matching sidecars are unchanged.

To restore an archived identity, stop Vortix, restore the matching `.conf` or
`.ovpn`, move its `.meta.toml` from `.vortix-legacy-sidecars-v1/` back beside
the config, back up and remove `.vortix-profile-inventory-v1.toml`, then restart
Vortix. The rebuilt inventory reads the restored sidecar and keeps its existing
profile ID. Do this only while Vortix is stopped; a config-set change against a
saved inventory intentionally fails closed.

If migration ever fails (read-only profile dir, unusual perms, etc.),
startup fails before any tunnel lifecycle mutation. No profile is silently
adopted or assigned a replacement identity. If the managed profile inventory
changed unexpectedly, restore that directory to its saved inventory first;
then add new profiles from outside it with `vortix import <path>`.

### Override

If you need to skip the startup backfill — typically while debugging a
filesystem permission issue — set `VORTIX_SKIP_MIGRATION` in your
environment:

```sh
export VORTIX_SKIP_MIGRATION=1
vortix up corp
```

Unset it to restore the implicit migration.

---

## What needs manual opt-in

### Session event journal (default on, opt-out)

v0.3.0 writes a JSON-lines event journal at
`~/.config/vortix/sessions/<ISO>-<pid>.jsonl` (the config dir's `sessions/`) for every run.
Retention is 30 days / 30 files (whichever cap hits first). Each line
is an `EngineEvent` record: connection state transitions, tunnel
up/down, IP changes, telemetry samples, and so on.

Find the current session's path via `vortix info`:

```
  Session journal: /Users/you/.config/vortix/sessions/2026-...-66210.jsonl
```

Tail it with standard shell tools:

```sh
tail -f "$(vortix info --json | jq -r '.data.journal_session')" | jq '.event'
```

If you don't want disk persistence, set in
`~/.config/vortix/settings.toml`:

```toml
[journal]
disk = false
```

The broadcast bus still works (so the TUI's live event stream is
unaffected); only the on-disk JSONL file is suppressed.

### Layered settings (opt-in if you want overrides)

A new `settings.toml` is read with figment-style layering: built-in
defaults → `<config_dir>/settings.toml` → `VORTIX_*` env vars
(highest precedence). You don't need to create the file; the
out-of-the-box defaults match v0.2.x behavior. To see what you've
configured, read your own `settings.toml`.

---

## OpenVPN remembered credentials and sudo upgrades

Existing owner-written `${XDG_CONFIG_HOME}/vortix/auth/<profile>.auth`
records remain compatible. Vortix can resolve an unambiguous legacy name, while
all new writes use the profile's stable ID. Profile rename therefore no
longer changes which remembered username/password belongs to the profile.

One credential store owns remembered credentials; the TUI, CLI, and OpenVPN
code do not independently read or write credential paths. Only the reusable username/password pair may be remembered;
OTP and static- or remote-challenge answers remain memory-only.

Older builds run through `sudo` could create the stable-ID `.auth` file as
root even though the Vortix configuration belongs to the invoking user. Running as
root, Vortix automatically transfers only that exact record
after proving it is a regular, single-link, mode-0600 file in the authenticated
owner's directory. Symlinks, loose permissions, unexpected owners, ambiguous
legacy names, malformed contents, and changed entries are left untouched and
Vortix asks for credentials again instead of guessing.

Choosing **Remember** is independent of the current connection attempt.
Vortix submits the in-memory answer first. If the owner-safe atomic save then
fails before publication, the connection may continue and the TUI reports that
credentials were not saved; the next connection will ask again. If publication
succeeds but directory durability cannot be confirmed, the TUI says the change
is visible but may need verification after restart. Auth Manager uses the same
truthful distinction for edit and clear operations.

Build without `sudo` and run the binary as root (`cargo build -p vortix &&
sudo ./target/debug/vortix`); `sudo cargo` makes the Cargo target directory
root-owned.

---

## New CLI surface at a glance

Everything here is additive. Pre-v0.3.0 commands are unchanged.

| Command | What it does |
|---|---|
| `vortix info` | Output now includes a `Session journal:` line pointing at the current session's JSONL file |

`vortix --json` envelopes now carry a top-level `schema_version`
field (1 in v0.3.0, 2 since v0.4.0) for forward-compatibility detection. Everything else is
internal architecture — engine FSM, layered settings, sidecar
migration logic — none of which you interact with through new CLI
verbs.

---

## Rollback

If anything breaks, downgrade to v0.2.2:

```sh
# crates.io
cargo install vortix --version 0.2.2 --force

# Homebrew
brew uninstall vortix && brew install vortix@0.2.2  # if pinned tap exists
# (otherwise: brew install with explicit version via tap revision)

# npm
npm install -g @harry-kp/vortix@0.2.2
```

What rollback does to your data:

- `.meta.toml` sidecars left behind are inert to v0.2.x — they're
  ignored, not parsed. Leave them in place or delete them; either
  works.
- `sessions/*.jsonl` under `~/.config/vortix/` are pure
  observability data; delete the directory if you want.
- `settings.toml` is ignored by v0.2.x. Your old `config.toml` (if any)
  is untouched.

There's no data destructively rewritten by v0.3.0 — every change is
read-then-write-new-file.

---

## V2 → V1 Downgrade (v0.4.x → v0.3.x)

The multi-connection release ("V2", v0.4.0+) introduces a richer
killswitch persisted-state shape, additional journal event variants,
and a multi-tunnel engine. If you need to roll back to
v0.3.x ("V1"), follow this procedure.

1. **Revert the binary to v0.3.x.**

   ```sh
   # crates.io
   cargo install vortix --version 0.3.1 --force

   # Homebrew
   brew uninstall vortix && brew install vortix@0.3.1

   # npm
   npm install -g @harry-kp/vortix@0.3.1
   ```

2. **Remove the V2 killswitch state file.** V2 persists killswitch
   state as JSON with `schema_version: 2`, which V1 cannot parse:

   ```sh
   rm ~/.config/vortix/killswitch.state
   ```

   Re-arm the killswitch on first run after downgrade:

   ```sh
   sudo vortix killswitch block-on-drop   # or "vpn-only", to taste
   ```

3. **Profile configs are unchanged.** No migration is needed for your
   `.conf` or `.ovpn` files. The `.meta.toml` sidecars introduced in
   v0.3.0 are V1-compatible and remain in place.

4. **Journal JSONL is compatible.** V2 introduces new `EngineEvent`
   variants (multi-tunnel state transitions), but
   the enum is `#[non_exhaustive]`-additive on the wire — V1 readers
   skip unknown variants rather than erroring. You can keep your
   `~/.config/vortix/sessions/*.jsonl` files in place; they
   stay readable by both V1 and V2 tooling.

No data destructively rewritten by V2 — every change is
read-then-write-new-file, so the worst-case rollback is "delete
`killswitch.state` and re-arm."

---

## Migrate profile scripts to lifecycle hooks

Vortix no longer permits executable directives inside WireGuard or OpenVPN
profiles. In particular, WireGuard `PreUp`, `PostUp`, `PreDown`, and
`PostDown`, and OpenVPN script/plugin directives are rejected before the
profile can reach a privileged protocol process. This closes the historical
path where `sudo vortix` could cause profile text to execute as root.

Move observational automation into `settings.toml` as a global hook:

```toml
[[hooks]]
event = "connected"
executable = "/usr/local/bin/vpn-notify"
args = ["connected"]
timeout_secs = 5
```

Supported events are `connect_started`, `connected`, `disconnect_started`,
`disconnected`, `connect_failed`, and `reconnecting`. The executable must be
an absolute path and arguments must be separate array entries; Vortix never
passes this through a shell. Hooks run asynchronously as the proved non-root
owner with a clean, allowlisted environment. They cannot veto or delay a VPN
transition, are attempted at most once, and may be lost if Vortix crashes.

There is no automatic conversion from a profile command string: shell syntax
cannot be translated safely into an executable/argv boundary. Split the old
command manually and choose the lifecycle fact that matches its observational
purpose. Firewall, route, DNS, and other privileged policy changes should use
Vortix's managed policy instead of a hook.

---

## Got stuck?

Run `vortix report` — it attaches the current session's
journal path and the last 10 event kinds, so the report carries the
state you'd otherwise need to recreate by hand. Paste the output into
a new issue.

Linux-specific issues are tracked in
[discussion #184](https://github.com/Harry-kp/vortix/discussions/184).
If you tested an RC build, drop a note in that thread before opening a
fresh issue — odds are good a fellow tester already saw it.
