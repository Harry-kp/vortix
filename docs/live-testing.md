# Live testing

What a live check needs: the test VPN servers, the Mac's root tmux panes and the Linux lab.
The `fix-bug`, `release-qa` and `autopilot` skills read this before any live step; the hard
rules are in [CLAUDE.md](../CLAUDE.md#live-testing).

## Test VPN servers

Every lab profile (`wg07`–`wg15`, `01-`–`06-openvpn-*`) points at one DigitalOcean droplet made by
`scripts/vpn-lab.sh`; it is often destroyed to save cost, and a new one has new addresses and keys.
Before anything connects a real tunnel, on either machine or in the distro VMs, run from the
Mac:

```bash
VPN_LAB_SYNC=harrykp@192.168.1.97 VPN_LAB_SYNC_KEY=~/.ssh/vortix_lab_ed25519 VPN_LAB_SYNC_VORTIX=vortix/target/debug/vortix scripts/vpn-lab.sh ensure
```

It keeps a live droplet or creates one, and replaces the lab profiles here and on the Linux
lab wherever they don't point at it (deleting the old names first); `scripts/p0-vms.sh` then copies them
into the VMs. Quit both dashboards first: an open one holds the lock and the import stops.
`scripts/vpn-lab.sh down --yes` destroys it when testing is done; OpenVPN credentials must be
saved again for each droplet (its `credentials.txt`).

## macOS

Claude never runs `sudo` on the Mac. The user keeps a tmux session `vxrun` with two root
panes: window 0 for the TUI, window 1 for a root shell (both started with
`sudo -s` and `export SUDO_UID=502 SUDO_GID=20 SUDO_USER=harshitchaudhary`).
Drive them with `tmux send-keys -t vxrun:0 …` and read frames with
`tmux capture-pane -p -t vxrun:0`. If the session is missing, ask the user to
create it. In the TUI: digits quick-connect a profile; with the sidebar
focused, `D` disconnects all (and asks `y`/`n` only when 2+ tunnels are up —
with one tunnel a following `y` copies the IP); `K` cycles the kill switch;
`q` quits. Window 1 is a root shell and `tmux send-keys` into it is allowed
without a prompt: treat it as root access. Verify host state from
window 1 (`netstat -rn -f inet`, `scutil --dns`, `pfctl -a com.apple/vortix.killswitch -sr`).

## Linux lab

An Ubuntu lab laptop is on the LAN: `ssh -i ~/.ssh/vortix_lab_ed25519
harrykp@192.168.1.97`, checkout at `~/vortix`, profiles already imported. It
has passwordless sudo and the user allows using it **there** (never on the
Mac). Sync with `git fetch origin <branch> && git checkout -B lab FETCH_HEAD`
(or `scp` a changed file), build with `cargo build -p vortix`, test with
`umask 022 && cargo test -p vortix` (the login umask 002 makes the file-safety tests refuse
their temp dirs), and run as
`sudo -n env SUDO_UID=1000 SUDO_GID=1000 SUDO_USER=harrykp ./target/debug/vortix …`.
tmux session `vxlinux` has root windows 1 and 2 for the TUI. The lab also hosts
`arch`, `cachyos` and `fedora44` VMs; `scripts/p0-vms.sh` runs the smoke set and a new
user's journey in them (P0.md "Distro VMs"). Check host state
with `ip -4 route`, `resolvectl dns`, `nft list table inet vortix_killswitch`.
Anything verified live on macOS should be verified here too.
