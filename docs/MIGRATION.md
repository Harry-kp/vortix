# Upgrading Vortix

Vortix 0.5.0 and later show these steps once, in the dashboard, the first time
you run `sudo vortix` after upgrading. This page is the full version.

## Upgrading from 0.4.3 to 0.5.0

0.5.0 manages tunnels and the kill switch differently from 0.4.3. Anything
0.4.3 left running when you upgraded is invisible to 0.5.0's controls, so let
0.4.3 clean up first. Everything else (profiles, saved OpenVPN passwords, the
kill switch mode, file ownership) moves over by itself.

### Best: before you upgrade, with 0.4.3 still installed

```bash
sudo vortix down                 # disconnect every tunnel
sudo vortix killswitch off       # 0.4.3 removes its own firewall rules
```

Then upgrade, run `sudo vortix`, and set your kill switch mode again if you
want one. Nothing else is needed unless a section below applies to you.

**Why:** 0.5.0 can see a tunnel 0.4.3 started but cannot stop it (`vortix down`
reports it as "not started by Vortix"). On macOS, 0.4.3's kill switch replaced
the Mac's main firewall rules, and 0.5.0 only manages its own section of the
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

0.5.0 dropped the iptables backend, so the kill switch cannot turn on without
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
[hooks](configuration.md#hooks).

### If you set up `vortix daemon` as a service

The command was removed. A service that still runs it fails and restarts every
few seconds.

| System | Remove it |
|---|---|
| Linux (systemd) | `sudo systemctl disable --now vortix-daemon` then `sudo rm /etc/systemd/system/vortix-daemon.service` |
| macOS (launchd) | `sudo launchctl bootout system/com.vortix.daemon` then `sudo rm /Library/LaunchDaemons/com.vortix.daemon.plist` |

### Going back to 0.4.3

0.4.3 cannot read settings that 0.5.0 writes (for example `theme` in
`config.toml`). Remove those lines, or the file, before downgrading.

## Upgrading from 0.3.x or earlier

The first run converts your profiles to the current storage and prints
`Migrated N profile(s) to the new sidecar scheme.`; nothing to do. Then follow
[the 0.4.3 steps](#upgrading-from-043-to-050). Setting `VORTIX_SKIP_MIGRATION=1`
skips the conversion; use it only when asked to while debugging a report.
