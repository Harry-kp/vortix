# Troubleshooting Vortix

`vortix report` prints a block with versions, your system and Vortix's configuration; attach it
to any issue after removing endpoint addresses you consider private.

## Starting Vortix

**`sudo: vortix: command not found`.** `cargo install` and the shell installer put Vortix in
`~/.cargo/bin`, which `sudo` usually does not search. Link it once:

```bash
sudo ln -s ~/.cargo/bin/vortix /usr/local/bin/vortix
```

**The dashboard exits without root.** It changes routes, DNS and the firewall, so it needs
`sudo vortix`. Read-only commands (`list`, `show`, `status`, `info`) work without it.

**"Another Vortix process is managing VPN state" (exit 4).** Only one Vortix may change state
at a time; the dashboard holds that role while it is open. Quit it (`q`) or wait for the other
command to finish.

**"Vortix found a profile metadata file it has no record of".** Vortix keeps a list of the
profiles it manages and refuses to act while `profiles/` holds a file it did not create. Move
the named file out of `~/.config/vortix/profiles/` and import it with `vortix import`; never
copy files into that directory by hand.

**Files in `~/.config/vortix` owned by root.** Give them back:

```bash
sudo chown -R "$(id -un):$(id -gn)" ~/.config/vortix
```

## Connecting

**`up` times out.** The connect is rolled back and nothing is left running. A slow server or a
large profile may need longer: `sudo vortix up <profile> --timeout 60`.

**"This profile needs saved credentials".** The CLI cannot type an OpenVPN username and
password. Save them once in the dashboard (`a` on the profile).

**"Not started by Vortix, left running".** `down` found a tunnel Vortix did not start: another
VPN tool's, or one an earlier Vortix version left behind. Stop it with the tool that started
it; for a leftover from Vortix 0.4.3, restart the computer once (see
[Upgrading](MIGRATION.md)).

**A split tunnel connects but the public IP does not change.** Expected: it carries only its
own routes. Security Guard shows `split-route — no exit`. Check a routed address instead:

```bash
route -n get 10.250.0.1        # macOS
ip route get 10.250.0.1        # Linux
```

**A profile name is refused.** WireGuard names become interface names: 1–15 characters of
letters, numbers, `_`, `.` or `-`. Rename the file (`work.conf`) and import it again.

**A profile with scripts is refused.** `PreUp`/`PostUp`/`PreDown`/`PostDown` and OpenVPN
`up`/`down`-style directives never run; move the commands to
[hooks](configuration.md#hooks).

## WireGuard

**No handshake.** The server never answered. Check the endpoint address and port, both keys
and any preshared key, and that UDP to the server is not blocked. `sudo wg show` shows what the
kernel sees.

**"Fwmark hijack risk".** See [the Role line](usage.md#connection-details-the-role-line).

**Linux desktop: "Activation of network connection failed".** Harmless. NetworkManager adopts
any interface it did not create and reports its removal as a failed activation; plain
`wg-quick up`/`down` does the same. To stop it, tell NetworkManager to leave WireGuard
interfaces alone (this also covers ones Vortix does not manage):

```ini
# /etc/NetworkManager/conf.d/99-wireguard-unmanaged.conf
[keyfile]
unmanaged-devices=interface-name:wg*
```

```bash
sudo systemctl reload NetworkManager
```

## OpenVPN

Each profile's daemon log is `~/.config/vortix/run/<profile-id>.log`, also shown in the
dashboard's Logs panel (`f` until the title names the profile).

- `AUTH_FAILED`: the server rejected the credentials or the one-time code. A saved password
  that is rejected is removed.
- TLS timeout: the server is unreachable, or the certificates or protocol do not match.
- Connected but no traffic: the server's pushed routes, forwarding or NAT.

## DNS

**Names do not resolve, or DNS shows `Unverified`.** The tunnel's resolvers could not be
applied; the tunnel stays up and Vortix keeps retrying. On Linux, Vortix needs systemd-resolved
or `resolvconf` for a profile that carries DNS (see [DNS](configuration.md#dns)). Inspect the
resolver in use:

```bash
scutil --dns                   # macOS
resolvectl status              # Linux with systemd-resolved
```

To tell a DNS problem from a routing one, query the VPN's resolver directly and fetch a page by
fixed IP:

```bash
dig +time=3 +tries=1 @<VPN_DNS_IP> example.com
curl -4 --max-time 15 --resolve cloudflare.com:443:104.16.132.229 https://cloudflare.com/cdn-cgi/trace
```

Device-management software or another VPN client that owns DNS can stop Vortix from applying
its resolvers.

## Kill switch

**No internet after a crash or with `vpn-only` and no tunnel.** Connect a profile, or remove
Vortix's rules and set the mode to `off`:

```bash
sudo vortix release-killswitch
```

It touches only Vortix's own rules. On Linux it also removes iptables chains left by Vortix
0.4.x. The kill switch needs `nft` on Linux.

## Reporting a problem

[Open an issue](https://github.com/Harry-kp/vortix/issues/new/choose) with the `vortix report`
output; say whether the same profile works with `wg-quick` or `openvpn` directly. Questions go
to [Discussions](https://github.com/Harry-kp/vortix/discussions).
