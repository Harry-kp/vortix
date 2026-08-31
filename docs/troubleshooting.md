# Troubleshooting Vortix

Start with:

```bash
vortix info
vortix report
```

`vortix report` is the preferred attachment for an issue. Review the generated report before posting if your VPN provider treats endpoint addresses as sensitive.

## Quick diagnosis

| Symptom | Likely cause | First action |
|---|---|---|
| `sudo: vortix: command not found` | `sudo` does not include the install directory in `PATH` | Link the binary into `/usr/local/bin` |
| A second Vortix instance exits | Another process owns the lifecycle lock | Use or close the running instance |
| Profile import rejects a name | Invalid or overlong WireGuard interface name | Rename the source file and import it again |
| Connect stays transitional | The durable operation has not reached a terminal observation | Use `vortix status` and query the reported operation ID |
| Connected split tunnel does not change public IP | The profile does not own the default route | Test a destination included in its declared routes |
| Connected tunnel cannot resolve names | DNS application, read-back, or resolver routing failed | Inspect the DNS section below |
| Kill switch blocks all traffic | `vpn-only` is active without an effective tunnel | Connect a VPN or use `release-kill-switch` in an emergency |
| Full-tunnel WireGuard fails on Linux | Missing kernel networking/firewall capability | Check nftables/iptables and kernel support |

## Installation and privileges

### Cargo install is not visible to `sudo`

Linux commonly omits `~/.cargo/bin` from sudo's secure path:

```bash
sudo ln -s ~/.cargo/bin/vortix /usr/local/bin/vortix
```

Homebrew, pacman, npm global installs, and packaged release binaries normally install into an already-visible path.

### A build directory became root-owned

Build as your user. If an earlier `sudo cargo build` changed ownership:

```bash
sudo chown -R "$(id -un):$(id -gn)" target
cargo build --bin vortix
sudo ./target/debug/vortix
```

### Running without root exits

The interactive dashboard owns tunnel lifecycle and must be started with `sudo vortix`. Read-only CLI commands remain available without root.

## Profiles and upgrades

Vortix validates the managed profile inventory and identity sidecars to avoid adopting the wrong secret file after an interrupted migration or external edit.

- Import from outside `~/.config/vortix/profiles/`.
- Do not place `.vortix-*` runtime files or hand-written sidecars in the managed directory.
- If startup reports an unexplained sidecar or changed inventory, stop and inspect the directory rather than deleting files blindly.
- Follow [Migration](MIGRATION.md) for release-specific recovery steps.

If files were created under the wrong account, restore invoking-user ownership:

```bash
sudo chown -R "$(id -un):$(id -gn)" ~/.config/vortix
```

## Connection state

### A CLI command timed out

A timeout does not erase the operation. Vortix keeps the command in durable history because the OS effect may still be reconciling.

```bash
vortix status
vortix status --operation <OPERATION_ID>
```

Do not repeatedly submit the same connect or disconnect while the earlier operation still owns the profile. If the TUI and CLI appear different, ensure both were built from and are running the same binary and config directory.

### Split-route tunnel shows the normal public IP

This is expected if the profile does not claim `0.0.0.0/0` or `::/0`. Verify a routed destination instead:

```bash
route -n get 10.250.0.1        # macOS example
ip route get 10.250.0.1        # Linux example
ping -c 3 10.250.0.1
```

The Security Guard should describe a split-route tunnel as having no exit rather than treating the unchanged public IP as a leak.

## DNS

Vortix treats DNS as a policy transition, not just a line in a profile. A successful connection requires the intended resolver state to be applied and read back safely; on failure Vortix restores the previous network settings.

### Inspect the active resolver

```bash
# macOS
scutil --dns

# systemd-resolved Linux
resolvectl status

# NetworkManager Linux
nmcli device show | grep -i dns

# Generic fallback
cat /etc/resolv.conf
```

Then test the intended VPN resolver directly:

```bash
dig +time=3 +tries=1 @<VPN_DNS_IP> example.com
```

Direct `dig` success proves the server is reachable; it does not prove the operating system's ordinary resolver selected it. Test both ordinary resolution and fixed-IP HTTPS to separate DNS from data-plane failures:

```bash
curl -4 --max-time 15 https://cloudflare.com/cdn-cgi/trace
curl -4 --max-time 15 \
  --resolve cloudflare.com:443:104.16.132.229 \
  https://cloudflare.com/cdn-cgi/trace
```

### Linux resolver dependencies

- systemd-resolved: Vortix uses per-link DNS; no resolvconf shim should be necessary.
- Hosts without resolved: install `openresolv` or the distribution equivalent if the profile declares `DNS =`.
- Non-systemd systems: confirm the guarded `/etc/resolv.conf` fallback is permitted and that another manager is not immediately replacing it.

If system DNS is externally managed by device policy, another VPN client, or enterprise software, Vortix may be unable to prove safe replacement. This is a host-policy conflict, not an authentication failure.

## WireGuard

### Profile name rejected

WireGuard interface names have platform length and character constraints. Vortix validates them during import and again before connection. Rename the source file to a short identifier such as `work.conf`, then import it again.

### No handshake

Compare Vortix with the system tool using the same profile:

```bash
sudo wg show
```

Check the endpoint, peer public key, local private key, preshared key, and UDP reachability. A configured interface without a recent handshake is not considered connected.

### `AllowedIPs` behavior

`AllowedIPs` controls both peer selection and routing:

```ini
AllowedIPs = 0.0.0.0/0, ::/0       # full tunnel
AllowedIPs = 10.0.0.0/8            # split tunnel
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16
```

Full-tunnel setup may require nftables/iptables support on Linux. Restricted containers or custom kernels may not expose the required capabilities; use a normal host kernel or a split-route profile appropriate to the environment.

## OpenVPN

OpenVPN runtime logs live under `~/.config/vortix/run/` while a session exists. Look for the exact server or management response:

```bash
vortix info
sudo find ~/.config/vortix/run -name '*.log' -maxdepth 1 -print
```

Common distinctions:

- `AUTH_FAILED`: credentials or challenge response were rejected by the server.
- TLS timeout: endpoint reachability, certificates, protocol, or server configuration.
- Initialization succeeds but traffic fails: inspect pushed routes, DNS policy, forwarding, and NAT on the VPN server.
- A management hold that never releases: report it with the runtime log; Vortix should surface a terminal error rather than leave the profile indefinitely connecting.

To isolate orchestration from a provider/server problem, test the same profile with the installed `openvpn` binary. Remove Vortix-specific runtime state from the comparison; do not rewrite the profile semantics just to make the test pass.

## Firewall and kill switch

Vortix uses PF on macOS and nftables or iptables on Linux. If `vpn-only` leaves you without connectivity after a crash:

```bash
sudo vortix release-kill-switch
```

On Linux, verify the chosen backend is present and supported by the running kernel. An error from `iptables-restore` or nft does not imply every cloud VM is unsupported; inspect that host's modules, capabilities, and container restrictions.

Kill-switch rules may be flushed by reboot. Check and re-arm the desired mode after boot.

## Reporting a problem

Include:

```bash
vortix report
vortix --version
uname -a
```

Linux reports should also include `/etc/os-release`, resolver choice, and firewall backend. Describe whether the same profile works with `wg-quick` or `openvpn` directly, and whether it is full-tunnel or split-route.

Open an [issue](https://github.com/Harry-kp/vortix/issues) for reproducible defects or use [Discussions](https://github.com/Harry-kp/vortix/discussions) when you are unsure whether observed behavior is expected.
