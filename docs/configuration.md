# Configuring Vortix

Vortix needs no configuration file; add only what you want to change. `vortix info` prints the
directory and files in use.

## Config directory

The first that applies:

1. `--config-dir <DIR>` / `-C <DIR>`
2. `VORTIX_CONFIG_DIR`
3. On Linux, `$XDG_CONFIG_HOME/vortix` when `XDG_CONFIG_HOME` is an absolute path
4. `~/.config/vortix`, where `~` is the invoking user's home even under `sudo`

Every file Vortix writes there is owned by you and private, including under `sudo`.

```text
~/.config/vortix/
├── profiles/          imported profiles; manage with import, rename and delete, not by hand
├── auth/              saved OpenVPN credentials
├── run/               OpenVPN runtime files and each profile's daemon log (<profile-id>.log)
├── tmp/               WireGuard configs staged for wg-quick, removed on disconnect
├── downloads/         URL imports while they are being imported
├── sessions/          session event journals (JSONL)
├── logs/              application logs
├── config.toml        optional: appearance, timing, retries, logs, probes
├── settings.toml      optional: engine settings, journal, hooks
├── state-version      the Vortix version that last ran here (for the upgrade notes)
├── killswitch.state   the saved kill-switch mode
├── real-ip.cache      last seen address without a VPN
└── real-ipv6.cache
```

## `config.toml`

Any subset of these keys; the values shown are the defaults. Unknown keys are rejected, so a
typo cannot silently change behaviour.

```toml
theme = "synthwave"       # synthwave, terminal, catppuccin-mocha, dracula, nord, gruvbox-dark, tokyo-night

# Timing (milliseconds for tick_rate, seconds otherwise)
tick_rate = 1000
telemetry_poll_rate = 30
api_timeout = 5
ping_timeout = 2

# Connecting and reconnecting (seconds)
connect_timeout = 35                     # OpenVPN
wireguard_handshake_timeout_secs = 20
wireguard_handshake_stale_secs = 180
disconnect_timeout = 30
connect_max_retries = 3
connect_retry_base_delay_secs = 2
connect_retry_max_delay_secs = 300
auto_reconnect = true
auto_reconnect_delay_secs = 3

# Event log
log_level = "info"
max_log_entries = 1000
log_rotation_size = 5242880
log_retention_days = 7

openvpn_verbosity = "3"

# Probes: latency targets (also the WireGuard health targets), and the public IP services
ping_targets = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]
ipv6_check_apis = ["https://ipv6.icanhazip.com", "https://v6.ident.me", "https://api6.ipify.org"]
ip_api_primary = "https://ipinfo.io/json"
ip_api_fallbacks = ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]
geolocation_api_fallback = "https://ipwho.is"
```

`p` in the dashboard cycles `theme` and rewrites only that key, keeping the rest of the file and
its comments. `terminal` follows your terminal's own colours, light or dark; the others are
designed for dark backgrounds.

## `settings.toml`

```toml
[engine]
openvpn_verbosity = "3"
connect_timeout_secs = 35                # OpenVPN
wireguard_handshake_timeout_secs = 20    # 1–300
wireguard_handshake_stale_secs = 180     # 1–86400
wireguard_health_targets = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]   # up to 64 addresses

[journal]
disk = true              # false: keep no session journals on disk
retention_days = 30
retention_count = 30
```

The five `[engine]` keys also exist in `config.toml` (under slightly different names for
`connect_timeout` and `ping_targets`). Each value comes from, highest first: an environment
variable, `settings.toml`, `config.toml`, the built-in default. Environment variables use `__`
between section and key, for example `VORTIX_ENGINE__CONNECT_TIMEOUT_SECS=60`. Unlike
`config.toml`, unknown keys here are ignored, so check spelling. A file with a newer
`schema_version` than this build understands is refused.

### Hooks

Run your own program when a tunnel changes state. This replaces the `PreUp`/`PostUp`-style
commands Vortix refuses in profiles.

```toml
[[hooks]]
event = "connected"       # connect_started, connected, disconnect_started, disconnected,
                          # connect_failed, reconnecting
executable = "/usr/local/bin/vpn-notify"   # absolute path; never run through a shell
args = ["connected"]
timeout_secs = 5          # default 5, at most 60
```

Hooks run as you, not root, after the change has happened, with a clean environment plus
`VORTIX_EVENT`, `VORTIX_EVENT_ID`, `VORTIX_PROFILE_ID`, `VORTIX_PROFILE_NAME` and
`VORTIX_PROTOCOL`. They cannot block or delay a connect, run at most once per event, and can be
lost if Vortix crashes. Up to 64 hooks.

## DNS

When a tunnel carries DNS (WireGuard `DNS =`, or DNS an OpenVPN server pushes), Vortix applies
it and restores the previous resolvers on disconnect:

- The tunnel that owns the default route answers every query.
- A split tunnel's resolvers answer only its search domains (a WireGuard `DNS =` entry that is
  not an IP address, or an OpenVPN `DOMAIN`), on macOS and with systemd-resolved; otherwise
  they are not used.

- **macOS:** System Configuration.
- **Linux:** systemd-resolved (per-link, through `resolvectl`), else `resolvconf`. With
  neither, a profile that carries DNS is refused as a missing dependency. NetworkManager and
  `/etc/resolv.conf` are only read, to show the current resolver.

If the resolvers cannot be applied, the tunnel stays up, Security Guard shows DNS `Unverified`
and the kill switch `Degraded`, and Vortix keeps retrying.
