# Configuring Vortix

Vortix works without a configuration file. Add only the settings you want to override.

## Config directory

The default user configuration directory is:

- macOS and Linux: `~/.config/vortix`
- XDG override: `${XDG_CONFIG_HOME}/vortix`

Resolution order is:

1. `--config-dir <PATH>`
2. `VORTIX_CONFIG_DIR`
3. the invoking user's home, including when Vortix runs through `sudo`
4. the platform default

Use `vortix info` to see the paths resolved on your machine.

Vortix keeps user files owned by the invoking user even when tunnel operations run as root. Do not run `sudo cargo build`; build as your user and elevate only the Vortix process.

## Managed files

```text
~/.config/vortix/
├── profiles/          imported profiles and identity sidecars
├── auth/              saved OpenVPN credentials
├── run/               transient tunnel runtime files
├── logs/              application logs
├── config.toml        optional UI and legacy runtime settings
├── settings.toml      optional layered engine settings
├── metadata.json      profile metadata such as last-used time
├── killswitch.state   persisted kill-switch preference
└── real-ip.cache      last observed un-tunneled identity
```

Treat `profiles/` as Vortix-managed storage. Import new files from outside it with `vortix import`; do not copy files into the directory while Vortix is running. Identity sidecars and runtime files are internal and may change between releases.

Session journals are observability data, so they use the platform data directory rather than the config directory:

- Linux: `~/.local/share/vortix/sessions/`
- macOS: `~/Library/Application Support/vortix/sessions/`

## `config.toml`

Create `~/.config/vortix/config.toml` with any subset of these fields:

```toml
# Appearance
theme = "synthwave"

# UI and telemetry timing
tick_rate = 1000
telemetry_poll_rate = 30
api_timeout = 5
ping_timeout = 2

# Connection deadlines and retry policy
connect_timeout = 35
wireguard_handshake_timeout_secs = 20
wireguard_handshake_stale_secs = 180
disconnect_timeout = 30
connect_max_retries = 3
connect_retry_base_delay_secs = 2
connect_retry_max_delay_secs = 300
auto_reconnect = true
auto_reconnect_delay_secs = 3

# Event log and files
log_level = "info"
max_log_entries = 1000
log_rotation_size = 5242880
log_retention_days = 7

# OpenVPN
openvpn_verbosity = "3"

# Network probes
ping_targets = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]
ipv6_check_apis = [
  "https://ipv6.icanhazip.com",
  "https://v6.ident.me",
  "https://api6.ipify.org",
]
ip_api_primary = "https://ipinfo.io/json"
ip_api_fallbacks = [
  "https://api.ipify.org",
  "https://icanhazip.com",
  "https://ifconfig.me/ip",
]
geolocation_api_fallback = "https://ipwho.is"
```

Unknown fields are rejected so misspellings do not silently change protection behavior.

### Themes

Available values are:

- `synthwave` (default)
- `terminal` (inherits terminal foreground and background colors)
- `catppuccin-mocha`
- `dracula`
- `nord`
- `gruvbox-dark`
- `tokyo-night`

Press `p` in the TUI to cycle themes. Vortix updates only the top-level `theme` key and preserves the rest of `config.toml`, including comments.

Use `terminal` when you want Vortix to follow a terminal application's light or dark palette. Fixed themes use their own colors and are intended for dark terminal backgrounds.

## Layered engine settings

`settings.toml` is the newer layered configuration surface for engine policy. Its precedence is:

1. built-in defaults
2. system settings
3. user `settings.toml`
4. `VORTIX_*` environment variables

`config.toml` remains supported for compatibility and appearance. Prefer the documented engine settings when a field exists in both places. Run `vortix info` to inspect the active files, and consult command help before automating an engine setting that may evolve.

## DNS integration

Vortix applies and verifies the DNS policy declared by the selected VPN topology:

- macOS uses the System Configuration framework.
- systemd-resolved hosts use per-link DNS registration.
- NetworkManager and resolvconf environments use their native integration.
- Non-systemd systems may use a guarded `/etc/resolv.conf` fallback.

On Linux, a WireGuard profile containing `DNS =` needs a working host resolver integration. systemd-resolved hosts normally need no extra package. A host without resolved may require `openresolv` or the distribution's equivalent.

Vortix distinguishes the DNS server currently projected by the OS from DNS-policy verification. A visible server is not, by itself, proof that every resolver route matches the intended tunnel.

## Profile and credential safety

- WireGuard and inline OpenVPN secrets remain in the imported profile and are masked in normal display output.
- Saved OpenVPN username/password material lives under `auth/` and is owner-restricted.
- OpenVPN external key and PKCS#12 references are validated before activation; unsupported ownership or recovery shapes fail closed.
- Do not publish `show --raw`, runtime logs, or generated reports without reviewing them for provider-specific data.

For upgrade-related storage changes, see [Migration](MIGRATION.md). For common failures, see [Troubleshooting](troubleshooting.md).
