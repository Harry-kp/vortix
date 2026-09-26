# Security Policy

## Supported versions

Only the latest release gets security fixes. Upgrade with the channel you installed from.

## Reporting a vulnerability

Do not open a public issue. Report it privately through
[GitHub's vulnerability reporting](https://github.com/Harry-kp/vortix/security/advisories/new),
with what you found, how to reproduce it and its impact.

- Acknowledgment: within 48 hours
- Initial assessment: within 1 week
- Fix: critical 24–72 hours, high 1–2 weeks, medium and low in the next release

Reporters are credited in the release notes unless they prefer not to be.

## What Vortix does with privilege and data

- **Root.** The dashboard and every command that changes tunnels, routes, DNS or the firewall
  run as root, because the operating system requires it. Commands that only read (`list`,
  `show`, `status`, `info`) do not.
- **Nothing runs from a profile.** Script directives (`PreUp`/`PostUp`/`PreDown`/`PostDown`,
  OpenVPN `up`, `down`, plugins and similar) are refused at import. [Hooks](docs/configuration.md#hooks)
  run as the invoking user, never root, from an absolute path without a shell.
- **Your files stay yours.** Everything under `~/.config/vortix` is owned by the invoking user
  and private (`0600` files, `0700` directories), also under `sudo`. Writes are atomic and never
  follow symlinks.
- **Credentials.** Saved OpenVPN credentials live in `~/.config/vortix/auth/`, one owner-only
  file per profile. Keys and passwords are masked in `show`, never passed on a command line, and
  kept out of logs and JSON output.
- **Network calls.** Vortix has no server and sends no analytics. It looks up your public
  address and its location with third-party services (by default ipinfo.io, ipwho.is,
  api.ipify.org, icanhazip.com, ifconfig.me and ident.me; see
  [`config.toml`](docs/configuration.md#configtoml)) and pings the latency targets.

## Trust assumptions

- **`vpn-only` and `block-on-drop` allow the servers of tunnels that are connecting.** While a
  profile connects, every server address it names is reachable, so a profile with many
  attacker-chosen `remote` lines opens traffic to those addresses for that time. Import profiles
  only from providers you trust.
- **A second WireGuard tunnel without `FwMark`** can have its own encrypted traffic to its
  server routed through the primary tunnel, so the primary's operator sees that you connect to
  the second server. Vortix warns about this (see
  [the Role line](docs/usage.md#connection-details-the-role-line)).
- **No outside review.** The kill switch and privilege boundaries have not been audited by a
  third party.
