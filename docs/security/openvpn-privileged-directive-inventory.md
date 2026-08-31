# OpenVPN privileged directive inventory

This is the default-deny input gate for U11's privileged helper. It is the
complete OpenVPN vocabulary admitted by the U15 canonical plan. The helper
must generate its command line from these typed facts; it must never receive
or reopen the source profile. A directive not listed here is rejected during
unprivileged profile conversion until a later reviewed schema version adds a
bounded typed representation.

## Profile-derived directives

| Profile meaning | Canonical representation | Bound or validation |
|---|---|---|
| `remote host port proto` | ordered `OpenVpnRemote { endpoint, transport }` | 1–16 remotes; strict DNS/IP endpoint, non-zero port; transport is only UDP or TCP |
| `remote-random` | `OpenVpnRemoteSelection::Randomized` | enum; absence is ordered selection |
| `ca` / inline `<ca>` | `OpenVpnCaCertificate` material slot | profile-owned fixed slot, never a source path |
| `cert` plus `key` / inline blocks | client-certificate auth factor plus the certificate and private-key material slots | certificate and key are an inseparable pair; never source paths |
| bare `auth-user-pass` | username/password auth factor | secret arrives only over the memory-only credential channel; a filename argument is rejected |
| `static-challenge` | static challenge factor | allowed only with username/password; prompt/answer are not helper-plan strings |
| server `AUTH_PENDING` / challenge response | remote challenge factor | allowed only with username/password; challenge content stays outside the helper plan |
| `tls-auth` / inline block | `OpenVpnTlsAuthKey` material slot plus optional `OpenVpnKeyDirection` | optional, fixed profile-owned slot; direction is only typed `zero` or `one`; mutually exclusive with `tls-crypt` |
| `tls-crypt` / inline block | `OpenVpnTlsCryptKey` material slot | optional, fixed profile-owned slot; mutually exclusive with `tls-auth` |
| `route network [netmask] [gateway] [metric]` | `OpenVpnRoute` | at most 256; validated CIDR, optional same-family unicast gateway, optional `u32` metric |

Authentication factors compose: a profile may use certificate/key,
username/password, or both. Static and remote challenges refine the
username/password factor rather than replacing certificate authentication.

## Helper-owned fixed directives

The helper may emit only these non-profile-controlled settings: client mode,
TUN mode, foreground/non-daemon execution, `remote-cert-tls server`,
`script-security 0`, `auth-nocache`, coordinator-owned routing through
`route-noexec`, fixed DNS suppression for `dhcp-option DNS`, `DOMAIN`, and
`DOMAIN-SEARCH`, the helper-owned management/credential descriptor,
helper-owned runtime log descriptor, and helper-selected bounded
status/timeout verbosity. Their values are implementation constants or
separately reviewed bounded helper settings, never strings copied from a
profile. The fixed DNS suppression uses helper-generated pull filters; no
profile-controlled pull filter reaches this boundary.

## Rejected vocabulary

Everything else is rejected, including unknown directives and generic option
maps. In particular there is no raw profile, `config`/`include`, arbitrary
file path, executable, command, argv, environment, plugin, script/hook,
management socket path, device name, log path, secret path, or passthrough
option field. Unsupported safe-looking directives such as cipher tuning,
compression, proxies, PKCS#11, external key providers, custom devices,
caller-controlled pull filters, and route/DNS scripts remain rejected until they receive their
own typed bounded schema and security review.

U11 cannot implement or approve a profile-to-helper converter that accepts
more than this inventory. Expanding the inventory requires a schema change,
contract tests for unknown-field rejection and bounds, and threat-model
review; it is never handled by an escape hatch.

## Wire allocation boundary

Every collection in the canonical privileged contract uses a streaming,
allocation-bounded decoder that stops at its schema limit. U11 must also cap
the outer authenticated frame before deserialization; the collection bounds
are defense in depth, not a substitute for that transport-level byte cap.
