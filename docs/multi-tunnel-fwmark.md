# Multi-tunnel fwmark warning

If Vortix is showing you a `⚠ fwmark` warning on one of your WireGuard
tunnels, this page explains what that means, why it matters more than
"the tunnel might not connect," and what to add to your config to make
it go away.

## What is fwmark hijack?

When you run two or more WireGuard tunnels on the same machine, the
kernel needs a way to tell each tunnel's encrypted packets apart —
otherwise it will helpfully route one tunnel's handshake *through*
the other tunnel before the packet ever reaches the internet.

WireGuard's `FwMark` directive is how each tunnel tags its own
encrypted outgoing traffic so the kernel's policy routing can keep
the tunnels separated. **When two WireGuard tunnels are active and
neither one (or only one) sets `FwMark`, the kernel can route the
secondary tunnel's encrypted packets through the primary tunnel.**
The secondary's WireGuard handshake — including its identifier
material — is then visible to whoever operates the primary's exit
node.

This is more than a connectivity bug. It is a credential exposure
across two different VPN operators. Concretely: if you run a
commercial VPN (Mullvad, ProtonVPN, etc.) as your primary and a
corporate or self-hosted WireGuard tunnel as a secondary without
`FwMark`, then your commercial provider's exit operator can observe
(and potentially log or intercept) the corporate tunnel's handshake.
That information was never intended to leave your machine in
plaintext.

## When does the warning fire?

Vortix shows the persistent `⚠ fwmark` line on a tunnel's Connection
Details panel when **both** of the following hold:

- Two or more WireGuard tunnels are currently active.
- At least one of those tunnels is missing a `FwMark = <integer>`
  directive in its `[Interface]` section.

The warning is intentionally not a dismissable toast: a single
unread toast on this exact failure mode would result in silent
credential exposure on every reconnect. The warning persists as long
as the conditions hold, and is mirrored as a `●!` annotation on the
affected row in the sidebar so you can spot the at-risk tunnel
without having to focus each row in turn.

The Connection Details panel links to this page via the warning
line (see U17 of the multi-connection plan).

## How to fix it

Add a `FwMark` line to the `[Interface]` section of each affected
WireGuard config. The value is a 32-bit integer; the conventional
choice is `51820` (WireGuard's well-known port), but any unique
integer works:

```ini
[Interface]
PrivateKey = ...
Address = 10.0.0.2/24
DNS = 10.0.0.1
FwMark = 51820          # <-- add this

[Peer]
...
```

**Each tunnel must have a different `FwMark`.** If two tunnels share
the same mark, the kernel cannot tell them apart and the warning
correctly fires again. Vortix does not auto-inject `FwMark` (that
would mutate user-authored config files); the fix has to live in
your `.conf` so it survives reimport and is visible to any other
WireGuard tooling you might use.

After editing the config, restart the affected tunnel(s):

```sh
vortix reconnect <profile>
```

The warning will disappear from Connection Details on the next
status refresh.

## Further reading

- [`wg-quick(8)` man page](https://man7.org/linux/man-pages/man8/wg-quick.8.html)
  — full semantics of `FwMark`, `Table`, and the related policy-routing directives.
- [Jeff Casavant, *WireGuard fwmark gotchas*](https://casavant.org/2020/10/10/wireguard-fwmark.html)
  — the primary external write-up of this failure mode that informed
  Vortix's warning design.
- [`SECURITY.md`](../SECURITY.md) — the multi-tunnel trust model,
  including the cross-operator exposure framing that justifies the
  persistent (non-dismissable) warning posture.
