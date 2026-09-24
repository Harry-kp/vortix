# Role labels in Connection Details

When you connect to a VPN profile, vortix shows a **Role** line in the Connection Details panel. This page is a plain-English glossary of every label you'll see there and what it means for the traffic on your machine.

Quick reference in the app: press `?` and scroll to **Connection Details: Role labels**.

---

## The short version

| Label | What it means | Where your internet traffic goes |
|---|---|---|
| `Primary` | This tunnel is your active exit. | Through this tunnel. |
| `Split tunnel` | Connected but not your exit. | Most traffic: through your normal LAN/wifi. Only the routes this tunnel declared go through it. |
| `Split tunnel (yielded)` | A full tunnel while another tunnel owns the default route. Seen briefly during a switch. | Through *another* tunnel. |
| `(external)` after any label | Started outside vortix and we can't fully track it. | Through this tunnel for whatever it routes. Vortix won't elect it as exit even if it's eligible. |

The Role line answers one question: **"if I open a new browser tab right now, where does the packet go?"** Primary = through this tunnel. Anything else = not through this tunnel (it goes through your real internet OR through whichever other tunnel is Primary).

---

## Every label, explained

### `Primary`

**Meaning**: This tunnel owns your kernel's default route. Open any website and the packet flows through here.

**When you see it**: You connected a "full-tunnel" profile (one that declares `AllowedIPs = 0.0.0.0/0` for WireGuard, or `redirect-gateway` for OpenVPN, or one whose server pushes the default route at runtime).

**Examples**:
- `Primary` — full-tunnel profile, no `route` directives in the config to enumerate.
- `Primary (10.0.0.0/8)` — declares the listed subnet AND owns the default route.
- `Primary (multi)` — declares more than one subnet AND owns the default route.

---

### `Split tunnel`

**Meaning**: The tunnel is up. Internet traffic does **not** go through it. Only the specific subnets it declared (its `AllowedIPs` for WireGuard, or `route` directives for OpenVPN) are routed through this tunnel; everything else still uses your normal internet connection.

**When you see it**: You connected a profile that doesn't claim the default route. Classic case: a corporate VPN configured to route just `10.0.0.0/8` so you can reach internal services without your personal browsing going through the company.

**Examples**:
- `Split tunnel` — no routes listed (rare; almost certainly a config gap).
- `Split tunnel (10.0.0.0/8)` — the listed subnet is the only thing this tunnel carries.
- `Split tunnel (multi)` — declares multiple non-default subnets.

**What this does NOT mean**: it does NOT mean the tunnel is broken. Split tunneling is a normal, useful configuration. If you're confused about whether traffic actually goes through it, run `curl https://api.ipify.org` — if you see your real ISP's IP, you're going out through your normal internet (correct for a split tunnel). To verify the *split* traffic reaches the tunnel, hit an IP inside the declared subnet.

---

### `Split tunnel (yielded)`

**Meaning**: This tunnel declared `0.0.0.0/0` (it wanted to be your exit), but another full tunnel owns the default route.

**When you see it**: Briefly during a switch. A switch brings the new tunnel up before stopping the one it replaces, so for a moment the old one shows `(yielded)` (or the new one does, until it takes over).

**Examples**:
- `Split tunnel (yielded)` — wanted default route, didn't win, declares nothing else specific.
- `Split tunnel (0.0.0.0/0, yielded)` — same; the 0/0 in parens is from the config.
- `Split tunnel (multi, yielded)` — declares multiple subnets including 0/0; another tunnel won.

If a `(yielded)` label stays after a switch finishes, disconnect that tunnel and file an issue.

---

### `(external)` suffix on any label

**Meaning**: Vortix detected this tunnel as up but can't reliably attribute its kernel interface to its process. Almost always: you started an OpenVPN tunnel outside of vortix (e.g. `sudo openvpn --config ...` from another terminal) while another OpenVPN tunnel was already up. On macOS, vortix can't tell which `utunN` device belongs to which `openvpn` PID when more than one is running.

**Why it matters**: Vortix won't elect this tunnel as your Primary even if its routes would qualify. The data it shows for this tunnel (server, MTU, byte counts) comes from the scanner's best effort but the interface name is unreliable, so we refuse to make routing claims on top of it.

**How to make it not say (external)**: start the tunnel through vortix (`vortix up <profile>` or Enter on its sidebar row). The connect path returns the authoritative interface from the protocol layer's output, and the entry is then fully tracked.

---

### `Reconnecting via Primary` / `Reconnecting via Split tunnel`

**Meaning**: A connected tunnel dropped and vortix is automatically retrying. The `via X` part names what its role was before the drop, so you know what to expect when it comes back.

---

## How vortix decides which label to use

The rule is one line: **the newest full tunnel owns the default route and DNS, and is Primary.**

Vortix's planner decides this from the set of tunnels that are up, then installs the matching routes and DNS. Tunnels that only declare specific subnets are `Split tunnel`.

This means the Role line is always consistent with reality:
- `route -n get 8.8.8.8` (macOS) or `ip route get 8.8.8.8` (Linux) tells you the kernel's chosen exit interface.
- Whichever tunnel owns that interface in vortix shows `Primary`.
- `curl https://api.ipify.org` will return that tunnel's exit IP.

If those three disagree, that's a bug — file an issue.

---

## Common confusing scenarios

**"I see `Split tunnel` but the profile claims `redirect-gateway` — why isn't it Primary?"**
The OpenVPN server probably isn't pushing the redirect at runtime (some VPN providers' free tiers do this). Check `route -n get 8.8.8.8` — if the answer isn't this tunnel's `utun*`, the kernel never installed the default route through it.

**"I'm using a split-only WireGuard for corp + a full-tunnel for browsing. Which one shows `Primary`?"**
The full-tunnel one. The corp WG shows `Split tunnel (10.0.0.0/8)` (or whatever its `AllowedIPs` are). Corp internal traffic goes through corp; everything else goes through the full-tunnel.

**"How do I switch primary between two full tunnels?"**
Connect the second one. The takeover overlay asks to switch: `Y`/`Enter` brings the new one up and stops the old one; `N`/`Esc` cancels.
