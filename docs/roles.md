# Role labels in Connection Details

When you connect to a VPN profile, vortix shows a **Role** line in the Connection Details panel. This page is a plain-English glossary of every label you'll see there and what it means for the traffic on your machine.

Quick reference in the app: press `?` and scroll to **Connection Details: Role labels**.

---

## The short version

| Label | What it means | Where your internet traffic goes |
|---|---|---|
| `Primary` | This tunnel is your active exit. | Through this tunnel. |
| `Split tunnel` | Connected but not your exit. | Most traffic: through your normal LAN/wifi. Only the routes this tunnel declared go through it. |
| `Split tunnel (yielded)` | Wanted to be exit but lost the race. | Through *another* tunnel. This one stays up but routes nothing useful (the declared routes are usually overridden). |
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

**Meaning**: This tunnel declared `0.0.0.0/0` (it wanted to be your exit), but another tunnel got there first. "Yielded" = "I claimed the default route but stood down for another tunnel that also wanted it."

**When you see it**: You used `Shift+B` (Both) on the takeover overlay to keep both full-tunnel profiles up. The OS's routing table picks ONE of them as the actual exit — typically whichever connected later. The one that *didn't* win renders as `(yielded)`.

**Why the OS picks one and not the other**: the kernel routing table has one default route at a time. When two tunnels both insert default-route entries, the OS picks one (last-inserted, on macOS). The other tunnel's routes are technically present but they don't carry your internet traffic.

**Examples**:
- `Split tunnel (yielded)` — wanted default route, didn't win, declares nothing else specific.
- `Split tunnel (0.0.0.0/0, yielded)` — same; the 0/0 in parens is from the config.
- `Split tunnel (multi, yielded)` — declares multiple subnets including 0/0; another tunnel won.

**What if both routes worked?** They don't — the OS routes each packet via exactly one path. The yielded tunnel sits idle from a default-traffic perspective. If the active primary disconnects, the kernel re-elects whichever tunnel still has matching routes (typically the yielded one); vortix reads the new state and updates the Primary label on the next scanner tick. Vortix doesn't actively switch tunnels — it reports whatever the kernel decided.

**Pet peeve note**: "yielded" is shorthand for "this VPN wanted to be primary but isn't right now." If you don't want it as a standby, just disconnect it.

---

### `(external)` suffix on any label

**Meaning**: Vortix detected this tunnel as up but can't reliably attribute its kernel interface to its process. Almost always: you started an OpenVPN tunnel outside of vortix (e.g. `sudo openvpn --config ...` from another terminal) while another OpenVPN tunnel was already up. On macOS, vortix can't tell which `utunN` device belongs to which `openvpn` PID when more than one is running.

**Why it matters**: Vortix won't elect this tunnel as your Primary even if its routes would qualify. The data it shows for this tunnel (server, MTU, byte counts) comes from the scanner's best effort but the interface name is unreliable, so we refuse to make routing claims on top of it.

**How to make it not say (external)**: start the tunnel through vortix (`vortix up <profile>` or Enter on its sidebar row). The connect path returns the authoritative interface from the protocol layer's output, and the entry is then fully tracked.

---

### `Reconnecting via Primary` / `Reconnecting via Split tunnel`

**Meaning**: A connected tunnel dropped and vortix is automatically retrying. The `via X` part names what its role was before the drop, so you know what to expect when it comes back.

---

### `n/a (awaiting input)`

**Meaning**: The tunnel is waiting for you to type something (a 2FA code, a passphrase, etc.). Press `Enter` while focused on Connection Details to surface the prompt overlay.

---

## How vortix decides which label to use

The rule is one line: **whoever currently owns the kernel's default route is Primary.**

Vortix does not pick. The OS routing table picks. Vortix just reads what the OS decided and labels each tunnel accordingly. If you press `Shift+B` to keep both full-tunnel profiles, the OS picks one based on routing-table insertion order (typically last-inserted-wins on macOS). Vortix reports the winner as `Primary` and the loser as `Split tunnel (yielded)`.

This means the Role line is always consistent with reality:
- `route -n get 8.8.8.8` (macOS) or `ip route get 8.8.8.8` (Linux) tells you the kernel's chosen exit interface.
- Whichever tunnel owns that interface in vortix shows `Primary`.
- `curl https://api.ipify.org` will return that tunnel's exit IP.

If those three disagree, that's a bug — file an issue.

---

## Common confusing scenarios

**"I connected two tunnels and one says `(multi, yielded)` — did I do something wrong?"**
No. You pressed Shift+B (Both), and one of the two full-tunnel profiles won the route race while the other stood down. The yielded one stays connected as a parallel tunnel; if the active primary drops, the kernel may or may not re-route through the yielded one depending on its routing-table state. Vortix reports whichever tunnel currently owns the default route as Primary — it does not actively promote.

**"I see `Split tunnel` but the profile claims `redirect-gateway` — why isn't it Primary?"**
Either (a) another tunnel is already Primary and you connected this one as a secondary without taking over, or (b) the OpenVPN server isn't actually pushing the redirect at runtime (some VPN providers' free tiers do this). Check `route -n get 8.8.8.8` — if the answer isn't this tunnel's `utun*`, the kernel never installed the default route through it.

**"I'm using a split-only WireGuard for corp + a full-tunnel for browsing. Which one shows `Primary`?"**
The full-tunnel one. The corp WG shows `Split tunnel (10.0.0.0/8)` (or whatever its `AllowedIPs` are). Corp internal traffic goes through corp; everything else goes through the full-tunnel.

**"How do I switch primary between two full-tunnels without using Shift+B?"**
Use `Shift+Y` on the takeover overlay: disconnect the current primary, then connect the new one. The yielded standby pattern only happens with Shift+B (Both).
