# Problem framing: OpenVPN's dynamic route push vs vortix multi-tunnel

## 1. Summary

Every multi-tunnel routing bug we've hit on macOS traces to a single fact:
**OpenVPN installs and removes the default-route entries itself, at runtime,
from server-pushed directives — and it has no mechanism to coordinate two
tunnels that both want the default route.** vortix currently lets openvpn own
the routing table while also observing and poking it, so vortix is caught in the
middle: it can't know a profile's routing intent before starting it, and
starting it to find out already corrupts whatever tunnel held the default. This
document frames the problem precisely so the fix targets the cause, not the
symptoms.

## 2. Observed symptoms (all one cause)

Each was reproduced live on macOS with debug logging.

### S1 — Split route lands on the wrong interface (#303, merged)
With a full tunnel owning `0.0.0.0/1`, a second tunnel's pushed split route
(e.g. `10.250.0.0/24`) is installed by openvpn *via its gateway*, which resolves
through the full tunnel → the split route lands on the full tunnel's utun.

### S2 — Full tunnel's own default lands wrong (mirror of #303, merged)
Reverse order: split up first, then full — the full tunnel's `def1` routes
resolve through the split tunnel's interface. Route read-back fails
(`0.0.0.0/0 should route through utunN, but routes through utunM`).

### S3 — Aborted-takeover corruption (the raised bug, OPEN)
`01` (full) up. Connect `03` (full) → vortix **dispatches 03's openvpn**
(`ovpn.up bc00c594`). 03 seizes/overwrites the shared `0/1`. Conflict detected
*after* dispatch → 03 torn down (`ovpn.down` ~1.3 s later) → its route-down
**deletes the shared `0/1`, which 01 also needed**. 01 is left "connected" but
`0.0.0.0/0 → en0`: real IP exposed. Direction `01→03` self-heals via the
`bind_route` `add` fix; direction `03→01` does not (survivor's route not
restored; primary election ambiguous) → stays broken until 03 is disconnected.

Evidence: during the modal (before any cancel), `netstat` showed `0/1` and
`128.0/1` already gone — the *attempt*, not the cancel, does the damage.

### S4 — Switch blackout (OPEN)
`Switch` (`ConnectExclusive`) is sequential: `ovpn.down 01` at 20:06:37, then
`ovpn.up 03` at 20:06:45 — an **8-second window with no tunnel owning the
default route**. Worse for password/slow profiles (03 is
`--management-hold --management-query-passwords`). Total connectivity blackout
during the gap.

### S5 — "NO EXIT" mislabel / stuck primary (surfaced)
Because the observed default-route interface stops matching any connected
tunnel, primary election yields none → header shows `○ NO EXIT` with the
physical IP even though a tunnel is "connected." A consequence of S2/S3, not an
independent bug.

## 3. How OpenVPN actually manages routes (the mechanism)

- `redirect-gateway def1` does **not** replace the kernel default. It installs
  `0.0.0.0/1` + `128.0.0.0/1` (covering all of IPv4, out-prioritising the real
  default) **plus a host route to the VPN server via the pre-existing default
  gateway** so the tunnel's own packets escape. On exit it deletes what it
  added.
- These directives arrive at **connect time** in `PUSH_REPLY` from the server —
  they are **not** in the client `.ovpn`. So a profile's full-vs-split nature is
  **unknowable until the tunnel is up**.
- **Two `redirect-gateway` tunnels cannot coexist** under plain openvpn: they
  fight over the same `0/1` prefix (last writer wins), and either one's teardown
  deletes it. OpenVPN's own docs warn stacking redirect directives "is not well
  supported." The sanctioned way to run multiple full tunnels is **policy
  routing** (per-tunnel routing tables + rules) — which plain openvpn does not
  do and macOS barely supports.

## 4. Root cause (why a "just a wrapper" gets hit)

vortix sits in the **worst middle ground**: two authorities touch the routing
table.

1. **openvpn owns install/teardown** (plain `redirect-gateway`), so two openvpn
   processes fight, and teardown of one corrupts the other. vortix can't prevent
   this while openvpn holds the pen.
2. **vortix half-manages on top** — observes the default route, elects a
   primary, pokes `bind_route` to "fix" mismatches. This races openvpn and can
   only ever react.
3. **Intent is unknowable pre-dispatch** (runtime push), so vortix's only way to
   learn "is this profile full?" is to *start* it — which, because of (1),
   already does the damage.

Net: vortix promises multi-tunnel UX that openvpn cannot coordinate, without
taking the one action that would let it — **owning the routing table**.

## 5. The invariant the fix must hold

1. At every instant, the kernel's default-route owner matches vortix's declared
   primary (or an explicit "no exit"), with **no window** where a tunnel is
   "connected" but not routing.
2. Tearing down any tunnel removes **only that tunnel's** routes — never a
   prefix another live tunnel still needs.
3. Discovering a profile's routing intent must be **side-effect-free** — no
   route change until vortix decides.
4. vortix's observed view == kernel truth (no stale "NO EXIT" / false PROTECTED).

## 6. Solution space

| Option | Idea | Verdict |
|---|---|---|
| **A. Cache intent** | Record each profile's observed routes; use for pre-dispatch conflict checks. | **Rejected** — band-aid; first connect still reactive; stale-cache risk; doesn't fix install/teardown corruption. |
| **B. `--route-noexec` + vortix owns routes** | openvpn computes routes, installs nothing, hands them to a vortix hook; vortix installs interface-scoped + per-tunnel-tagged, removes only its own on teardown. | **Recommended** — holds all four invariants; uses openvpn's own sanctioned mechanism; makes discovery side-effect-free; enables atomic switch. |
| **C. Policy routing** | Per-tunnel routing tables + rules for true simultaneous full tunnels. | **Out of scope** — large; poor macOS support; not needed for single-full-tunnel model. |
| **D. Single-full-tunnel enforcement only** | Never run two full tunnels; switch = clean disconnect→connect. | Necessary but insufficient alone — still needs B to know intent without corrupting, and to close the switch gap. |

## 7. Recommendation

Build **B**, which subsumes **D**: vortix becomes the single routing authority
via `--route-noexec`. Implementation plan and permutation test matrix:
`docs/plans/2026-09-23-01-feature-openvpn-route-noexec-plan.md`.

## 8. Open question blocking implementation

Empirically confirm what env vars openvpn's `--route-up` receives for a
`redirect-gateway` profile under `--route-noexec`: does it expand to
`route_network_{n}` = `0.0.0.0/1` + `128.0.0.0/1`, or only set
`route_redirect_gateway_ipv4=1` and expect the script to expand? OpenVPN docs
are ambiguous; this decides the hook's parsing. Verify by running one openvpn
connect with an env-dumping `--route-up` script and capturing the live
environment (requires a brief VPN connect on macOS).

## 9. Non-goals

- Simultaneous multiple **full** tunnels (policy routing) — single-full-tunnel
  stays the model.
- Re-introducing any control-mutation daemon path (see CLAUDE.md — background
  mode is removed).
