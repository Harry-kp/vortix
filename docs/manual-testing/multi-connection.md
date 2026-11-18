# Multi-tunnel manual verification matrix

17 scenarios covering multi-tunnel across **both** protocols and in both
directions (see
`docs/brainstorms/2026-06-01-multi-tunnel-state-authority-requirements.md`).
Run them on a real host with the one-droplet compatibility lab available (run
`scripts/vpn-lab.sh up`) and import its profiles. Use `01`/`03`/`05` or
`wg08`/`wg11` as full-tunnel profiles and `02`/`04`/`06`/`wg07` as split-only
profiles.

Earlier versions of this matrix treated WireGuard and OpenVPN profiles as
interchangeable "full" and "split" classes. They are not, and that assumption
hid a real defect — see the asymmetry section below before reading the table.

**Terminology**:
- **F** — a full-tunnel profile (claims the default route).
- **S** — a split-only profile (claims specific CIDRs, never the default).
- **W** prefix means WireGuard, **O** prefix means OpenVPN: `WF` = WireGuard full
  (`wg08`), `WS` = WireGuard split (`wg07`), `OF` = OpenVPN full (`01`, `03`),
  `OS` = OpenVPN split (`02`, `04`).
- **Egress probe**: `curl -sS https://api.ipify.org` shows whose exit IP.
- **Kernel probe**: `route -n get 8.8.8.8` (macOS) / `ip route get 8.8.8.8` (Linux).
- Evidence for a whole state in one command: `./scripts/verify-multi-tunnel.sh`.

## What Vortix knows before you connect — the asymmetry that drives these cases

The protocols do not declare their routes the same way, and every conflict
decision happens *before* a tunnel exists:

| | Where the default-route claim lives | Known before connecting? |
|---|---|---|
| WireGuard | `AllowedIPs = 0.0.0.0/0` in the `.conf` | **Yes** — parsed from the file |
| OpenVPN | pushed by the server (`redirect-gateway`) at negotiation | **No** — only after the tunnel is up |

The lab's `01` contains no `redirect-gateway` and no `route` line at all; its
full-tunnel nature arrives entirely from the server. So a conflict against an
*already-connected* OpenVPN tunnel is detectable (its claim has been observed),
while a conflict against an OpenVPN tunnel *being connected* is not. Any
scenario below whose "claim known" column says **no** is a case where Vortix
cannot prompt before the fact — treat a missing overlay there as the known gap,
not a fresh bug.

Two tunnels can never both hold the default route. The only offered outcomes
are **[Y] Switch** and **[N] Cancel**; the old "keep both, demote one to a split
tunnel" option was removed — it served no real use case and never converged.

| # | Setup | Claim known before connect? | Expected overlay | Expected outcome |
|---|---|---|---|---|
| 1 | Connect `WF` alone | — | none | `WF` primary, its exit IP |
| 2 | Connect `OF` alone | — | none | `OF` primary, its exit IP |
| 3 | Connect `S` alone (either protocol) | — | none | no exit; split routes only |
| 4 | `OF` up, connect `OS` (disjoint) | n/a — no default claimed | none | both up; `OS` carries its subnet on its own interface |
| 5 | `OS` up, connect `OF` | n/a | none | both up; `OF` takes egress, `OS` keeps its subnet |
| 6 | `OF` up, connect second `OF` | yes (incumbent observed) | takeover → `[Y]`/`[N]` | `[Y]`: incumbent stands down, newcomer takes egress, **any split tunnel stays up** |
| 7 | `WF` up, connect second `WF` | yes (both declared) | takeover → `[Y]`/`[N]` | as #6 |
| 8 | `WF` up, connect `OF` | **no** — OpenVPN claim is pushed | *none today* | known gap: both claim default, convergence stalls |
| 9 | `OF` up, connect `WF` | yes (incumbent observed + declared) | takeover → `[Y]`/`[N]` | as #6 |
| 10 | `WF` up, connect `OS` | n/a | none | both up; split subnet on its own interface |
| 11 | `WS` up, connect `OF` | n/a | none | both up |
| 12 | `OF` + `OS` up, connect another `OF`, press `[Y]` | yes | takeover names the **full** tunnel only | the other full tunnel goes; the split tunnel keeps running |
| 13 | From #4, disconnect `OS` | — | none | `OF` still up and still carrying egress |
| 14 | From #4, disconnect `OF` | — | none | `OS` still up; no exit |
| 15 | Disconnect all with two up | — | confirm when multi | both torn down, both named |
| 16 | Two up, restart the TUI | — | none | both adopted; check DNS row still names the VPN resolvers |
| 17 | Two up, kill switch `vpn-only` | — | none | `nft` shows an accept rule per tunnel interface |

Rows 6, 7, 9 and 12 are the ones that used to offer a third "keep both" choice.
They must now offer exactly two.

## Critical invariants every scenario must hold

These derive from the state-authority contract — any violation is a bug, not a
test-setup quirk:

1. **Sidebar asterisk == header CONNECTED-name == Role: Primary owner.** All three
   surfaces derive from `registry.primary`; they cannot diverge.
2. **`route -n get 8.8.8.8`'s interface output equals the asterisked tunnel's
   `details.interface`.** Byte-for-byte. If kernel and vortix disagree, the
   registry has been corrupted.
3. **`curl https://api.ipify.org` returns the exit IP of whichever profile shows
   `*`**. UI claim matches reality at the egress.
4. **Scanner reports never change `details.interface` of an existing Connected
   entry.** Even when the scanner ticks during a connect race, the iface set
   by `Tunnel::up()`'s log scrape is preserved.

## Acceptance Examples cross-reference

Each scenario maps to an AE in
`docs/brainstorms/2026-06-01-multi-tunnel-state-authority-requirements.md`:

| Scenario | AE | Requirements exercised |
|---|---|---|
| 1 | AE1 | R1, R7, R9, R10 |
| 2 | AE2 | R7, R9, R10 |
| 3 | AE3 | R1, R2, R3, R7, R9, R10 |
| 4 | AE4 | R7, R9, R10 |
| 5 | AE5 | R1, R7, R8, R9 |
| 6 | AE6 | R1, R7, R9, R10 |
| 7 | AE7 | R7, R8, R9, R10 |
| 8 | AE8 | R7, R9 |
| 9 | AE9 | R7, R9 |
| 10 | AE10 | R7, R8, R9, R10 |
| 11 | AE11 | R1, R7, R9, R10 |
| 12 | AE12 | R1, R3, R7, R9, R10 |

## Density principle reminder

Every scenario above must render cleanly at 80×24 with no panel cropping. The
TUI density rule (CLAUDE.md §TUI density principle) is load-bearing: signal
via badge/color/sigil changes, never via new panels. If any scenario needs a
new panel to render correctly, that's a design defect to surface, not a layout
tweak.

## Reporting

When running this matrix as part of a release verification, capture either:
- a screenshot per scenario (sidebar + header + Connection Details + Security Guard
  visible), or
- a `vortix status --json` dump for each state plus the corresponding
  `route -n get 8.8.8.8` output.

The JSON dump is sufficient evidence for scenarios 1–4 and 9–12; the visual
verification is necessary for 5, 6, and 11 because the takeover overlay is
visible-only state.

## DNS agreement addendum

For every scenario with two active tunnels, capture the resolver view beside
the route and JSON evidence:

- Linux resolved: `resolvectl status <primary-iface>` and each secondary.
- Linux fallback: `resolvconf -l`.
- macOS: `scutil --dns` plus `ls -l /etc/resolver` and the Vortix-managed file contents.

Exactly one `Role::Primary` may own catch-all DNS (`~.` on resolved or the
Vortix-marked `default` resolver on macOS). A secondary with explicit search
domains may own only those suffixes; otherwise its requested global DNS is
suppressed. Resolver suppression must never remove its CIDR/AllowedIPs routes.
During scenarios 6–8 (primary transfer/disconnect), record the DNS policy
generation before and after, verify only prior-generation Vortix resources
were released, and repeat the final reconcile/release to prove idempotency.
