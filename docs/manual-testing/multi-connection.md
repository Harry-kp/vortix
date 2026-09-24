# Multi-tunnel manual verification matrix

12 scenarios that exercise every branch of the multi-tunnel state-authority contract.
Each row names the setup and the per-surface expected output. Run them on a real
macOS host with the one-droplet compatibility lab available (run
`scripts/vpn-lab.sh up`) and import its profiles. Use `01`/`03`/`05` or `wg08`/`wg11`
as full-tunnel profiles and `02`/`04`/`06`/`wg07` as split-only profiles.

**Terminology**:
- **F1**, **F2**, **F1'** — full-tunnel profiles (client config has `redirect-gateway`
  or aggregated /1 split routes that claim default).
- **S** — split-only profile (no default-route claim).
- **Egress probe**: `curl -sS https://api.ipify.org` shows whose exit IP.
- **Kernel probe**: `route -n get 8.8.8.8` (macOS) / `ip route get 8.8.8.8` (Linux).

| # | Setup | Header `CONNECTED (?/?)` | Sidebar `*` on | Role (F1) | Role (F2) | Role (S) | SG IP row | Overlay |
|---|---|---|---|---|---|---|---|---|
| 1 | Connect F1 alone | F1 | F1 | Primary | — | — | F1's exit IP, ✓ | none |
| 2 | Connect S alone | (no exit) | — (S has dot only, no `*`) | — | — | Addressable | "split-route — no exit" | none |
| 3 | F1 up, then connect S (disjoint CIDR) | F1 | F1 | Primary | — | Addressable | F1's exit IP, ✓ | none (disjoint = no prompt) |
| 4 | F1 up, then connect S where S's route overlaps F1's | F1 | F1 | Primary | — | Addressable | F1's exit IP, ✓ | ConfirmRouteOverlap → press Y |
| 5 | F1 up, then connect F2, press Y on takeover (Switch) | F2 | F2 | — (disconnected) | Primary | — | F2's exit IP, ✓ | ConfirmDefaultRouteTakeover → Y |
| 6 | F1 up, then connect F2, press B on takeover (Both) | F2 | F2 | AddressableSuppressed | Primary | — | F2's exit IP, ✓ | ConfirmDefaultRouteTakeover → B |
| 7 | From #6 state, disconnect F2 | F1 | F1 | Primary | — | — | F1's exit IP, ✓ | none — user disconnects/reconnects manually if they want a different primary |
| 8 | From #6 state, disconnect F1 | F2 | F2 | — | Primary | — | F2's exit IP, ✓ | none |
| 9 | From #3 state, disconnect S | F1 | F1 | Primary | — | — | F1's exit IP, ✓ | none |
| 10 | From #3 state, disconnect F1 | (no exit) | — | — | — | Addressable | "split-route — no exit" | none |
| 11 | From #6 state, connect F1' (third F-class profile) | F1' | F1' | AddressableSuppressed | AddressableSuppressed | — | F1''s exit IP, ✓ | ConfirmDefaultRouteTakeover → B |
| 12 | Connect S, then connect F1 (S already up, no overlap) | F1 | F1 | Primary | — | Addressable | F1's exit IP, ✓ | none (no conflict — S didn't own default) |

## Critical invariants every scenario must hold

These derive from the state-authority contract — any violation is a bug, not a
test-setup quirk:

1. **Sidebar asterisk == header CONNECTED-name == Role: Primary owner.** All three
   surfaces derive from the engine snapshot's primary tunnel; they cannot diverge.
2. **`route -n get 8.8.8.8`'s interface output equals the asterisked tunnel's
   `details.interface`.** Byte-for-byte. If kernel and vortix disagree, the
   engine snapshot is wrong.
3. **`curl https://api.ipify.org` returns the exit IP of whichever profile shows
   `*`**. UI claim matches reality at the egress.
4. **Scanner reports never change `details.interface` of an existing Connected
   entry.** Even when the scanner ticks during a connect race, the iface set
   by `Tunnel::up()`'s log scrape is preserved.

## Density principle reminder

Every scenario above must render cleanly at 80×24 with no panel cropping. The
TUI density rule (see CLAUDE.md) is load-bearing: signal
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

## OpenVPN route-authority gate

Run these checks in both directions with two full profiles before release:

1. Connect F1, attempt F2, and cancel the takeover. Capture a frame showing F1
   still primary plus a kernel probe showing F1's interface. Neither `/1`
   route may disappear during the prompt or cancellation.
2. Repeat and choose Switch. Capture one frame while F2 is preparing and one
   after completion. F1 must remain present until F2 has a live interface; the
   final kernel probe and header must both name F2.
3. With F1 active, connect S. Probe one address inside S's CIDR and one public
   address. The split address must use S; public traffic must continue through
   F1.
4. Disconnect every tunnel. Confirm neither platform retains a route scoped to
   the former `tun`/`utun` interfaces.
