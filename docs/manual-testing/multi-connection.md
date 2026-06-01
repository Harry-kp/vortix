# Multi-tunnel manual verification matrix

12 scenarios that exercise every branch of the multi-tunnel state-authority contract
(see `docs/brainstorms/2026-06-01-multi-tunnel-state-authority-requirements.md`).
Each row names the setup and the per-surface expected output. Run them on a real
macOS host with at least two openvpn test droplets available (via
`scripts/test-infra.sh up ovpn-cert ovpn-auth`) and one split-only profile (a
WireGuard `wg-split` or an OpenVPN profile with explicit non-default routes only).

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
