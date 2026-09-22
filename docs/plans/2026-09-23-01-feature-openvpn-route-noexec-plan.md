# OpenVPN route ownership via `--route-noexec` — implementation plan

## Problem (RCA, proven live)

OpenVPN cannot coordinate multiple `redirect-gateway` tunnels — each process
installs/deletes `0.0.0.0/1` + `128.0.0.0/1` on its own schedule, so two full
tunnels fight over the shared prefix and either teardown corrupts the other.
vortix inherits this because it lets **openvpn** own the routing table while
half-managing on top. Symptoms, all one root cause:

- Aborted-takeover corruption: connecting a 2nd full tunnel dispatches its
  openvpn, whose teardown deletes the incumbent's `/1` routes → leak/blackhole
  that only clears on disconnect.
- Switch blackout: `ConnectExclusive` disconnects the incumbent ~8 s before the
  replacement is up → no default route.
- Split-route-on-wrong-interface (#303), NO-EXIT mislabels — same source.

## Design

Make **vortix the single routing authority**. Spawn openvpn with
`--route-noexec`: it computes pushed routes (incl. `redirect-gateway def1`
expansion) but installs **nothing**, handing them to a vortix `--route-up` hook
via env vars. vortix installs them interface-scoped, tagged per tunnel, and on
teardown removes **only that tunnel's** routes. Discovery of a tunnel's intent
(full vs split) becomes side-effect-free: openvpn touched no routes, so a
conflicting tunnel can be refused/queued with zero impact on the incumbent.

Reuses existing machinery: `push.rs` already parses `PUSH_REPLY`; the registry
already has `observed.openvpn_routes` / `openvpn_route_claims`.

## Units (each ships with its test, verified by revert)

- **U1 — spawn flags.** `build_ovpn_args` adds `--route-noexec --route-up <hook>
  --route-pre-down <hook>`. Test: argv contains the flags in order.
- **U2 — route hook mode.** New `vortix __vortix-route-hook` subcommand: reads
  `dev`, `route_network_N/route_netmask_N/route_gateway_N`, `redirect_gateway`,
  `ifconfig_*` from env, writes a per-profile routes file under `run/`. Test:
  env → parsed `RouteInstall` struct (full → `/1` halves; split → the CIDRs).
- **U3 — vortix installs.** On the route-up report, install each route
  interface-scoped + record ownership `{profile → [cidr]}`. Reuse
  `route_table.bind_route`. Test: install set matches parsed routes; ownership
  recorded.
- **U4 — teardown removes only own routes.** On disconnect/abort, delete exactly
  the profile's recorded routes; never a cidr another live tunnel owns. Test:
  two tunnels sharing no cidr → teardown of one leaves the other's intact; a
  cidr owned by both is kept until the last owner leaves.
- **U5 — pre-dispatch conflict from live intent.** Because openvpn installs
  nothing, a 2nd full tunnel's route-up reports `0/0` before anything is
  installed → vortix refuses the takeover (RouteConflict → modal) without having
  disturbed the incumbent. Test: connect-full-while-full → incumbent routes
  unchanged, modal raised.
- **U6 — atomic switch.** `ConnectExclusive`: bring the new tunnel up and install
  its routes, then remove the old — order flipped so `0/0` is always owned by
  someone. Test: switch plan installs-before-removes.

## Permutation test matrix (manual, live — mac AND linux)

Run each on macOS and on the Ubuntu droplet. Pass = correct exit owner +
`route get 8.8.8.8`/`ip route get 8.8.8.8` on the expected iface + no residual
leak after.

| # | Start | Action | Expected |
|---|-------|--------|----------|
| 1 | none | connect FULL(A) | A owns default |
| 2 | FULL(A) | connect FULL(B) → Cancel | A untouched, still exit |
| 3 | FULL(A) | connect FULL(B) → Switch | B exit, A gone, no gap-leak |
| 4 | FULL(B) | connect FULL(A) → Cancel | B untouched (the raised bug) |
| 5 | FULL(A) | connect SPLIT(C) | both up, C on its own iface (#303) |
| 6 | SPLIT(C) | connect FULL(A) → Cancel | C untouched |
| 7 | SPLIT(C) | connect FULL(A) → Switch | A exit, C torn down cleanly |
| 8 | FULL(A)+SPLIT(C) | disconnect A | C intact, default back to phys |
| 9 | FULL(A) | quit TUI, restart | A adopted, still exit |
| 10 | any leak repro | — | self-heals within one scan tick |

## Rollback

Feature-gate the `--route-noexec` path behind a check; if a route-up report is
missing/times out, fall back to letting openvpn install (current behavior) so a
hook failure can't leave a tunnel with no routes. Keep the `bind_route` `add`
self-heal as the safety net.

## Non-goals

Policy-routing / simultaneous multiple full tunnels (needs per-tunnel routing
tables; out of scope — single-full-tunnel remains the model, switching is clean).
