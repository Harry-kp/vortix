# Control-plane invariants — three structural flaws

Origin: a live testing session on Ubuntu 26.04 surfaced six user-visible bugs in
one evening. Each was fixed individually, but the same three structural causes
produced all of them. This records those causes so the remediation is a
deliberate piece of work rather than another round of symptom fixes.

Status: **flaw 3 done** (`cargo xtask check-dead-gates`). Flaws 1 and 2 open,
deliberately deferred until the current manual test round finishes — both touch
code under active test, and churn there makes it impossible to tell a real
regression from refactor noise.

## Flaw 1 — observations carry no provenance

`VpnRuntime.public_ip` is a bare `String`. Nothing records the network
conditions under which it was sampled, so any reader can use it in a context
where it is not valid.

Three separate user-visible bugs, one cause:

- Real IPv4 vanished into `detecting…` on connect — the displayed value was
  never the remembered one.
- After disconnect, the VPN's exit address was shown as the user's real IP for
  a full poll interval.
- Immediately after connect, the pre-VPN sample equalled the real address and
  raised a red "real IPv4 exposed" alarm on a healthy tunnel.

The interim fix added `public_ip_from_tunnel`, then `public_ipv6_from_tunnel`,
then invalidation on egress-path change. **Three patches for one missing idea**
— that is the evidence, not the remedy.

**Wanted:** one type that carries the reading together with its context, so
comparing readings taken under different conditions is unrepresentable rather
than merely guarded.

```rust
struct EgressReading { value: IpAddr, taken_through_tunnel: bool, at: Instant }
```

Landing this deletes all three ad-hoc flags. Touches `vpn_runtime`,
`app/update.rs`, `ui/dashboard/security.rs`.

## Flaw 2 — sibling lifecycles are coupled by convention, not construction

A challenge, an operation, a policy transaction and a tunnel worker each have
independent lifecycles, linked only by ids and reconciled by a level-triggered
loop. Nothing forces terminating one to terminate what it owns.

- `cancel_challenge` removed the challenge and did nothing to its operation.
  The connect stayed admitted for its full deadline, holding the profile lease
  and the control plane: the user's next command was rejected, then timed out,
  and the abandoned connect reported itself long afterwards.
- The same shape produced the original bug in this series: an operation's
  deadline and its tunnel effect's lifetime were unrelated facts about one
  thing, so a late read-back tore down a working tunnel.

`cancel_operation_for_refused_challenge` is one instance of the missing seam.

**Wanted:** a single "terminate this operation and everything it owns" path
that cancel, expire and fail all route through, so they cannot diverge again.
Control-plane surgery — deserves its own focused pass.

## Flaw 3 — refactors leave live gates behind (DONE)

`scanner_first_tick_done` was read by two caching gates and assigned **only by
tests**. Its production writer disappeared with `Message::SyncSystemState`, so
the flag was permanently `false` and real-IP caching had been silently dead
ever since.

The test suite actively concealed it: tests set the flag by hand, encoding the
intended invariant while never checking that anything establishes it. A green
suite was evidence *for* the broken behaviour.

Fixed by `cargo xtask check-dead-gates`, which flags a field initialised to the
same literal in every production constructor, never assigned in production, and
assigned in test code. It caught a second instance on its first run
(`PanelState.show_section_headers`, a constant `true` whose doc comment
described a code path that no longer existed).

**Generalisation worth considering:** wherever tests construct state directly,
they satisfy invariants real writers may not. This lint covers one shape of
that; the broader question is where else the suite asserts on states production
cannot reach.
