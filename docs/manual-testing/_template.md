# Manual Test Plan — &lt;Feature Name&gt;

Plan: [`docs/plans/<slug>.md`](../plans/<slug>.md)
Brainstorm: [`docs/brainstorms/<slug>.md`](../brainstorms/<slug>.md)
Shipped in: v&lt;version&gt;

Checks that automated tests cannot cover — real kernels, real subprocesses, real terminals, real adversaries.

## Setup prerequisites

- [ ] &lt;real WG profile / OVPN profile / dev machine / etc.&gt;
- [ ] &lt;sudo available, second user account, etc.&gt;

## Regression — existing behavior must keep working

- [ ] &lt;list things that existed before this feature and should be unchanged&gt;

## Happy paths

- [ ] &lt;new feature golden flows&gt;

## Edge cases / conflict paths

- [ ] &lt;boundary conditions, races, alternate UIs&gt;

## CLI / JSON / wire surface

- [ ] &lt;exit codes, JSON envelope shapes, IPC wire-format compatibility&gt;

## Failure modes / negative paths

- [ ] &lt;crashes, bad input, partial state, network drops, disk full&gt;

## Security spot-checks

- [ ] &lt;permissions, symlink attacks, credential exposure, daemon UID gate&gt;

## Cross-platform parity

- [ ] macOS (Apple Silicon)
- [ ] macOS (Intel) — if available
- [ ] Linux (iptables)
- [ ] Linux (nftables)
- [ ] Windows (if applicable; many features are stubbed per project policy)

## Performance / scale

- [ ] &lt;N=10, N=50, narrow terminal, slow disk, etc.&gt;

## Migration / upgrade / downgrade

- [ ] &lt;v0.X.Y → this version, this version → v0.X.Y rollback&gt;

## Observability

- [ ] &lt;journal / log / status JSON content for the new events / state&gt;
