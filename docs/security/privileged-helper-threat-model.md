# Privileged helper threat model

Status: U11 contract frozen; U12 authenticated observation/recovery core is
implemented but dormant; helper staged and **unenrolled**. No privileged
operation is reachable in this release. U12 enables remaining operation
families behind the dormant boundary; U13 alone may enroll authority.

## Security objective

Background mode reduces the privileged computing base to a root helper that
accepts only validated, typed Vortix operations. The helper is not a generic
command runner. It never accepts profile text, shell text, executable names,
arguments, environment variables, client paths, or client-selected service
files.

This boundary protects root-owned network state and Vortix-owned tunnel
processes from malformed or replayed daemon requests. It does not attempt to
isolate applications running as the same Unix user from one another.

## Trust assumptions

- The kernel, service manager, root account, package manager, and platform
  signature verifier are trusted.
- The installed helper, bootstrap, daemon, release manifest, service template,
  and root ledger are root-owned and not group/world writable.
- The enrolled owner is one non-root UID. Any process with that UID can use the
  client-to-daemon socket and answer that user's Vortix challenges. Vortix does
  not claim same-UID application isolation.
- The daemon is unprivileged and may be compromised. Its scalar identity claims
  are untrusted until matched against kernel and service-manager facts.
- Imported VPN profiles, protocol servers, local clients, environment, IPC
  bytes, filesystem names outside fixed roots, PIDs, and scanner observations
  are attacker-controlled.
- Standard mode intentionally retains the existing `sudo vortix` full-client
  trust boundary for compatibility. It is not equivalent to Background mode's
  narrow helper. Users seeking a smaller privileged computing base should use
  Background mode once enrollment ships.

## Components and boundaries

1. CLI/TUI clients authenticate to the unprivileged daemon as the enrolled UID.
2. The daemon converts already-validated profiles into the canonical
   `vortix_core::privileged` plan. It cannot construct root authority.
3. The root helper authenticates the daemon using peer UID/PID, process start
   token, service-manager instance/containment, root-owned executable digest,
   manager nonce, current boot scope, authority epoch, and lease.
4. The helper independently decodes and validates the canonical plan, admits it
   through the replay ledger, executes only its fixed operation family, and
   returns an untrusted receipt. The daemon trusts a receipt only after binding
   it back to the authenticated helper, request digest, epoch, lease, and
   sequence.

U11 implements step 2's wire vocabulary and step 3's verification seam. U12's
first typed slice adds replay-before-read observation, authenticated receipts,
and post-delivery loss classification without a listener or platform executor.
The `vortix-helper` binary exits with code 78 for every entrypoint except
`--version`.

## Admitted operation family

The contract is closed and typed:

- start one WireGuard or OpenVPN tunnel from a canonical protocol plan;
- stop one exact Vortix-owned tunnel resource;
- establish, apply, observe, or release one generation-owned network policy;
- observe an explicit bounded resource set;
- clean up explicit tunnel/process-group/runtime-secret resources owned by the
  current authority.

Protocol plans use fixed material slots and validated addresses, CIDRs,
hostnames, routes, DNS assignments, generations, and stable profile IDs. The
OpenVPN directive allowlist is documented in
`docs/security/openvpn-privileged-directive-inventory.md`. Unknown variants,
fields, protocols, directives, resources, duplicates, and over-bound
collections fail during strict deserialization.

There is deliberately no operation for arbitrary process execution, arbitrary
file access, arbitrary firewall/DNS/route commands, service installation,
profile parsing, hooks, or arbitrary cleanup.

## Wire and authorization

- Helper frames are capped at 256 KiB before JSON allocation.
- Strict serde shapes reject unknown fields and unknown enum variants.
- A mandatory first handshake negotiates product, protocol range, schema range,
  and required capabilities.
- The U11 staged helper enables only `handshake`. Advertising the future
  contract does not enable it; requests for operational capabilities fail.
- The service claim alone grants nothing. The helper compares every claim field
  to OS-owned facts before an opaque root-authority capability can exist.
- Operation IDs bind authority epoch, lease, helper epoch, sequence, principal,
  and canonical semantic digest. Same-ID/different-digest requests fail.
- The root replay high-water record is monotonic, boot/lease bound, and written
  atomically before an effect is admitted.
- PID identity always includes a process start token and containment identity;
  a numeric PID alone is never ownership evidence.

After a framing timeout, authentication mismatch, helper restart, reply loss,
or mid-operation disconnect, the connection is discarded. The daemon marks the
operation unavailable or ambiguous, reconnects with a new handshake, scans, and
reconciles before any retry. It never assumes that a missing reply means an
effect did not happen.

## Installation and enrollment

The guided CLI/TUI setup and advanced service-install command must consume the
same immutable `InstallPlan`; they may not implement separate privileged copy
logic. The guided client never re-executes itself as root. It may invoke system
`sudo` directly, without a shell, only for an absolute package-supplied
bootstrap after preflight.

The bootstrap accepts a sanitized `InstallRequest` containing only owner UID,
target platform layout, package channel, manifest generation/digest, and a nonce. It rejects root as an
owner, unknown fields, unsafe environment, replay, changed manifest, and every
unsupported channel. It re-verifies its own root-owned/immutable or signed
identity and the canonical manifest before staging fixed paths.

| Platform | Artifact | Fixed path |
|---|---|---|
| Linux | daemon | `/usr/libexec/vortix/vortix` |
| Linux | helper | `/usr/libexec/vortix/vortix-helper` |
| Linux | bootstrap | `/usr/libexec/vortix/vortix-bootstrap` |
| Linux | helper socket | `/run/vortix/helper.sock` |
| Linux | root ledger | `/var/lib/vortix/helper-ledger.json` |
| macOS | daemon | `/Library/Application Support/Vortix/bin/vortix` |
| macOS | helper | `/Library/PrivilegedHelperTools/com.vortix.helper` |
| macOS | bootstrap | `/Library/PrivilegedHelperTools/com.vortix.bootstrap` |
| macOS | helper socket | `/var/run/vortix/helper.sock` |
| macOS | root ledger | `/Library/Application Support/Vortix/helper-ledger.json` |

Package-channel classification is fail closed:

| Channel | Background enrollment |
|---|---|
| Linux distro/system package | supported after artifact verification |
| Signed macOS installer package | supported after signature verification |
| Homebrew | unsupported; Standard mode plus signed-package guidance |
| `cargo install` | unsupported; user-writable layout remains Standard mode |
| source build | unsupported unless a trusted administrator creates a system package |

Installing files or cancelling setup does not enroll, enable, or start a daemon
or helper. Service examples are disabled templates. U13 must transactionally
create the enrollment marker, lease, socket metadata, and service enablement.
Failure or cancellation revokes setup-created leases and metadata, stops jobs,
and removes setup-created staged artifacts. Package-owned inactive files may
remain only when verified, disclosed, and safe for retry.

## Upgrade and uninstall

Upgrade is expand-first:

1. verify and stage the new daemon/helper/bootstrap and manifest beside the
   current generation;
2. preserve the prior manifest digest and binary generation;
3. negotiate overlapping protocol/schema capabilities;
4. stop admission, drain bounded work, and reconcile ambiguous effects;
5. switch the service-manager identity atomically;
6. retain rollback artifacts until the new generation completes a handshake
   and read-only health check;
7. revoke the old lease before deleting prior artifacts.

Uninstall first disables admission and boot policy, preserves fail-closed
network protection while owned tunnels are reconciled, stops/reaps owned
children, removes only ledger-owned policy resources, revokes leases and
sockets, then removes service definitions and artifacts. If ownership or
read-back is ambiguous, uninstall stops and reports recovery instructions
instead of broadly flushing firewall, DNS, routes, or foreign processes.

## Threat review

| Threat | Control | Residual severity |
|---|---|---|
| Malformed/oversized/deep wire | frame cap, strict bounded decoding, closed enums | low |
| Generic command/path/environment injection | no such contract fields; fixed roots/material slots | low |
| Same-user daemon impostor | service-manager instance, peer PID/start token, executable digest, nonce, containment | low after U12 OS verifier |
| Cross-user/root-owner enrollment | non-root owner rule plus peer credentials | low |
| PID reuse or stale process observation | start token, containment ID, generation-owned resource | low |
| Replay or duplicate ID mutation | boot/lease/epoch/sequence/digest ledger | low |
| Symlink/path substitution | fixed root-owned paths; `openat`/`O_NOFOLLOW`; inode recheck | low after installer implementation |
| Replaced package/bootstrap/manifest | digest/signature and root ownership verification | low after installer implementation |
| Reply/helper loss after effect | ambiguous result, scan-before-retry reconciliation | medium availability; low integrity |
| Compromised enrolled UID answers challenges | explicit Unix same-UID assumption | accepted model limitation |
| Compromised root/kernel/package manager | outside Vortix's threat boundary | accepted platform limitation |
| Standard mode runs full client as root | explicit compatibility tradeoff; recommend Background | accepted until user opts in |

No unresolved high-severity finding is accepted for implementation. Controls
marked “after U12” or “after installer implementation” are represented by
non-constructible/dormant seams in U11; authority remains unreachable until
those controls and their Linux/macOS adversarial tests are complete.
