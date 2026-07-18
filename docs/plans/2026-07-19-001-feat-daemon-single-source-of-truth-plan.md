---
date: 2026-07-19
seq: 001
type: feat
slug: daemon-single-source-of-truth
status: active
depth: deep
origin: docs/brainstorms/2026-07-18-daemon-tunnel-ownership-requirements.md
issues: ["#234", "#250", "#153", "#16"]
supersedes: docs/plans/2026-07-18-001-feat-daemon-tunnel-ownership-plan.md
---

# Plan: Daemon as the single source of truth

> **Why this supersedes the 2026-07-18 arc.** The prior plan sequenced the
> daemon as incremental capabilities (Remote read → registry → CLI writes →
> supervision → boot). Building it that way produced a working *server* but an
> unstable *architecture*: the daemon carried a single-tunnel FSM **and** a
> separately-scanned registry, while the TUI ran a **third** in-process engine.
> A 5-reviewer audit (2026-07-19) found a cluster of bugs (false-success
> reconnect, "connected to B" lies, wrong-tunnel `down`) that were **all
> symptoms of unsynchronized sources of truth**. This plan re-centers the arc
> on the end goal — one owner of state, every UI a thin client — and sequences
> the work to collapse the three stores into one. The prior plan's shipped work
> is not thrown away; it is re-homed (see "What's already built").

## North Star

**One long-lived process owns all VPN state and is the only thing that mutates
it. The CLI, TUI, and any future GUI are thin clients that read, subscribe, and
command through it, so every surface is always in sync — the way `redis-cli`,
libraries, and dashboards all see one `redis-server`.** `up`/`down` are
singleton operations against that one owner. State — and the tunnels
themselves — survive any individual client exiting, the daemon restarting, and
the machine rebooting.

Two guardrails keep the star sharp:

1. **Authoritative when present, never *required*.** vortix's identity is
   works-over-SSH, zero-fuss. On a box with no daemon, `sudo vortix up <p>`
   still works, self-contained, with today's behavior — just without
   cross-process sync/persistence. The daemon is the source of truth *when it
   is running*; the no-daemon path stays first-class (R11) and is protected by
   a golden-parity suite.
2. **The daemon's primary value is persistence + headless supervision +
   kill-switch-across-reboot + no-sudo.** Multi-surface *sync* is a benefit
   that falls out for free once one process owns state — it is not the main
   justification, and must not outrank the supervision/persistence guarantees
   in scope decisions.

## Acceptance tests (the four scenarios — this plan is done when these pass)

These are the user's stated goals, promoted to the arc's definition of done.
Each is a live test on the DigitalOcean infra (`scripts/test-infra.sh`), across
both WireGuard and OpenVPN profiles.

- **S1 — Persistence across client exit.** `sudo vortix up <ovpn>` in a
  terminal; close the terminal. The tunnel stays up **and** the daemon still
  owns/reports it. Then reboot (with a daemon service installed): the tunnel
  (or the armed kill switch) persists per policy.
- **S2 — Instant, complete attach.** With a tunnel up, open the TUI in another
  terminal. It **instantly** shows the connected profile, its live
  telemetry/logs, and kill-switch state — sourced from the daemon, not
  independently re-derived.
- **S3 — Bidirectional sync.** A mutation on the TUI (connect/disconnect/
  kill-switch change) is reflected in the CLI's next `status`, and a CLI
  mutation is reflected live in an open TUI. Neither surface holds private
  state the other can't see.
- **S4 — Many clients, one state.** Multiple TUIs (and CLIs) open at once all
  show identical state and stream the same events. No duplicate engines, no
  duplicate scanners, no divergent views, no double-execution of a command.

Supporting acceptance examples from the origin brainstorm (AE1 no-sudo, AE2/AE3
headless reconnect, AE4 daemon-restart survival, AE5 reboot leak window, AE6
no-daemon parity, AE7 arbitration, AE8 version skew) remain and map onto the
phases below.

## The core architectural decision

**The daemon owns a registry of per-profile engines, and that registry is the
one and only source of truth.** Everything else follows from this.

Today there are three state stores:

| Store | Owner | Problem |
|---|---|---|
| Single `EngineHandle` FSM | daemon | one tunnel only; never told about drops → goes stale |
| Scanned `RegistryHandle` | daemon | separate from the FSM; only kernel-derived |
| In-process engine | each TUI | a third truth, per TUI process |

The target is **one** store: a `RegistryHandle` that owns `N` real, drivable
`Engine<TunnelKind>` instances — one per active/connecting tunnel — and
serializes **all** mutation through its single owner task (the redis-server
analog). Then:

- **Connect/Disconnect/Reconnect `{profile}`** drive *that profile's* engine.
  No shared slot, no cross-profile clobber (retires F1–F4 structurally).
- **Supervision** (drop detection, retry ladder, kill-switch sync, netmon)
  drives the same per-profile engines — not a parallel bookkeeping registry.
- **The kernel scanner is an *input*, not a truth store:** it feeds observed
  sessions to the registry (adoption = create/refresh an engine for an
  externally-started tunnel), and confirms reconnect success. It never holds
  authoritative state of its own.
- **Snapshots + the event stream** are projections of this one store, served
  over IPC. Every client renders from them; no client re-derives state.

The `EngineHandle::{Local,Remote}` seam already models "in-process vs.
daemon-hosted." The target makes **Remote** the path every surface takes when a
daemon is present, and keeps **Local** as the self-contained no-daemon path.

```
          ┌──────────────────────── vortix daemon (root, boot-started) ────────────┐
          │  RegistryHandle  = THE state (single owner task, all mutation serial)   │
          │    profile "corp" → Engine<TunnelKind>  (real, drivable)                │
          │    profile "home" → Engine<TunnelKind>  (real, drivable)                │
          │  supervisor: scan → adopt/refresh/drop → retry/kill-switch on engines   │
          │  IPC server: RegistrySnapshot (projection) + event stream + Execute     │
          └────────────────────────────────────────────────────────────────────────┘
   owner-UID gate │ ▲ subscribe (events)   ▲ snapshot (state)   ▲ execute (commands)
                  ▼ │                       │                    │
   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │ vortix CLI │   │  vortix TUI│   │  vortix TUI│   │   (future  │
   │ thin client│   │ thin client│   │ thin client│   │    GUI)    │
   └────────────┘   └────────────┘   └────────────┘   └────────────┘
        └───────────── no daemon? → in-process Engine::Local (self-contained, R11) ┘
```

## Scope

**In scope:** everything required for S1–S4 plus the origin arc — per-profile
engine ownership, owner-based auth, CLI + TUI as thin clients, event streaming
consumed live, persistent boot service, early-boot kill switch, and the
no-daemon path preserved bit-for-bit.

**Out of scope (unchanged from origin):** Windows; multi-user ACLs beyond a
single owner; auto-spawn-on-demand; per-tunnel OS units; a network-exposed
daemon API; new TUI panels beyond what sync requires.

## Requirements traceability

| Origin req | Delivered by |
|---|---|
| R1 daemon owns registry | P1 |
| R2 CLI writes via IPC | P3 |
| R3 TUI as client | P4 |
| R4 registry snapshot + events over IPC | P1 (served), P4 (consumed) |
| R5 supervision in daemon | P1 |
| R6 arbitration | P1 (single owner serializes) + P3 |
| R7 tunnels survive daemon restart | P1 (adoption) |
| R8 early-boot kill switch | P5 |
| R9 boot-persisted profiles | P5 |
| R10 privilege separation | P2 (owner gate + hardening), P6 (audit) |
| R11 no-daemon parity | every phase; verified P6 |
| R12 service install/uninstall | P5 |
| R13 version-skew detection | already shipped (U1) |

## Phased delivery

Each phase leaves `main` shippable and the no-daemon path green. Phases are the
commit-groups within PR #251 (or its successor).

### P1 — Daemon owns per-profile engines (the keystone)

**Goal:** collapse the daemon's single-FSM + scanned-registry into one
`RegistryHandle` that owns a real `Engine<TunnelKind>` per tunnel and serializes
all mutation. Route every daemon-side Connect/Disconnect/Reconnect and all
supervision through the per-profile engine. Adoption creates a real (drivable)
engine, not a placeholder; success/drops are confirmed by the scanner feeding
the registry.

**Delivers:** S3/S4's "single source of mutation" server-side; AE2/AE3 correct
multi-tunnel reconnect; AE4 restart survival; AE7 arbitration (one owner task
serializes commands). Structurally retires F1–F4.

**Retires:** the daemon's shared single `EngineHandle`; the placeholder-engine
adoption; the client-side re-scan honesty patches (no longer needed once the
daemon state is authoritative).

**Verification:** unit tests on the registry actor (per-profile connect/
disconnect/reconnect isolation; adoption creates a drivable engine; drop →
retry drives the right engine); loopback integration (two profiles, independent
lifecycles); live AE2/AE3/AE4 on the droplet.

### P2 — Owner-based auth (reach a root daemon without sudo)

**Goal:** the UID gate accepts the daemon's **owner** UID (the user who
installed it), not only its own euid — so a root daemon serves its owning user.
Establish the owner at install/config time (not client-assertable). Keep the
server-side input hardening. The client's socket-owner check (already shipped)
is the reciprocal.

**Delivers:** AE1 no-sudo — the reason the review found no-sudo "fail-closed but
non-functional." No privilege escalation: the daemon only executes validated
vortix operations for its configured owner.

**Verification:** owner-UID accept + foreign-UID reject tests; the daemon must
assert it is root before offering privileged ops; security review of the owner-
establishment path (P6 confirms).

### P3 — CLI as a complete thin client

**Goal:** every CLI op routes through the daemon when present — reads (status/
list) and writes (up/down/reconnect/killswitch) — against the per-profile
engines from P1, so `up B`/`down B`/`reconnect B` target the right tunnel and
report truthfully by construction (not via re-scan patches). No-daemon → Local,
unchanged.

**Delivers:** AE1/AE7 end-to-end for the CLI; removes the honest-failure
stopgaps from the review fixes.

**Verification:** CLI integration against a loopback daemon for each verb;
no-daemon golden parity (P6); live multi-tunnel up/down/reconnect targeting.

### P4 — TUI as a thin client (the cutover)

**Goal:** when a daemon is present, the TUI does **not** start its own engine/
scanner/retry/netmon; it renders from `RegistrySnapshot`, streams events via
`subscribe`, and sends commands via `execute`. When absent, it runs the
in-process engine exactly as today (Local fallback). Translate daemon events
into the existing `Message` variants so render handlers are minimally
disturbed.

**Delivers:** **S2, S3, S4** — the heart of the North Star. This is the piece
that makes multiple UIs share one state.

**Execution note:** highest live-iteration need in the arc — TUI correctness
(smooth render, no flicker, no-daemon path intact) is only verifiable in a real
terminal. Build behind the daemon-present gate; validate live against the infra;
keep the Local path continuously exercised.

**Verification:** event→Message translation unit tests; TUI-with-daemon starts
no local scanner (assert via runtime flag); live S2/S3/S4 with two TUIs + a CLI
against one daemon; no-daemon TUI regression suite.

### P5 — Persistent service (always-on owner)

**Goal:** `vortix service install/uninstall` generating systemd units / launchd
plists + the early-boot blocking unit; boot-persisted profiles; kill-switch
across reboot. `sudo` elevation, no GUI dialogs (SSH-friendly). Uninstall leaves
zero artifacts.

**Delivers:** S1's "across shutdown/reboot"; closes #250 (reboot kill-switch
gap) and #16 (boot persistence); AE5.

**Verification:** unit/plist generation goldens; carve-out ruleset tests;
uninstall-leaves-nothing tests; live reboot leak-window test on the droplet.

### P6 — Closure

**Goal:** no-daemon golden-parity suite (AE6/R11 — protects the default path);
kill-switch-on-drop firewall; security review of the whole boundary; README +
`docs/manual-testing` rows framed around S1–S4; CHANGELOG; close
#234/#250/#153/#16.

**Verification:** golden parity green in CI; security findings resolved/filed;
S1–S4 executed and recorded; all four issues closed with evidence.

## What's already built, and how it folds in

The 2026-07-18 arc (PR #251, all CI-green) is the foundation, not waste:

| Already shipped | Fate under this plan |
|---|---|
| Version handshake, `EngineHandle::Remote` (snapshot/registry/execute/subscribe) | **Kept** — the client seam every thin client uses |
| IPC server: concurrent accept, dispatch, input validation, socket-owner check, graceful shutdown, idle/scan timeouts | **Kept** — hardened transport for P1–P4 |
| Subscribe event streaming (server push + client reader) | **Kept** — P4 consumes it in the TUI |
| `RegistryHandle` actor + reconcile/adoption/retry | **Evolved in P1** — from bookkeeping + placeholder engines into the owner of real per-profile engines |
| Daemon's single shared FSM | **Retired in P1** — replaced by per-profile engines |
| Review fixes F1–F4 (honest reporting via re-scan / profile-match) | **Superseded in P1/P3** — correct-by-construction once state is authoritative; the stopgaps come out |
| UID gate `peer_uid == daemon_uid` | **Changed in P2** — owner-UID |
| R7 startup adoption, headless auto-reconnect (fresh-engine) | **Folded into P1** — becomes per-profile-engine driven |

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| P1 registry-of-engines is a large refactor of the daemon core | Land it behind the existing IPC surface with the no-daemon path untouched; heavy unit + loopback coverage before live; it *removes* net complexity (three stores → one) |
| P4 TUI cutover regresses the default no-daemon UX | Gate strictly on daemon-present; keep Local path compiled + tested; event→Message translation keeps render handlers stable; live-validate |
| P2 owner-auth widens the privilege boundary | Owner set at install (root-only), never client-asserted; retain input hardening; P6 security review of the establishment path |
| Two execution paths (Local/Remote) forever | Accepted standing cost; the `EngineHandle` seam confines the branch to one place; golden-parity suite makes Local regressions loud |
| Scope creep toward "sync demos" over supervision | Guardrail 2: persistence/kill-switch/supervision outrank sync in every scope call |

## Success metrics

- **S1–S4 all pass live** on WireGuard and OpenVPN profiles.
- AE1–AE8 pass; #234/#250/#153/#16 closed.
- No-daemon golden-parity suite green in CI throughout.
- The daemon holds exactly one authoritative state store; no surface re-derives
  it when the daemon is present.

## Verification plan (every phase)

Full CI parity per `docs/ci-parity.md` before each push; live verification on
the DigitalOcean infra (`vortix-test-397797` servers + a Linux client droplet)
for P1–P5; macOS manual passes for install/uninstall (P5) and the TUI cutover
(P4).
