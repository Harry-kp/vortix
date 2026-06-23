---
date: 2026-06-24
topic: flip-panel-back-faces
focus: What should each of the three flip-panel back faces reveal in vortix? Issue #235 community ideation.
mode: repo-grounded
issue: https://github.com/Harry-kp/vortix/issues/235
---

# Ideation: Flip-panel back faces (issue #235)

## Grounding Context

(See `/tmp/compound-engineering/ce-ideate/0b22f235/grounding.md` for the full grounding summary.)

Key constraints threaded through every survivor:

- **Front faces are stable** (per issue body) — survivors operate on back faces only.
- **Density via signaling, not duplication** — 4× rejected UI additions in repo history.
- **Multi-tunnel scoping is binding** — Security Guard back = primary; Connection Details back = focused; Chart back = primary per H7 telemetry attribution.
- **`SocketAudit` port already supplies both per-process (#166) and per-socket (#168) data** — they're two UI shapes over one source.
- **The flip pattern itself is novel** — vortix's own `ratatui-flip-panel` crate is the prior art.

## Topic Axes (Phase 1.5)

1. Throughput back face content
2. Connection Details back face content
3. Security Guard back face content
4. Cross-panel interactions & shared affordances
5. Density & graceful degradation

## Ranked Survivors

### 1. Verdict-first contract: the back face is proof, not the primary surprise

**Description:** Every back face leads with a single verdict line (e.g. *"47/47 sockets via primary utun3 ✓"*, *"Latency degraded 3min ago, stable since"*, *"3 processes active, 0 routed via VPN — LEAK"*). The table / sparkline / timeline beneath earns its rows by being evidence for the verdict — never primary signal. The front face is the headline; the back face is the proof. This is the meta-thesis that should govern all three sub-issue designs.

**Axis:** 4 (cross-panel & shared affordances) — applies uniformly to all three panels.

**Basis:** `direct:` CLAUDE.md / grounding §Density: *"Prefer one signal (e.g., '47/47 sockets via primary utun ✓' or 'all flows VPN-routed') over per-entity row dump. Earn the table from the verdict."* Six independent frames (Pain, Inversion, Assumption, Leverage, Analogy, Constraint) converged on this principle — strong signal it's the right invariant.

**Rationale:** The density principle has been tested 4+ times in this repo and rejected every UI addition that violated it. A 47-row scrolling table is exactly the "panel grew" outcome the principle pushes back against. Verdict-first inverts: the back face's first row tells you the answer; anything beneath is auditable evidence. Solves Q(c) "what's overkill?" structurally — the table is overkill whenever the verdict can stand alone.

**Downsides:** Requires picking the verdict vocabulary carefully (see #2 BackFace v1 spec for the implementation hook). Cuts against the "table-first" framing of #166 — the per-process table becomes the *evidence pane* below a verdict line, not the panel itself.

**Confidence:** 90% — directly grounded in repo's load-bearing density principle, with strong cross-frame convergence.
**Complexity:** Low (it's a design rule, applied per panel during implementation).
**Status:** Unexplored

---

### 2. "BackFace v1" spec — shared contract for all back faces

**Description:** Codify a `BackFaceLayout` contract every back face implements: row 0 verdict band (color + glyph + one phrase), middle rows panel-specific body, penultimate row scope footer (`scope: primary` / `scope: utun5 (focused, secondary)` / `scope: external-adopted (unauthoritative)` / `scope: windows (unsupported)`), last row nav-hint band (`/ filter  s sort  K act  Esc back`). Pair with a unified verdict vocabulary (`Excellent` / `Watching` / `Degraded` / `Failed` / `Unknown`) used in TUI rows, JSON envelope, and CLI siblings. Add a `BackFaceProvider<T>` trait promoted from `SocketAudit` so new back faces can be added without renderer plumbing. Optional sibling CLI: `vortix back <panel> --json`.

**Axis:** 4 (cross-panel & shared affordances).

**Basis:** `direct:` grounding §"Same port supplies #166 AND #168 — they're two UI shapes over one data source"; CLAUDE.md kill-switch helper section is the existing template (`KillSwitchMode::display_name`, `cli_verb`, etc.) — same shape applied to back-face verdicts. `external:` agent-native parity (any UI action → agent action) implies JSON envelope.

**Rationale:** Once shipped, #166/#167/#168 collapse to renderer-body code — the layout, vocabulary, scope handling, and CLI parity are all free. Adding a fourth back face six months from now becomes a new `BackFaceProvider` impl, not a renderer rewrite. Solves Q(d) cross-panel interactions structurally: shared sort/filter/Esc keys, common verdict vocabulary, consistent scope rendering.

**Downsides:** Up-front cost before any back face ships value — the contract has to be designed first. Risk of over-engineering: if the three back faces turn out to be heterogeneous enough that no useful common layout exists, the contract is just typing tax. Mitigation: prototype one back face inside the contract before committing to the others.

**Confidence:** 75% — strong leverage payoff but right-sizing the contract requires a brainstorm pass.
**Complexity:** Medium (trait + helper module + three renderer adaptations).
**Status:** Explored — selected as first build alongside survivor #4. Requirements: `docs/brainstorms/2026-06-24-backface-v1-spec-requirements.md`

---

### 3. Quality Timeline (#167) refinement — dual-timescale sparkline + verdict, not flat stats grid

**Description:** Replace the proposed flat menu of stats with a verdict line plus two stacked sparklines at different timescales — one for the last 60s, one for the last 10min, color-coded by quality. Verdict examples: *"Latency stable, 42ms avg"* / *"Latency degraded 3min ago — current 87ms"* / *"Loss spiking, 4% in last 60s."* Below: one row each for latency / jitter / loss, with the dual sparkline pair + numeric range. Session stats (min/avg/max/drops) collapse to a single row.

**Axis:** 2 (Connection Details back face content).

**Basis:** `direct:` grounding §Sub-issue proposals describes #167 as "latency/jitter/loss sparklines + session stats (min/avg/max RTT, drops, quality score%)" — a flat menu without privileging the inflection-point question that summons the flip. `external:` Tufte sparkline 45° rule (data must fill vertical range so slope carries meaning); trippy's per-hop sparklines render in-cell for the same reason.

**Rationale:** The pain summoning `f` on Connection Details is almost always *"this number changed — is it a blip or a trend?"* Two timescales answer that directly (60s sparkline carries the immediate context; 10min carries the trend). A flat stats grid forces the user to compute the answer mentally. Verdict line + dual sparkline turns "see history" into "diagnose change."

**Downsides:** Requires new state — jitter/loss history ring buffers (grounding §"Data NOT currently held"). Two timescales mean two ring buffers per metric. Modest memory cost but a real architectural addition that #167 as-proposed sidesteps.

**Confidence:** 80% — direct refinement of an already-named proposal; the shape change is principled.
**Complexity:** Medium (history ring buffers + dual-timescale layout in the existing connection_details renderer).
**Status:** Unexplored

---

### 4. EICAS-style alert ribbon for Security Guard back (#168)

**Description:** Borrow from aviation Engine-Indicating and Crew-Alerting System: the back face is a fixed ribbon at the top listing active anomalies only, strictly priority-ordered (Red Warning → Amber Caution → Cyan Advisory → white Status), one row per active issue. Below the ribbon, a single bold verdict line: *"47/47 sockets via primary utun3 ✓"* when the ribbon is empty. The 47-row socket table NEVER renders unless an exception exists. If three sockets leak, the ribbon shows three lines: `LEAK pid 4421 firefox → 1.1.1.1:443 (8s)`.

**Axis:** 3 (Security Guard back face content).

**Basis:** `external:` EICAS standard (Boeing 757-onwards, ARP 4102/4) — cockpit shows ONLY active alerts, never the 200 nominal parameters; "earn the row from the exception" is structurally the same principle as vortix's density principle. `direct:` grounding §Density: *"earn the table from the verdict."*

**Rationale:** Most VPN sessions are clean (the boring case axis 5 explicitly names). #168 as-proposed pays a 47-row carry cost every flip even when 47/47 are fine. EICAS inverts: silent until exception, exceptions-first when present, nominal data deliberately hidden because reading it during an alarm is dangerous. Maps cleanly to the verdict-first thesis (#1) and solves Q(c) "what's overkill?" for #168 specifically.

**Downsides:** Users who *want* to see the inventory during the all-OK case need a separate affordance (an explicit second key, or a "show all" filter). Risk: power users feel deprived. Mitigation: `s` cycles between "exceptions only" (default), "VPN sockets only", "all sockets" — but only when no exceptions are present.

**Confidence:** 70% — strong density alignment, novel for VPN-monitor space, but introduces an alarm-prioritization decision that needs a brainstorm.
**Complexity:** Low-Medium (ribbon + verdict line is small; the priority logic and "expand on demand" mode is the medium cost).
**Status:** Unexplored

---

### 5. Bloomberg small-multiples for Throughput back (#166 alternative)

**Description:** Replace the proposed flat per-process Network Activity Table with a 3×3 grid of tiny braille sparklines — one per top-bandwidth process over the last 60 ticks, each labelled `firefox 4.2M↓ V` (process | rate | 1-char route sigil: V/D/L). Sort by total bytes; ninth cell shows `+12 others`. No table, no sortable columns — the chart-shape stays the user's mental model. Verdict line above: *"3 processes active, 0 routed via VPN — LEAK"* or *"12 processes, all VPN-routed."*

**Axis:** 1 (Throughput back face content).

**Basis:** `external:` Bloomberg Terminal small-multiples (Tufte 1983) — compresses N time-series into a constant footprint by stripping chrome and using shape, not labels, to carry signal. trippy renders per-hop sparklines in table cells for the same density reason.

**Rationale:** The front face is a chart; flipping to a sortable per-process table is a context switch (table-reading mode vs chart-reading mode). Small-multiples keeps the user in chart mode but pivots from aggregate to per-process. Constant footprint regardless of process count. Differentiates vortix from `nethogs` / `bandwhich` (both columnar). Solves Q(a) for #166: maybe the right second view ISN'T a sortable table.

**Downsides:** Sortable columns / filter / kill-process affordances from #166 don't have a clean home in a grid — they become "select cell to expand" or move to a separate CLI. Some users prefer columnar; the grid is a stronger opinion. Per-process bandwidth state is still required (same data the table needed).

**Confidence:** 55% — interesting but uncommon at TUI density; needs a prototype to validate readability at 80×24.
**Complexity:** Medium-High (per-process polling + 3×3 layout + per-cell sparkline render).
**Status:** Unexplored

---

### 6. Single shared "Inspector" + entity pinning + role preset (alternative architecture)

**Description:** Replace three bespoke back faces with one shared full-screen Inspector overlay. Three tabs at top: `[bandwidth] [quality] [audit]`. `f` from any panel opens the Inspector pinned to that panel's tab; `←/→` cycles tabs. Every entity rendered (pid, remote IP, socket 5-tuple) is a node — `Tab` cycles "next related view" with the entity pre-pinned (pin `pid 4421` in bandwidth, Tab to audit with that pid filtered). Optional `--role={auditor,operator,observer}` startup flag picks per-tab default content. This is the "anything missing entirely?" answer — if the three-independent-back-faces design is wrong, this is what it would be replaced with.

**Axis:** 4 (cross-panel & shared affordances) — the architecture itself.

**Basis:** `external:` k9s `d`-describe full-screen detail pattern; Maltego/i2 Analyst's Notebook entity pivoting; Bubble Tea's stack-based model navigation. `reasoned:` grounding §Cross-panel question (235.d) — *"should jumping from Network Activity → Connection Audit be a single keypress?"* — is answered structurally by making them the same surface.

**Rationale:** Three back faces, three implementations, three sets of sort/filter conventions, three sets of column choices — the maintenance surface is real. One Inspector = one codebase, one keymap, free cross-panel jumps via Tab. Investigation workflows (chasing a leak through bandwidth → audit → quality) become natural instead of requiring three flips. Honors the issue's "anything missing entirely?" question by surfacing the alternative pattern.

**Downsides:** Invalidates the just-published `ratatui-flip-panel` crate as the primary UX pattern (the crate can still exist; vortix would no longer use it as primary). Full-screen overlay breaks the bounded-panel density philosophy. Migration cost is non-trivial. This is a real fork — survivors #1-#5 assume three independent back faces; this one rejects that premise.

**Confidence:** 50% — depends entirely on whether the maintainer treats three-independent-back-faces as fixed (then this is wrong) or as a design choice up for re-evaluation (then it deserves serious comparison).
**Complexity:** High (full alternative architecture).
**Status:** Unexplored

---

### 7. "n/a (secondary)" gets an explained back face with a workaround

**Description:** A focused secondary tunnel's Connection Details front face renders "Latency: n/a (secondary tunnel)" — dead end. The back face for that case should explain *why* (telemetry attribution rule) plus offer the actionable workaround in one line: *"Active probing through utun7 requires `curl --interface utun7`"*. Below: the secondary's available data (transfer stats history, handshake age timeline). Same pattern for Windows (`socket audit unsupported on Windows — use vortix audit --json on Linux/macOS`), no-root macOS (`partial socket inventory — same-user sockets only`), and external-adopted OpenVPN (`interface unmapped — verdict unauthoritative`).

**Axis:** 5 (density & graceful degradation).

**Basis:** `direct:` grounding §Multi-tunnel scoping: *"Connection Details for a focused secondary already renders 'Latency: n/a (secondary tunnel)'"* and *"Active probing through a secondary needs `curl --interface utunN`"*. `direct:` grounding §Cross-platform degradation enumerates four "we don't actually know" cases with no panel currently explaining them.

**Rationale:** The "n/a" / "Unsupported" cases are silent today — users see emptiness, not explanation. Back faces are the only place dense enough to teach the constraint AND offer the workaround without polluting front faces. Sets the precedent for how all three back faces handle the "front had nothing useful for this case" pattern. Generalizes the scope-footer idea from #2's spec into actionable content.

**Downsides:** Modest content per back face — for some cases, the explanation IS the back face. Could read as "back face says you can't have a back face." Mitigation: combine with whatever back-face content does exist for the available data (transfer stats history, handshake age timeline).

**Confidence:** 85% — clear pain, clear fix, low cost; uses existing data.
**Complexity:** Low (UI text + scope-footer helper, mostly).
**Status:** Unexplored

---

## Rejection Summary

| # | Idea | Reason rejected |
|---|---|---|
| 1.2 | Verdict line above process table | Subsumed by survivor #1 (verdict-first contract) |
| 1.6 | `?` per back face cheat-sheet | Covered by survivor #2 (BackFace v1 spec nav-hint band) |
| 1.7 | Jump key: leak row → PID | Subsumed by survivor #6 (Inspector entity-pinning) for shared-arch path; would be a sensible separate item only if three-independent-back-faces is kept |
| 1.8 | Boring-case audit trail | Subsumed by survivors #1 + #4 (verdict-first + EICAS) |
| 2.1 | Kill chart back face; replace front with one-line strip | Violates issue body's "front faces are stable" — subject-replacement-adjacent |
| 2.2 | `f` re-probes (verb not noun) | Invalidates just-published `ratatui-flip-panel` crate's reveal purpose |
| 2.3 | Single full-screen Inspector (standalone) | Captured in cross-cut survivor #6 |
| 2.4 | Drop Quality Timeline; promote grade to header | Header is space-constrained; density principle 4× rejected similar header additions |
| 2.5 | Back faces emit proactive alerts (no manual flip) | Auto-flip-on-anomaly is interesting but heavy; would need its own brainstorm; partly captured in #6 spirit |
| 2.6 | `f` writes JSON snapshot, no UI second face | Removes UI dimension entirely; the JSON envelope idea survives via #2 BackFace v1 spec |
| 2.7 | Kill `f` entirely; CLI subcommands only | Invalidates just-published crate; partly captured via #2's optional CLI sibling |
| 2.8 | Security Guard back = one sentence + number | Subsumed by survivors #1 + #4 |
| 3.1 | Back face as command palette | Removes data-reveal purpose; better as brainstorm variant |
| 3.2 | Single shared back face (Audit board) | Subsumed by survivor #6 (Inspector) |
| 3.4 | Time-travel back face (same panel in "last hour" mode) | Heavy state requirement; partially achievable via survivor #3 dual-timescale; full version is a brainstorm |
| 3.5 | Security Guard back = bandwidth-of-leaks | Captured by survivors #1 + #4 spirit (verdict-from-numbers) |
| 3.6 | Chart back = adversarial probe console (DNS/WebRTC/IPv6 leak tests) | Strong but novel — wants its own brainstorm; doesn't displace survivor #5 |
| 3.7 | Sequence-of-faces (N-face flip) | Adds UX cost (state per panel, dot indicator); sidesteps rather than answers Q(a) |
| 3.8 | Role-driven back face | Partially captured by survivor #6 role preset; standalone pushes off the design decision rather than making it |
| 4.1 | Shared BackFaceLayout contract | Subsumed by cross-cut survivor #2 |
| 4.2 | Unified verdict vocabulary | Subsumed by survivor #2 |
| 4.3 | Front-face summary band previewing back | Strong but adds front-face content (tension with "front faces are stable"); deferred to brainstorm |
| 4.4 | Back-face provider registry | Subsumed by survivor #2 |
| 4.5 | Flip-audit trace (`vortix audit --since-flip`) | Partly subsumed by survivor #2's CLI sibling; full version is a brainstorm |
| 4.6 | Standard scope footer | Subsumed by survivor #2 and given content by survivor #7 |
| 4.7 | Shared `/ s K Esc` affordance set | Subsumed by survivor #2 |
| 4.8 | Back-face JSON envelope | Subsumed by survivor #2 |
| 5.1 | Bedside vitals strip (ICU monitors) | Strong content alternative for #167, displaced by survivor #3 which already incorporates trend-via-dual-sparkline |
| 5.4 | DAW solo/mute | Strong cross-panel but requires changing the front-face chart (tension with "fronts are stable"); deferred to brainstorm |
| 5.5 | Forensic graph (Maltego pin-and-cycle) | Subsumed by survivor #6 |
| 5.6 | Observatory run log | Strong alternative content for #168, displaced by survivor #4 (EICAS) which serves similar density principle |
| 5.7 | SCADA topology view | Strong but adds an entirely new visual idiom (ASCII tree) — better as standalone brainstorm |
| 5.8 | ATC predicted-state extrapolation | Speculation logic feels heavy for ideation survivor; better brainstorm topic |
| 6.1 | Sigil-only back face | Useful thinking probe; lesson (one-glyph verdicts) captured by survivor #1 |
| 6.2 | Auto-flip on interesting | Heavy — push-vs-pull is its own brainstorm |
| 6.3 | All-back-at-once `F` flips all three | Interesting probe but adds an affordance not strongly motivated yet |
| 6.4 | Audience-shift (back face for auditor) | Reframe without concrete content; brainstorm question |
| 6.5 | Stateless back face | Useful info (#167 could be stateless), partly captured by survivor #3's dual-timescale; standalone is a tradeoff doc |
| 6.6 | 5-second-window back face | Thinking probe — lesson (1-line headline mandatory) captured by survivor #1 |
| 6.7 | Identity-flip (all back faces same content) | Thinking probe; not a viable standalone design |
| 6.8 | CLI-only back face | Subsumed by survivor #2's JSON envelope + CLI sibling |
