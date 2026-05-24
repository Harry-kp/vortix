---
plan_id: 2026-05-24-014
title: "feat: v0.3.0 announcement materials"
type: feat
status: completed
created: 2026-05-24
target_branch: refactor/architectural-migration-v1
target_pr: 201
target_version: 0.3.0
related_plans:
  - 2026-05-24-007-feat-rollout-architectural-migration-v1-plan.md
  - 2026-05-24-008-feat-architectural-completion-quick-wins-plan.md
---

# feat: v0.3.0 announcement materials

## Problem Frame

PR #201 ships v0.3.0 — the architectural migration v1 bundle (six
plans, 34+ commits, ~16k LOC, 155+ files) plus the rollout playbook
and the quick-wins completion sweep. Existing v0.3.0 documentation
covers three audiences cleanly:

- `docs/MIGRATION.md` — "I'm upgrading. What do I do?"
- `docs/RELEASE-PLAYBOOK-v0.3.0.md` — "I'm shipping the release. What
  steps do I follow?"
- `docs/architecture-migration-v1.md` — "I'm contributing. What's the
  technical surface map?"

What's missing is the **scannable, conversational "what changed?"
artifact** — the one any user, contributor, or curious passer-by
opens after seeing "v0.3.0 available" in their terminal or feed. It
needs to answer the simple-question form ("what's new?") in under 30
seconds. None of the three existing docs do that — they're too long,
too task-oriented, or too technical.

This plan also delivers the secondary surfaces an announcement
benefits from: a short FAQ for the most common upgrade-time questions,
a README "What's new" subsection, a CHANGELOG curated preamble (added
at release-plz-PR-review time), a GitHub Release body template the
maintainer pastes into both the RC and GA releases, and the
announcement-copy variants the existing playbook can grow into.

Everything is documentation. No code changes. Lands in PR #201
alongside the rollout work so v0.3.0 ships with its announcement
in place.

---

## Summary

Six units, all documentation:

- **U1.** `docs/v0.3.0-RELEASE-NOTES.md` — the "what changed?"
  highlights doc. 100% the single source of truth that every other
  artifact links into.
- **U2.** `docs/v0.3.0-FAQ.md` — focused FAQ answering 6 most-likely
  upgrade-time questions.
- **U3.** README.md — replace the existing one-line upgrade banner
  with a "What's new in v0.3.0" subsection pointing at U1, U2, and
  MIGRATION.md.
- **U4.** Playbook addition — instruction for the maintainer to inject
  a curated preamble into the release-plz CHANGELOG PR before merging.
- **U5.** Playbook addition — GitHub Release body templates for both
  `v0.3.0-rc.1` and `v0.3.0` GA, plus refined discussion #184 post
  copy.
- **U6.** Playbook addition — broadcast-copy templates (short, neutral)
  for the post-72h amplification window: tweet/Mastodon/Bluesky and a
  Hacker News "Show HN" draft.

---

## Scope Boundaries

**In scope:**
- The six units above
- Cross-linking between MIGRATION.md, RELEASE-NOTES, FAQ, and README
  so a user finding any one of them can navigate to the others
- Wording style consistent with vortix's existing terse-table README
  voice

**Deferred to Follow-Up Work:**
- In-TUI "What's New" overlay (issue #164) — UI work, separate plan
  (014 reserves the slot for announcement docs; a future plan covers
  the overlay)
- Updating the GitHub repo description / social card
- A separate blog post on the Every / personal channel
- Localised versions of the announcement materials

**Outside this product's identity:**
- Marketing-funnel pages, landing-page-style copy, conversion CTAs.
  Vortix's voice is terse and table-heavy; announcement copy stays in
  that register
- Pre-recorded video demos / asciicasts of the new commands

---

## Requirements

| ID | Requirement | Source |
|----|-------------|--------|
| R1 | A user reading `docs/v0.3.0-RELEASE-NOTES.md` can answer "what's new in v0.3.0?" in under 60 seconds | Origin: user's framing — "simple question from any user what has changed" |
| R2 | A user with a common upgrade question (safety, profiles, .auth files, CLI changes, rollback, secret store) finds a clear answer in `docs/v0.3.0-FAQ.md` | Origin: pre-empts most-likely first-week support burden |
| R3 | The README's landing surface has a "What's new in v0.3.0" subsection visible above the fold, linking to release notes / FAQ / MIGRATION | Origin: announcement discoverability |
| R4 | CHANGELOG.md for v0.3.0 carries a curated preamble framing the bundle, in addition to release-plz's auto-generated per-commit entries | Origin: scale of bundle deserves framing; release-plz output reads as a developer changelog |
| R5 | The release playbook contains a copy-pasteable GitHub Release body template for both `v0.3.0-rc.1` and `v0.3.0` | Origin: maintainer needs zero-friction publish step |
| R6 | The release playbook contains short, neutral broadcast-copy templates for tweet/Mastodon/Bluesky/HN, reserved for the 72h+ post-GA window | Origin: avoid writing under pressure when the window opens |

---

## Key Technical Decisions

### D1. RELEASE-NOTES is the single source of truth
Every other surface (FAQ, README, GitHub Release body, broadcast copy, CHANGELOG preamble) links to or extracts from `docs/v0.3.0-RELEASE-NOTES.md`. Changes to the message happen in one place. Rationale: amplification venues will be edited and re-shared over weeks; a single canonical artifact keeps them consistent.

### D2. FAQ is question-format, not how-to
`docs/MIGRATION.md` already has the upgrade-instructions how-to. The FAQ uses the question/answer format because users searching "vortix 0.3.0 break my .auth?" land on a literal answer, not a procedure. The two artifacts are complementary, not redundant — the FAQ links to MIGRATION sections for procedural answers.

### D3. CHANGELOG preamble is injected at release-plz-PR-review time
`release-plz` regenerates the CHANGELOG from conventional commits via the cliff template. Pre-populating `[Unreleased]` risks being overwritten or merged in surprising ways. The playbook instructs the maintainer to add the curated preamble (3–5 lines) between the version heading and the first `### Features` group **after** release-plz opens its PR, before merging. The preamble text is stored in this plan / RELEASE-NOTES so the maintainer copy-pastes from a known source.

### D4. Broadcast copy is reserved, not embargoed
The 72h-post-GA waiting period in the playbook stands. But the *drafts* live in the playbook now, so when the window opens the maintainer pastes a known-good message rather than composing one cold while watching for regressions. Drafts use neutral framing ("v0.3.0 ships an architectural migration") rather than hype ("biggest release ever") so they age well.

### D5. Voice and tone match the existing README
Terse, table-heavy where appropriate, no marketing fluff, links over prose. The README is the voice anchor for the project; announcement materials read consistent with it.

---

## Implementation Units

### U1. Write `docs/v0.3.0-RELEASE-NOTES.md`

- **Goal:** A scannable highlights doc that answers "what changed in v0.3.0?" in under 60 seconds of reading.
- **Requirements:** R1
- **Dependencies:** none
- **Files:**
  - `docs/v0.3.0-RELEASE-NOTES.md` (new)
- **Approach:** Sections in this order, kept tight:
  1. **One-line frame:** "v0.3.0 is the architectural migration v1 ship. Upgrade is automatic; existing profiles, CLI commands, and killswitch state all keep working unchanged."
  2. **Highlights** — 5–7 bullets max, one line each, each linking to a relevant deeper doc:
     - Engine FSM + JSONL session journal → link to `vortix journal --help` and `crates/vortix-core/src/engine/`
     - Layered secret store (keyring + AES) → link to `docs/MIGRATION.md#encrypted-secret-store-opt-in`
     - Six new CLI subcommands → link to README's "New in v0.3.0" subsection
     - Hardened startup (defense-in-depth migration, orphan scan, perf ceiling)
     - Cargo workspace + 12 crates → link to `docs/architecture-migration-v1.md`
     - JSON output now carries `schema_version` → link to module docs
  3. **What's automatic** — 3 bullets: profile sidecar backfill, existing CLI unchanged, killswitch state preserved across upgrade
  4. **What's opt-in** — 3 bullets: encrypted secrets via `vortix secrets set`, session journal (default on, opt-out via settings), figment settings.toml
  5. **What's NOT in v0.3.0** — explicit non-goals: no Windows binary (stub crate only), no daemon mode, no lifecycle hooks (those are in plans 009/010 for future PRs)
  6. **For maintainers / contributors** — one line linking to `docs/architecture-migration-v1.md` and the plan series
  7. **Upgrade & rollback** — one line linking to `docs/MIGRATION.md`
  8. **Got questions?** — one line linking to `docs/v0.3.0-FAQ.md` and discussion #184
- **Patterns to follow:** README's terse, table-heavy voice; one-line bullets; links over prose. Reference the existing `## Features` and "Why Vortix?" sections of README for the right register.
- **Test scenarios:** Test expectation: none — documentation-only unit.
- **Verification:** Maintainer reads top-to-bottom in under 60 seconds. Every internal link resolves (no broken paths). Word count under 600.

### U2. Write `docs/v0.3.0-FAQ.md`

- **Goal:** Six focused Q&A pairs answering the questions a v0.2.x user is most likely to ask in their first hour of v0.3.0.
- **Requirements:** R2
- **Dependencies:** U1 (FAQ links to release notes for context)
- **Files:**
  - `docs/v0.3.0-FAQ.md` (new)
- **Approach:** Question-format, not procedure-format. Each answer is 2–4 sentences plus optional link to MIGRATION for the deeper how-to. Six questions:
  1. **Is the upgrade safe? Will I lose anything?** — answer: idempotent migration, nothing destructively rewritten, rollback is one command.
  2. **Will my existing profiles work?** — answer: yes, no flags to change, sidecars appear automatically next to .conf/.ovpn.
  3. **What happens to my OpenVPN `.auth` files?** — answer: unchanged, legacy path still honored, optionally move to encrypted store via `vortix secrets set`.
  4. **Did `vortix up/down/status/list/import` change?** — answer: no, all unchanged. Six *new* additive subcommands; link to README "New in v0.3.0".
  5. **How do I roll back if something breaks?** — answer: `cargo install vortix --version 0.2.2 --force` (or equivalent for Homebrew/npm). Migration artifacts are inert to v0.2.x.
  6. **What's the encrypted secret store and do I have to use it?** — answer: opt-in via `vortix secrets set`; nothing else touches it; existing auth flows unchanged.
  - Header line: "Frequently asked questions about Vortix v0.3.0. For step-by-step upgrade instructions see `docs/MIGRATION.md`."
  - Footer line: "Question not here? Open an issue or check discussion #184."
- **Patterns to follow:** existing README troubleshooting section style; question as `### How do I X?`; answer as 2–4 sentence paragraph.
- **Test scenarios:** Test expectation: none — documentation-only unit.
- **Verification:** Each Q&A is self-contained; a user landing on the FAQ via search lands on a complete answer without having to read above or below the question.

### U3. Update `README.md` — "What's new in v0.3.0" subsection

- **Goal:** Replace the existing one-line upgrade banner with a richer "What's new" subsection that lives at the top of the README and links to RELEASE-NOTES + FAQ + MIGRATION.
- **Requirements:** R3
- **Dependencies:** U1, U2
- **Files:**
  - `README.md` (modify)
- **Approach:**
  - The current banner (added in plan 007 U6) reads: *"Upgrading from v0.2.x? Read [the migration guide](docs/MIGRATION.md) — it takes two minutes."*
  - Replace with a slightly fuller subsection between the one-line description and the demo gif, kept above-the-fold:
    ```
    > **New in v0.3.0 — architectural migration v1.** Engine FSM, session
    > journal, encrypted secret store, six new CLI subcommands. Upgrade is
    > automatic; existing profiles and commands work unchanged.
    >
    > - [Release notes](docs/v0.3.0-RELEASE-NOTES.md) — what changed (60s read)
    > - [Upgrade guide](docs/MIGRATION.md) — for v0.2.x users
    > - [FAQ](docs/v0.3.0-FAQ.md) — common upgrade questions
    ```
  - Mirror the existing blockquote style used elsewhere in the README for tip boxes.
- **Patterns to follow:** existing README structure; blockquote prefix `>`; one short paragraph then 3 bullets.
- **Test scenarios:** Test expectation: none — documentation-only unit.
- **Verification:** GitHub renders the subsection cleanly; all three links work; no broken paths.

### U4. Add CHANGELOG preamble instruction to release playbook

- **Goal:** Document the curated CHANGELOG preamble text and the procedure for injecting it into the release-plz-generated CHANGELOG PR before merging.
- **Requirements:** R4
- **Dependencies:** U1 (preamble draws from RELEASE-NOTES)
- **Files:**
  - `docs/RELEASE-PLAYBOOK-v0.3.0.md` (modify — add a subsection under Stage 5)
- **Approach:**
  - Add a step in Stage 5 ("Promote to GA") between "verify release-plz PR proposes v0.3.0" and the merge step. Title: "Inject CHANGELOG preamble before merge."
  - Provide the exact preamble text (3–5 lines) to paste between the `## [0.3.0] - YYYY-MM-DD` heading and the first `### Features` block. Example preamble:
    ```
    > **Architectural migration v1.** This release lands six coordinated
    > plans: Cargo workspace split, CommandRunner port, capability ports +
    > Platform aggregate, Tunnel trait + per-protocol crates, Engine FSM
    > + JSONL session journal, and a layered Config / ProfileStore /
    > SecretStore. Existing CLI commands, profiles, and killswitch state
    > are preserved unchanged. See [v0.3.0 release notes](docs/v0.3.0-RELEASE-NOTES.md)
    > and [upgrade guide](docs/MIGRATION.md).
    ```
  - Document that release-plz's regeneration on subsequent runs *will* preserve manually-edited preamble text as long as the structural markers (`## [version]` headings, `###` groups) remain intact. If a future release-plz run wipes it, the playbook tells the maintainer to re-paste from the canonical text here.
- **Patterns to follow:** existing playbook Stage structure; numbered substeps within a stage.
- **Test scenarios:** Test expectation: none — runbook content.
- **Verification:** A maintainer reading the new Stage 5 step can paste the preamble into the release-plz PR without ambiguity. The preamble text matches RELEASE-NOTES's framing.

### U5. Add GitHub Release body templates + refine discussion #184 post

- **Goal:** Provide copy-pasteable GitHub Release body templates for both `v0.3.0-rc.1` (prerelease) and `v0.3.0` (GA), and refine the existing discussion #184 RC-soak post template.
- **Requirements:** R5
- **Dependencies:** U1, U2 (templates link to RELEASE-NOTES and FAQ)
- **Files:**
  - `docs/RELEASE-PLAYBOOK-v0.3.0.md` (modify — add subsections to Stage 3 and Stage 5)
- **Approach:**
  - **RC Release body template** (Stage 3 addition):
    ```
    Release candidate for v0.3.0 — the architectural migration v1 ship.

    **Soak period:** [5–7 days, target promote date YYYY-MM-DD]
    **For testers:** install, run `bash <(curl -sL …/scripts/smoke-v0.3.0.sh) 0.3.0-rc.1`, report on discussion #184
    **What changed:** [link to docs/v0.3.0-RELEASE-NOTES.md]
    **Upgrade safety:** [link to docs/MIGRATION.md]

    Roll back: `cargo install vortix --version 0.2.2 --force`
    ```
  - **GA Release body template** (Stage 5 addition):
    ```
    v0.3.0 ships the architectural migration v1 bundle. Six plans, ~16k
    LOC, every existing CLI command preserved.

    - [What changed](docs/v0.3.0-RELEASE-NOTES.md) (60s read)
    - [Upgrade guide](docs/MIGRATION.md)
    - [FAQ](docs/v0.3.0-FAQ.md)

    Thanks to RC testers in #184 who soaked this for [N] days.

    Roll back: `cargo install vortix --version 0.2.2 --force`
    ```
  - **Discussion #184 RC post** — refinement of the existing template in Stage 4 of the playbook. Tighter, three-section structure: install (one-line per channel), test (point at smoke script), report (point at the comment thread). Link to RELEASE-NOTES + MIGRATION + FAQ.
- **Patterns to follow:** existing release-body conventions in past vortix releases (skim `gh release view v0.2.2` for shape).
- **Test scenarios:** Test expectation: none.
- **Verification:** Templates are self-contained; maintainer pastes without editing more than the date/version-number placeholders.

### U6. Add 72h-post-GA broadcast templates to playbook

- **Goal:** Short, neutral copy variants for tweet / Mastodon / Bluesky / HN that the maintainer can paste when the 72h window opens, without composing under pressure.
- **Requirements:** R6
- **Dependencies:** U1 (links to RELEASE-NOTES)
- **Files:**
  - `docs/RELEASE-PLAYBOOK-v0.3.0.md` (modify — add subsection under Stage 6)
- **Approach:**
  - New Stage 6 subsection: "Broadcast templates (use only after 72h post-GA with no reported issues)."
  - Provide four template variants:
    - **Twitter / Bluesky / Mastodon (280-char form):**
      ```
      Vortix v0.3.0 is out — architectural migration v1.

      Engine FSM, session journal, encrypted secret store, six new CLI
      subcommands. Existing profiles & commands work unchanged.

      What changed → [github.com/Harry-kp/vortix/blob/main/docs/v0.3.0-RELEASE-NOTES.md]
      ```
    - **Hacker News "Show HN" form:**
      ```
      Title: Show HN: Vortix v0.3.0 — TUI for WireGuard/OpenVPN with real-time telemetry

      Body:
      Vortix is a terminal UI for managing WireGuard and OpenVPN with
      live telemetry, killswitch, and leak detection. v0.3.0 just shipped
      after an architectural migration — Engine FSM, session journal,
      encrypted secret store, six new CLI subcommands.

      Background: I built this because the existing options (wg show,
      NetworkManager, Tunnelblick) either lacked real-time telemetry or
      required a GUI. ~15MB RAM, <500ms startup, keyboard-driven, works
      over SSH.

      Source / install: github.com/Harry-kp/vortix
      What's in 0.3.0: [link]
      ```
    - **Reddit (r/selfhosted / r/linux) form:** a 3–4 paragraph variant
      between the tweet's terseness and the HN post's length. Same content,
      different rhythm.
  - Tone guidance: neutral framing ("ships," "is out") rather than hype ("biggest release," "game-changing"). Drafts age well; hype dates fast.
  - Explicit reminder above the templates: "Do not post these until the 72h-post-GA monitoring window closes with no P0 incidents."
- **Patterns to follow:** existing playbook Stage 6 monitoring section structure.
- **Test scenarios:** Test expectation: none.
- **Verification:** Each template is self-contained, fits the channel's character/style limits, and links to RELEASE-NOTES as the canonical "what changed?" source.

---

## System-Wide Impact

| Surface | Impact | Mitigation |
|---|---|---|
| README landing page | "What's new" subsection now occupies ~6 lines above the fold | Mirrors existing tip-box convention; doesn't displace "Why Vortix?" or "Features" |
| Existing `docs/MIGRATION.md` | Becomes one of three v0.3.0 docs linked from README; not modified by this plan | Linked from RELEASE-NOTES + FAQ + README so discoverability improves, not degrades |
| Existing `docs/RELEASE-PLAYBOOK-v0.3.0.md` | Gains four subsections (U4, U5×2, U6) | Each addition slots into the existing Stage 3/4/5/6 structure |
| Search engines / link previews | New RELEASE-NOTES URL becomes the canonical "what's new" target | RELEASE-NOTES uses the same H1 style and keywords as the README so SEO is consistent |
| CHANGELOG.md | Untouched by this plan; preamble added at release-plz-PR-review time per U4 | Not pre-populated; release-plz handles structure |

---

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| RELEASE-NOTES drifts out of date as v0.3.x patches ship | Medium | Low | Document is named with the version in the filename; v0.4.0 gets its own RELEASE-NOTES, this one stays as the historical record |
| FAQ misses a question that becomes common | Medium | Low | The 6-question scope is a launch baseline; new questions get appended after launch as they surface |
| release-plz overwrites the CHANGELOG preamble on subsequent runs | Low | Low | U4's playbook step documents re-paste from canonical text. release-plz typically preserves manual edits between auto-generated markers; first re-run after v0.3.0 confirms behavior |
| Broadcast template tone feels off for one channel | Medium | Low | Drafts are starting points, not enforced wording; maintainer can edit on the day |
| README's "What's new" section feels like marketing | Low | Low | D5 anchors the voice to existing README terseness; review at U3 verification step |
| Multiple v0.3.0 docs confuse users about which to read first | Medium | Medium | RELEASE-NOTES is the entry point; every other doc links *to* it and explicitly tells the user what its scope is ("If you're upgrading, read MIGRATION", etc.) |

---

## Verification Strategy

| Check | When |
|---|---|
| Word-count target on RELEASE-NOTES (< 600) | After U1 |
| All cross-document links resolve | After U3 (the README is the link-density hot spot) |
| GitHub-rendered preview of README, RELEASE-NOTES, FAQ looks coherent | After U3 |
| Discussion #184 post template fits in a GitHub Discussion body | After U5 |
| GA Release body template fits the GH Release UI without truncation | After U5 |
| Broadcast templates fit channel character limits (Twitter 280, Bluesky 300, HN title <80) | After U6 |
| Maintainer can paste each template with only date/version edits | After U6 (manual review) |

---

## Implementation Unit Ordering

U1 → U2 → U3 → U4 → U5 → U6

- **U1 first** because every subsequent unit either links to it or
  pulls content from it. RELEASE-NOTES is the single source of truth
  (D1).
- **U2 second** because the FAQ links to MIGRATION and to RELEASE-NOTES
  for context.
- **U3 third** because the README banner replaces the existing one
  with a richer subsection that links to U1 + U2.
- **U4–U6 last** because they're playbook enhancements that pull from
  U1 and U2; they can be done in parallel within the playbook file
  but the sequence here is presentation order in the playbook.

---

## Out of Scope (cross-reference)

This plan does NOT deliver:

- An in-TUI "What's New" overlay (issue #164) — reserved for a future plan
  (likely 015 when picked up)
- Updates to the GitHub repo description, social card, or pinned post
- A long-form blog post or video demo
- Marketing-funnel pages, conversion-CTA copy, or landing-page material
- Translated versions of the announcement materials
- Code changes of any kind
