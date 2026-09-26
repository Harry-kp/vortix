---
name: docs-review
description: Check a vortix diff for documentation it makes wrong or leaves missing, and fix the docs in the same change. Mandatory before every commit in this repo, right after ponytail-review, and part of fix-bug and release-qa. Use it whenever code, CLI flags, keys, TUI text, settings, errors, CI or scripts change, even if the user did not mention docs.
---

# Docs review

The docs are read mostly by agents, who act on them without checking. A doc that is out of date
is worse than a missing one. This review keeps the docs true of the diff being committed, so
the fix goes in the same commit.

## 1. Run the mechanical check

```bash
cargo xtask check-docs
```

It covers links and anchors, the subcommands and flags in `docs/usage.md`, and the config keys
in `docs/configuration.md`. Fix every failure before going on.

## 2. Map the diff to its owners

Run `git diff origin/main --stat` and read the diff. For each changed surface, open its owner in
CLAUDE.md's "Docs" table and read the section it touches. Look for:

- **Renamed or removed things:** `rg` the old name in every `*.md`, `.claude/skills/` and the
  help strings in code (`HELP_TEXT`, clap `about`/`after_help`, `Hint`s). Update or delete each
  hit.
- **Changed behaviour:** defaults, timeouts, limits, exit codes, JSON fields, error text, which
  OS a feature supports. Update the sentence that states the old behaviour; the check in step 1
  does not read meaning.
- **New things a user can hit:** a flag, key, setting or error needs a line in its owner. An
  error message a user must act on also gets a troubleshooting entry.
- **Moved code:** paths in CLAUDE.md's "Where things live", the skills and `docs/ci-parity.md`.
- **Upgrade impact:** if an existing user must act, `docs/MIGRATION.md` and `whats_new.rs`
  (see the `release-changelog` skill).

## 3. Write like the existing docs

- Every sentence must be true of the code on this branch: grep before you write. A doc claim
  copied from a PR body or a comment is a guess.
- One owner per fact. Link to its heading instead of restating it; a second copy drifts.
- Describe what the program does now. No history ("used to", "since 0.4"), plan IDs, phase
  names or roadmap promises, except in `MIGRATION.md` and the changelog.
- Short, plain sentences; tables for lists of keys, flags or options.

## 4. Report

Add the doc edits to the same commit as the code. Then give one line per file changed, or
`Docs match the diff.` if nothing needed changing. If a doc change needs a product decision (for
example, whether to document a hidden flag), ask rather than guessing.
