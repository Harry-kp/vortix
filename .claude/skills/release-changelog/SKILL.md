---
name: release-changelog
description: Write the user-facing changelog, version and upgrade notes for a vortix release — gather every PR since the last tag, keep only what an end user notices or must act on, verify each claim against the code, pick the version (breaking before 1.0 bumps minor), write the in-app upgrade notes and MIGRATION.md section, and put the final text on the release-plz PR last. Use whenever the user is preparing a release, asks for release notes or a changelog, asks what changed since the last version, or asks whether the version number is right.
---

# Release changelog

A changelog is for the person who runs `brew upgrade vortix`, not for the
people who wrote the code. It says what they will notice, what they must do,
and nothing else. release-plz already writes one from commit subjects; that
version lists every internal fix and is not what ships.

## 1. Gather

First find the release PR release-plz already opened: it holds the version and
the changelog you will edit (step 7). Never open another PR for the changelog.

```bash
gh pr list --state open --label release --json number,title,headRefName   # e.g. "chore: release v0.5.1"
LAST=$(git describe --tags --abbrev=0 origin/main)
git log -1 --format=%cI "$LAST"                      # the tag's date
gh pr list --state merged --base main --limit 200 --search "merged:>$(git log -1 --format=%cs $LAST)" \
  --json number,title -q '.[] | "\(.number) \(.title)"'
```

Read the body of every PR that is not a dependency, CI or docs-only bump
(`gh pr view <n> --json title,body`). A subagent can read them in parallel;
give it the rules in step 2 and ask for draft text plus a list of removed or
changed user-facing surface. Treat its numbers as claims to verify.

## 2. Keep only what users notice

Keep: new features, fixes to behaviour people saw, removed or renamed
commands, flags, settings keys, JSON fields and exit codes, changed defaults,
new platform support, security fixes, size or speed they can feel.

Drop: refactors, tests, CI, dependency bumps (except security fixes), and
internal renames. Many small fixes to one area become one bullet about the
effect ("Disconnect and reconnect finish cleanly"). Never paste commit
subjects.

Find removals by diffing the surface, not by reading commits:

```bash
git diff "$LAST"..origin/main -- crates/vortix/src/cli/args.rs crates/vortix/src/config/
```

## 3. Verify every claim

Every sentence must be true of the code at `origin/main`: grep for the flag,
the setting name, the file path, the key binding. Measure numbers yourself —
build the previous tag and the current tree in release mode and compare
`stat` sizes. A number from a PR body or a subagent is wrong until measured
(0.5.0's draft said "45% smaller"; the measurement was 32%).

## 4. Pick the version

The release-plz PR owns the version; never edit `Cargo.toml` for it.
release-plz bumps the patch for any `fix:` or `feat:` before 1.0. If the
release removes or breaks something an existing user relies on (a command,
a flag, a settings key, a profile directive, a backend), it is breaking: ask
the user, recommending the next minor. Mark it on a commit that lands on
main and touches `crates/vortix`: a squash-merged PR titled `feat!: …` (or
`fix!: …`) with a `BREAKING CHANGE:` note. release-plz then proposes the
next minor. Check the release PR's version after that merge.

## 5. Upgrade notes, when anything is breaking

- Add a `Release` to `whats_new::RELEASES` (`crates/vortix/src/whats_new.rs`):
  the steps a user must take, each with its OS and a `When` condition so a
  machine sees only what applies, plus at most five highlights. Keep steps
  few; prefer one step that fixes everything (a restart) over a manual.
- Add "Upgrading from X to Y" to `docs/MIGRATION.md` with the full commands
  per OS and distribution, and point `UPGRADE_URL` at its anchor.
- Check the steps actually work: the `release-qa` skill's upgrade test
  (previous tag creates the state, the new build takes over), and
  `scripts/upgrade-preview.sh` for how the popup looks on each OS.

## 6. Write it

Match the existing `CHANGELOG.md` style. Sections in order, empty ones left
out: **Upgrading from X** (only when step 5 applies), **Highlights** (at most
six), **Fixed**, **Changed**, **Removed**, **Security**. Each bullet: a bold
lead phrase saying the user-visible result, one plain sentence, then PR
links like `([#292](https://github.com/Harry-kp/vortix/pull/292))`.

## 7. Put it on the release PR last

release-plz rewrites its PR's changelog on every push to main, so edit it
only after everything else for the release has merged:

```bash
gh pr list --label release --json number,headRefName
git fetch origin <branch> && git switch -c release-edit origin/<branch>
# replace the generated `## [X.Y.Z]` section in crates/vortix/CHANGELOG.md
git commit -am "docs: user-facing changelog for X.Y.Z" && git push origin HEAD:<branch>
gh pr diff <number> -- crates/vortix/CHANGELOG.md     # check it landed
```

Nothing else may merge to `main` until the release PR does: release-plz would
regenerate its changelog and drop your edit. Hold other PRs (including skill
or doc fixes) until after the release.

Merging the release PR publishes the release, so leave that to the user
unless they said to merge it. Tell them the PR number, the version, and
anything in the changelog you could not verify.

## 8. After the release

`release-notes.yml` does not run: a release created with `GITHUB_TOKEN`
triggers no other workflow. Check the GitHub release page, and if it shows
only the install instructions, prepend the changelog section as
`## Release Notes` with `gh release edit v<X.Y.Z> --notes-file <file>`.
