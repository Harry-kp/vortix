# Releasing Vortix

The `release-changelog` skill (`.claude/skills/release-changelog/`) walks through a release
step by step; this page is the pipeline it drives.

## Pipeline

1. Every push to `main` makes **release-plz** open or update a release PR (`chore: release
   vX.Y.Z`, label `release`): it bumps the version in `Cargo.toml` and writes
   `crates/vortix/CHANGELOG.md` from the commit subjects.
2. That generated changelog is replaced by hand with the user-facing one, as the last step
   before merging, because release-plz rewrites it on every push to `main`. Nothing else merges
   to `main` in between.
3. Merging the release PR publishes to crates.io and pushes the tag `vX.Y.Z`.
4. The tag runs **cargo-dist** (`release.yml`): macOS (x86_64, arm64) and Linux gnu and musl
   (x86_64, aarch64) archives, the GitHub release, the shell installer, the Homebrew tap and
   npm.
5. After publishing, check the GitHub release page. A release created with `GITHUB_TOKEN`
   triggers no other workflow, so `release-notes.yml` and the release trigger of
   `install-sanity.yml` never run: prepend the changelog section as `## Release Notes` with
   `gh release edit vX.Y.Z --notes-file <file>`.

## Versions

Before 1.0, release-plz bumps the patch for `fix:` and `feat:`, and the minor for a breaking
change (`feat!:` / `fix!:`, or a `BREAKING CHANGE:` footer) on a commit that touches
`crates/vortix`. `docs:`, `test:`, `chore:` and `ci:` alone do not release.

## Secrets

| Secret | Used by |
|---|---|
| `RELEASE_PLZ_TOKEN` | release-plz, to open PRs that trigger CI |
| `CARGO_REGISTRY_TOKEN` | crates.io publish |
| `HOMEBREW_TAP_TOKEN` | the Homebrew formula push to `Harry-kp/homebrew-tap` |
| `NPM_TOKEN` | npm publish; publish tokens expire, and an expired one fails with a 404 |

A failed publish job can be re-run alone: `gh run rerun <run-id> --failed`.
