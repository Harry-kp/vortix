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
   npm. Its `custom-linux-packages` job runs `linux-packages.yml`, which builds `.deb` and
   `.rpm` from the musl binaries (`scripts/linux-packages.sh`), installs them on Ubuntu, Debian
   and Fedora images, and attaches them to the release. To add them to an older release:
   `gh workflow run linux-packages.yml -f tag=vX.Y.Z`.
5. Its `custom-release-notes` job runs `release-notes.yml`, which prepends the version's
   `crates/vortix/CHANGELOG.md` section to the release as `## Release Notes`. (These run as
   jobs of the release workflow because a release created with `GITHUB_TOKEN` triggers no
   other workflow.) Check the release page; to redo the notes:
   `gh workflow run release-notes.yml -f tag=vX.Y.Z`.

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
