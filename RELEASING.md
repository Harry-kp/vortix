# Releasing Vortix

The `release-changelog` skill (`.claude/skills/release-changelog/`) walks through a release
step by step; this page is the pipeline it drives.

## Pipeline

1. Every push to `main` makes **release-plz** open or update a release PR (`chore: release
   vX.Y.Z`, label `release`): it bumps the version in `Cargo.toml` and writes
   `CHANGELOG.md` (repo root) from the commit subjects.
2. That generated changelog is replaced by hand with the user-facing one, as the last step
   before merging, because release-plz rewrites it on every push to `main`. Nothing else merges
   to `main` in between.
3. Merging the release PR publishes to crates.io and pushes the tag `vX.Y.Z`.
4. The tag runs **cargo-dist** (`release.yml`): macOS (x86_64, arm64) and Linux gnu and musl
   (x86_64, aarch64) archives, the GitHub release and the shell installer. Its
   `custom-npm-publish` job (`npm-publish.yml`) packs those binaries into the npm package
   (`scripts/npm-package.sh`: no install script, nothing downloaded) and publishes it. Homebrew needs
   nothing: homebrew-core's bot bumps the `vortix` formula when it sees the new tag. The release notes are that version's `CHANGELOG.md` section, which cargo-dist reads
   only from the repo root. Its `custom-linux-packages` job runs `linux-packages.yml`, which builds `.deb` and
   `.rpm` from the musl binaries with nfpm (`scripts/nfpm.yaml`), installs them on Ubuntu, Debian
   and Fedora images, and attaches them to the release. To add them to an older release:
   `gh workflow run linux-packages.yml -f tag=vX.Y.Z`.
5. Extra release steps run as jobs of the release workflow: a release created with
   `GITHUB_TOKEN` triggers no other workflow. Check the release page after publishing.

## Versions

Before 1.0, release-plz bumps the patch for `fix:` and `feat:`, and the minor for a breaking
change (`feat!:` / `fix!:`, or a `BREAKING CHANGE:` footer) on a commit that touches
`crates/vortix`. `docs:`, `test:`, `chore:` and `ci:` alone do not release.

## Secrets

| Secret | Used by |
|---|---|
| `RELEASE_PLZ_TOKEN` | release-plz, to open PRs that trigger CI |

crates.io and npm need no secret: both use trusted publishing, where the registry checks the
workflow's GitHub identity token. One-time setup, as the package owner:

- crates.io: the crate's Settings → Trusted Publishing → add GitHub: owner `Harry-kp`,
  repository `vortix`, workflow `release-plz.yml`, no environment.
- npmjs.com: the package's Settings → Trusted publisher → GitHub Actions: `Harry-kp/vortix`,
  workflow `release.yml` (the caller, not `npm-publish.yml`).

A failed publish job can be re-run alone: `gh run rerun <run-id> --failed`.
