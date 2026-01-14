# Releasing Vortix

## Automated Release Pipeline

Everything is automated. Just write code and merge PRs.

```
┌─────────────────────────────────────────────────────────────────┐
│  1. You push commits to main (or merge a PR)                    │
│                           ↓                                     │
│  2. release-plz automatically creates a Release PR              │
│     - Bumps version in Cargo.toml (based on commit types)       │
│     - Updates CHANGELOG.md                                      │
│                           ↓                                     │
│  3. You review and merge the Release PR                         │
│                           ↓                                     │
│  4. release-plz automatically:                                  │
│     - Publishes to crates.io                                    │
│     - Creates git tag (e.g., v0.2.0)                            │
│                           ↓                                     │
│  5. Git tag triggers cargo-dist which:                          │
│     - Builds macOS binaries (Intel + Apple Silicon)             │
│     - Creates GitHub Release with binaries attached             │
│     - Generates shell installer script                          │
└─────────────────────────────────────────────────────────────────┘
```

## Your Only Manual Step

**Merge the Release PR** — that's it.

## Commit Message Guidelines

Use conventional commits to control version bumps:

| Prefix | Version Bump | Example |
|--------|--------------|---------|
| `fix:` | Patch (0.0.X) | `fix: resolve connection timeout` |
| `feat:` | Minor (0.X.0) | `feat: add kill switch toggle` |
| `feat!:` or `BREAKING CHANGE:` | Major (X.0.0) | `feat!: redesign config format` |
| `chore:`, `docs:`, `style:` | No bump | `docs: update README` |

## Required Secrets

Ensure these are set in GitHub repo settings → Secrets → Actions:

| Secret | Purpose |
|--------|---------|
| `CARGO_REGISTRY_TOKEN` | Publish to crates.io |

`GITHUB_TOKEN` is automatically provided by GitHub Actions.

## Tools

| Tool | Purpose |
|------|---------|
| **release-plz** | Version bumps, changelog, crates.io publishing, git tags |
| **cargo-dist** | macOS binaries, GitHub releases, shell installer |

## Manual Release (if needed)

If automation fails, you can trigger manually:

1. Go to Actions → Release-plz → Run workflow
2. After PR is merged, cargo-dist runs automatically on the tag

## Troubleshooting

**Release PR not created?**
- Check if commits use conventional commit format
- Check Actions tab for errors

**Not published to crates.io?**
- Verify `CARGO_REGISTRY_TOKEN` secret exists and is valid
- Get new token from https://crates.io/settings/tokens

**Binaries not built?**
- Check if git tag was created (v0.X.X format)
- Check Actions tab → Release workflow
