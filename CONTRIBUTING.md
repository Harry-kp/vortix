# Contributing to Vortix

Thanks for your interest in contributing! 🎉

## Quick Start

```bash
git clone https://github.com/Harry-kp/vortix.git
cd vortix
cargo build -p vortix && sudo ./target/debug/vortix
```

## Ways to Contribute

- 🐛 **Report bugs** — Open an issue with steps to reproduce
- 💡 **Suggest features** — Check the [project board](https://github.com/users/Harry-kp/projects/6) first, then open an issue
- 📖 **Improve docs** — README, code comments, examples
- 🧪 **Add tests** — Unit tests, integration tests
- 🐧 **Linux support** — Test and fix Linux distro differences

## Linux Help Wanted

Vortix is developed primarily on macOS, so Linux users can have outsized impact.

Ways Linux contributors can help:
- Test PRs and release candidates on Ubuntu, Fedora, and Arch
- Report distro-specific issues around firewall backends, DNS detection, and privilege handling
- Contribute fixes for Linux-only regressions
- Share packaging and install feedback from real systems

If you regularly use Vortix on Linux and want to help more deeply, start in the [Linux tester discussion](https://github.com/Harry-kp/vortix/discussions/184) with your distro and what you are willing to test.

## Before You Open a Pull Request

**For anything bigger than a small fix, open an issue first** and wait for a reply, so neither
of us spends time on a change that will not land.

Pull requests I will close:
- New dependencies, Cargo features or `unsafe` code that were not agreed in an issue first
- A background daemon or privileged helper (removed on purpose)
- Reformatting or renaming in files the change does not otherwise touch
- A behaviour change or bug fix with no test that fails without it

## Development Workflow

1. Fork the repo and branch from `main`.
2. Build and run as your user; only the binary needs root:
   ```bash
   cargo build -p vortix && sudo ./target/debug/vortix
   ```
   Never `sudo cargo`. If an earlier one left `target/` owned by root:
   `sudo chown -R "$(id -un):$(id -gn)" target`.
3. Make the change with a test that fails without it.
4. Run what CI runs, which must end with `All checks passed.`:
   ```bash
   scripts/ci-local.sh           # full set, before you push
   scripts/ci-local.sh --quick   # without the release build, while iterating
   ```
   [docs/ci-parity.md](docs/ci-parity.md) maps it to each CI job.
5. Commit with a [conventional commit](https://www.conventionalcommits.org/) subject
   (`fix:`, `feat:`, `docs:`, `refactor:`, `test:`) and open a PR.

The project's rules (where code goes, comments, tests, boundaries) are in
[CLAUDE.md](CLAUDE.md); they apply to people as much as to coding agents.

## Questions?

Open a [discussion](https://github.com/Harry-kp/vortix/discussions) or reach out on [Twitter/X](https://twitter.com/harrykp007).
