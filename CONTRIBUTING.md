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

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run what CI runs:
   ```bash
   scripts/ci-local.sh           # full set
   scripts/ci-local.sh --quick   # skips the release build
   ```
   See [docs/ci-parity.md](docs/ci-parity.md) for the individual steps.
5. Commit with [conventional commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation
   - `refactor:` code refactoring
6. Push and open a PR

## Code Style

- `scripts/ci-local.sh` must pass before you push
- Keep functions small and focused
- Add doc comments for public APIs

## Testing

Vortix requires root for VPN operations. For testing:

```bash
# Run unit tests (no root needed)
cargo test -p vortix

# Run the debug build (never `sudo cargo`)
cargo build -p vortix && sudo ./target/debug/vortix
```

For Linux bug reports, include as much of the following as possible:
- distro + version
- kernel version
- install method (`cargo`, Homebrew, npm, package manager, binary installer)
- `vortix report`
- whether your system uses `iptables`, `nftables`, `firewalld`, `NetworkManager`, or `systemd-resolved`

## Questions?

Open a [discussion](https://github.com/Harry-kp/vortix/discussions) or reach out on [Twitter/X](https://twitter.com/harrykp007).
