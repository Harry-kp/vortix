# Contributing to Vortix

Thank you for your interest in contributing to Vortix! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
1. Check the [existing issues](https://github.com/Harry-kp/vortix/issues) to avoid duplicates
2. Use the bug report template when creating a new issue
3. Include as much detail as possible:
   - macOS version
   - Vortix version (`vortix --version`)
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or screenshots

### Suggesting Features

Feature requests are welcome! Please:
1. Check existing issues and discussions first
2. Use the feature request template
3. Explain the use case and why it would benefit users

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   # or
   git checkout -b fix/bug-description
   ```
3. **Make your changes** following the coding standards below
4. **Test** your changes:
   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```
5. **Commit** with a clear message following [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add new telemetry widget
   fix: resolve DNS leak detection false positive
   docs: update keyboard shortcuts in README
   ```
6. **Push** and create a Pull Request

## Development Setup

### Prerequisites

- Rust 1.75 or later
- macOS (primary development platform)
- WireGuard tools (for testing WireGuard features)
- OpenVPN (for testing OpenVPN features)

### Building

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vortix.git
cd vortix

# Build debug
cargo build

# Build release
cargo build --release

# Run
sudo cargo run
```

### Project Structure

```
src/
├── main.rs          # Entry point
├── app.rs           # Core application state and logic
├── event.rs         # Terminal event handling
├── scanner.rs       # System VPN detection
├── telemetry.rs     # Background network monitoring
├── constants.rs     # Application constants
├── theme.rs         # Color palette definitions
├── utils.rs         # Utility functions
├── cli/             # CLI argument parsing
│   ├── mod.rs
│   ├── args.rs      # Clap argument definitions
│   └── commands.rs  # Command handlers
├── ui/              # TUI rendering
│   ├── mod.rs
│   ├── dashboard.rs # Main dashboard layout
│   ├── widgets/     # Reusable UI components
│   └── overlays/    # Modal overlays (help, toast)
└── vpn/             # VPN profile management
    └── mod.rs
```

## Coding Standards

### Formatting

- Run `cargo fmt` before committing
- Use default rustfmt settings

### Linting

- Zero warnings policy: `cargo clippy -- -D warnings`
- Address all clippy suggestions

### Documentation

- Add rustdoc comments (`///`) to all public items
- Include examples in documentation where helpful
- Update README.md for user-facing changes

### Error Handling

- Use `color_eyre::Result` for fallible functions
- Avoid `.unwrap()` and `.expect()` in production code
- Provide meaningful error messages

### Commits

Follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Description |
|--------|-------------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `style:` | Formatting, no code change |
| `refactor:` | Code restructuring |
| `perf:` | Performance improvement |
| `test:` | Adding tests |
| `chore:` | Build, CI, dependencies |

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

## Release Process (Maintainers)

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` with changes
3. Commit: `git commit -am "chore: release v0.x.x"`
4. Tag: `git tag v0.x.x`
5. Push: `git push origin main --tags`
6. GitHub Actions will automatically:
   - Build binaries for macOS (Intel + Apple Silicon)
   - Create GitHub Release with changelog
   - Publish to crates.io

## Getting Help

- [GitHub Issues](https://github.com/Harry-kp/vortix/issues) - Bug reports and feature requests
- [GitHub Discussions](https://github.com/Harry-kp/vortix/discussions) - Questions and ideas

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
