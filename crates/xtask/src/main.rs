//! `cargo xtask <task>` — workspace build chores.

use clap::{Parser, Subcommand};
use std::path::Path;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "vortix workspace build chores", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum Command {
    /// Verify no raw `Command::new` outside `vortix-process` (plan 002 R12).
    CheckSubprocess,
    /// Verify no `cfg(target_os)` outside `vortix-platform-*` (plan 003 R12).
    CheckPlatformLeak,
    /// Verify no protocol-specific subprocess names outside their protocol crates (plan 004).
    CheckProtocolLeak,
    /// Verify no shell-outs to system binaries that plan 002 replaced.
    CheckNoShellRegressions,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckSubprocess => check_subprocess(),
        Command::CheckPlatformLeak => check_platform_leak(),
        Command::CheckProtocolLeak => check_protocol_leak(),
        Command::CheckNoShellRegressions => check_no_shell_regressions(),
    }
}

/// Scan the workspace for raw `Command::new` use outside `vortix-process`.
///
/// Allowed:
/// - `vortix-process/src/real.rs` (the one legitimate caller of `tokio::process::Command::new`)
/// - Lines annotated with `// xtask:allow-subprocess` (explicit opt-out)
/// - Matches inside `xtask`'s own source (this file references the pattern in the
///   error message and the allowlist below — we don't lint ourselves).
fn check_subprocess() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = workspace_root()?;
    let crates_dir = workspace_root.join("crates");

    let mut violations = Vec::new();

    let walker = ignore::WalkBuilder::new(&crates_dir)
        .hidden(false)
        .git_ignore(true)
        .build();

    for result in walker {
        let Ok(entry) = result else { continue };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if is_allowlisted_file(path, &workspace_root) {
            continue;
        }

        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };

        for (idx, line) in content.lines().enumerate() {
            if !line_contains_violation(line) {
                continue;
            }
            if line.contains("// xtask:allow-subprocess") {
                continue;
            }
            violations.push(format!(
                "{}:{}: {}",
                path.strip_prefix(&workspace_root).unwrap_or(path).display(),
                idx + 1,
                line.trim()
            ));
        }
    }

    if violations.is_empty() {
        eprintln!("xtask check-subprocess: ok (crates/ scanned)");
        Ok(())
    } else {
        eprintln!(
            "xtask check-subprocess: {} violation(s) — all subprocess invocations must flow through `vortix_process::CommandRunner` (plan 002 R12). Annotate exceptions with `// xtask:allow-subprocess: <reason>`.",
            violations.len()
        );
        for v in &violations {
            eprintln!("  {v}");
        }
        std::process::exit(1)
    }
}

fn line_contains_violation(line: &str) -> bool {
    // Match `std::process::Command::new(` and `tokio::process::Command::new(`.
    // Bare `Command::new(` only triggers when preceded by a `use std::process::Command`
    // import — but rather than tracking imports, the lint catches the fully-qualified
    // forms only; we already rewrote all bare usages in plan 002. Adding a bare
    // `Command::new(` later requires either a fully-qualified path or an annotation.
    line.contains("std::process::Command::new") || line.contains("tokio::process::Command::new")
}

fn is_allowlisted_file(path: &Path, workspace_root: &Path) -> bool {
    let rel = path.strip_prefix(workspace_root).unwrap_or(path);
    let rel_str = rel.to_string_lossy();

    // Allow the runner impl itself.
    if rel_str == "crates/vortix-process/src/real.rs"
        || rel_str == "crates/vortix/src/vortix_process/real.rs"
    {
        return true;
    }

    // Allow xtask itself (it documents the pattern in strings).
    if rel_str.starts_with("crates/xtask/") {
        return true;
    }

    false
}

/// Scan the workspace for naked `cfg(target_os = ...)` use outside platform
/// boundaries (plan 003 R12).
///
/// Allowlist:
/// - `crates/vortix-platform-{macos,linux,windows}/**` — platform crates.
/// - `crates/vortix/src/platform/**` — binary-side platform aggregate.
/// - `crates/vortix/src/constants.rs` — OS-specific compile-time constants.
/// - `crates/xtask/src/main.rs` — this lint references the pattern.
/// - Lines annotated with `// xtask:allow-platform-cfg: <reason>`.
/// - Cargo.toml `target.'cfg(target_os = ...)'.dependencies` entries.
fn check_platform_leak() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = workspace_root()?;
    let crates_dir = workspace_root.join("crates");

    let mut violations = Vec::new();

    let walker = ignore::WalkBuilder::new(&crates_dir)
        .hidden(false)
        .git_ignore(true)
        .build();

    for result in walker {
        let Ok(entry) = result else { continue };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Only Rust source files participate in this lint.
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if is_platform_leak_allowlisted(path, &workspace_root) {
            continue;
        }

        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if !line.contains("cfg(target_os") {
                continue;
            }
            // Skip comment-only lines (the lint is about real cfg attributes,
            // not prose mentioning the pattern).
            if line.trim_start().starts_with("//") {
                continue;
            }
            // Annotations may live on the same line, on the previous line, or
            // on the next line (rustfmt sometimes splits trailing comments
            // off cfg attributes onto a fresh line).
            let same = line.contains("// xtask:allow-platform-cfg");
            let prev = idx
                .checked_sub(1)
                .and_then(|i| lines.get(i))
                .is_some_and(|l| l.contains("// xtask:allow-platform-cfg"));
            let next = lines
                .get(idx + 1)
                .is_some_and(|l| l.contains("// xtask:allow-platform-cfg"));
            if same || prev || next {
                continue;
            }
            violations.push(format!(
                "{}:{}: {}",
                path.strip_prefix(&workspace_root).unwrap_or(path).display(),
                idx + 1,
                line.trim()
            ));
        }
    }

    if violations.is_empty() {
        eprintln!("xtask check-platform-leak: ok (crates/ scanned)");
        Ok(())
    } else {
        eprintln!(
            "xtask check-platform-leak: {} violation(s) — `cfg(target_os = ...)` must live in `vortix-platform-*` or `vortix::platform::*`. Route OS-specific calls through `crate::platform::current_platform()`; for genuine compile-time gates, annotate with `// xtask:allow-platform-cfg: <reason>`.",
            violations.len()
        );
        for v in &violations {
            eprintln!("  {v}");
        }
        std::process::exit(1)
    }
}

fn is_platform_leak_allowlisted(path: &Path, workspace_root: &Path) -> bool {
    let rel = path.strip_prefix(workspace_root).unwrap_or(path);
    let rel_str = rel.to_string_lossy();

    rel_str.starts_with("crates/vortix-platform-")
        || rel_str.starts_with("crates/vortix/src/vortix_platform_")
        || rel_str.starts_with("crates/vortix/src/platform/")
        || rel_str == "crates/vortix/src/lib.rs"
        || rel_str == "crates/vortix/src/constants.rs"
        || rel_str.starts_with("crates/xtask/")
}

/// Scan the workspace for protocol-specific binary names appearing in
/// `CommandSpec` invocations outside their protocol crates (plan 004 R13).
///
/// Allowlist:
/// - `crates/vortix-protocol-wireguard/**` may invoke `wg-quick` and `wg`.
/// - `crates/vortix-protocol-openvpn/**` may invoke `openvpn`.
/// - `crates/xtask/**` references the patterns in error strings.
/// - Lines annotated `// xtask:allow-protocol-leak: <reason>` are accepted
///   (on the same line, the line above, or the line below — rustfmt may
///   split trailing comments).
///
/// The lint targets `CommandSpec::oneshot("<name>"` and the equivalent
/// `CommandSpec::detached("<name>"` patterns. Other uses of the name as a
/// string (logging, error messages, documentation) are not flagged.
fn check_protocol_leak() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = workspace_root()?;
    let crates_dir = workspace_root.join("crates");

    let mut violations = Vec::new();

    let walker = ignore::WalkBuilder::new(&crates_dir)
        .hidden(false)
        .git_ignore(true)
        .build();

    for result in walker {
        let Ok(entry) = result else { continue };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let Some(rel_str) = path
            .strip_prefix(&workspace_root)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
        else {
            continue;
        };

        let allowed_names: &[&str] = if rel_str.starts_with("crates/vortix-protocol-wireguard/")
            || rel_str.starts_with("crates/vortix/src/vortix_protocol_wireguard/")
        {
            &["openvpn"]
        } else if rel_str.starts_with("crates/vortix-protocol-openvpn/")
            || rel_str.starts_with("crates/vortix/src/vortix_protocol_openvpn/")
        {
            &["wg", "wg-quick"]
        } else if rel_str.starts_with("crates/xtask/") {
            continue;
        } else {
            &["wg", "wg-quick", "openvpn"]
        };

        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            // Skip comment-only lines.
            if line.trim_start().starts_with("//") {
                continue;
            }
            // Annotation may live on the same line, within the previous 3
            // lines (rustfmt may break a chained `.run(...)` call across
            // multiple lines), or on the next line.
            let annotated = line.contains("// xtask:allow-protocol-leak")
                || (1..=3).any(|n| {
                    idx.checked_sub(n)
                        .and_then(|i| lines.get(i))
                        .is_some_and(|l| l.contains("// xtask:allow-protocol-leak"))
                })
                || lines
                    .get(idx + 1)
                    .is_some_and(|l| l.contains("// xtask:allow-protocol-leak"));
            if annotated {
                continue;
            }

            for name in allowed_names {
                let needle1 = format!(r#"CommandSpec::oneshot("{name}""#);
                let needle2 = format!(r#"CommandSpec::detached("{name}""#);
                if line.contains(&needle1) || line.contains(&needle2) {
                    violations.push(format!("{rel_str}:{}: {}", idx + 1, line.trim()));
                    break;
                }
            }
        }
    }

    if violations.is_empty() {
        eprintln!("xtask check-protocol-leak: ok (crates/ scanned)");
        Ok(())
    } else {
        eprintln!(
            "xtask check-protocol-leak: {} violation(s) — protocol-specific binaries (`wg`, `wg-quick`, `openvpn`) must only be invoked from their protocol crate. Route via `crate::tunnel::tunnel_for(...)`; for legitimate exceptions, annotate with `// xtask:allow-protocol-leak: <reason>`.",
            violations.len()
        );
        for v in &violations {
            eprintln!("  {v}");
        }
        std::process::exit(1)
    }
}

/// System binaries that plan 002 replaced. Once a binary is on this
/// list, any future code that `CommandSpec::oneshot("<name>", ...)`s
/// it gets caught at build time — preventing the regression class
/// the Fedora-without-`which` incident (PR #1 `fcf9508`) revealed.
///
/// The list deliberately covers tools removed in U1 (`which`), U2/U6
/// (`kill`), U3 (`uname`, `sw_vers`), U4/U5/U6 (`ifconfig`, `ip`,
/// `ps`), U7 (`netstat`, `lsof`, `scutil`), U8 (`pbcopy`, `xclip`,
/// `wl-copy`), U9 (`curl`), and U10 (`ping`). It does NOT cover the
/// irreducible product-behavior binaries (`wg-quick`, `wg`, `openvpn`,
/// `iptables-restore`, `nft`, `pfctl`, `resolvconf`).
const FORBIDDEN_SHELL_OUTS: &[&str] = &[
    "curl",
    "ping",
    "which",
    "pbcopy",
    "xclip",
    "wl-copy",
    "xsel",
    "ifconfig",
    "ip",
    "ps",
    "netstat",
    "lsof",
    "scutil",
    "networksetup",
    "kill",
    "pkill",
    "uname",
    "sw_vers",
];

/// Scan `crates/vortix/src/` for `CommandSpec::oneshot("<deprecated>"` —
/// any literal program name on `FORBIDDEN_SHELL_OUTS` reappearing in
/// a oneshot call fails the build.
///
/// Allowlist:
/// - `crates/xtask/src/main.rs` — the lint references the pattern.
/// - Lines annotated with `// xtask:allow-shell-regression: <reason>`
///   (same/prev/next-line — same parser as the other boundary checks).
fn check_no_shell_regressions() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = workspace_root()?;
    let crates_dir = workspace_root.join("crates");

    let mut violations = Vec::new();

    let walker = ignore::WalkBuilder::new(&crates_dir)
        .hidden(false)
        .git_ignore(true)
        .build();

    for result in walker {
        let Ok(entry) = result else { continue };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        // Self-exclude: the lint mentions every forbidden name in its
        // own source.
        let rel = path.strip_prefix(&workspace_root).unwrap_or(path);
        if rel.to_string_lossy() == "crates/xtask/src/main.rs" {
            continue;
        }

        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let Some(program) = find_forbidden_oneshot(line) else {
                continue;
            };
            // Annotation parser mirrors check_platform_leak's: accept
            // same/prev/next line. rustfmt sometimes splits trailing
            // comments off the call site.
            let marker = "// xtask:allow-shell-regression";
            let same = line.contains(marker);
            let prev = idx
                .checked_sub(1)
                .and_then(|i| lines.get(i))
                .is_some_and(|l| l.contains(marker));
            let next = lines.get(idx + 1).is_some_and(|l| l.contains(marker));
            if same || prev || next {
                continue;
            }
            violations.push(format!(
                "{}:{}: CommandSpec::oneshot(\"{}\", ...)",
                rel.display(),
                idx + 1,
                program
            ));
        }
    }

    if violations.is_empty() {
        eprintln!("xtask check-no-shell-regressions: ok (crates/ scanned)");
        Ok(())
    } else {
        eprintln!(
            "xtask check-no-shell-regressions: {} violation(s) — plan 002 replaced these system-binary shell-outs with native Rust. Re-introducing them risks the Fedora-without-`which` regression class. For legitimate exceptions, annotate with `// xtask:allow-shell-regression: <reason>`.",
            violations.len()
        );
        for v in &violations {
            eprintln!("  {v}");
        }
        std::process::exit(1)
    }
}

/// Does `line` contain a `CommandSpec::oneshot("<forbidden>"`? If so,
/// return the forbidden program name. The match must be tight: we
/// look for the literal substring `CommandSpec::oneshot("<name>"`
/// (with quotes) so prose mentioning a tool name elsewhere on the
/// line doesn't trip the lint.
fn find_forbidden_oneshot(line: &str) -> Option<&'static str> {
    let needle_prefix = "CommandSpec::oneshot(\"";
    let start = line.find(needle_prefix)?;
    let rest = &line[start + needle_prefix.len()..];
    let end = rest.find('"')?;
    let program = &rest[..end];
    FORBIDDEN_SHELL_OUTS.iter().copied().find(|&p| p == program)
}

fn workspace_root() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    // `cargo xtask` runs from the workspace root by convention; CARGO_MANIFEST_DIR
    // points at `crates/xtask` so step up two levels.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let root = std::path::PathBuf::from(manifest_dir)
        .parent()
        .and_then(Path::parent)
        .ok_or("CARGO_MANIFEST_DIR has no grandparent")?
        .to_path_buf();
    Ok(root)
}
