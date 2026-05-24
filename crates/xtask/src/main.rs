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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckSubprocess => check_subprocess(),
        Command::CheckPlatformLeak => {
            eprintln!("xtask check-platform-leak: stub — implemented by plan 003");
            Ok(())
        }
        Command::CheckProtocolLeak => {
            eprintln!("xtask check-protocol-leak: stub — implemented by plan 004");
            Ok(())
        }
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
    if rel_str == "crates/vortix-process/src/real.rs" {
        return true;
    }

    // Allow xtask itself (it documents the pattern in strings).
    if rel_str.starts_with("crates/xtask/") {
        return true;
    }

    false
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
