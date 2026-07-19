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
    /// Verify no raw `Command::new` outside `vortix-process`.
    CheckSubprocess,
    /// Verify no `cfg(target_os)` outside `vortix-platform-*`.
    CheckPlatformLeak,
    /// Verify no protocol-specific subprocess names outside their protocol crates.
    CheckProtocolLeak,
    /// Verify no shell-outs to system binaries that the `CommandRunner` port replaced.
    CheckNoShellRegressions,
    /// Freeze control-plane ownership while the canonical service replaces legacy writers.
    CheckControlBoundaries,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckSubprocess => check_subprocess(),
        Command::CheckPlatformLeak => check_platform_leak(),
        Command::CheckProtocolLeak => check_protocol_leak(),
        Command::CheckNoShellRegressions => check_no_shell_regressions(),
        Command::CheckControlBoundaries => check_control_boundaries(),
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
            "xtask check-subprocess: {} violation(s) — all subprocess invocations must flow through `vortix_process::CommandRunner`. Annotate exceptions with `// xtask:allow-subprocess: <reason>`.",
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
    // forms only; we already rewrote all bare usages. Adding a bare
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
/// boundaries.
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
/// `CommandSpec` invocations outside their protocol crates.
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

/// System binaries that the `CommandRunner` port replaced. Once a binary is on this
/// list, any future code that `CommandSpec::oneshot("<name>", ...)`s
/// it gets caught at build time — preventing the regression class
/// the Fedora-without-`which` incident (PR #1 `fcf9508`) revealed.
///
/// The list deliberately covers tools we replaced:
/// `which`, `kill`, `uname`, `sw_vers`, `ifconfig`, `ip`, `ps`,
/// `netstat`, `lsof`, `scutil`, `pbcopy`, `xclip`, `wl-copy`,
/// `curl`, and `ping`. It does NOT cover the
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
            "xtask check-no-shell-regressions: {} violation(s) — the CommandRunner port replaced these system-binary shell-outs with native Rust. Re-introducing them risks the Fedora-without-`which` regression class. For legitimate exceptions, annotate with `// xtask:allow-shell-regression: <reason>`.",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ControlBoundaryKind {
    ClientMutationImport,
    SeedOrMirrorWriter,
    RootPrivilegeRequest,
    UnboundedChannel,
}

impl ControlBoundaryKind {
    const fn label(self) -> &'static str {
        match self {
            Self::ClientMutationImport => "direct client mutation-layer import",
            Self::SeedOrMirrorWriter => "production seed/mirror writer",
            Self::RootPrivilegeRequest => "root privilege request outside an owner",
            Self::UnboundedChannel => "unbounded production channel",
        }
    }
}

#[derive(Debug)]
struct ControlBoundaryViolation {
    kind: ControlBoundaryKind,
    path: String,
    line: usize,
    source: String,
}

/// Existing migration bridges are frozen as occurrence budgets instead of
/// exempting entire directories. A new occurrence in one of these files still
/// fails. The named unit must reduce/remove its budget when it deletes the
/// bridge.
const LEGACY_CONTROL_BUDGETS: &[(&str, ControlBoundaryKind, usize, &str)] = &[
    (
        "crates/vortix/src/app/connection.rs",
        ControlBoundaryKind::ClientMutationImport,
        1,
        "U8 removes the App-side protocol parser",
    ),
    (
        "crates/vortix/src/cli/commands.rs",
        ControlBoundaryKind::ClientMutationImport,
        1,
        "U7 removes the CLI process probe",
    ),
    (
        "crates/vortix/src/cli/report.rs",
        ControlBoundaryKind::ClientMutationImport,
        3,
        "U7 moves report probes behind the control boundary",
    ),
    (
        "crates/vortix/src/app/connection.rs",
        ControlBoundaryKind::SeedOrMirrorWriter,
        11,
        "U8 deletes the TUI mirror bridge",
    ),
    (
        "crates/vortix/src/app/update.rs",
        ControlBoundaryKind::SeedOrMirrorWriter,
        4,
        "U8 deletes the TUI mirror bridge",
    ),
    (
        "crates/vortix/src/vortix_core/engine/fsm.rs",
        ControlBoundaryKind::SeedOrMirrorWriter,
        5,
        "U14 deletes seed APIs after cutover",
    ),
    (
        "crates/vortix/src/vortix_core/engine/registry.rs",
        ControlBoundaryKind::SeedOrMirrorWriter,
        8,
        "U14 deletes seed calls after cutover",
    ),
    (
        "crates/vortix/src/vortix_core/journal/mod.rs",
        ControlBoundaryKind::UnboundedChannel,
        2,
        "U6 replaces the journal transport with bounded backpressure",
    ),
    (
        "crates/vortix/src/vortix_core/journal/writer.rs",
        ControlBoundaryKind::UnboundedChannel,
        2,
        "U6 replaces the journal transport with bounded backpressure",
    ),
];

fn check_control_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    let violations = scan_control_boundaries_at(&root)?;
    if violations.is_empty() {
        eprintln!("xtask check-control-boundaries: ok (legacy budgets unchanged)");
        return Ok(());
    }

    eprintln!(
        "xtask check-control-boundaries: {} violation(s) — clients must use the control contract; writers, privilege and queue ownership stay behind their approved boundaries.",
        violations.len()
    );
    for violation in violations {
        eprintln!(
            "  {}:{}: {}: {}",
            violation.path,
            violation.line,
            violation.kind.label(),
            violation.source
        );
    }
    std::process::exit(1)
}

fn scan_control_boundaries_at(
    root: &Path,
) -> Result<Vec<ControlBoundaryViolation>, Box<dyn std::error::Error>> {
    use std::collections::HashMap;

    let crates_dir = root.join("crates");
    let mut candidates = Vec::new();
    let walker = ignore::WalkBuilder::new(&crates_dir)
        .hidden(false)
        .git_ignore(true)
        .build();

    for result in walker {
        let Ok(entry) = result else { continue };
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_string_lossy().replace('\\', "/");
        if relative.starts_with("crates/xtask/")
            || relative.contains("/tests/")
            || relative.ends_with("/tests.rs")
        {
            continue;
        }
        let content = std::fs::read_to_string(path)?;
        let mut pending_test_cfg = false;
        let mut skipping_test_item = false;
        let mut test_item_indent = 0usize;
        for (index, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();

            if skipping_test_item {
                let indent = line.len() - trimmed.len();
                if indent == test_item_indent && (trimmed == "}" || trimmed == "};") {
                    skipping_test_item = false;
                }
                continue;
            }

            if trimmed == "#[cfg(test)]" {
                pending_test_cfg = true;
                test_item_indent = line.len() - trimmed.len();
                continue;
            }

            if pending_test_cfg && trimmed.starts_with("#[") {
                continue;
            }

            if pending_test_cfg {
                if trimmed.ends_with(';') {
                    pending_test_cfg = false;
                } else if let Some(open) = line.find('{') {
                    pending_test_cfg = false;
                    skipping_test_item = line[open + 1..].find('}').is_none();
                }
                continue;
            }

            if trimmed.starts_with("//") {
                continue;
            }
            let kind = control_boundary_kind(&relative, line);
            if let Some(kind) = kind {
                candidates.push(ControlBoundaryViolation {
                    kind,
                    path: relative.clone(),
                    line: index + 1,
                    source: trimmed.to_string(),
                });
            }
        }
    }

    let mut seen: HashMap<(String, ControlBoundaryKind), usize> = HashMap::new();
    let mut violations = Vec::new();
    for candidate in candidates {
        let key = (candidate.path.clone(), candidate.kind);
        let count = seen.entry(key).or_default();
        *count += 1;
        let budget = legacy_control_budget(&candidate.path, candidate.kind);
        if *count > budget {
            violations.push(candidate);
        }
    }
    Ok(violations)
}

fn control_boundary_kind(path: &str, line: &str) -> Option<ControlBoundaryKind> {
    let is_client = path.starts_with("crates/vortix/src/app/")
        || path.starts_with("crates/vortix/src/cli/")
        || path.starts_with("crates/vortix/src/ui/");
    let direct_mutation_layer = line.contains("crate::vortix_protocol_")
        || line.contains("crate::vortix_platform_")
        || line.contains("crate::vortix_process::");
    if is_client && direct_mutation_layer {
        return Some(ControlBoundaryKind::ClientMutationImport);
    }

    let seed_or_mirror = line.contains(".seed_")
        || line.contains(".mirror_")
        || line.contains("fn seed_")
        || line.contains("fn mirror_");
    if seed_or_mirror {
        return Some(ControlBoundaryKind::SeedOrMirrorWriter);
    }

    if line.contains(".privilege(PrivilegeReq::Root)") && !is_privilege_owner(path) {
        return Some(ControlBoundaryKind::RootPrivilegeRequest);
    }

    let unbounded = line.contains("unbounded_channel")
        || line.contains("UnboundedSender")
        || line.contains("UnboundedReceiver")
        || line.contains("async_channel::unbounded")
        || line.contains("crossbeam_channel::unbounded")
        || line.contains("flume::unbounded");
    if unbounded {
        return Some(ControlBoundaryKind::UnboundedChannel);
    }

    None
}

fn is_privilege_owner(path: &str) -> bool {
    path.starts_with("crates/vortix/src/vortix_protocol_")
        || path.starts_with("crates/vortix/src/vortix_platform_")
        || path.starts_with("crates/vortix/src/helper/")
        || path.starts_with("crates/vortix/src/privileged/")
}

fn legacy_control_budget(path: &str, kind: ControlBoundaryKind) -> usize {
    LEGACY_CONTROL_BUDGETS
        .iter()
        .find_map(|(allowed_path, allowed_kind, count, _removal)| {
            (*allowed_path == path && *allowed_kind == kind).then_some(*count)
        })
        .unwrap_or(0)
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

#[cfg(test)]
mod control_boundary_tests {
    use super::{scan_control_boundaries_at, ControlBoundaryKind};
    use std::path::{Path, PathBuf};

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "vortix-xtask-{name}-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("crates/vortix/src")).unwrap();
            Self { root }
        }

        fn write(&self, relative: &str, body: &str) {
            let path = self.root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }

        fn root(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn rejects_direct_client_mutation_imports() {
        let fixture = Fixture::new("client-import");
        fixture.write(
            "crates/vortix/src/cli/new_writer.rs",
            "use crate::vortix_protocol_wireguard::WgTunnel;\n",
        );

        let violations = scan_control_boundaries_at(fixture.root()).unwrap();
        assert!(violations
            .iter()
            .any(|v| v.kind == ControlBoundaryKind::ClientMutationImport));
    }

    #[test]
    fn rejects_seed_mirror_root_and_unbounded_leaks() {
        let fixture = Fixture::new("writer-leaks");
        fixture.write(
            "crates/vortix/src/core/new_writer.rs",
            "engine.seed_connected_state(id, details, since);\n",
        );
        fixture.write(
            "crates/vortix/src/core/root.rs",
            "let spec = spec.privilege(PrivilegeReq::Root);\n",
        );
        fixture.write(
            "crates/vortix/src/control/queue.rs",
            "let (tx, rx) = mpsc::unbounded_channel();\n",
        );

        let violations = scan_control_boundaries_at(fixture.root()).unwrap();
        for kind in [
            ControlBoundaryKind::SeedOrMirrorWriter,
            ControlBoundaryKind::RootPrivilegeRequest,
            ControlBoundaryKind::UnboundedChannel,
        ] {
            assert!(
                violations.iter().any(|v| v.kind == kind),
                "missing {kind:?} violation: {violations:?}"
            );
        }
    }

    #[test]
    fn approved_owners_pass_and_legacy_budget_cannot_grow() {
        let approved = Fixture::new("approved-owner");
        approved.write(
            "crates/vortix/src/vortix_platform_linux/firewall.rs",
            "let spec = spec.privilege(PrivilegeReq::Root);\n",
        );
        assert!(scan_control_boundaries_at(approved.root())
            .unwrap()
            .is_empty());

        let legacy = Fixture::new("legacy-budget");
        legacy.write(
            "crates/vortix/src/vortix_core/journal/mod.rs",
            "mpsc::unbounded_channel();\nmpsc::unbounded_channel();\nmpsc::unbounded_channel();\n",
        );
        let violations = scan_control_boundaries_at(legacy.root()).unwrap();
        assert!(violations
            .iter()
            .any(|v| v.kind == ControlBoundaryKind::UnboundedChannel));
    }

    #[test]
    fn production_after_inline_test_module_is_still_scanned() {
        let fixture = Fixture::new("production-after-tests");
        fixture.write(
            "crates/vortix/src/cli/new_writer.rs",
            "#[cfg(test)]\nuse crate::vortix_process::CommandSpec;\n\n#[cfg(test)]\nfn ignored_helper() {\n    mpsc::unbounded_channel();\n}\n\n#[cfg(test)]\nmod tests {\n    fn ignored() {\n        engine.seed_connected_state(id, details, since);\n    }\n}\n\nfn production() {\n    crate::vortix_process::run_to_output(spec);\n}\n",
        );

        let violations = scan_control_boundaries_at(fixture.root()).unwrap();
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(
            violations[0].kind,
            ControlBoundaryKind::ClientMutationImport
        );
    }
}
