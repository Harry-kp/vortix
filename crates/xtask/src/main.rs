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
    DuplicateControlVocabulary,
}

impl ControlBoundaryKind {
    const fn label(self) -> &'static str {
        match self {
            Self::ClientMutationImport => "direct client mutation-layer import",
            Self::SeedOrMirrorWriter => "production seed/mirror writer",
            Self::RootPrivilegeRequest => "root privilege request outside an owner",
            Self::UnboundedChannel => "unbounded production channel",
            Self::DuplicateControlVocabulary => "duplicate canonical control vocabulary",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlItemKind {
    Enum,
    Struct,
}

struct CanonicalControlItem {
    name: &'static str,
    kind: ControlItemKind,
    path: &'static str,
}

/// Exact owners for vocabulary that crosses the canonical control boundary.
/// Public aliases are checked separately against the compatibility allowlist.
const CANONICAL_CONTROL_ITEMS: &[CanonicalControlItem] = &[
    CanonicalControlItem {
        name: "UserCommand",
        kind: ControlItemKind::Enum,
        path: "crates/vortix/src/vortix_core/control/command.rs",
    },
    CanonicalControlItem {
        name: "ControlEvent",
        kind: ControlItemKind::Enum,
        path: "crates/vortix/src/vortix_core/control/model.rs",
    },
    CanonicalControlItem {
        name: "DesiredState",
        kind: ControlItemKind::Struct,
        path: "crates/vortix/src/vortix_core/control/model.rs",
    },
    CanonicalControlItem {
        name: "ObservedState",
        kind: ControlItemKind::Struct,
        path: "crates/vortix/src/vortix_core/control/model.rs",
    },
    CanonicalControlItem {
        name: "EffectiveState",
        kind: ControlItemKind::Struct,
        path: "crates/vortix/src/vortix_core/control/model.rs",
    },
    CanonicalControlItem {
        name: "ControlSnapshot",
        kind: ControlItemKind::Struct,
        path: "crates/vortix/src/vortix_core/control/snapshot.rs",
    },
    CanonicalControlItem {
        name: "OperationRecord",
        kind: ControlItemKind::Struct,
        path: "crates/vortix/src/vortix_core/control/model.rs",
    },
    CanonicalControlItem {
        name: "ChallengeRecord",
        kind: ControlItemKind::Struct,
        path: "crates/vortix/src/vortix_core/control/model.rs",
    },
    CanonicalControlItem {
        name: "ChallengeKind",
        kind: ControlItemKind::Enum,
        path: "crates/vortix/src/vortix_core/control/model.rs",
    },
];

const COMPATIBILITY_CONTROL_NAMES: &[&str] = &["EngineEvent", "PromptKind"];

#[derive(Debug)]
struct RustToken {
    text: String,
    line: usize,
}

#[derive(Debug)]
enum PublicControlItem {
    Definition {
        name: String,
        kind: Option<ControlItemKind>,
        line: usize,
    },
    Reexport {
        name: String,
        line: usize,
        statement: String,
    },
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
];

fn check_control_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    let violations = scan_control_boundaries_at(&root)?;
    if violations.is_empty() {
        eprintln!("xtask check-control-boundaries: ok");
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
    let mut public_control_items = Vec::new();
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
        for item in scan_public_control_items(&content) {
            public_control_items.push((relative.clone(), item));
        }
        candidates.extend(scan_token_control_boundaries(&relative, &content));
    }

    candidates.extend(duplicate_control_violations(root, public_control_items));

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

fn duplicate_control_violations(
    root: &Path,
    mut items: Vec<(String, PublicControlItem)>,
) -> Vec<ControlBoundaryViolation> {
    use std::collections::HashMap;

    items.sort_by(|(left_path, left), (right_path, right)| {
        left_path
            .cmp(right_path)
            .then_with(|| public_control_item_line(left).cmp(&public_control_item_line(right)))
    });

    let mut canonical_definition_counts: HashMap<&'static str, usize> = HashMap::new();
    let mut violations = Vec::new();
    for (path, item) in items {
        let (name, line, valid) = match &item {
            PublicControlItem::Definition { name, kind, line } => {
                let Some(canonical) = canonical_control_item(name) else {
                    continue;
                };
                let count = canonical_definition_counts
                    .entry(canonical.name)
                    .or_default();
                let valid = path == canonical.path && *kind == Some(canonical.kind) && *count == 0;
                if path == canonical.path && *kind == Some(canonical.kind) {
                    *count += 1;
                }
                (name, *line, valid)
            }
            PublicControlItem::Reexport {
                name,
                line,
                statement,
            } => (
                name,
                *line,
                allowed_control_reexport(&path, name, statement),
            ),
        };
        if !valid {
            let source = content_line_at(root, &path, line).unwrap_or_else(|| name.clone());
            violations.push(ControlBoundaryViolation {
                kind: ControlBoundaryKind::DuplicateControlVocabulary,
                path,
                line,
                source,
            });
        }
    }
    violations
}

fn public_control_item_line(item: &PublicControlItem) -> usize {
    match item {
        PublicControlItem::Definition { line, .. } | PublicControlItem::Reexport { line, .. } => {
            *line
        }
    }
}

fn canonical_control_item(name: &str) -> Option<&'static CanonicalControlItem> {
    CANONICAL_CONTROL_ITEMS
        .iter()
        .find(|item| item.name == name)
}

fn is_control_vocabulary_name(name: &str) -> bool {
    canonical_control_item(name).is_some() || COMPATIBILITY_CONTROL_NAMES.contains(&name)
}

fn allowed_control_reexport(path: &str, name: &str, statement: &str) -> bool {
    if path == "crates/vortix/src/vortix_core/control/mod.rs" {
        return match name {
            "UserCommand" => statement.starts_with("command::{"),
            "ControlSnapshot" => {
                statement.starts_with("snapshot::ControlSnapshot")
                    || statement.starts_with("snapshot::{")
            }
            "ControlEvent" | "DesiredState" | "ObservedState" | "EffectiveState"
            | "OperationRecord" | "ChallengeRecord" | "ChallengeKind" => {
                statement.starts_with("model::{")
            }
            _ => false,
        };
    }

    match (path, name) {
        ("crates/vortix/src/vortix_core/control/model.rs", "EngineEvent") => {
            statement == "ControlEventasEngineEvent"
        }
        ("crates/vortix/src/vortix_core/engine/event.rs", "EngineEvent") => {
            statement.contains("control::model::{ControlEventasEngineEvent")
        }
        ("crates/vortix/src/vortix_core/engine/state.rs", "PromptKind") => {
            statement.contains("control::model::ChallengeKindasPromptKind")
        }
        ("crates/vortix/src/vortix_core/engine/input.rs", "UserCommand") => {
            statement == "EngineUserCommandasUserCommand"
        }
        ("crates/vortix/src/vortix_core/engine/mod.rs", "EngineEvent") => {
            statement.starts_with("event::{")
        }
        ("crates/vortix/src/vortix_core/engine/mod.rs", "UserCommand") => {
            statement.starts_with("input::{")
        }
        _ => false,
    }
}

fn content_line_at(root: &Path, path: &str, line: usize) -> Option<String> {
    std::fs::read_to_string(root.join(path))
        .ok()?
        .lines()
        .nth(line.saturating_sub(1))
        .map(str::trim)
        .map(ToOwned::to_owned)
}

/// Lightweight Rust item scanner for the small public-vocabulary manifest.
/// It tokenizes identifiers/punctuation while discarding comments, string
/// literals, raw strings, and character literals. This deliberately avoids a
/// full parser dependency in `xtask` while still handling multiline items and
/// `pub(crate)` visibility.
fn scan_public_control_items(content: &str) -> Vec<PublicControlItem> {
    let tokens = rust_tokens(content);
    let mut items = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index].text != "pub" {
            index += 1;
            continue;
        }
        let line = tokens[index].line;
        let mut cursor = index + 1;
        if tokens.get(cursor).is_some_and(|token| token.text == "(") {
            while cursor < tokens.len() && tokens[cursor].text != ")" {
                cursor += 1;
            }
            cursor += usize::from(cursor < tokens.len());
        }

        match tokens.get(cursor).map(|token| token.text.as_str()) {
            Some("enum" | "struct" | "type") => {
                let kind = match tokens[cursor].text.as_str() {
                    "enum" => Some(ControlItemKind::Enum),
                    "struct" => Some(ControlItemKind::Struct),
                    "type" => None,
                    _ => unreachable!(),
                };
                if let Some(name) = tokens.get(cursor + 1) {
                    if canonical_control_item(&name.text).is_some() {
                        items.push(PublicControlItem::Definition {
                            name: name.text.clone(),
                            kind,
                            line,
                        });
                    }
                }
            }
            Some("use") => {
                let end = tokens[cursor + 1..]
                    .iter()
                    .position(|token| token.text == ";")
                    .map_or(tokens.len(), |offset| cursor + 1 + offset);
                let statement = tokens[cursor + 1..end]
                    .iter()
                    .map(|token| token.text.as_str())
                    .collect::<String>();
                for export_index in cursor + 1..end {
                    let name = &tokens[export_index].text;
                    if !is_control_vocabulary_name(name) {
                        continue;
                    }
                    let previous_is_as =
                        export_index > cursor + 1 && tokens[export_index - 1].text == "as";
                    let followed_by_as = tokens
                        .get(export_index + 1)
                        .is_some_and(|token| token.text == "as");
                    let terminates_export = tokens
                        .get(export_index + 1)
                        .is_none_or(|token| matches!(token.text.as_str(), "," | "}" | ";"));
                    if previous_is_as || (!followed_by_as && terminates_export) {
                        items.push(PublicControlItem::Reexport {
                            name: name.clone(),
                            line,
                            statement: statement.clone(),
                        });
                    }
                }
                index = end;
            }
            _ => {}
        }
        index += 1;
    }
    items
}

fn rust_tokens(content: &str) -> Vec<RustToken> {
    let bytes = content.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => {
                line += 1;
                index += 1;
            }
            byte if byte.is_ascii_whitespace() => index += 1,
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut depth = 1usize;
                while index < bytes.len() && depth > 0 {
                    if bytes[index] == b'\n' {
                        line += 1;
                        index += 1;
                    } else if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                        depth += 1;
                        index += 2;
                    } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                        depth -= 1;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
            }
            b'"' => skip_quoted(bytes, &mut index, &mut line, b'"'),
            b'\'' if looks_like_char_literal(bytes, index) => {
                skip_quoted(bytes, &mut index, &mut line, b'\'');
            }
            b'r' if raw_string_hashes(bytes, index).is_some() => {
                skip_raw_string(bytes, &mut index, &mut line);
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                tokens.push(RustToken {
                    text: content[start..index].to_owned(),
                    line,
                });
            }
            punctuation @ (b'(' | b')' | b'{' | b'}' | b',' | b';' | b':') => {
                tokens.push(RustToken {
                    text: char::from(punctuation).to_string(),
                    line,
                });
                index += 1;
            }
            _ => index += 1,
        }
    }
    tokens
}

fn scan_token_control_boundaries(path: &str, content: &str) -> Vec<ControlBoundaryViolation> {
    use std::collections::HashSet;

    let production = production_source_without_test_items(content);
    let tokens = rust_tokens(&production);
    let is_client = path.starts_with("crates/vortix/src/app/")
        || path.starts_with("crates/vortix/src/cli/")
        || path.starts_with("crates/vortix/src/ui/");
    let mut violations = Vec::new();
    let mut seen_lines = HashSet::new();

    for (index, token) in tokens.iter().enumerate() {
        let kind = if is_client
            && (token.text.starts_with("vortix_protocol_")
                || token.text.starts_with("vortix_platform_")
                || token.text == "vortix_process")
        {
            Some(ControlBoundaryKind::ClientMutationImport)
        } else if token.text.starts_with("seed_") || token.text.starts_with("mirror_") {
            Some(ControlBoundaryKind::SeedOrMirrorWriter)
        } else if token.text == "privilege"
            && !is_privilege_owner(path)
            && tokens[index + 1..tokens.len().min(index + 9)]
                .windows(3)
                .any(|window| {
                    window[0].text == "PrivilegeReq"
                        && window[1].text == ":"
                        && window[2].text == ":"
                })
            && tokens[index + 1..tokens.len().min(index + 11)]
                .iter()
                .any(|candidate| candidate.text == "Root")
        {
            Some(ControlBoundaryKind::RootPrivilegeRequest)
        } else if matches!(
            token.text.as_str(),
            "unbounded_channel" | "UnboundedSender" | "UnboundedReceiver" | "unbounded"
        ) {
            Some(ControlBoundaryKind::UnboundedChannel)
        } else {
            None
        };
        if let Some(kind) = kind.filter(|kind| seen_lines.insert((*kind, token.line))) {
            let source = content
                .lines()
                .nth(token.line.saturating_sub(1))
                .map(str::trim)
                .unwrap_or_default()
                .to_string();
            violations.push(ControlBoundaryViolation {
                kind,
                path: path.to_string(),
                line: token.line,
                source,
            });
        }
    }
    violations
}

fn production_source_without_test_items(content: &str) -> String {
    let mut output = String::with_capacity(content.len());
    let mut pending_test_cfg = false;
    let mut skipping_test_item = false;
    let mut test_item_indent = 0usize;
    for line in content.lines() {
        let trimmed = line.trim_start();
        let mut retain = true;
        if skipping_test_item {
            retain = false;
            let indent = line.len() - trimmed.len();
            if indent == test_item_indent && (trimmed == "}" || trimmed == "};") {
                skipping_test_item = false;
            }
        } else if trimmed == "#[cfg(test)]" {
            retain = false;
            pending_test_cfg = true;
            test_item_indent = line.len() - trimmed.len();
        } else if pending_test_cfg && trimmed.starts_with("#[") {
            retain = false;
        } else if pending_test_cfg {
            retain = false;
            if trimmed.ends_with(';') {
                pending_test_cfg = false;
            } else if let Some(open) = line.find('{') {
                pending_test_cfg = false;
                skipping_test_item = line[open + 1..].find('}').is_none();
            }
        }
        if retain {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

fn skip_quoted(bytes: &[u8], index: &mut usize, line: &mut usize, quote: u8) {
    *index += 1;
    while *index < bytes.len() {
        if bytes[*index] == b'\\' {
            *index = (*index + 2).min(bytes.len());
        } else if bytes[*index] == quote {
            *index += 1;
            break;
        } else {
            if bytes[*index] == b'\n' {
                *line += 1;
            }
            *index += 1;
        }
    }
}

fn looks_like_char_literal(bytes: &[u8], index: usize) -> bool {
    let mut cursor = index + 1;
    if bytes.get(cursor) == Some(&b'\\') {
        cursor += 2;
    } else {
        cursor += 1;
    }
    bytes.get(cursor) == Some(&b'\'')
}

fn raw_string_hashes(bytes: &[u8], index: usize) -> Option<usize> {
    let mut cursor = index + 1;
    let mut hashes = 0;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'"')).then_some(hashes)
}

fn skip_raw_string(bytes: &[u8], index: &mut usize, line: &mut usize) {
    let hashes = raw_string_hashes(bytes, *index).expect("raw string prefix");
    *index += 2 + hashes;
    while *index < bytes.len() {
        if bytes[*index] == b'\n' {
            *line += 1;
            *index += 1;
            continue;
        }
        if bytes[*index] == b'"'
            && bytes
                .get(*index + 1..*index + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            *index += 1 + hashes;
            break;
        }
        *index += 1;
    }
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
    fn rejects_grouped_imports_and_multiline_privilege_requests() {
        let fixture = Fixture::new("multiline-boundary-leaks");
        fixture.write(
            "crates/vortix/src/cli/grouped.rs",
            "use crate::{\n    vortix_protocol_wireguard::WgTunnel,\n    vortix_core::profile::ProfileId,\n};\n",
        );
        fixture.write(
            "crates/vortix/src/core/root.rs",
            "let spec = spec.privilege(\n    PrivilegeReq::Root,\n);\n",
        );

        let violations = scan_control_boundaries_at(fixture.root()).unwrap();
        assert!(violations
            .iter()
            .any(|violation| violation.kind == ControlBoundaryKind::ClientMutationImport));
        assert!(violations
            .iter()
            .any(|violation| violation.kind == ControlBoundaryKind::RootPrivilegeRequest));
    }

    #[test]
    fn rejects_duplicate_control_vocabulary_but_allows_compatibility_reexports() {
        let duplicate = Fixture::new("duplicate-control-vocabulary");
        duplicate.write(
            "crates/vortix/src/daemon/model.rs",
            "pub enum UserCommand { Connect }\npub struct ControlSnapshot;\n",
        );
        let violations = scan_control_boundaries_at(duplicate.root()).unwrap();
        assert_eq!(
            violations
                .iter()
                .filter(
                    |violation| violation.kind == ControlBoundaryKind::DuplicateControlVocabulary
                )
                .count(),
            2
        );

        let reexport = Fixture::new("control-compatibility-reexport");
        reexport.write(
            "crates/vortix/src/vortix_core/engine/input.rs",
            "pub use EngineUserCommand as UserCommand;\n",
        );
        assert!(scan_control_boundaries_at(reexport.root())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn duplicate_vocabulary_scanner_handles_multiline_visibility_and_aliases() {
        let fixture = Fixture::new("adversarial-control-vocabulary");
        fixture.write(
            "crates/vortix/src/daemon/multiline.rs",
            "pub(crate)\nstruct\nDesiredState { generation: u64 }\n\npub\ntype\nControlSnapshot = ();\n",
        );
        fixture.write(
            "crates/vortix/src/vortix_core/control/shadow.rs",
            "pub enum UserCommand { Shadow }\n",
        );
        fixture.write(
            "crates/vortix/src/daemon/reexport.rs",
            "pub use crate::elsewhere::Thing as EffectiveState;\n",
        );

        let violations = scan_control_boundaries_at(fixture.root()).unwrap();
        assert_eq!(
            violations
                .iter()
                .filter(|violation| {
                    violation.kind == ControlBoundaryKind::DuplicateControlVocabulary
                })
                .count(),
            4,
            "{violations:#?}"
        );
    }

    #[test]
    fn duplicate_vocabulary_scanner_ignores_comments_strings_and_lifetimes() {
        let fixture = Fixture::new("control-vocabulary-non-code");
        fixture.write(
            "crates/vortix/src/daemon/prose.rs",
            r##"
// pub enum UserCommand { Fake }
/* pub struct ControlSnapshot; */
const TEXT: &str = "pub struct DesiredState;";
const RAW: &str = r#"pub enum ControlEvent { Fake }"#;
fn lifetime<'a>(value: &'a str) -> &'a str { value }
"##,
        );

        assert!(scan_control_boundaries_at(fixture.root())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn only_documented_engine_compatibility_reexports_are_allowed() {
        let allowed = Fixture::new("documented-engine-reexport");
        allowed.write(
            "crates/vortix/src/vortix_core/engine/input.rs",
            "pub use EngineUserCommand as UserCommand;\n",
        );
        assert!(scan_control_boundaries_at(allowed.root())
            .unwrap()
            .is_empty());

        let spoofed = Fixture::new("spoofed-engine-reexport");
        spoofed.write(
            "crates/vortix/src/vortix_core/engine/input.rs",
            "pub use Elsewhere as ControlSnapshot;\n",
        );
        assert!(scan_control_boundaries_at(spoofed.root())
            .unwrap()
            .iter()
            .any(|violation| {
                violation.kind == ControlBoundaryKind::DuplicateControlVocabulary
            }));

        let wrong_facade_source = Fixture::new("wrong-control-facade-source");
        wrong_facade_source.write(
            "crates/vortix/src/vortix_core/control/mod.rs",
            "pub use crate::elsewhere::DesiredState;\n",
        );
        assert!(scan_control_boundaries_at(wrong_facade_source.root())
            .unwrap()
            .iter()
            .any(|violation| {
                violation.kind == ControlBoundaryKind::DuplicateControlVocabulary
            }));
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
