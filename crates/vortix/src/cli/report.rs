//! Bug report generator.
//!
//! Collects safe system diagnostics, shows a preview, lets the user describe
//! their issue, then either opens a pre-filled GitHub issue in the browser or
//! copies the report to the clipboard.
//!
//! Privacy-by-design: only collects non-identifying data. Never touches IPs,
//! server endpoints, profile names, credentials, DNS servers, or log contents.

use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

use crate::constants;

// ── Data structures ─────────────────────────────────────────────────────────

/// Status of a runtime dependency (e.g. `curl`, `wg-quick`).
struct ToolStatus {
    name: &'static str,
    path: Option<String>,
    version: Option<String>,
}

/// All diagnostic data collected for the report.
struct ReportInfo {
    version: String,
    install_method: String,
    os_info: String,
    arch: String,
    terminal: String,
    terminal_size: String,
    shell: String,
    is_root: bool,
    tools: Vec<ToolStatus>,
    config_dir: String,
    config_source: String,
    config_toml_status: String,
    profile_counts: (u32, u32),
    killswitch_state: String,
}

// ── Public entry point ──────────────────────────────────────────────────────

/// Run the bug report flow: collect, preview, prompt, submit.
pub fn run(config_dir: &Path, config_source: &str) {
    println!("\nCollecting system information...\n");

    let info = collect_report(config_dir, config_source);

    // 1. Show preview
    print_preview(&info);

    // 2. Privacy notice
    println!(
        "  \x1b[2mNOT included: IP addresses, server endpoints, profile\n  \
         names, auth credentials, DNS servers, log contents\x1b[0m\n"
    );

    // 3. Read user description
    let description = read_user_description();

    // 4. Format the full issue body
    let body = format_issue_body(&info, &description);

    // 5. Prompt for action
    let is_ssh = std::env::var("SSH_TTY").is_ok() || std::env::var("SSH_CLIENT").is_ok();
    loop {
        if is_ssh {
            println!("  [c] Copy to clipboard");
            println!("  [p] Print report");
            println!("  [q] Cancel");
        } else {
            println!("  [o] Open in browser (pre-filled GitHub issue)");
            println!("  [c] Copy to clipboard");
            println!("  [p] Print report");
            println!("  [q] Cancel");
        }
        print!("\n  > ");
        let _ = io::stdout().flush();

        let mut choice = String::new();
        if io::stdin().read_line(&mut choice).is_err() {
            break;
        }

        match choice.trim().to_lowercase().as_str() {
            "o" if !is_ssh => {
                let url = build_github_url(&body);
                println!("\n  Opening browser...");
                if open::that(&url).is_err() {
                    eprintln!("  Failed to open browser. Copying to clipboard instead...");
                    if !copy_to_clipboard(&body) {
                        print_fallback(&body);
                    }
                }
                break;
            }
            "c" => {
                if copy_to_clipboard(&body) {
                    println!("\n  Copied to clipboard!");
                    println!(
                        "  Paste it into a new issue at: {}/issues/new?labels=bug",
                        constants::GITHUB_REPO_URL
                    );
                } else {
                    print_fallback(&body);
                }
                break;
            }
            "p" => {
                println!("\n{body}");
                println!(
                    "Open a new issue at: {}/issues/new?labels=bug\n",
                    constants::GITHUB_REPO_URL
                );
                break;
            }
            "q" => {
                println!("\n  Cancelled.");
                break;
            }
            _ => {
                println!("  Invalid choice. Please enter o, c, p, or q.\n");
            }
        }
    }
}

// ── Collection ──────────────────────────────────────────────────────────────

fn collect_report(config_dir: &Path, config_source: &str) -> ReportInfo {
    let config_file = config_dir.join("config.toml");
    let config_toml_status = if config_file.is_file() {
        "found".to_string()
    } else {
        "not found (using defaults)".to_string()
    };

    let profiles_dir = config_dir.join(constants::PROFILES_DIR_NAME);
    let profile_counts = super::commands::count_profiles(&profiles_dir);

    let ks_state = match crate::core::killswitch::load_state() {
        Some(state) => format!("{:?} ({:?})", state.mode, state.state),
        None => "off".to_string(),
    };

    let (term_cols, term_rows) = crossterm::terminal::size().unwrap_or((0, 0));
    let terminal_size = if term_cols > 0 {
        format!("{term_cols}x{term_rows}")
    } else {
        "unknown".to_string()
    };

    ReportInfo {
        version: constants::APP_VERSION.to_string(),
        install_method: detect_install_method(),
        os_info: get_os_info(),
        arch: std::env::consts::ARCH.to_string(),
        terminal: std::env::var("TERM").unwrap_or_else(|_| "unknown".to_string()),
        terminal_size,
        shell: std::env::var("SHELL").unwrap_or_else(|_| "unknown".to_string()),
        is_root: crate::utils::is_root(),
        tools: collect_tool_statuses(),
        config_dir: redact_home_prefix(&config_dir.display().to_string()),
        config_source: config_source.to_string(),
        config_toml_status,
        profile_counts,
        killswitch_state: ks_state,
    }
}

// ── Install method detection ────────────────────────────────────────────────

fn detect_install_method() -> String {
    let exe = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return "unknown".to_string(),
    };

    install_method_from_path(&exe).to_string()
}

/// Determine install method from an executable path string.
fn install_method_from_path(exe: &str) -> &'static str {
    if exe.contains("/.cargo/bin/") {
        "cargo install"
    } else if exe.contains("/opt/homebrew/") || exe.contains("/usr/local/Cellar/") {
        "homebrew"
    } else if exe.contains("/nix/store/") {
        "nix"
    } else if exe.contains("/usr/bin/") || exe.contains("/usr/local/bin/") {
        "system package"
    } else if exe.contains("/target/debug/") || exe.contains("/target/release/") {
        "built from source"
    } else {
        "binary"
    }
}

// ── OS detection ────────────────────────────────────────────────────────────

fn get_os_info() -> String {
    #[cfg(target_os = "macos")]
    {
        let version = cmd_stdout("sw_vers", &["-productVersion"]).unwrap_or_default();
        let kernel = cmd_stdout("uname", &["-r"]).unwrap_or_default();
        if version.is_empty() {
            format!("macOS (Darwin {kernel})")
        } else {
            format!("macOS {version} (Darwin {kernel})")
        }
    }

    #[cfg(target_os = "linux")]
    {
        let distro = linux_distro_name().unwrap_or_else(|| "Linux".to_string());
        let kernel = cmd_stdout("uname", &["-r"]).unwrap_or_default();
        if kernel.is_empty() {
            distro
        } else {
            format!("{distro} (kernel {kernel})")
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_distro_name() -> Option<String> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

// ── Tool status checks ─────────────────────────────────────────────────────

fn collect_tool_statuses() -> Vec<ToolStatus> {
    let mut tools = vec![
        check_tool("curl", &["--version"]),
        check_tool("wg-quick", &["--version"]),
        check_tool("wg", &["--version"]),
        check_tool("openvpn", &["--version"]),
    ];

    #[cfg(target_os = "macos")]
    tools.push(check_tool_exists("pfctl"));

    #[cfg(target_os = "linux")]
    {
        tools.push(check_tool("iptables", &["--version"]));
        tools.push(check_tool("nft", &["--version"]));
    }

    tools
}

/// Check if a tool exists on `$PATH` and try to get its version.
fn check_tool(name: &'static str, version_args: &[&str]) -> ToolStatus {
    let path = cmd_stdout("which", &[name]);

    // wg-quick --version exits non-zero on some systems; try to get version anyway
    let version = match Command::new(name).args(version_args).output() {
        Ok(output) => {
            let raw = if output.stdout.is_empty() {
                String::from_utf8_lossy(&output.stderr).to_string()
            } else {
                String::from_utf8_lossy(&output.stdout).to_string()
            };
            parse_version_line(&raw)
        }
        Err(_) => None,
    };

    ToolStatus {
        name,
        path: path.map(|p| p.trim().to_string()),
        version,
    }
}

/// Check if a tool exists (path only, no version — for tools like `pfctl`).
#[cfg(target_os = "macos")]
fn check_tool_exists(name: &'static str) -> ToolStatus {
    let path = cmd_stdout("which", &[name]);
    ToolStatus {
        name,
        path: path.map(|p| p.trim().to_string()),
        version: None,
    }
}

/// Extract the first meaningful version string from command output.
/// Handles formats like "curl 8.4.0 (aarch64...)", "openvpn 2.6.8", "wg v1.0...", etc.
fn parse_version_line(raw: &str) -> Option<String> {
    let first_line = raw.lines().next()?.trim();
    if first_line.is_empty() {
        return None;
    }

    // Look for a token that starts with a digit or 'v' followed by a digit
    for token in first_line.split_whitespace() {
        let t = token.strip_prefix('v').unwrap_or(token);
        if t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.contains('.') {
            // Strip trailing junk like commas or parens
            let clean: String = t
                .chars()
                .take_while(|c| *c == '.' || c.is_ascii_alphanumeric())
                .collect();
            if !clean.is_empty() {
                return Some(clean);
            }
        }
    }

    // No version-like token found (e.g. usage text, error messages)
    None
}

// ── Preview formatting ──────────────────────────────────────────────────────

fn print_preview(info: &ReportInfo) {
    let (wg, ovpn) = info.profile_counts;
    let total = wg + ovpn;

    println!("Bug Report Preview");
    println!("==================\n");
    println!("  Vortix:       {} ({})", info.version, info.install_method);
    println!("  OS:           {} ({})", info.os_info, info.arch);
    println!("  Terminal:     {} ({})", info.terminal, info.terminal_size);
    println!("  Shell:        {}", info.shell);
    if info.is_root {
        println!("  Running as:   root (via sudo)");
    } else {
        println!("  Running as:   user");
    }

    println!("\n  Dependencies:");
    for tool in &info.tools {
        let status = match (&tool.path, &tool.version) {
            (Some(p), Some(v)) => format!("{p} ({v})"),
            (Some(p), None) => p.clone(),
            _ => "not found".to_string(),
        };
        println!("    {:<12} {status}", tool.name);
    }

    println!("\n  Config:");
    println!(
        "    Directory:   {} ({})",
        info.config_dir, info.config_source
    );
    println!("    config.toml: {}", info.config_toml_status);
    println!("    Profiles:    {total} ({wg} WireGuard, {ovpn} OpenVPN)");
    println!("    Kill switch: {}", info.killswitch_state);
    println!();
}

// ── User input ──────────────────────────────────────────────────────────────

/// Read a multiline description from stdin. An empty line finishes input.
fn read_user_description() -> String {
    // Skip interactive prompt if stdin is not a terminal (piped input)
    if !atty_is_terminal() {
        return String::new();
    }

    println!("Describe the issue (press Enter on an empty line to finish):");

    let stdin = io::stdin();
    let mut lines = Vec::new();

    loop {
        print!("  ");
        let _ = io::stdout().flush();

        let mut buf = String::new();
        match stdin.read_line(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = buf.trim_end_matches(&['\r', '\n'][..]).to_string();
                if line.is_empty() {
                    break;
                }
                lines.push(line);
            }
        }
    }

    let desc = lines.join("\n").trim().to_string();
    if !desc.is_empty() {
        println!();
    }
    desc
}

/// Best-effort check for an interactive terminal without pulling in extra deps.
fn atty_is_terminal() -> bool {
    // crossterm can tell us (it already does isatty internally)
    crossterm::tty::IsTty::is_tty(&io::stdin())
}

// ── Issue body formatting ───────────────────────────────────────────────────

fn format_issue_body(info: &ReportInfo, description: &str) -> String {
    let (wg, ovpn) = info.profile_counts;
    let total = wg + ovpn;

    let mut body = String::with_capacity(2048);

    // Bug Description
    let _ = writeln!(body, "## Bug Description\n");
    if description.is_empty() {
        let _ = writeln!(
            body,
            "<!-- Describe what happened and what you expected -->\n"
        );
    } else {
        let _ = writeln!(body, "{description}\n");
    }

    // Steps to Reproduce
    let _ = writeln!(body, "## Steps to Reproduce\n");
    let _ = writeln!(body, "<!-- How can we reproduce this? -->\n");
    let _ = writeln!(body, "1. ");
    let _ = writeln!(body, "2. ");
    let _ = writeln!(body, "3. \n");

    // Environment (auto-filled)
    let _ = writeln!(body, "## Environment\n");
    let _ = writeln!(body, "```");
    let _ = writeln!(
        body,
        "Vortix:       {} ({})",
        info.version, info.install_method
    );
    let _ = writeln!(body, "OS:           {} ({})", info.os_info, info.arch);
    let _ = writeln!(
        body,
        "Terminal:     {} ({})",
        info.terminal, info.terminal_size
    );
    let _ = writeln!(body, "Shell:        {}", info.shell);
    if info.is_root {
        let _ = writeln!(body, "Running as:   root (via sudo)");
    } else {
        let _ = writeln!(body, "Running as:   user");
    }
    let _ = writeln!(body, "```\n");

    // Dependencies (auto-filled)
    let _ = writeln!(body, "## Dependencies\n");
    let _ = writeln!(body, "```");
    for tool in &info.tools {
        let status = match (&tool.path, &tool.version) {
            (Some(p), Some(v)) => format!("{p} ({v})"),
            (Some(p), None) => p.clone(),
            _ => "not found".to_string(),
        };
        let _ = writeln!(body, "{:<12} {status}", tool.name);
    }
    let _ = writeln!(body, "```\n");

    // Config (auto-filled)
    let _ = writeln!(body, "## Config\n");
    let _ = writeln!(body, "```");
    let _ = writeln!(
        body,
        "Directory:   {} ({})",
        info.config_dir, info.config_source
    );
    let _ = writeln!(body, "config.toml: {}", info.config_toml_status);
    let _ = writeln!(
        body,
        "Profiles:    {total} ({wg} WireGuard, {ovpn} OpenVPN)"
    );
    let _ = writeln!(body, "Kill switch: {}", info.killswitch_state);
    let _ = writeln!(body, "```\n");

    // Additional Context
    let _ = writeln!(body, "## Additional Context\n");
    let _ = writeln!(
        body,
        "<!-- Screenshots, error messages, log snippets (redact any IPs/endpoints) -->"
    );

    body
}

// ── GitHub URL construction ─────────────────────────────────────────────────

fn build_github_url(body: &str) -> String {
    let encoded_title = urlencoding::encode("[Bug] ");
    let base_prefix = format!(
        "{}/issues/new?labels=bug&title={}&body=",
        constants::GITHUB_REPO_URL,
        encoded_title,
    );

    let encoded_body = urlencoding::encode(body);
    let full_url = format!("{base_prefix}{encoded_body}");

    // GitHub silently truncates URLs beyond ~8100 chars
    if full_url.len() <= constants::GITHUB_ISSUE_URL_LIMIT {
        return full_url;
    }

    // Truncate the *raw* body (never the encoded URL) to avoid splitting
    // percent-encoding sequences like %0A. Binary search for the longest
    // prefix that fits within the limit when encoded.
    let suffix = "\n\n<!-- Report truncated due to URL length limit. Please add remaining details manually. -->";
    let max_body_encoded_len = constants::GITHUB_ISSUE_URL_LIMIT.saturating_sub(base_prefix.len());

    if max_body_encoded_len == 0 {
        return base_prefix;
    }

    let body_chars: Vec<char> = body.chars().collect();
    let mut low = 0usize;
    let mut high = body_chars.len();
    let mut best_url = base_prefix.clone();

    while low <= high {
        let mid = (low + high) / 2;

        let candidate_raw: String = body_chars.iter().take(mid).collect();
        let candidate_with_suffix = format!("{candidate_raw}{suffix}");
        let encoded_candidate = urlencoding::encode(&candidate_with_suffix);

        if encoded_candidate.len() <= max_body_encoded_len {
            best_url = format!("{base_prefix}{encoded_candidate}");
            if mid == body_chars.len() {
                break;
            }
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    best_url
}

// ── Clipboard ───────────────────────────────────────────────────────────────

fn copy_to_clipboard(text: &str) -> bool {
    #[cfg(target_os = "macos")]
    let result = pipe_to_command("pbcopy", text);

    #[cfg(target_os = "linux")]
    let result = if std::env::var("WAYLAND_DISPLAY").is_ok() {
        pipe_to_command("wl-copy", text)
            .or_else(|| pipe_to_command("xclip", text))
            .or_else(|| pipe_to_command("xsel", text))
    } else {
        pipe_to_command("xclip", text)
            .or_else(|| pipe_to_command("xsel", text))
            .or_else(|| pipe_to_command("wl-copy", text))
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: Option<()> = None;

    result.is_some()
}

/// Pipe `text` to a command's stdin.
fn pipe_to_command(cmd: &str, text: &str) -> Option<()> {
    use std::process::Stdio;

    let mut child = Command::new(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes()).ok()?;
    }

    let status = child.wait().ok()?;
    status.success().then_some(())
}

/// Fallback when clipboard is unavailable.
fn print_fallback(body: &str) {
    println!("\n  Could not copy to clipboard.\n");
    println!("{body}");
    println!(
        "Open a new issue at: {}/issues/new?labels=bug\n",
        constants::GITHUB_REPO_URL
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Replace the user's home directory prefix with `~` for privacy.
fn redact_home_prefix(path: &str) -> String {
    if let Some(home) = crate::utils::home_dir() {
        let home_str = home.to_string_lossy();
        if let Some(rest) = path.strip_prefix(home_str.as_ref()) {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

/// Run a command and return its stdout as a trimmed string.
fn cmd_stdout(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_curl() {
        let raw = "curl 8.4.0 (aarch64-apple-darwin23.0) libcurl/8.4.0";
        assert_eq!(parse_version_line(raw), Some("8.4.0".to_string()));
    }

    #[test]
    fn test_parse_version_openvpn() {
        let raw = "OpenVPN 2.6.8 x86_64-pc-linux-gnu [SSL (OpenSSL)]";
        assert_eq!(parse_version_line(raw), Some("2.6.8".to_string()));
    }

    #[test]
    fn test_parse_version_wg() {
        let raw = "wireguard-tools v1.0.20210914 - https://git.zx2c4.com/wireguard-tools/";
        assert_eq!(parse_version_line(raw), Some("1.0.20210914".to_string()));
    }

    #[test]
    fn test_parse_version_empty() {
        assert_eq!(parse_version_line(""), None);
        assert_eq!(parse_version_line("  \n  "), None);
    }

    #[test]
    fn test_parse_version_no_version_token() {
        // Usage text or error messages should return None, not a false "version"
        let raw = "Usage: wg-quick [ up | down | save | strip ] [ CONFIG_FILE ]";
        assert_eq!(parse_version_line(raw), None);

        let raw2 = "some-tool (no version)";
        assert_eq!(parse_version_line(raw2), None);
    }

    #[test]
    fn test_install_method_from_path() {
        assert_eq!(
            install_method_from_path("/Users/user/.cargo/bin/vortix"),
            "cargo install"
        );
        assert_eq!(
            install_method_from_path("/opt/homebrew/bin/vortix"),
            "homebrew"
        );
        assert_eq!(
            install_method_from_path("/usr/local/Cellar/vortix/0.1/bin/vortix"),
            "homebrew"
        );
        assert_eq!(
            install_method_from_path("/nix/store/abc-vortix/bin/vortix"),
            "nix"
        );
        assert_eq!(
            install_method_from_path("/usr/bin/vortix"),
            "system package"
        );
        assert_eq!(
            install_method_from_path("/usr/local/bin/vortix"),
            "system package"
        );
        assert_eq!(
            install_method_from_path("/home/user/vortix/target/debug/vortix"),
            "built from source"
        );
        assert_eq!(
            install_method_from_path("/home/user/vortix/target/release/vortix"),
            "built from source"
        );
        assert_eq!(
            install_method_from_path("/some/random/path/vortix"),
            "binary"
        );
    }

    #[test]
    fn test_build_github_url_within_limit() {
        let body = "## Test\n\nShort body";
        let url = build_github_url(body);
        assert!(url.starts_with(&format!("{}/issues/new", constants::GITHUB_REPO_URL)));
        assert!(url.len() <= constants::GITHUB_ISSUE_URL_LIMIT);
    }

    #[test]
    fn test_build_github_url_truncation() {
        // Create a body that will exceed the URL limit when encoded
        let body = "A".repeat(10_000);
        let url = build_github_url(&body);
        assert!(url.len() <= constants::GITHUB_ISSUE_URL_LIMIT);
    }

    #[test]
    fn test_format_issue_body_with_description() {
        let info = ReportInfo {
            version: "0.1.4".to_string(),
            install_method: "cargo install".to_string(),
            os_info: "macOS 14.2".to_string(),
            arch: "aarch64".to_string(),
            terminal: "xterm-256color".to_string(),
            terminal_size: "120x40".to_string(),
            shell: "/bin/zsh".to_string(),
            is_root: false,
            tools: vec![],
            config_dir: "~/.config/vortix".to_string(),
            config_source: "default".to_string(),
            config_toml_status: "found".to_string(),
            profile_counts: (2, 1),
            killswitch_state: "off".to_string(),
        };

        let body = format_issue_body(&info, "WireGuard shows connected but no traffic");
        assert!(body.contains("## Bug Description"));
        assert!(body.contains("WireGuard shows connected but no traffic"));
        assert!(body.contains("## Environment"));
        assert!(body.contains("0.1.4 (cargo install)"));
        assert!(body.contains("## Dependencies"));
        assert!(body.contains("## Config"));
        assert!(body.contains("3 (2 WireGuard, 1 OpenVPN)"));
    }

    #[test]
    fn test_format_issue_body_empty_description() {
        let info = ReportInfo {
            version: "0.1.4".to_string(),
            install_method: "unknown".to_string(),
            os_info: "Linux".to_string(),
            arch: "x86_64".to_string(),
            terminal: "unknown".to_string(),
            terminal_size: "unknown".to_string(),
            shell: "unknown".to_string(),
            is_root: true,
            tools: vec![],
            config_dir: "/root/.config/vortix".to_string(),
            config_source: "default".to_string(),
            config_toml_status: "not found (using defaults)".to_string(),
            profile_counts: (0, 0),
            killswitch_state: "off".to_string(),
        };

        let body = format_issue_body(&info, "");
        assert!(body.contains("<!-- Describe what happened"));
        assert!(body.contains("root (via sudo)"));
    }
}
