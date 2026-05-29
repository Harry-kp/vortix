//! Structured output formatting for CLI commands.
//!
//! Provides three output modes:
//! - **Human** (default): colored, aligned, Unicode indicators
//! - **Json**: consistent JSON envelope with `schema_version`, `ok`,
//!   `command`, `data`, `error`, `next_actions`
//! - **Quiet**: no stdout; errors on stderr; exit code is the signal
//!
//! # JSON envelope schema
//!
//! The `schema_version` field declares the contract version of the JSON
//! envelope. Consumers should check it and bail (or log) if they see an
//! unexpected version.
//!
//! Bump policy:
//! - Bump on any field rename, type change, or removal.
//! - Do NOT bump on additive field additions (consumers must tolerate
//!   unknown fields, per JSON convention).
//!
//! v0.3.0 shipped `schema_version = 1` with a single-tunnel
//! `data.connection` block carrying `state`/`profile`/`protocol`/
//! `uptime_secs`.
//!
//! ## v1 → v2 contract (multi-connection plan U21)
//!
//! v0.4.0 bumps `schema_version` to `2` to admit multi-tunnel state in
//! the `status` payload:
//!
//! - **v2 readers** SHOULD prefer `data.connections` (an array of
//!   [`ConnectionEntry`]) and `data.primary` (the profile id of the
//!   primary tunnel, or `null` if none is elected).
//! - **v1 readers** see `data.connection`: the primary tunnel's entry
//!   when a primary exists, or `null` when none does. The field is
//!   retained verbatim for the primary-only case so v0.3.x scripts that
//!   read `data.connection.state` keep working as long as a primary is
//!   active. The only behavioural difference v0.3 → v0.4 in the
//!   primary-only case is that `data.connection` is now `null` (instead
//!   of `{ state: "disconnected" }`) when nothing is connected.

use serde::Serialize;

/// Current version of the structured JSON output envelope.
///
/// Bump when changing the shape of [`CliResponse`] in a non-additive
/// way (renames, removals, type changes). Field additions do not
/// require a bump.
///
/// - `1` (plan 008 U1): single-tunnel `data.connection` block.
/// - `2` (multi-connection plan U21): adds `data.connections` (array)
///   and `data.primary` (profile id, nullable). `data.connection` is
///   retained as the primary's entry for v1 back-compat. See the module
///   docs for the full v1 → v2 contract.
pub const SCHEMA_VERSION: u32 = 2;

/// Per-tunnel snapshot used in the v2 `data.connections` array and
/// (back-compat) `data.connection` field.
///
/// Field set matches the v1 `data.connection` block so v1 readers can
/// keep accessing `data.connection.{state,profile,protocol,uptime_secs}`
/// against the primary tunnel without changes.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionEntry {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
}

/// Output mode selected by global CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
    Quiet,
}

/// Semantic exit codes for CLI commands.
#[derive(Debug, Clone, Copy)]
pub enum ExitCode {
    Success = 0,
    GeneralError = 1,
    PermissionDenied = 2,
    NotFound = 3,
    StateConflict = 4,
    DependencyMissing = 5,
    Timeout = 6,
}

impl ExitCode {
    #[must_use]
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Structured CLI error with machine-readable code and human-friendly hint.
#[derive(Debug, Clone, Serialize)]
pub struct CliError {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Top-level JSON response envelope.
///
/// The `schema_version` field is always serialized first and pinned to
/// the [`SCHEMA_VERSION`] constant. See the module docs for the bump
/// policy.
#[derive(Debug, Serialize)]
pub struct CliResponse<T: Serialize> {
    pub schema_version: u32,
    pub ok: bool,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_actions: Option<Vec<String>>,
}

impl<T: Serialize> CliResponse<T> {
    pub fn success(command: &str, data: T, next_actions: Vec<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ok: true,
            command: command.to_string(),
            data: Some(data),
            error: None,
            next_actions: if next_actions.is_empty() {
                None
            } else {
                Some(next_actions)
            },
        }
    }
}

/// Build an error response (data type doesn't matter, use `()` as placeholder).
#[must_use]
pub fn error_response(command: &str, err: CliError) -> CliResponse<()> {
    CliResponse {
        schema_version: SCHEMA_VERSION,
        ok: false,
        command: command.to_string(),
        data: None,
        error: Some(err),
        next_actions: None,
    }
}

/// Print a successful response in the given output mode.
pub fn print_success<T: Serialize>(
    mode: OutputMode,
    command: &str,
    data: &T,
    next_actions: Vec<String>,
) {
    match mode {
        OutputMode::Json => {
            let resp = CliResponse {
                schema_version: SCHEMA_VERSION,
                ok: true,
                command: command.to_string(),
                data: Some(data),
                error: None::<CliError>,
                next_actions: if next_actions.is_empty() {
                    None
                } else {
                    Some(next_actions)
                },
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
            );
        }
        OutputMode::Quiet => {}
        OutputMode::Human => {
            // Human output is command-specific; callers handle this before calling print_success.
            // This path is used as a fallback JSON dump if the caller didn't handle human mode.
            println!(
                "{}",
                serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".into())
            );
        }
    }
}

/// Print an error and exit with the appropriate code.
pub fn print_error_and_exit(mode: OutputMode, command: &str, err: CliError, exit: ExitCode) -> ! {
    match mode {
        OutputMode::Json => {
            let resp = error_response(command, err);
            // Errors go to stdout in JSON mode (consistent envelope)
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
            );
        }
        OutputMode::Quiet => {
            eprintln!("error: {}", err.message);
        }
        OutputMode::Human => {
            eprintln!("error: {}", err.message);
            if let Some(hint) = &err.hint {
                eprintln!("  hint: {hint}");
            }
        }
    }
    std::process::exit(exit.code());
}

/// Convenience: build a `CliError` for permission denied.
#[must_use]
pub fn err_permission_denied(fix_command: &str) -> CliError {
    CliError {
        code: "permission_denied",
        message: "VPN operations require root privileges".into(),
        hint: Some(format!("Re-run with: sudo {fix_command}")),
    }
}

/// Convenience: build a `CliError` for profile not found.
#[must_use]
pub fn err_not_found(profile: &str) -> CliError {
    CliError {
        code: "not_found",
        message: format!("Profile '{profile}' not found"),
        hint: Some("Run 'vortix list' to see available profiles".into()),
    }
}

/// Convenience: build a `CliError` for missing dependencies.
#[must_use]
pub fn err_dependency_missing(deps: &[String]) -> CliError {
    CliError {
        code: "dependency_missing",
        message: format!("Missing dependencies: {}", deps.join(", ")),
        hint: Some(
            deps.iter()
                .map(|d| format!("Install: {}", crate::platform::install_hint(d)))
                .collect::<Vec<_>>()
                .join("; "),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_pinned_to_2() {
        // Plan 008 U1 + multi-connection U21: any change to
        // SCHEMA_VERSION must be a deliberate contract bump per the
        // policy in the module docs. This test pins the current value
        // so a future drive-by edit can't quietly ship `schema_version
        // = 3` (or revert to 1) without removing this guard.
        assert_eq!(SCHEMA_VERSION, 2);
    }

    #[test]
    fn cli_response_success_serializes_with_schema_version() {
        #[derive(Serialize)]
        struct Payload {
            name: &'static str,
        }
        let resp = CliResponse::success("test", Payload { name: "x" }, vec![]);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"schema_version\":2"),
            "missing schema_version in: {json}"
        );
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"command\":\"test\""));
    }

    #[test]
    fn error_response_serializes_with_schema_version() {
        let err = CliError {
            code: "test_error",
            message: "boom".into(),
            hint: None,
        };
        let resp = error_response("test", err);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"schema_version\":2"),
            "missing schema_version in: {json}"
        );
        assert!(json.contains("\"ok\":false"));
    }

    #[test]
    fn connection_entry_serializes_with_v1_field_set() {
        // v1 readers query `data.connection.{state,profile,protocol,
        // uptime_secs}`. ConnectionEntry is the underlying type for
        // both `data.connection` (back-compat) and the `data.connections`
        // array, so its field set must remain a superset of the v1
        // shape. This test pins that contract.
        let entry = ConnectionEntry {
            state: "connected".into(),
            profile: Some("corp".into()),
            protocol: Some("wireguard".into()),
            uptime_secs: Some(42),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"state\":\"connected\""));
        assert!(json.contains("\"profile\":\"corp\""));
        assert!(json.contains("\"protocol\":\"wireguard\""));
        assert!(json.contains("\"uptime_secs\":42"));
    }

    #[test]
    fn connection_entry_omits_optionals_when_disconnected() {
        let entry = ConnectionEntry {
            state: "disconnected".into(),
            profile: None,
            protocol: None,
            uptime_secs: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert_eq!(json, "{\"state\":\"disconnected\"}");
    }
}
