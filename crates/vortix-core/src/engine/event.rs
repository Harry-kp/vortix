//! `EngineEvent` schema and JSONL envelope (plan #005 U1).
//!
//! Fifteen day-one event variants describe everything the FSM emits to the
//! journal and the broadcast channel. The envelope carries a
//! `schema_version: u32` (starts at 1) so future schema evolution can be
//! detected by replay tooling.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::engine::state::{ConnectionHealth, DegradedReason, FailureReason};
use crate::profile::{ProfileId, ProtocolKind};

/// Current journal schema version. Bumped when `EngineEvent`'s wire format
/// changes incompatibly.
pub const SCHEMA_VERSION: u32 = 1;

/// JSONL envelope written to disk and broadcast to subscribers.
///
/// Each envelope is one line in the journal file. `timestamp` is RFC3339;
/// `event` is the tagged enum below.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: u32,
    pub timestamp: SystemTime,
    pub event: EngineEvent,
}

impl EventEnvelope {
    /// Wrap an event in a fresh envelope stamped with the current schema
    /// version and "now".
    #[must_use]
    pub fn new(event: EngineEvent) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp: SystemTime::now(),
            event,
        }
    }
}

/// Everything the FSM emits.
///
/// `#[non_exhaustive]` so future variants don't break replay tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineEvent {
    /// FSM started a connect attempt for `profile_id`.
    ConnectAttemptStarted {
        profile_id: ProfileId,
        protocol: ProtocolKind,
        attempt: u32,
    },
    /// A connect / reconnect attempt failed without exhausting the retry
    /// budget. Followed by `RetryScheduled` or `RetryBudgetExhausted`.
    ConnectAttemptFailed {
        profile_id: ProfileId,
        attempt: u32,
        reason: FailureReason,
    },
    /// Tunnel came up successfully.
    TunnelUp {
        profile_id: ProfileId,
        protocol: ProtocolKind,
        interface_name: String,
        pid: Option<u32>,
    },
    /// Tunnel went down (user-initiated disconnect, network loss, or daemon
    /// exit).
    TunnelDown {
        profile_id: ProfileId,
        reason: TunnelDownReason,
    },
    /// `wg show` reports `latest_handshake` exceeding the staleness threshold.
    HandshakeStale {
        profile_id: ProfileId,
        seconds_since_last_handshake: u64,
    },
    /// `Connected` health field changed.
    ConnectionHealthChanged {
        profile_id: ProfileId,
        old: ConnectionHealth,
        new: ConnectionHealth,
    },
    /// Detected a public IP change (telemetry-observed).
    IpChanged { old: Option<String>, new: String },
    /// Kill switch transitioned to actively blocking.
    KillswitchEngaged { reason: KillswitchEngageReason },
    /// Kill switch released.
    KillswitchDisengaged,
    /// A retry was scheduled after a transient failure.
    RetryScheduled {
        profile_id: ProfileId,
        next_attempt: u32,
        delay: Duration,
        retry_budget_remaining: Duration,
    },
    /// The retry budget was exhausted; FSM is moving back to
    /// `Disconnected { last_failure: RetryBudgetExhausted }`.
    RetryBudgetExhausted {
        profile_id: ProfileId,
        total_attempts: u32,
        elapsed: Duration,
    },
    /// Network monitor detected loss of the default route.
    NetworkLinkLost,
    /// Network monitor detected the default route returning.
    NetworkLinkRestored { new_gateway: Option<String> },
    /// Profile renamed by the user; FSM updates display name in place
    /// (`profile_id` is stable across renames per plan #005 R3).
    ProfileRenamed {
        profile_id: ProfileId,
        old_display_name: String,
        new_display_name: String,
    },
    /// User requested deletion of a profile that's currently in scope; FSM
    /// may have to tear down the tunnel before honoring the request.
    ProfileDeletionRequested { profile_id: ProfileId },
    /// Journal startup retention pass deleted N stale files.
    JournalRetentionApplied { deleted: u32 },
    /// A degraded condition cleared (paired with `ConnectionHealthChanged`
    /// when health returns to `Healthy`).
    DegradedReasonCleared {
        profile_id: ProfileId,
        reason: DegradedReason,
    },
    /// Plan 008 U2: the FSM needs the user to supply input to continue
    /// (2FA code, passphrase, etc.). Reserved for issue #191; no
    /// consumer wired in v0.3.0. The corresponding `UserCommand::UserAnswered`
    /// references the same `prompt_id`.
    UserPromptRequested {
        profile_id: ProfileId,
        prompt_id: String,
        prompt_kind: crate::engine::state::PromptKind,
        prompt_text: String,
    },
    /// Plan 016: a lifecycle hook fired with the given outcome. Emitted
    /// for every fire (Success and otherwise) so consumers can render
    /// a complete history. Toast emission applies its own filter on the
    /// consumer side.
    HookOutcome {
        hook_name: String,
        event_kind: String,
        record: HookOutcomeRecord,
    },
}

/// Serializable record of one hook fire (plan 016 U1).
///
/// Outcome label, exit code (when known), and truncated stdout/stderr.
/// Lives next to `EngineEvent` so journal consumers don't drag in the
/// runtime `HookOutcome` enum from `engine::hooks`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookOutcomeRecord {
    /// `success`, `failed`, `timed_out`, or `aborted`.
    pub outcome: HookOutcomeLabel,
    /// Subprocess exit code. `None` for `timed_out` / `aborted` / when
    /// the runner couldn't recover an exit status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Truncated stdout (UTF-8 lossy; max 1 KiB). Empty string when
    /// nothing was captured.
    #[serde(default)]
    pub stdout: String,
    /// Truncated stderr (UTF-8 lossy; max 1 KiB). Empty string when
    /// nothing was captured.
    #[serde(default)]
    pub stderr: String,
    /// Whether the body was truncated (for either stream).
    #[serde(default)]
    pub truncated: bool,
}

/// Outcome label tagged for serde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum HookOutcomeLabel {
    Success,
    Failed,
    TimedOut,
    Aborted,
}

/// Maximum bytes captured per stream in a [`HookOutcomeRecord`].
pub const HOOK_OUTPUT_CAP_BYTES: usize = 1024;

impl HookOutcomeRecord {
    /// Build a record from raw subprocess output, truncating each
    /// stream to [`HOOK_OUTPUT_CAP_BYTES`] and flagging when truncation
    /// happened. Truncation is byte-aware: cuts at a UTF-8 boundary so
    /// the resulting strings don't panic on `from_utf8_lossy`.
    #[must_use]
    pub fn new(
        outcome: HookOutcomeLabel,
        exit_code: Option<i32>,
        stdout_bytes: &[u8],
        stderr_bytes: &[u8],
    ) -> Self {
        let (stdout, stdout_truncated) = truncate_stream(stdout_bytes);
        let (stderr, stderr_truncated) = truncate_stream(stderr_bytes);
        Self {
            outcome,
            exit_code,
            stdout,
            stderr,
            truncated: stdout_truncated || stderr_truncated,
        }
    }
}

fn truncate_stream(bytes: &[u8]) -> (String, bool) {
    if bytes.len() <= HOOK_OUTPUT_CAP_BYTES {
        return (String::from_utf8_lossy(bytes).into_owned(), false);
    }
    // Walk back to a char boundary at or below the cap.
    let mut end = HOOK_OUTPUT_CAP_BYTES;
    while end > 0 && !is_utf8_char_boundary(bytes, end) {
        end -= 1;
    }
    (
        String::from_utf8_lossy(&bytes[..end]).into_owned(),
        true,
    )
}

impl From<&crate::engine::hooks::HookOutcome> for HookOutcomeRecord {
    /// Map the runtime [`HookOutcome`](crate::engine::hooks::HookOutcome)
    /// to a serializable record. `exit_code` stays `None` until the
    /// runtime enum is enriched to carry it.
    fn from(outcome: &crate::engine::hooks::HookOutcome) -> Self {
        use crate::engine::hooks::HookOutcome;
        match outcome {
            HookOutcome::Success => Self::new(HookOutcomeLabel::Success, Some(0), b"", b""),
            HookOutcome::Failed(msg) => {
                Self::new(HookOutcomeLabel::Failed, None, b"", msg.as_bytes())
            }
            HookOutcome::TimedOut => Self::new(HookOutcomeLabel::TimedOut, None, b"", b""),
            HookOutcome::Aborted(msg) => {
                Self::new(HookOutcomeLabel::Aborted, None, b"", msg.as_bytes())
            }
        }
    }
}

fn is_utf8_char_boundary(bytes: &[u8], i: usize) -> bool {
    if i == bytes.len() {
        return true;
    }
    // A UTF-8 char boundary byte is NOT a continuation byte
    // (0b10xxxxxx). Continuation byte mask: 0xC0 == 0x80.
    bytes.get(i).map_or(true, |b| (b & 0xC0) != 0x80)
}

/// Why a tunnel went down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TunnelDownReason {
    UserDisconnect,
    NetworkLinkLost,
    DaemonExited,
    HandshakeFailed,
}

/// Why the kill switch engaged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum KillswitchEngageReason {
    UserRequest,
    AutoOnConnect,
    AlwaysOn,
    RecoveredFromCrash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_json() {
        let env = EventEnvelope::new(EngineEvent::TunnelUp {
            profile_id: ProfileId::new("corp"),
            protocol: ProtocolKind::WireGuard,
            interface_name: "wg0".to_string(),
            pid: None,
        });
        let json = serde_json::to_string(&env).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        match back.event {
            EngineEvent::TunnelUp { interface_name, .. } => {
                assert_eq!(interface_name, "wg0");
            }
            _ => panic!("expected TunnelUp"),
        }
    }

    #[test]
    fn snake_case_tag_uses_kind() {
        let env = EventEnvelope::new(EngineEvent::NetworkLinkLost);
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""kind":"network_link_lost""#));
    }

    // Plan 016 U1 — HookOutcome + HookOutcomeRecord coverage.

    #[test]
    fn hook_outcome_success_json_round_trip() {
        let record = HookOutcomeRecord::new(HookOutcomeLabel::Success, Some(0), b"ok\n", b"");
        let env = EventEnvelope::new(EngineEvent::HookOutcome {
            hook_name: "shell:post_connect".into(),
            event_kind: "post_connect".into(),
            record: record.clone(),
        });
        let json = serde_json::to_string(&env).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        match back.event {
            EngineEvent::HookOutcome {
                hook_name,
                event_kind,
                record: back_record,
            } => {
                assert_eq!(hook_name, "shell:post_connect");
                assert_eq!(event_kind, "post_connect");
                assert_eq!(back_record, record);
                assert_eq!(back_record.outcome, HookOutcomeLabel::Success);
                assert_eq!(back_record.exit_code, Some(0));
                assert_eq!(back_record.stdout, "ok\n");
                assert_eq!(back_record.stderr, "");
                assert!(!back_record.truncated);
            }
            _ => panic!("expected HookOutcome"),
        }
    }

    #[test]
    fn hook_outcome_failed_carries_nonzero_exit_and_stderr() {
        let record =
            HookOutcomeRecord::new(HookOutcomeLabel::Failed, Some(127), b"", b"command not found");
        let json = serde_json::to_string(&record).unwrap();
        let back: HookOutcomeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.outcome, HookOutcomeLabel::Failed);
        assert_eq!(back.exit_code, Some(127));
        assert!(back.stderr.contains("command not found"));
    }

    #[test]
    fn hook_outcome_timed_out_omits_exit_code() {
        let record = HookOutcomeRecord::new(HookOutcomeLabel::TimedOut, None, b"", b"");
        let json = serde_json::to_string(&record).unwrap();
        // Option::None is skipped from serialization (skip_serializing_if).
        assert!(!json.contains("exit_code"));
        let back: HookOutcomeRecord = serde_json::from_str(&json).unwrap();
        assert!(back.exit_code.is_none());
    }

    #[test]
    fn hook_outcome_aborted_round_trips() {
        let record = HookOutcomeRecord::new(HookOutcomeLabel::Aborted, None, b"", b"task panicked");
        let json = serde_json::to_string(&record).unwrap();
        let back: HookOutcomeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.outcome, HookOutcomeLabel::Aborted);
    }

    #[test]
    fn hook_outcome_stdout_above_cap_is_truncated() {
        // 2 KiB of ASCII — well above the 1 KiB cap. Truncation byte
        // boundary is trivially safe for ASCII.
        let big = vec![b'x'; 2048];
        let record = HookOutcomeRecord::new(HookOutcomeLabel::Success, Some(0), &big, b"");
        assert_eq!(record.stdout.len(), HOOK_OUTPUT_CAP_BYTES);
        assert!(record.truncated);
    }

    #[test]
    fn hook_outcome_truncation_respects_utf8_boundary() {
        // 1024 ASCII bytes + a multi-byte char straddling the cap.
        // The 4-byte poo emoji (🚽 — U+1F6BD, 4 bytes in UTF-8)
        // starts at byte 1022; cutting at 1024 would split it.
        // Truncator must walk back to a char boundary.
        let mut bytes = vec![b'x'; 1022];
        bytes.extend_from_slice("🚽🚽".as_bytes()); // each 4 bytes; total 1022+8=1030 bytes
        let record = HookOutcomeRecord::new(HookOutcomeLabel::Success, Some(0), &bytes, b"");
        // String::from_utf8 must succeed on the truncated body —
        // from_utf8_lossy doesn't panic but might insert replacement
        // chars. Better signal: the truncated body re-encoded round-
        // trips losslessly into UTF-8 string.
        assert!(record.truncated);
        // The first 1022 bytes (all 'x') plus zero, one, or two 4-byte
        // chars at the end. Length must be one of: 1022, 1026, 1024-cap-fallback.
        // We expect 1022 (truncated before the multi-byte char).
        assert_eq!(record.stdout.len(), 1022);
    }

    #[test]
    fn record_from_runtime_outcome_maps_each_label() {
        use crate::engine::hooks::HookOutcome;
        let success: HookOutcomeRecord = (&HookOutcome::Success).into();
        assert_eq!(success.outcome, HookOutcomeLabel::Success);
        assert_eq!(success.exit_code, Some(0));

        let failed: HookOutcomeRecord = (&HookOutcome::Failed("nope".into())).into();
        assert_eq!(failed.outcome, HookOutcomeLabel::Failed);
        assert_eq!(failed.exit_code, None);
        assert_eq!(failed.stderr, "nope");

        let timed_out: HookOutcomeRecord = (&HookOutcome::TimedOut).into();
        assert_eq!(timed_out.outcome, HookOutcomeLabel::TimedOut);

        let aborted: HookOutcomeRecord = (&HookOutcome::Aborted("panic".into())).into();
        assert_eq!(aborted.outcome, HookOutcomeLabel::Aborted);
        assert_eq!(aborted.stderr, "panic");
    }

    #[test]
    fn hook_outcome_empty_streams_serialize_to_empty_strings() {
        let record = HookOutcomeRecord::new(HookOutcomeLabel::Success, Some(0), b"", b"");
        let json = serde_json::to_string(&record).unwrap();
        let back: HookOutcomeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stdout, "");
        assert_eq!(back.stderr, "");
    }
}
