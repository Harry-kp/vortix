//! Bounded, allowlisted control-plane diagnostics.
//!
//! Diagnostics are safe by construction: callers can select only stable
//! codes and fixed-shape public fields. There is no string-bearing escape
//! hatch for log messages, profile data, command arguments, addresses,
//! paths, stderr, or privileged helper payloads.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

pub const DIAGNOSTIC_SCHEMA_VERSION: u16 = 1;
pub const MAX_DIAGNOSTIC_RECORDS: usize = 512;
pub const MAX_DIAGNOSTIC_BYTES: usize = 1024 * 1024;
pub const MAX_FALLBACK_RECORDS: usize = 256;
pub const MAX_FALLBACK_BYTES: usize = 512 * 1024;
pub const DEFAULT_FALLBACK_STALE_AFTER_MILLIS: u64 = 30_000;
pub const MAX_FALLBACK_STALE_AFTER_MILLIS: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticComponent {
    Control,
    Reconciliation,
    Protection,
    Tunnel,
    Queue,
    Audit,
    Helper,
    Daemon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Stable public codes. Adding a variant is an explicit privacy review point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    RecordsDropped,
    ControlStarted,
    ConnectStarted,
    Connected,
    DisconnectStarted,
    Disconnected,
    ConnectFailed,
    Reconnecting,
    OperationAdmitted,
    OperationSucceeded,
    OperationFailed,
    OperationCancelled,
    OperationExpired,
    DesiredStateChanged,
    ChallengeIssued,
    ChallengeResolved,
    ChallengeExpired,
    ChallengeCancelled,
    ConnectAttemptStarted,
    ConnectAttemptFailed,
    TunnelUp,
    TunnelDown,
    HandshakeStale,
    HandshakeObserved,
    ConnectionHealthChanged,
    NetworkIdentityChanged,
    ProtectionEngaged,
    ProtectionDisengaged,
    ProtectionGatesUnverified,
    RetryScheduled,
    RetryBudgetExhausted,
    NetworkLinkLost,
    NetworkLinkRestored,
    ProfileCatalogChanged,
    JournalRetentionApplied,
    DegradedReasonCleared,
    UserPromptRequested,
    PrimaryTunnelChanged,
    TopologyConflict,
    ReconciliationStateChanged,
    QueueSaturated,
    HelperHealthChanged,
    DaemonStarted,
    PassiveObservationChanged,
    FallbackWriteFailed,
    FallbackWriteRecovered,
}

/// Fixed-shape public values. Deliberately contains no `String`, byte buffer,
/// profile identifier, address, or path type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiagnosticFields {
    None,
    Count {
        value: u32,
    },
    Attempt {
        value: u32,
    },
    Generation {
        value: u64,
    },
    Queue {
        depth: u16,
        capacity: u16,
    },
    SequenceGap {
        first: u64,
        last: u64,
    },
    Readiness {
        authority_verified: bool,
        reconciliation_complete: bool,
    },
    HelperCounters {
        accepted: u32,
        rejected: u32,
        ambiguous: u32,
    },
    /// Which protection read-backs the platform could prove. Recorded whenever
    /// a policy audit cannot prove all four, so `vortix report` names the gate
    /// instead of leaving a bare degraded status with no reason.
    ProtectionGates {
        interface: bool,
        route: bool,
        dns: bool,
        firewall: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRecord {
    pub sequence: u64,
    /// Age according to the emitting process's monotonic clock.
    pub age_millis: u64,
    pub component: DiagnosticComponent,
    pub severity: DiagnosticSeverity,
    pub code: DiagnosticCode,
    pub fields: DiagnosticFields,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperDiagnosticState {
    #[default]
    Unavailable,
    Staged,
    EnrolledHealthy,
    Degraded,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackDiagnosticState {
    #[default]
    Unavailable,
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticStatus {
    pub authority_verified: bool,
    pub reconciliation_complete: bool,
    pub helper: HelperDiagnosticState,
    pub fallback: FallbackDiagnosticState,
}

/// A bounded point-in-time diagnostic payload. Its status fields are
/// observations only; this type cannot grant authority or cleanup rights.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSnapshot {
    pub schema_version: u16,
    pub generation: u64,
    pub generated_at_unix_millis: u64,
    pub stale_after_millis: u64,
    pub product_version: String,
    pub status: DiagnosticStatus,
    pub records: Vec<DiagnosticRecord>,
}

impl DiagnosticSnapshot {
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        let gap_is_valid = self.records.first().is_none_or(|record| {
            if record.code != DiagnosticCode::RecordsDropped {
                return true;
            }
            matches!(
                record.fields,
                DiagnosticFields::SequenceGap { first, last }
                    if first > 0 && first <= last && record.sequence == last
            )
        });
        self.schema_version == DIAGNOSTIC_SCHEMA_VERSION
            && !self.product_version.is_empty()
            && self.product_version.len() <= 64
            && (1..=MAX_FALLBACK_STALE_AFTER_MILLIS).contains(&self.stale_after_millis)
            && gap_is_valid
            && self
                .records
                .iter()
                .skip(1)
                .all(|record| record.code != DiagnosticCode::RecordsDropped)
            && self
                .records
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
    }
}

/// Trust label supplied by the transport, never accepted from fallback disk
/// content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSource {
    AuthenticatedLive,
    UnauthenticatedAdvisoryFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticView {
    pub source: DiagnosticSource,
    pub stale: bool,
    pub age_millis: u64,
    pub snapshot: DiagnosticSnapshot,
}

impl DiagnosticView {
    #[must_use]
    pub const fn may_establish_authority(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn may_authorize_cleanup(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn may_claim_protection(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDiagnosticView {
    pub generation: u64,
    pub records: Vec<DiagnosticRecord>,
}

#[derive(Debug, Clone)]
struct StoredRecord {
    sequence: u64,
    observed_at_millis: u64,
    component: DiagnosticComponent,
    severity: DiagnosticSeverity,
    code: DiagnosticCode,
    fields: DiagnosticFields,
    maximum_encoded_bytes: usize,
}

/// Single-owner bounded ring used by the control actor and daemon service.
#[derive(Debug, Clone)]
pub struct DiagnosticBuffer {
    records: VecDeque<StoredRecord>,
    next_sequence: u64,
    dropped: Option<(u64, u64, u64)>,
    retained_bytes: usize,
    max_records: usize,
    max_bytes: usize,
}

impl Default for DiagnosticBuffer {
    fn default() -> Self {
        Self::new(MAX_DIAGNOSTIC_RECORDS, MAX_DIAGNOSTIC_BYTES)
    }
}

impl DiagnosticBuffer {
    #[must_use]
    pub fn new(max_records: usize, max_bytes: usize) -> Self {
        assert!(max_records >= 2);
        assert!(max_bytes >= 1024);
        Self {
            records: VecDeque::new(),
            next_sequence: 0,
            dropped: None,
            retained_bytes: 0,
            max_records,
            max_bytes,
        }
    }

    pub fn push(
        &mut self,
        observed_at_millis: u64,
        component: DiagnosticComponent,
        severity: DiagnosticSeverity,
        code: DiagnosticCode,
        fields: DiagnosticFields,
    ) {
        self.next_sequence = self.next_sequence.saturating_add(1);
        let record = DiagnosticRecord {
            sequence: self.next_sequence,
            age_millis: u64::MAX,
            component,
            severity,
            code,
            fields,
        };
        let maximum_encoded_bytes = encoded_len(&record);
        self.retained_bytes = self.retained_bytes.saturating_add(maximum_encoded_bytes);
        self.records.push_back(StoredRecord {
            sequence: record.sequence,
            observed_at_millis,
            component,
            severity,
            code,
            fields,
            maximum_encoded_bytes,
        });
        self.enforce_limits(observed_at_millis);
    }

    #[must_use]
    pub fn view(&self, now_millis: u64) -> ControlDiagnosticView {
        ControlDiagnosticView {
            generation: self.next_sequence,
            records: self.records_for(now_millis),
        }
    }

    #[must_use]
    pub fn snapshot(
        &self,
        now_millis: u64,
        generated_at_unix_millis: u64,
        status: DiagnosticStatus,
    ) -> DiagnosticSnapshot {
        self.snapshot_with_stale_after(
            now_millis,
            generated_at_unix_millis,
            DEFAULT_FALLBACK_STALE_AFTER_MILLIS,
            status,
        )
    }

    #[must_use]
    pub fn snapshot_with_stale_after(
        &self,
        now_millis: u64,
        generated_at_unix_millis: u64,
        stale_after_millis: u64,
        status: DiagnosticStatus,
    ) -> DiagnosticSnapshot {
        DiagnosticSnapshot {
            schema_version: DIAGNOSTIC_SCHEMA_VERSION,
            generation: self.next_sequence,
            generated_at_unix_millis,
            stale_after_millis,
            product_version: env!("CARGO_PKG_VERSION").into(),
            status,
            records: self.records_for(now_millis),
        }
    }

    /// Produce the smaller disk fallback view without weakening the live
    /// ring's limits or mutating its retained history.
    #[must_use]
    pub fn fallback_snapshot(
        &self,
        now_millis: u64,
        generated_at_unix_millis: u64,
        status: DiagnosticStatus,
    ) -> DiagnosticSnapshot {
        self.fallback_snapshot_with_stale_after(
            now_millis,
            generated_at_unix_millis,
            DEFAULT_FALLBACK_STALE_AFTER_MILLIS,
            status,
        )
    }

    #[must_use]
    pub fn fallback_snapshot_with_stale_after(
        &self,
        now_millis: u64,
        generated_at_unix_millis: u64,
        stale_after_millis: u64,
        status: DiagnosticStatus,
    ) -> DiagnosticSnapshot {
        let mut bounded = self.clone();
        bounded.max_records = MAX_FALLBACK_RECORDS;
        bounded.max_bytes = MAX_FALLBACK_BYTES;
        bounded.enforce_limits(now_millis);
        bounded.snapshot_with_stale_after(
            now_millis,
            generated_at_unix_millis,
            stale_after_millis,
            status,
        )
    }

    fn enforce_limits(&mut self, now_millis: u64) {
        loop {
            let gap_bytes = self
                .gap_record(u64::MAX)
                .map_or(0, |record| encoded_len(&record));
            let count = self.records.len() + usize::from(self.dropped.is_some());
            if count <= self.max_records
                && self.retained_bytes.saturating_add(gap_bytes) <= self.max_bytes
            {
                break;
            }
            let Some(removed) = self.records.pop_front() else {
                break;
            };
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(removed.maximum_encoded_bytes);
            self.dropped = Some(match self.dropped {
                Some((first, _, _)) => (first, removed.sequence, now_millis),
                None => (removed.sequence, removed.sequence, now_millis),
            });
        }
    }

    fn records_for(&self, now_millis: u64) -> Vec<DiagnosticRecord> {
        let mut records = Vec::with_capacity(
            self.records
                .len()
                .saturating_add(usize::from(self.dropped.is_some())),
        );
        if let Some(gap) = self.gap_record(now_millis) {
            records.push(gap);
        }
        records.extend(self.records.iter().map(|record| DiagnosticRecord {
            sequence: record.sequence,
            age_millis: now_millis.saturating_sub(record.observed_at_millis),
            component: record.component,
            severity: record.severity,
            code: record.code,
            fields: record.fields,
        }));
        records
    }

    fn gap_record(&self, now_millis: u64) -> Option<DiagnosticRecord> {
        self.dropped
            .map(|(first, last, dropped_at_millis)| DiagnosticRecord {
                sequence: last,
                age_millis: now_millis.saturating_sub(dropped_at_millis),
                component: DiagnosticComponent::Queue,
                severity: DiagnosticSeverity::Warning,
                code: DiagnosticCode::RecordsDropped,
                fields: DiagnosticFields::SequenceGap { first, last },
            })
    }
}

fn encoded_len(record: &DiagnosticRecord) -> usize {
    struct ByteCounter(usize);

    impl std::io::Write for ByteCounter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, record).map_or(usize::MAX, |()| counter.0.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_bounded_and_emits_one_gap_marker() {
        let mut buffer = DiagnosticBuffer::new(4, 4096);
        for value in 0..20 {
            buffer.push(
                value,
                DiagnosticComponent::Control,
                DiagnosticSeverity::Info,
                DiagnosticCode::DesiredStateChanged,
                DiagnosticFields::Generation { value },
            );
        }
        let view = buffer.view(20);
        assert_eq!(view.records.len(), 4);
        assert_eq!(view.records[0].code, DiagnosticCode::RecordsDropped);
        assert_eq!(view.records[0].age_millis, 1);
        assert_eq!(
            view.records
                .iter()
                .filter(|record| record.code == DiagnosticCode::RecordsDropped)
                .count(),
            1
        );
        assert!(serde_json::to_vec(&view.records).unwrap().len() <= 4096);
    }

    #[test]
    fn diagnostic_view_can_never_establish_runtime_truth() {
        let view = DiagnosticView {
            source: DiagnosticSource::AuthenticatedLive,
            stale: false,
            age_millis: 0,
            snapshot: DiagnosticBuffer::default().snapshot(
                0,
                0,
                DiagnosticStatus {
                    authority_verified: true,
                    reconciliation_complete: true,
                    helper: HelperDiagnosticState::EnrolledHealthy,
                    ..DiagnosticStatus::default()
                },
            ),
        };
        assert!(!view.may_establish_authority());
        assert!(!view.may_authorize_cleanup());
        assert!(!view.may_claim_protection());
    }
}
