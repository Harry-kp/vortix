//! Scanner-only query source for the passive daemon candidate.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use tokio::sync::broadcast;

use crate::state::{Protocol, VpnProfile};
use crate::vortix_core::engine::state::{Connection, ConnectionHealth, DetailedConnectionInfo};
use crate::vortix_core::ipc::{PassiveSnapshot, PassiveTunnel};
use crate::vortix_core::profile::ProtocolKind;

const EVENT_CAPACITY: usize = 64;

/// Read-only snapshot/subscription surface consumed by the IPC server.
pub trait PassiveQueryProvider: Send + Sync + 'static {
    fn snapshot(&self) -> PassiveSnapshot;
    fn subscribe(&self) -> broadcast::Receiver<PassiveSnapshot>;
}

pub(crate) trait PassiveDiagnosticSink: Send + Sync + 'static {
    fn observer_ready(&self, active_tunnels: u32);
    fn observation_changed(&self, active_tunnels: u32);
}

impl PassiveDiagnosticSink for super::diagnostics::DiagnosticHub {
    fn observer_ready(&self, active_tunnels: u32) {
        self.mark_passive_observer_ready(active_tunnels);
    }

    fn observation_changed(&self, active_tunnels: u32) {
        self.record_passive_observation(active_tunnels);
    }
}

/// Periodically scans already-known profiles. It owns no desired state,
/// authority lock, persistence store, retry loop, or mutation capability.
pub struct ScannerQueryProvider {
    snapshot: Arc<Mutex<PassiveSnapshot>>,
    events: broadcast::Sender<PassiveSnapshot>,
    stopping: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ScannerQueryProvider {
    /// Start the passive scanner thread.
    ///
    /// # Errors
    ///
    /// Returns an OS error when the observer thread cannot be created.
    pub fn start(profiles: Vec<VpnProfile>, interval: Duration) -> std::io::Result<Self> {
        Self::start_with_diagnostics(profiles, interval, None)
    }

    pub(crate) fn start_with_diagnostics(
        profiles: Vec<VpnProfile>,
        interval: Duration,
        diagnostics: Option<Arc<dyn PassiveDiagnosticSink>>,
    ) -> std::io::Result<Self> {
        let initial = scan(&profiles, 1);
        if let Some(diagnostics) = &diagnostics {
            diagnostics.observer_ready(initial.tunnels.len().try_into().unwrap_or(u32::MAX));
        }
        let snapshot = Arc::new(Mutex::new(initial));
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_snapshot = Arc::clone(&snapshot);
        let worker_events = events.clone();
        let worker_stopping = Arc::clone(&stopping);
        let worker_diagnostics = diagnostics;
        let interval = interval.max(Duration::from_millis(100));
        let worker = std::thread::Builder::new()
            .name("vortix-passive-observer".into())
            .spawn(move || {
                while !worker_stopping.load(Ordering::Acquire) {
                    std::thread::park_timeout(interval);
                    if worker_stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let mut next = scan(&profiles, 0);
                    let mut current = worker_snapshot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let changed = !same_tunnels(&current.tunnels, &next.tunnels);
                    next.generation = if changed {
                        current.generation.saturating_add(1)
                    } else {
                        current.generation
                    };
                    *current = next.clone();
                    drop(current);
                    if changed {
                        if let Some(diagnostics) = &worker_diagnostics {
                            diagnostics.observation_changed(
                                next.tunnels.len().try_into().unwrap_or(u32::MAX),
                            );
                        }
                        let _ = worker_events.send(next);
                    }
                }
            })?;
        Ok(Self {
            snapshot,
            events,
            stopping,
            worker: Some(worker),
        })
    }
}

impl PassiveQueryProvider for ScannerQueryProvider {
    fn snapshot(&self) -> PassiveSnapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn subscribe(&self) -> broadcast::Receiver<PassiveSnapshot> {
        self.events.subscribe()
    }
}

impl Drop for ScannerQueryProvider {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

fn scan(profiles: &[VpnProfile], generation: u64) -> PassiveSnapshot {
    let observed_at_millis = super::diagnostics::unix_millis();
    let profiles_by_name = profiles.iter().fold(BTreeMap::new(), |mut index, profile| {
        index.entry(profile.name.as_str()).or_insert(profile);
        index
    });
    let mut tunnels = crate::core::scanner::get_active_profiles(profiles)
        .into_iter()
        .filter_map(|session| {
            let profile = profiles_by_name.get(session.name.as_str())?;
            Some(PassiveTunnel {
                profile_id: profile.id.clone(),
                display_name: profile.name.clone(),
                protocol: match profile.protocol {
                    Protocol::WireGuard => ProtocolKind::WireGuard,
                    Protocol::OpenVPN => ProtocolKind::OpenVpn,
                },
                interface_name: session.interface,
                observed_at_millis,
            })
        })
        .collect::<Vec<_>>();
    tunnels.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    PassiveSnapshot {
        generation,
        observed_at_millis,
        tunnels,
        authoritative: false,
    }
}

fn same_tunnels(left: &[PassiveTunnel], right: &[PassiveTunnel]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.profile_id == right.profile_id
                && left.display_name == right.display_name
                && left.protocol == right.protocol
                && left.interface_name == right.interface_name
        })
}

/// Compatibility projection for existing read-only clients. The projection
/// remains explicitly scanner-derived; it never enters canonical control.
#[must_use]
pub fn legacy_connection(snapshot: &PassiveSnapshot) -> Connection {
    let Some(tunnel) = snapshot.tunnels.first() else {
        return Connection::Disconnected { last_failure: None };
    };
    Connection::Connected {
        profile_id: tunnel.profile_id.clone(),
        since: SystemTime::now(),
        health: ConnectionHealth::Unknown,
        details: Box::new(DetailedConnectionInfo {
            interface: tunnel.interface_name.clone(),
            interface_authoritative: false,
            ..DetailedConnectionInfo::default()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::control::DiagnosticCode;
    use crate::vortix_core::profile::ProfileId;

    #[test]
    fn comparison_ignores_observation_time_but_not_identity() {
        let tunnel = PassiveTunnel {
            profile_id: ProfileId::new("corp"),
            display_name: "corp".into(),
            protocol: ProtocolKind::WireGuard,
            interface_name: "wg0".into(),
            observed_at_millis: 1,
        };
        let mut later = tunnel.clone();
        later.observed_at_millis = 2;
        assert!(same_tunnels(
            std::slice::from_ref(&tunnel),
            std::slice::from_ref(&later)
        ));
        later.interface_name = "wg1".into();
        assert!(!same_tunnels(&[tunnel], &[later]));
    }

    #[test]
    fn legacy_projection_never_claims_authoritative_interface() {
        let snapshot = PassiveSnapshot {
            generation: 1,
            observed_at_millis: 1,
            tunnels: vec![PassiveTunnel {
                profile_id: ProfileId::new("corp"),
                display_name: "corp".into(),
                protocol: ProtocolKind::WireGuard,
                interface_name: "wg0".into(),
                observed_at_millis: 1,
            }],
            authoritative: false,
        };
        let Connection::Connected { details, .. } = legacy_connection(&snapshot) else {
            panic!("expected connected projection");
        };
        assert!(!details.interface_authoritative);
    }

    #[test]
    fn production_observer_startup_feeds_the_served_diagnostic_hub() {
        let diagnostics = Arc::new(super::super::diagnostics::DiagnosticHub::start(None).unwrap());
        let sink: Arc<dyn PassiveDiagnosticSink> = diagnostics.clone();
        let provider = ScannerQueryProvider::start_with_diagnostics(
            Vec::new(),
            Duration::from_secs(60),
            Some(sink),
        )
        .unwrap();

        let snapshot =
            super::super::diagnostics::DiagnosticQueryProvider::snapshot(diagnostics.as_ref());
        assert!(snapshot.status.reconciliation_complete);
        assert!(!snapshot.status.authority_verified);
        assert!(snapshot
            .records
            .iter()
            .any(|record| record.code == DiagnosticCode::PassiveObservationChanged));
        drop(provider);
    }
}
