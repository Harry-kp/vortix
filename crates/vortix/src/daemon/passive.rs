//! Scanner-only query source for the passive daemon candidate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let initial = scan(&profiles, 1);
        let snapshot = Arc::new(Mutex::new(initial));
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_snapshot = Arc::clone(&snapshot);
        let worker_events = events.clone();
        let worker_stopping = Arc::clone(&stopping);
        let interval = interval.max(Duration::from_millis(100));
        let worker = std::thread::Builder::new()
            .name("vortix-passive-observer".into())
            .spawn(move || {
                while !worker_stopping.load(Ordering::Acquire) {
                    std::thread::park_timeout(interval);
                    if worker_stopping.load(Ordering::Acquire) {
                        break;
                    }
                    let prior = worker_snapshot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    let mut next = scan(&profiles, prior.generation);
                    let changed = !same_tunnels(&prior.tunnels, &next.tunnels);
                    if changed {
                        next.generation = prior.generation.saturating_add(1);
                    }
                    *worker_snapshot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = next.clone();
                    if changed {
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
    let observed_at_millis = unix_millis();
    let mut tunnels = crate::core::scanner::get_active_profiles(profiles)
        .into_iter()
        .filter_map(|session| {
            let profile = profiles
                .iter()
                .find(|profile| profile.name == session.name)?;
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

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
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
}
