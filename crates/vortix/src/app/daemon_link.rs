//! Live link to a running daemon.
//!
//! `DaemonLink` existing on [`App`](super::App) IS the attached state:
//! registry reads come from polled `RegistrySnapshot`s, writes route
//! through `Execute` over IPC, and none of the local scanner/retry
//! machinery runs. Detaching drops the link, which parks the poll and
//! clears in-flight write markers by construction — there is no way to
//! hold poll or in-flight state without a socket.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use crate::constants;
use crate::daemon::client::ClientError;
use crate::vortix_core::engine::registry_handle::RegistrySnapshot;
use crate::vortix_core::profile::ProfileId;

/// Outcome of collecting the previous snapshot poll.
pub(crate) enum PollSlot {
    /// No poll outstanding — free to spawn one.
    Idle,
    /// Previous poll still running — don't spawn another.
    InFlight,
    /// Previous poll finished with this result.
    Ready(Result<RegistrySnapshot, ClientError>),
}

/// Consecutive timed-out polls before the TUI warns that its rendered
/// state may be stale. Each poll spends a 2s read deadline, so the
/// threshold means the daemon has been unresponsive for ~10s+ — well
/// past any legitimate serial-actor busy window for a single write.
const STALE_POLL_WARN_THRESHOLD: u32 = 5;

pub struct DaemonLink {
    /// Socket path every poll/write worker thread connects to.
    pub socket: PathBuf,
    /// In-flight `RegistrySnapshot` poll (spawn-on-demand, one at a
    /// time — same pattern as the scanner channel).
    poll_rx: Option<mpsc::Receiver<Result<RegistrySnapshot, ClientError>>>,
    /// Profiles with a daemon-routed write in flight, keyed to when the
    /// write started. While a profile is here, polled snapshots neither
    /// overwrite nor remove its optimistic registry entry (the daemon
    /// registers the entry a beat after `Execute` lands; without this
    /// the badge would flicker).
    inflight: HashMap<ProfileId, Instant>,
    /// One-time `OpenVPN` auth files that must outlive the daemon-routed
    /// connect consuming them. Deleted when the write result lands,
    /// when its in-flight marker expires, or on link drop — never
    /// before the daemon has had its chance to read them.
    pending_auth_cleanup: std::collections::HashSet<String>,
    /// Consecutive timed-out polls. A run past
    /// [`STALE_POLL_WARN_THRESHOLD`] means the daemon is alive but
    /// wedged and the rendered state has stopped being live.
    consecutive_poll_timeouts: u32,
    /// Whether the staleness warning already fired for the current
    /// timeout run (re-arms on the next successful poll).
    stale_warned: bool,
}

impl DaemonLink {
    #[must_use]
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            poll_rx: None,
            inflight: HashMap::new(),
            pending_auth_cleanup: std::collections::HashSet::new(),
            consecutive_poll_timeouts: 0,
            stale_warned: false,
        }
    }

    /// Collect the previous poll's result, if any.
    pub(crate) fn take_poll_result(&mut self) -> PollSlot {
        let Some(rx) = &self.poll_rx else {
            return PollSlot::Idle;
        };
        match rx.try_recv() {
            Ok(result) => {
                self.poll_rx = None;
                PollSlot::Ready(result)
            }
            Err(mpsc::TryRecvError::Empty) => PollSlot::InFlight,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.poll_rx = None;
                PollSlot::Idle
            }
        }
    }

    /// Kick off the next snapshot poll on a background thread. No-op
    /// while one is already in flight.
    pub(crate) fn spawn_poll(&mut self) {
        if self.poll_rx.is_some() {
            return;
        }
        let socket = self.socket.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(crate::daemon::client::registry_snapshot(&socket));
        });
        self.poll_rx = Some(rx);
    }

    /// Record a daemon-routed write as in flight for `profile_id`.
    pub(crate) fn mark_inflight(&mut self, profile_id: ProfileId) {
        self.inflight.insert(profile_id, Instant::now());
    }

    /// The write result landed — stop pinning the optimistic entry.
    pub(crate) fn clear_inflight(&mut self, profile_id: &ProfileId) {
        self.inflight.remove(profile_id);
    }

    /// Expire stuck markers (a lost result message must not pin stale
    /// optimistic state forever), then return the live in-flight set.
    /// The expiry window exceeds the 60s Execute transport timeout, so
    /// a live write never expires. An expired marker also releases its
    /// deferred one-time auth file — the daemon's window to read it is
    /// over.
    pub(crate) fn live_inflight_ids(&mut self) -> HashSet<ProfileId> {
        let pending = &mut self.pending_auth_cleanup;
        self.inflight.retain(|id, started| {
            let live = started.elapsed() < constants::DAEMON_INFLIGHT_EXPIRY;
            if !live && pending.remove(id.as_str()) {
                crate::utils::delete_openvpn_auth_file(id.as_str());
            }
            live
        });
        self.inflight.keys().cloned().collect()
    }

    /// Whether a daemon-routed write is currently in flight for
    /// `profile_id`.
    pub(crate) fn is_inflight(&self, profile_id: &ProfileId) -> bool {
        self.inflight.contains_key(profile_id)
    }

    /// Defer deletion of `profile`'s one-time auth file until the
    /// daemon-routed connect consuming it concludes. The local path
    /// deletes immediately (openvpn reads the file at spawn); the
    /// daemon reads it only after the IPC round-trip, so an immediate
    /// delete would deterministically starve it of credentials.
    pub(crate) fn defer_auth_cleanup(&mut self, profile: String) {
        self.pending_auth_cleanup.insert(profile);
    }

    /// The write for `profile` concluded — delete its deferred one-time
    /// auth file, if any. No-op for profiles without a deferral.
    pub(crate) fn finish_auth_cleanup(&mut self, profile: &str) {
        if self.pending_auth_cleanup.remove(profile) {
            crate::utils::delete_openvpn_auth_file(profile);
        }
    }

    /// Record a timed-out poll. Returns `true` exactly once per
    /// timeout run, when the run first crosses the staleness threshold
    /// — the caller surfaces the warning then.
    pub(crate) fn note_poll_timeout(&mut self) -> bool {
        self.consecutive_poll_timeouts = self.consecutive_poll_timeouts.saturating_add(1);
        if self.consecutive_poll_timeouts >= STALE_POLL_WARN_THRESHOLD && !self.stale_warned {
            self.stale_warned = true;
            return true;
        }
        false
    }

    /// Record a successful poll: the state is live again; re-arm the
    /// staleness warning. Returns `true` when this poll ends a warned
    /// timeout run (caller logs the recovery).
    pub(crate) fn note_poll_success(&mut self) -> bool {
        let recovered = self.stale_warned;
        self.consecutive_poll_timeouts = 0;
        self.stale_warned = false;
        recovered
    }

    /// Whether any write is currently marked in flight (test seam).
    #[cfg(test)]
    pub(crate) fn has_inflight(&self) -> bool {
        !self.inflight.is_empty()
    }
}

impl Drop for DaemonLink {
    fn drop(&mut self) {
        // Detach or app exit: one-time credentials must never outlive
        // the link that deferred their deletion.
        for profile in &self.pending_auth_cleanup {
            crate::utils::delete_openvpn_auth_file(profile);
        }
    }
}
