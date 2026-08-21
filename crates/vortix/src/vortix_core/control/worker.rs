//! Bounded supervised workers for tunnel and complete topology effects.
//!
//! The coordinator only reserves work and consumes receipts.  Potentially
//! blocking protocol and policy calls run on owned threads with cancellation,
//! deadlines, exact revision fencing, and bounded result paths.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::control::model::{AuthorityEpoch, OperationId, PolicyDigest};
use crate::vortix_core::ports::owned_routes::canonical_route_destination;
pub use crate::vortix_core::ports::tunnel::TunnelCancellation as CancellationToken;
use crate::vortix_core::ports::tunnel::{
    AdoptionEvidence, HandshakeEvidence, ProbeReceipt, TunnelKindTag,
};
use crate::vortix_core::privileged::OpenVpnRouteEvidence;
use crate::vortix_core::profile::ProfileId;
use crate::vortix_core::state::killswitch::KillSwitchMode;

/// Exact fence carried by desired state, observations, work, and receipts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControlRevision {
    pub authority_epoch: AuthorityEpoch,
    pub generation: u64,
    pub digest: PolicyDigest,
}

/// Per-profile tunnel intent fence.
///
/// Tunnel effects advance only when that profile is targeted. Global policy
/// changes use [`ControlRevision`] and must not invalidate healthy tunnels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TunnelRevision {
    pub authority_epoch: AuthorityEpoch,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMutation {
    Connect,
    Disconnect,
}

#[derive(Debug, Clone)]
pub struct TunnelWork {
    pub profile_id: ProfileId,
    pub operation_id: OperationId,
    /// Revision of the desired state this work is converging toward.
    pub revision: TunnelRevision,
    /// Exact generation of the helper/protocol resource being affected.
    /// Connect work creates this revision; teardown may target an older
    /// generation while remaining fenced by the newer desired revision.
    pub resource_revision: TunnelRevision,
    pub mutation: TunnelMutation,
    pub protocol: TunnelKindTag,
    pub deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkFailure {
    Busy,
    RouteConflict,
    TimedOut,
    Cancelled,
    Panicked,
    EffectFailed,
    /// `WireGuard` connect returned without exact current-generation peer proof.
    HandshakeFailed,
    /// An interactive credential was not delivered to the admitted operation.
    ChallengeFailed,
    /// The effect may have happened but no trustworthy receipt was obtained.
    OutcomeUnknown,
    Stale,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelWorkResult {
    pub profile_id: ProfileId,
    pub operation_id: OperationId,
    pub revision: TunnelRevision,
    pub lease_id: LeaseId,
    pub mutation: TunnelMutation,
    /// Protocol-authoritative identity produced by the exact successful
    /// connect call. Scanner presence alone can never manufacture this.
    pub adoption: Option<AdoptionEvidence>,
    pub handshake: Option<HandshakeEvidence>,
    pub openvpn_routes: Option<OpenVpnRouteEvidence>,
    pub probe_receipts: Vec<ProbeReceipt>,
    pub result: Result<(), WorkFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TunnelExecutionReceipt {
    pub adoption: Option<AdoptionEvidence>,
    pub handshake: Option<HandshakeEvidence>,
    pub openvpn_routes: Option<OpenVpnRouteEvidence>,
    pub probe_receipts: Vec<ProbeReceipt>,
}

impl TunnelExecutionReceipt {
    /// Construct the typed receipt required for a successful connect.
    pub fn attested(
        profile_id: ProfileId,
        interface_name: impl Into<String>,
        kind: TunnelKindTag,
        pid: Option<u32>,
        protocol_attestation: impl Into<String>,
    ) -> Result<Self, String> {
        AdoptionEvidence::attest(profile_id, interface_name, kind, pid, protocol_attestation)
            .map(|adoption| Self {
                adoption: Some(adoption),
                handshake: None,
                openvpn_routes: None,
                probe_receipts: Vec::new(),
            })
            .map_err(|error| error.to_string())
    }

    /// Construct a `WireGuard` receipt whose adoption and cryptographic proof
    /// are bound to the exact worker generation.
    pub fn wireguard(
        profile_id: ProfileId,
        interface_name: impl Into<String>,
        attestation: impl Into<String>,
        handshake: HandshakeEvidence,
    ) -> Result<Self, String> {
        AdoptionEvidence::attest(
            profile_id,
            interface_name,
            TunnelKindTag::WireGuard,
            None,
            attestation,
        )
        .map(|adoption| Self {
            adoption: Some(adoption),
            handshake: Some(handshake),
            openvpn_routes: None,
            probe_receipts: Vec::new(),
        })
        .map_err(|error| error.to_string())
    }

    #[must_use]
    pub fn with_probe_receipts(mut self, receipts: Vec<ProbeReceipt>) -> Self {
        self.probe_receipts = receipts;
        self
    }

    #[must_use]
    pub fn with_openvpn_routes(mut self, routes: OpenVpnRouteEvidence) -> Self {
        self.openvpn_routes = Some(routes);
        self
    }
}

pub trait TunnelExecutor: Send + Sync + 'static {
    fn execute(
        &self,
        work: &TunnelWork,
        cancellation: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String>;

    /// Classify a concrete executor error without exposing protocol strings to
    /// the supervisor. Existing deterministic fakes keep `EffectFailed`.
    fn classify_failure(&self, _error: &str) -> WorkFailure {
        WorkFailure::EffectFailed
    }

    /// Compensate a successful effect whose receipt cannot be accepted due to
    /// a late cancellation, deadline, or post-effect reservation conflict.
    fn compensate_unaccepted_success(&self, _work: &TunnelWork) -> Result<(), String> {
        Ok(())
    }

    /// Fence an effect whose executor panicked or returned a malformed
    /// receipt after dispatch. The default cannot prove absence and is
    /// intentionally fail-closed.
    fn compensate_uncertain(&self, _work: &TunnelWork) -> Result<(), String> {
        Err("executor cannot prove uncertain-effect absence".into())
    }
}

/// Canonical, host-bit-normalized route claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteClaim {
    network: std::net::IpAddr,
    prefix_len: u8,
}

impl RouteClaim {
    /// Parse and normalize a route claim.
    pub fn parse(value: &str) -> Result<Self, WorkFailure> {
        let cidr: Cidr = value.parse().map_err(|_| WorkFailure::RouteConflict)?;
        Ok(Self::from_cidr(cidr))
    }

    fn from_cidr(cidr: Cidr) -> Self {
        let cidr = canonical_route_destination(cidr);
        Self {
            network: cidr.addr,
            prefix_len: cidr.prefix_len,
        }
    }

    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        Cidr::new(self.network, self.prefix_len)
            .zip(Cidr::new(other.network, other.prefix_len))
            .is_some_and(|(left, right)| left.intersects(&right))
    }

    #[must_use]
    pub const fn network(self) -> std::net::IpAddr {
        self.network
    }

    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    #[must_use]
    pub const fn is_default(self) -> bool {
        self.prefix_len == 0
    }

    /// Stable address used for kernel route read-back of this claim.
    #[must_use]
    pub fn probe_address(self) -> std::net::IpAddr {
        match (self.network, self.prefix_len) {
            (std::net::IpAddr::V4(_), 0) => "1.1.1.1".parse().expect("fixed IPv4 address"),
            (std::net::IpAddr::V6(_), 0) => {
                "2606:4700:4700::1111".parse().expect("fixed IPv6 address")
            }
            (std::net::IpAddr::V4(address), prefix) if prefix < 32 => {
                std::net::IpAddr::V4((u32::from(address).saturating_add(1)).into())
            }
            (std::net::IpAddr::V6(address), prefix) if prefix < 128 => {
                std::net::IpAddr::V6((u128::from(address).saturating_add(1)).into())
            }
            (address, _) => address,
        }
    }
}

impl std::fmt::Display for RouteClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeaseId(u64);

#[derive(Debug, Clone)]
struct LeaseRecord {
    profile_id: ProfileId,
    routes: BTreeSet<RouteClaim>,
    refs: usize,
    active: bool,
    ambiguous: bool,
}

#[derive(Debug, Default)]
struct Reservations {
    next_lease: u64,
    leases: BTreeMap<LeaseId, LeaseRecord>,
}

/// Coordinator-owned reservation ledger. Successful connects are promoted to
/// topology leases and live until confirmed disconnect/compensation.
#[derive(Debug, Clone, Default)]
pub struct ReservationBook(Arc<Mutex<Reservations>>);

impl ReservationBook {
    pub fn reserve(
        &self,
        profile_id: &ProfileId,
        routes: impl IntoIterator<Item = String>,
    ) -> Result<Reservation, WorkFailure> {
        self.reserve_with_acknowledgement(profile_id, routes, None)
    }

    pub fn reserve_with_acknowledgement(
        &self,
        profile_id: &ProfileId,
        routes: impl IntoIterator<Item = String>,
        acknowledgement: Option<&crate::vortix_core::engine::registry::Conflict>,
    ) -> Result<Reservation, WorkFailure> {
        let routes = routes
            .into_iter()
            .map(|route| RouteClaim::parse(&route))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut state = self.0.lock().expect("reservation mutex poisoned");
        if has_route_conflict(&state, profile_id, &routes, None, acknowledgement) {
            return Err(WorkFailure::RouteConflict);
        }
        if let Some((lease_id, lease)) = state
            .leases
            .iter_mut()
            .find(|(_, lease)| lease.profile_id == *profile_id && lease.routes == routes)
        {
            if lease.ambiguous {
                return Err(WorkFailure::Busy);
            }
            lease.refs = lease.refs.saturating_add(1);
            return Ok(Reservation {
                book: self.clone(),
                lease_id: *lease_id,
                released: false,
            });
        }
        state.next_lease = state.next_lease.saturating_add(1);
        let lease_id = LeaseId(state.next_lease);
        state.leases.insert(
            lease_id,
            LeaseRecord {
                profile_id: profile_id.clone(),
                routes,
                refs: 1,
                active: false,
                ambiguous: false,
            },
        );
        Ok(Reservation {
            book: self.clone(),
            lease_id,
            released: false,
        })
    }

    #[must_use]
    pub fn is_reserved(&self, profile_id: &ProfileId) -> bool {
        self.0
            .lock()
            .expect("reservation mutex poisoned")
            .leases
            .values()
            .any(|lease| lease.profile_id == *profile_id)
    }

    #[must_use]
    pub fn active_lease(&self, profile_id: &ProfileId) -> Option<LeaseId> {
        self.0
            .lock()
            .expect("reservation mutex poisoned")
            .leases
            .iter()
            .find_map(|(id, lease)| {
                (lease.profile_id == *profile_id && lease.active).then_some(*id)
            })
    }

    pub fn release_profile(&self, profile_id: &ProfileId) {
        self.0
            .lock()
            .expect("reservation mutex poisoned")
            .leases
            .retain(|_, lease| lease.profile_id != *profile_id);
    }

    fn promote(&self, lease_id: LeaseId) {
        if let Some(lease) = self
            .0
            .lock()
            .expect("reservation mutex poisoned")
            .leases
            .get_mut(&lease_id)
        {
            lease.active = true;
            lease.ambiguous = false;
        }
    }

    fn mark_ambiguous(&self, lease_id: LeaseId) {
        if let Some(lease) = self
            .0
            .lock()
            .expect("reservation mutex poisoned")
            .leases
            .get_mut(&lease_id)
        {
            lease.active = true;
            lease.ambiguous = true;
        }
    }

    fn release(&self, lease_id: LeaseId) {
        let mut state = self.0.lock().expect("reservation mutex poisoned");
        if let Some(lease) = state.leases.get_mut(&lease_id) {
            lease.refs = lease.refs.saturating_sub(1);
            if lease.refs == 0 && !lease.active && !lease.ambiguous {
                state.leases.remove(&lease_id);
            }
        }
    }

    fn refine_routes(
        &self,
        lease_id: LeaseId,
        routes: &BTreeSet<RouteClaim>,
    ) -> Result<(), WorkFailure> {
        let mut state = self.0.lock().expect("reservation mutex poisoned");
        let lease = state.leases.get(&lease_id).ok_or(WorkFailure::Stale)?;
        if lease.ambiguous {
            return Err(WorkFailure::Busy);
        }
        let profile_id = lease.profile_id.clone();
        let additional = routes
            .difference(&lease.routes)
            .copied()
            .collect::<BTreeSet<_>>();
        if additional.is_empty() {
            return Ok(());
        }
        if has_route_conflict(&state, &profile_id, &additional, Some(lease_id), None) {
            return Err(WorkFailure::RouteConflict);
        }
        state
            .leases
            .get_mut(&lease_id)
            .expect("lease identity checked")
            .routes
            .extend(additional);
        Ok(())
    }
}

fn has_route_conflict(
    state: &Reservations,
    profile_id: &ProfileId,
    routes: &BTreeSet<RouteClaim>,
    excluded: Option<LeaseId>,
    acknowledgement: Option<&crate::vortix_core::engine::registry::Conflict>,
) -> bool {
    state.leases.iter().any(|(lease_id, lease)| {
        Some(*lease_id) != excluded
            && lease.profile_id != *profile_id
            && lease
                .routes
                .iter()
                .any(|existing| routes.iter().any(|route| existing.overlaps(*route)))
            && !acknowledges_peer(acknowledgement, &lease.profile_id, profile_id)
    })
}

fn acknowledges_peer(
    acknowledgement: Option<&crate::vortix_core::engine::registry::Conflict>,
    existing: &ProfileId,
    target: &ProfileId,
) -> bool {
    match acknowledgement {
        Some(crate::vortix_core::engine::registry::Conflict::DefaultRouteTakeover {
            current,
            new,
        }) => current == existing && new == target,
        Some(crate::vortix_core::engine::registry::Conflict::RouteOverlap { with, .. }) => {
            with == existing
        }
        None => false,
    }
}

#[derive(Debug)]
pub struct Reservation {
    book: ReservationBook,
    lease_id: LeaseId,
    released: bool,
}

impl Reservation {
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    fn refine_routes(&self, routes: &BTreeSet<RouteClaim>) -> Result<(), WorkFailure> {
        self.book.refine_routes(self.lease_id, routes)
    }

    fn finish(mut self, mutation: TunnelMutation, result: Result<(), WorkFailure>) {
        match (mutation, result) {
            (TunnelMutation::Connect, Ok(())) => self.book.promote(self.lease_id),
            (_, Err(WorkFailure::TimedOut | WorkFailure::OutcomeUnknown)) => {
                self.book.mark_ambiguous(self.lease_id);
            }
            (TunnelMutation::Disconnect, Ok(())) => {
                self.book.release_profile_for_lease(self.lease_id);
            }
            _ => self.book.release(self.lease_id),
        }
        self.released = true;
    }
}

impl ReservationBook {
    fn release_profile_for_lease(&self, lease_id: LeaseId) {
        let profile = self
            .0
            .lock()
            .expect("reservation mutex poisoned")
            .leases
            .get(&lease_id)
            .map(|lease| lease.profile_id.clone());
        if let Some(profile) = profile {
            self.release_profile(&profile);
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.released {
            self.book.release(self.lease_id);
        }
    }
}

struct WorkEnvelope {
    work: TunnelWork,
    cancellation: CancellationToken,
    reservation: Reservation,
    inbox: InboxReservation,
}

#[derive(Debug, Default)]
struct InboxReservations {
    per_profile: BTreeMap<ProfileId, usize>,
}

/// An actual bounded profile-inbox slot plus normalized route lease.  It is
/// acquired before operation allocation and consumed by exactly one dispatch.
#[derive(Debug)]
pub struct ProfileAdmission {
    profile_id: ProfileId,
    inbox: InboxReservation,
    reservation: Reservation,
}

#[derive(Debug)]
struct InboxReservation {
    profile_id: ProfileId,
    slots: Arc<Mutex<InboxReservations>>,
    released: bool,
}

impl InboxReservation {
    fn release(&mut self) {
        if self.released {
            return;
        }
        let mut slots = self.slots.lock().expect("inbox reservation mutex poisoned");
        if let Some(count) = slots.per_profile.get_mut(&self.profile_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                slots.per_profile.remove(&self.profile_id);
            }
        }
        self.released = true;
    }
}

impl Drop for InboxReservation {
    fn drop(&mut self) {
        self.release();
    }
}

struct ProfileWorker {
    tx: Option<mpsc::SyncSender<WorkEnvelope>>,
    join: Option<JoinHandle<()>>,
    last_used: Instant,
}

/// Bounded serial workers keyed by profile. The number of live/known profile
/// actors is capped and idle actors are retired before admitting new keys.
pub struct ProfileWorkerPool {
    workers: Mutex<BTreeMap<ProfileId, ProfileWorker>>,
    executor: Arc<dyn TunnelExecutor>,
    results: Arc<Mutex<BTreeMap<ProfileId, TunnelWorkResult>>>,
    inbox_reservations: Arc<Mutex<InboxReservations>>,
    queue_capacity: usize,
    max_profiles: usize,
    idle_timeout: Duration,
    reservations: ReservationBook,
    stopping: Arc<AtomicBool>,
    active: Arc<Mutex<BTreeMap<ProfileId, CancellationToken>>>,
}

impl ProfileWorkerPool {
    #[must_use]
    pub fn new(
        executor: Arc<dyn TunnelExecutor>,
        queue_capacity: usize,
        result_capacity: usize,
    ) -> Self {
        Self::with_limits(
            executor,
            queue_capacity,
            result_capacity,
            result_capacity.max(1),
            Duration::from_secs(30),
        )
    }

    #[must_use]
    pub fn with_limits(
        executor: Arc<dyn TunnelExecutor>,
        queue_capacity: usize,
        result_capacity: usize,
        max_profiles: usize,
        idle_timeout: Duration,
    ) -> Self {
        assert!(queue_capacity > 0 && result_capacity > 0 && max_profiles > 0);
        Self {
            workers: Mutex::new(BTreeMap::new()),
            executor,
            results: Arc::new(Mutex::new(BTreeMap::new())),
            inbox_reservations: Arc::new(Mutex::new(InboxReservations::default())),
            queue_capacity,
            max_profiles,
            idle_timeout,
            reservations: ReservationBook::default(),
            stopping: Arc::new(AtomicBool::new(false)),
            active: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Reserve both resources that can make post-admission dispatch fail.
    pub fn reserve(
        &self,
        profile_id: &ProfileId,
        routes: impl IntoIterator<Item = String>,
    ) -> Result<ProfileAdmission, WorkFailure> {
        self.reserve_with_acknowledgement(profile_id, routes, None)
    }

    pub fn reserve_with_acknowledgement(
        &self,
        profile_id: &ProfileId,
        routes: impl IntoIterator<Item = String>,
        acknowledgement: Option<&crate::vortix_core::engine::registry::Conflict>,
    ) -> Result<ProfileAdmission, WorkFailure> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(WorkFailure::Stopped);
        }
        let workers = self.workers.lock().expect("worker mutex poisoned");
        let mut inboxes = self
            .inbox_reservations
            .lock()
            .expect("inbox reservation mutex poisoned");
        let known_reserved = inboxes.per_profile.contains_key(profile_id);
        let known_profiles = workers
            .keys()
            .chain(inboxes.per_profile.keys())
            .collect::<BTreeSet<_>>()
            .len();
        if !workers.contains_key(profile_id)
            && !known_reserved
            && known_profiles >= self.max_profiles
        {
            return Err(WorkFailure::Busy);
        }
        let count = inboxes.per_profile.entry(profile_id.clone()).or_default();
        if *count >= self.queue_capacity {
            return Err(WorkFailure::Busy);
        }
        *count += 1;
        drop(inboxes);
        drop(workers);
        let inbox = InboxReservation {
            profile_id: profile_id.clone(),
            slots: Arc::clone(&self.inbox_reservations),
            released: false,
        };
        let reservation =
            self.reservations
                .reserve_with_acknowledgement(profile_id, routes, acknowledgement)?;
        Ok(ProfileAdmission {
            profile_id: profile_id.clone(),
            inbox,
            reservation,
        })
    }

    pub fn dispatch(
        &self,
        work: TunnelWork,
        routes: impl IntoIterator<Item = String>,
    ) -> Result<CancellationToken, WorkFailure> {
        let admission = self.reserve(&work.profile_id, routes)?;
        self.dispatch_admitted(work, admission)
    }

    pub fn dispatch_admitted(
        &self,
        work: TunnelWork,
        admission: ProfileAdmission,
    ) -> Result<CancellationToken, WorkFailure> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(WorkFailure::Stopped);
        }
        if admission.profile_id != work.profile_id {
            return Err(WorkFailure::Stale);
        }
        if work.resource_revision.authority_epoch != work.revision.authority_epoch {
            return Err(WorkFailure::Stale);
        }
        if work.resource_revision.generation == 0
            || (work.mutation == TunnelMutation::Connect && work.resource_revision != work.revision)
        {
            return Err(WorkFailure::EffectFailed);
        }
        let cancellation = CancellationToken::default();
        let mut workers = self.workers.lock().expect("worker mutex poisoned");
        retire_idle(&mut workers, self.idle_timeout);
        if !workers.contains_key(&work.profile_id) && workers.len() >= self.max_profiles {
            return Err(WorkFailure::Busy);
        }
        let worker = workers.entry(work.profile_id.clone()).or_insert_with(|| {
            spawn_profile_worker(
                Arc::clone(&self.executor),
                Arc::clone(&self.results),
                self.queue_capacity,
                Arc::clone(&self.stopping),
                Arc::clone(&self.active),
                self.reservations.clone(),
            )
        });
        worker.last_used = Instant::now();
        worker
            .tx
            .as_ref()
            .ok_or(WorkFailure::Stopped)?
            .try_send(WorkEnvelope {
                work,
                cancellation: cancellation.clone(),
                reservation: admission.reservation,
                inbox: admission.inbox,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => WorkFailure::Busy,
                mpsc::TrySendError::Disconnected(_) => WorkFailure::Stopped,
            })?;
        Ok(cancellation)
    }

    pub fn try_result(&self) -> Option<TunnelWorkResult> {
        self.results
            .lock()
            .expect("result mutex poisoned")
            .pop_first()
            .map(|(_, result)| result)
    }

    #[must_use]
    pub fn reservations(&self) -> ReservationBook {
        self.reservations.clone()
    }

    #[must_use]
    pub fn dropped_results(&self) -> u64 {
        0
    }

    pub fn cancel_profile(&self, profile_id: &ProfileId) {
        if let Some(token) = self
            .active
            .lock()
            .expect("active mutex poisoned")
            .get(profile_id)
        {
            token.cancel();
        }
    }

    pub fn confirm_absence(&self, profile_id: &ProfileId) {
        self.reservations.release_profile(profile_id);
    }

    /// Cooperative, bounded shutdown. A non-cooperative executor is reported
    /// as still owned; its join handle is retained and never silently detached.
    pub fn shutdown_bounded(&self, timeout: Duration) -> bool {
        self.stopping.store(true, Ordering::Release);
        for token in self.active.lock().expect("active mutex poisoned").values() {
            token.cancel();
        }
        let deadline = Instant::now() + timeout;
        {
            let mut workers = self.workers.lock().expect("worker mutex poisoned");
            for worker in workers.values_mut() {
                worker.tx.take();
            }
        }
        loop {
            let mut workers = self.workers.lock().expect("worker mutex poisoned");
            let finished = workers
                .iter()
                .filter_map(|(profile, worker)| {
                    worker
                        .join
                        .as_ref()
                        .is_some_and(JoinHandle::is_finished)
                        .then_some(profile.clone())
                })
                .collect::<Vec<_>>();
            for profile in finished {
                if let Some(mut worker) = workers.remove(&profile) {
                    if let Some(join) = worker.join.take() {
                        let _ = join.join();
                    }
                }
            }
            if workers.is_empty() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            drop(workers);
            thread::yield_now();
        }
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_bounded(Duration::from_millis(100));
    }
}

fn retire_idle(workers: &mut BTreeMap<ProfileId, ProfileWorker>, idle: Duration) {
    let now = Instant::now();
    workers.retain(|_, worker| {
        !(now.saturating_duration_since(worker.last_used) >= idle
            && worker.join.as_ref().is_some_and(JoinHandle::is_finished))
    });
}

fn spawn_profile_worker(
    executor: Arc<dyn TunnelExecutor>,
    results: Arc<Mutex<BTreeMap<ProfileId, TunnelWorkResult>>>,
    capacity: usize,
    stopping: Arc<AtomicBool>,
    active: Arc<Mutex<BTreeMap<ProfileId, CancellationToken>>>,
    reservations: ReservationBook,
) -> ProfileWorker {
    let (tx, rx) = mpsc::sync_channel::<WorkEnvelope>(capacity);
    let join = thread::Builder::new()
        .name("vortix-tunnel-worker".into())
        .spawn(move || {
            while let Ok(envelope) = rx.recv() {
                // The queue slot is reusable as soon as this worker owns the
                // envelope. The route lease remains with the effect receipt.
                drop(envelope.inbox);
                let work = envelope.work;
                active
                    .lock()
                    .expect("active mutex poisoned")
                    .insert(work.profile_id.clone(), envelope.cancellation.clone());
                let execution =
                    run_tunnel_effect(&executor, &work, &envelope.cancellation, &stopping);
                active
                    .lock()
                    .expect("active mutex poisoned")
                    .remove(&work.profile_id);
                let reservation = envelope.reservation;
                let execution =
                    refine_openvpn_reservation(&executor, &work, &reservation, execution);
                let lease_id = reservation.lease_id();
                let result = execution.as_ref().map(|_| ()).map_err(|error| *error);
                reservation.finish(work.mutation, result);
                let (adoption, handshake, openvpn_routes, probe_receipts) =
                    execution.map_or((None, None, None, Vec::new()), |receipt| {
                        (
                            receipt.adoption,
                            receipt.handshake,
                            receipt.openvpn_routes,
                            receipt.probe_receipts,
                        )
                    });
                let completion = TunnelWorkResult {
                    profile_id: work.profile_id,
                    operation_id: work.operation_id,
                    revision: work.revision,
                    lease_id,
                    mutation: work.mutation,
                    adoption,
                    handshake,
                    openvpn_routes,
                    probe_receipts,
                    result,
                };
                // A per-profile latest terminal slot is bounded by the worker
                // cardinality and cannot lose the state needed for recovery.
                results
                    .lock()
                    .expect("result mutex poisoned")
                    .insert(completion.profile_id.clone(), completion);
            }
            drop(reservations);
        })
        .expect("profile worker thread should start");
    ProfileWorker {
        tx: Some(tx),
        join: Some(join),
        last_used: Instant::now(),
    }
}

fn refine_openvpn_reservation(
    executor: &Arc<dyn TunnelExecutor>,
    work: &TunnelWork,
    reservation: &Reservation,
    execution: Result<TunnelExecutionReceipt, WorkFailure>,
) -> Result<TunnelExecutionReceipt, WorkFailure> {
    let receipt = execution?;
    if work.mutation != TunnelMutation::Connect || work.protocol != TunnelKindTag::OpenVpn {
        return Ok(receipt);
    }
    let Some(evidence) = receipt.openvpn_routes.as_ref() else {
        // Standard mode preserves its local configured-route contract until
        // helper-backed OpenVPN activation makes authenticated evidence
        // mandatory for this executor path.
        return Ok(receipt);
    };
    let claims = openvpn_route_claims(evidence);
    if let Err(failure) = reservation.refine_routes(&claims) {
        return match executor.compensate_unaccepted_success(work) {
            Ok(()) => Err(failure),
            Err(_) => Err(WorkFailure::OutcomeUnknown),
        };
    }
    Ok(receipt)
}

pub(crate) fn openvpn_route_claims(evidence: &OpenVpnRouteEvidence) -> BTreeSet<RouteClaim> {
    let mut claims = evidence
        .configured()
        .routes()
        .iter()
        .chain(evidence.pushed().routes())
        .map(|route| RouteClaim::from_cidr(route.destination()))
        .collect::<BTreeSet<_>>();
    for redirect in [
        evidence.configured().redirect_gateway(),
        evidence.pushed().redirect_gateway(),
    ]
    .into_iter()
    .flatten()
    {
        if redirect.ipv4() {
            claims.insert(RouteClaim::from_cidr(
                Cidr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
                    .expect("IPv4 default route is valid"),
            ));
        }
        if redirect.ipv6() {
            claims.insert(RouteClaim::from_cidr(
                Cidr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
                    .expect("IPv6 default route is valid"),
            ));
        }
    }
    claims
}

fn run_tunnel_effect(
    executor: &Arc<dyn TunnelExecutor>,
    work: &TunnelWork,
    cancellation: &CancellationToken,
    stopping: &AtomicBool,
) -> Result<TunnelExecutionReceipt, WorkFailure> {
    if stopping.load(Ordering::Acquire) || cancellation.is_cancelled() {
        return Err(WorkFailure::Cancelled);
    }
    if Instant::now() >= work.deadline {
        return Err(WorkFailure::TimedOut);
    }
    let result =
        match panic::catch_unwind(AssertUnwindSafe(|| executor.execute(work, cancellation))) {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) => return Err(executor.classify_failure(&error)),
            Err(_) => {
                return match executor.compensate_uncertain(work) {
                    Ok(()) => Err(WorkFailure::Panicked),
                    Err(_) => Err(WorkFailure::OutcomeUnknown),
                };
            }
        };
    if stopping.load(Ordering::Acquire) || cancellation.is_cancelled() {
        return match executor.compensate_unaccepted_success(work) {
            Ok(()) => Err(WorkFailure::Cancelled),
            Err(_) => Err(WorkFailure::OutcomeUnknown),
        };
    }
    if Instant::now() >= work.deadline {
        return match executor.compensate_unaccepted_success(work) {
            Ok(()) => Err(WorkFailure::TimedOut),
            Err(_) => Err(WorkFailure::OutcomeUnknown),
        };
    }
    if work.mutation == TunnelMutation::Connect && result.adoption.is_none() {
        return match executor.compensate_uncertain(work) {
            Ok(()) => Err(WorkFailure::EffectFailed),
            Err(_) => Err(WorkFailure::OutcomeUnknown),
        };
    }
    if work.mutation == TunnelMutation::Connect
        && work.protocol == TunnelKindTag::WireGuard
        && result
            .handshake
            .as_ref()
            .is_none_or(|evidence| evidence.generation != work.revision.generation)
    {
        return match executor.compensate_uncertain(work) {
            Ok(()) => Err(WorkFailure::HandshakeFailed),
            Err(_) => Err(WorkFailure::OutcomeUnknown),
        };
    }
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyBarrier {
    Blocking,
    Tunnel,
    Route,
    Dns,
    Observation,
    EffectivePublication,
}

impl PolicyBarrier {
    pub const ORDERED: [Self; 6] = [
        Self::Blocking,
        Self::Tunnel,
        Self::Route,
        Self::Dns,
        Self::Observation,
        Self::EffectivePublication,
    ];
}

/// One bounded phase of a topology transaction.
///
/// Required blocking is installed and confirmed before tunnel workers are
/// admitted. The final stage deliberately excludes that barrier so failure
/// compensation cannot undo the safety fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyStage {
    PreTunnelBlocking,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyTransitionKind {
    Connect,
    Disconnect,
    Reconnect,
    PrimaryTransfer,
    PolicyOnly,
    Recovery,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopologyState {
    pub profiles: BTreeSet<ProfileId>,
    /// Exact protocol identity for each profile in this topology snapshot.
    pub protocols: BTreeMap<ProfileId, crate::vortix_core::profile::ProtocolKind>,
    pub interfaces: BTreeMap<ProfileId, String>,
    pub routes: BTreeMap<ProfileId, BTreeSet<RouteClaim>>,
    /// Complete authenticated configured/pushed `OpenVPN` route vocabulary
    /// for the current tunnel generation. CIDR claims remain the admission
    /// index; this evidence is the mutation contract.
    pub openvpn_routes: BTreeMap<ProfileId, OpenVpnRouteEvidence>,
    pub server_ips: BTreeMap<ProfileId, BTreeSet<std::net::IpAddr>>,
    pub dns_requests: BTreeMap<ProfileId, crate::vortix_core::ports::dns::DnsRequest>,
    pub dns_digest: PolicyDigest,
    pub kill_switch: KillSwitchMode,
    /// Whether the policy executor has applied an egress-blocking firewall
    /// shape for this exact topology revision.
    pub firewall_blocking: bool,
    pub firewall_digest: PolicyDigest,
    pub ownership_receipts: BTreeSet<String>,
}

/// Complete immutable topology transition. Executors must use only this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyPolicy {
    pub generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub digest: PolicyDigest,
    pub operation_id: OperationId,
    pub deadline: Instant,
    pub prior: TopologyState,
    pub target: TopologyState,
    /// Exact helper-owned identity of every managed tunnel in `prior`.
    pub prior_tunnel_revisions: BTreeMap<ProfileId, TunnelRevision>,
    /// Expected identity of every managed tunnel in `target`.
    pub tunnel_revisions: BTreeMap<ProfileId, TunnelRevision>,
    pub transition: TopologyTransitionKind,
    pub required_blocking: bool,
    pub stage: PolicyStage,
}

impl TopologyPolicy {
    #[must_use]
    pub fn revision(&self) -> ControlRevision {
        ControlRevision {
            authority_epoch: self.authority_epoch,
            generation: self.generation,
            digest: self.digest.clone(),
        }
    }

    fn barriers(&self) -> &'static [PolicyBarrier] {
        const PRE_TUNNEL: &[PolicyBarrier] = &[PolicyBarrier::Blocking];
        const FINAL_AFTER_PRE: &[PolicyBarrier] = &[
            PolicyBarrier::Tunnel,
            PolicyBarrier::Route,
            PolicyBarrier::Dns,
            PolicyBarrier::Observation,
            PolicyBarrier::EffectivePublication,
        ];
        match self.stage {
            PolicyStage::PreTunnelBlocking => PRE_TUNNEL,
            PolicyStage::Final if self.required_blocking => FINAL_AFTER_PRE,
            PolicyStage::Final => &PolicyBarrier::ORDERED,
        }
    }
}

pub trait PolicyExecutor: Send + Sync + 'static {
    fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String>;
    fn compensate(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String>;
    fn apply_cancellable(
        &self,
        policy: &TopologyPolicy,
        barrier: PolicyBarrier,
        _cancellation: &CancellationToken,
    ) -> Result<(), String> {
        self.apply(policy, barrier)
    }
    fn compensate_cancellable(
        &self,
        policy: &TopologyPolicy,
        barrier: PolicyBarrier,
        _cancellation: &CancellationToken,
    ) -> Result<(), String> {
        self.compensate(policy, barrier)
    }

    /// Return fresh platform read-back produced by the exact final policy.
    /// Implementations that cannot prove every gate return `None`; worker
    /// completion alone is never protection truth.
    fn verification(&self, _policy: &TopologyPolicy) -> Option<PolicyExecutionEvidence> {
        None
    }
}

/// Platform read-back attached only to an exact successful final policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Explicit gates are an auditable proof bit-set.
pub struct PolicyExecutionEvidence {
    pub observed_at_millis: u64,
    pub interface_verified: bool,
    pub route_verified: bool,
    pub dns_verified: bool,
    pub firewall_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOutcome {
    Applied,
    Failed,
    Superseded,
    TimedOut,
    Cancelled,
    Panicked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBarrierReceipt {
    pub barrier: PolicyBarrier,
    pub applied: bool,
    pub compensated: bool,
    pub preserved_for_safety: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    pub generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub digest: PolicyDigest,
    pub operation_id: OperationId,
    pub stage: PolicyStage,
    pub verification: Option<PolicyExecutionEvidence>,
    pub outcome: PolicyOutcome,
    pub superseded_by: Option<ControlRevision>,
    pub receipts: Vec<PolicyBarrierReceipt>,
    // Compatibility projections retained for U5/U6 callers.
    pub completed_barriers: Vec<PolicyBarrier>,
    pub failed_at: Option<PolicyBarrier>,
}

struct PolicyState {
    pending: Option<TopologyPolicy>,
    superseded: VecDeque<PolicyResult>,
    max_superseded: usize,
    active_cancel: Option<CancellationToken>,
}

/// Latest-complete coalescing worker. Replaced policies get explicit receipts;
/// barriers in an active generation are never skipped.
pub struct PolicyWorker {
    state: Arc<Mutex<PolicyState>>,
    nudge_tx: Mutex<Option<mpsc::SyncSender<()>>>,
    result_rx: Mutex<mpsc::Receiver<PolicyResult>>,
    stopping: Arc<AtomicBool>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl PolicyWorker {
    #[must_use]
    pub fn start(executor: Arc<dyn PolicyExecutor>, result_capacity: usize) -> Self {
        assert!(result_capacity > 0);
        let state = Arc::new(Mutex::new(PolicyState {
            pending: None,
            superseded: VecDeque::new(),
            max_superseded: result_capacity,
            active_cancel: None,
        }));
        let stopping = Arc::new(AtomicBool::new(false));
        let (nudge_tx, nudge_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(result_capacity);
        let thread_state = Arc::clone(&state);
        let thread_stopping = Arc::clone(&stopping);
        let join = thread::Builder::new()
            .name("vortix-policy-worker".into())
            .spawn(move || {
                while nudge_rx.recv().is_ok() {
                    if thread_stopping.load(Ordering::Acquire) {
                        break;
                    }
                    loop {
                        let policy = {
                            let mut state =
                                thread_state.lock().expect("policy state mutex poisoned");
                            let policy = state.pending.take();
                            if policy.is_some() {
                                state.active_cancel = Some(CancellationToken::default());
                            }
                            policy
                        };
                        let Some(policy) = policy else { break };
                        let token = thread_state
                            .lock()
                            .expect("policy state mutex poisoned")
                            .active_cancel
                            .clone()
                            .expect("token installed");
                        let result = run_policy(&executor, policy, &token, &thread_stopping);
                        thread_state
                            .lock()
                            .expect("policy state mutex poisoned")
                            .active_cancel = None;
                        if result_tx.send(result).is_err() {
                            break;
                        }
                        if thread_stopping.load(Ordering::Acquire) {
                            break;
                        }
                    }
                }
            })
            .expect("policy worker thread should start");
        Self {
            state,
            nudge_tx: Mutex::new(Some(nudge_tx)),
            result_rx: Mutex::new(result_rx),
            stopping,
            join: Mutex::new(Some(join)),
        }
    }

    pub fn submit(&self, policy: TopologyPolicy) -> Result<(), WorkFailure> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(WorkFailure::Stopped);
        }
        let mut state = self.state.lock().expect("policy state mutex poisoned");
        if let Some(current) = &state.pending {
            if current.authority_epoch != policy.authority_epoch
                || current.generation > policy.generation
                || (current.generation == policy.generation
                    && current.digest == policy.digest
                    && current.operation_id == policy.operation_id
                    && current.stage >= policy.stage)
            {
                return Err(WorkFailure::Stale);
            }
            if state.superseded.len() >= state.max_superseded {
                return Err(WorkFailure::Busy);
            }
            let old = state.pending.take().expect("checked pending");
            state.superseded.push_back(superseded_result(&old, &policy));
        }
        state.pending = Some(policy);
        drop(state);
        let guard = self.nudge_tx.lock().expect("nudge mutex poisoned");
        let Some(tx) = guard.as_ref() else {
            return Err(WorkFailure::Stopped);
        };
        match tx.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => Err(WorkFailure::Stopped),
        }
    }

    pub fn try_result(&self) -> Option<PolicyResult> {
        if let Some(result) = self
            .state
            .lock()
            .expect("policy state mutex poisoned")
            .superseded
            .pop_front()
        {
            return Some(result);
        }
        self.result_rx
            .lock()
            .expect("policy result mutex poisoned")
            .try_recv()
            .ok()
    }

    #[must_use]
    pub fn dropped_results(&self) -> u64 {
        0
    }

    pub fn shutdown_bounded(&self, timeout: Duration) -> bool {
        self.stopping.store(true, Ordering::Release);
        if let Some(token) = self
            .state
            .lock()
            .expect("policy state mutex poisoned")
            .active_cancel
            .as_ref()
        {
            token.cancel();
        }
        let sender = self.nudge_tx.lock().expect("nudge mutex poisoned").take();
        if let Some(tx) = sender {
            let _ = tx.try_send(());
            drop(tx);
        }
        let deadline = Instant::now() + timeout;
        let mut guard = self.join.lock().expect("join mutex poisoned");
        let Some(join) = guard.take() else {
            return true;
        };
        while !join.is_finished() && Instant::now() < deadline {
            // A full non-droppable result channel may be the only thing
            // keeping the owned worker alive during shutdown.
            while self
                .result_rx
                .lock()
                .expect("policy result mutex poisoned")
                .try_recv()
                .is_ok()
            {}
            thread::yield_now();
        }
        if join.is_finished() {
            let _ = join.join();
            true
        } else {
            *guard = Some(join);
            false
        }
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_bounded(Duration::from_millis(100));
    }
}

fn superseded_result(old: &TopologyPolicy, next: &TopologyPolicy) -> PolicyResult {
    PolicyResult {
        generation: old.generation,
        authority_epoch: old.authority_epoch,
        digest: old.digest.clone(),
        operation_id: old.operation_id.clone(),
        stage: old.stage,
        verification: None,
        outcome: PolicyOutcome::Superseded,
        superseded_by: Some(next.revision()),
        receipts: Vec::new(),
        completed_barriers: Vec::new(),
        failed_at: None,
    }
}

#[allow(clippy::too_many_lines)] // Barrier application and compensation form one safety audit unit.
fn run_policy(
    executor: &Arc<dyn PolicyExecutor>,
    policy: TopologyPolicy,
    cancellation: &CancellationToken,
    stopping: &AtomicBool,
) -> PolicyResult {
    let mut receipts = Vec::new();
    let mut completed = Vec::new();
    let mut failed_at = None;
    let mut outcome = PolicyOutcome::Applied;
    for &barrier in policy.barriers() {
        if stopping.load(Ordering::Acquire) || cancellation.is_cancelled() {
            outcome = PolicyOutcome::Cancelled;
            failed_at = Some(barrier);
            break;
        }
        if Instant::now() >= policy.deadline {
            outcome = PolicyOutcome::TimedOut;
            failed_at = Some(barrier);
            cancellation.cancel();
            break;
        }
        match run_policy_call(executor, &policy, barrier, cancellation) {
            Ok(()) => {
                completed.push(barrier);
                receipts.push(PolicyBarrierReceipt {
                    barrier,
                    applied: true,
                    compensated: false,
                    preserved_for_safety: false,
                });
            }
            Err(WorkFailure::Panicked) => {
                outcome = PolicyOutcome::Panicked;
                failed_at = Some(barrier);
                receipts.push(PolicyBarrierReceipt {
                    barrier,
                    applied: false,
                    compensated: false,
                    preserved_for_safety: false,
                });
                break;
            }
            Err(WorkFailure::TimedOut | WorkFailure::OutcomeUnknown) => {
                outcome = PolicyOutcome::TimedOut;
                failed_at = Some(barrier);
                cancellation.cancel();
                receipts.push(PolicyBarrierReceipt {
                    barrier,
                    applied: false,
                    compensated: false,
                    preserved_for_safety: false,
                });
                break;
            }
            Err(WorkFailure::Cancelled) => {
                outcome = PolicyOutcome::Cancelled;
                failed_at = Some(barrier);
                receipts.push(PolicyBarrierReceipt {
                    barrier,
                    applied: false,
                    compensated: false,
                    preserved_for_safety: false,
                });
                break;
            }
            Err(_) => {
                outcome = PolicyOutcome::Failed;
                failed_at = Some(barrier);
                receipts.push(PolicyBarrierReceipt {
                    barrier,
                    applied: false,
                    compensated: false,
                    preserved_for_safety: false,
                });
                break;
            }
        }
    }
    if outcome != PolicyOutcome::Applied {
        for receipt in receipts.iter_mut().rev() {
            if receipt.barrier == PolicyBarrier::Blocking
                && policy.required_blocking
                && receipt.applied
            {
                receipt.preserved_for_safety = true;
                continue;
            }
            match run_policy_compensation(executor, &policy, receipt.barrier) {
                Ok(()) => receipt.compensated = true,
                Err(WorkFailure::Panicked) => outcome = PolicyOutcome::Panicked,
                Err(WorkFailure::TimedOut | WorkFailure::OutcomeUnknown) => {
                    outcome = PolicyOutcome::TimedOut;
                }
                Err(_) => outcome = PolicyOutcome::Failed,
            }
        }
    }
    let verification = (outcome == PolicyOutcome::Applied && policy.stage == PolicyStage::Final)
        .then(|| executor.verification(&policy))
        .flatten();
    PolicyResult {
        generation: policy.generation,
        authority_epoch: policy.authority_epoch,
        digest: policy.digest,
        operation_id: policy.operation_id,
        stage: policy.stage,
        verification,
        outcome,
        superseded_by: None,
        receipts,
        completed_barriers: completed,
        failed_at,
    }
}

fn run_policy_call(
    executor: &Arc<dyn PolicyExecutor>,
    policy: &TopologyPolicy,
    barrier: PolicyBarrier,
    cancellation: &CancellationToken,
) -> Result<(), WorkFailure> {
    if cancellation.is_cancelled() || Instant::now() >= policy.deadline {
        return Err(WorkFailure::Cancelled);
    }
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        executor.apply_cancellable(policy, barrier, cancellation)
    }))
    .map_err(|_| WorkFailure::Panicked)?
    .map_err(|error| {
        tracing::warn!(
            target: "vortix::control::policy",
            operation = %policy.operation_id,
            generation = policy.generation,
            ?barrier,
            reason = %error,
            "policy barrier failed"
        );
        WorkFailure::EffectFailed
    });
    if cancellation.is_cancelled() {
        return Err(WorkFailure::Cancelled);
    }
    if Instant::now() >= policy.deadline {
        return Err(WorkFailure::TimedOut);
    }
    result
}

fn run_policy_compensation(
    executor: &Arc<dyn PolicyExecutor>,
    policy: &TopologyPolicy,
    barrier: PolicyBarrier,
) -> Result<(), WorkFailure> {
    let cancellation = CancellationToken::default();
    panic::catch_unwind(AssertUnwindSafe(|| {
        executor.compensate_cancellable(policy, barrier, &cancellation)
    }))
    .map_err(|_| WorkFailure::Panicked)?
    .map_err(|error| {
        tracing::warn!(
            target: "vortix::control::policy",
            operation = %policy.operation_id,
            generation = policy.generation,
            ?barrier,
            reason = %error,
            "policy compensation failed"
        );
        WorkFailure::EffectFailed
    })
}

/// Poll a bounded result without introducing a runtime-specific clock.
pub fn wait_until<T>(timeout: Duration, mut poll: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(value) = poll() {
            return Some(value);
        }
        thread::yield_now();
    }
    None
}
