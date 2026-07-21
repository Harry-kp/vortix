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
use crate::vortix_core::ports::tunnel::{AdoptionEvidence, TunnelKindTag};
use crate::vortix_core::profile::ProfileId;
use crate::vortix_core::state::killswitch::KillSwitchMode;

/// Exact fence carried by desired state, observations, work, and receipts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControlRevision {
    pub authority_epoch: AuthorityEpoch,
    pub generation: u64,
    pub digest: PolicyDigest,
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
    pub generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub policy_digest: PolicyDigest,
    pub mutation: TunnelMutation,
    pub deadline: Instant,
}

impl TunnelWork {
    #[must_use]
    pub fn revision(&self) -> ControlRevision {
        ControlRevision {
            authority_epoch: self.authority_epoch,
            generation: self.generation,
            digest: self.policy_digest.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkFailure {
    Busy,
    RouteConflict,
    TimedOut,
    Cancelled,
    Panicked,
    EffectFailed,
    /// The effect may have happened but no trustworthy receipt was obtained.
    OutcomeUnknown,
    Stale,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelWorkResult {
    pub profile_id: ProfileId,
    pub operation_id: OperationId,
    pub generation: u64,
    pub authority_epoch: AuthorityEpoch,
    pub policy_digest: PolicyDigest,
    pub lease_id: LeaseId,
    pub mutation: TunnelMutation,
    /// Protocol-authoritative identity produced by the exact successful
    /// connect call. Scanner presence alone can never manufacture this.
    pub adoption: Option<AdoptionEvidence>,
    pub result: Result<(), WorkFailure>,
}

/// Cooperative cancellation visible to deterministic and real executors.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TunnelExecutionReceipt {
    pub adoption: Option<AdoptionEvidence>,
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
            })
            .map_err(|error| error.to_string())
    }
}

pub trait TunnelExecutor: Send + Sync + 'static {
    fn execute(
        &self,
        work: &TunnelWork,
        cancellation: &CancellationToken,
    ) -> Result<TunnelExecutionReceipt, String>;
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
        let network = match cidr.addr {
            std::net::IpAddr::V4(addr) => {
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - cidr.prefix_len))
                    .unwrap_or(0);
                std::net::IpAddr::V4((u32::from(addr) & mask).into())
            }
            std::net::IpAddr::V6(addr) => {
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - cidr.prefix_len))
                    .unwrap_or(0);
                std::net::IpAddr::V6((u128::from(addr) & mask).into())
            }
        };
        Ok(Self {
            network,
            prefix_len: cidr.prefix_len,
        })
    }

    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        Cidr::new(self.network, self.prefix_len)
            .zip(Cidr::new(other.network, other.prefix_len))
            .is_some_and(|(left, right)| left.intersects(&right))
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
        let routes = routes
            .into_iter()
            .map(|route| RouteClaim::parse(&route))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut state = self.0.lock().expect("reservation mutex poisoned");
        if state.leases.values().any(|lease| {
            lease.profile_id != *profile_id
                && lease
                    .routes
                    .iter()
                    .any(|existing| routes.iter().any(|route| existing.overlaps(*route)))
        }) {
            return Err(WorkFailure::RouteConflict);
        }
        if let Some((lease_id, lease)) = state
            .leases
            .iter_mut()
            .find(|(_, lease)| lease.profile_id == *profile_id && lease.routes == routes)
        {
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
        let reservation = self.reservations.reserve(profile_id, routes)?;
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
                let lease_id = envelope.reservation.lease_id();
                let result = execution.as_ref().map(|_| ()).map_err(|error| *error);
                envelope.reservation.finish(work.mutation, result);
                let completion = TunnelWorkResult {
                    profile_id: work.profile_id,
                    operation_id: work.operation_id,
                    generation: work.generation,
                    authority_epoch: work.authority_epoch,
                    policy_digest: work.policy_digest,
                    lease_id,
                    mutation: work.mutation,
                    adoption: execution.ok().and_then(|receipt| receipt.adoption),
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
    let result = panic::catch_unwind(AssertUnwindSafe(|| executor.execute(work, cancellation)))
        .map_err(|_| WorkFailure::Panicked)?
        .map_err(|_| WorkFailure::EffectFailed)?;
    if stopping.load(Ordering::Acquire) || cancellation.is_cancelled() {
        return Err(WorkFailure::Cancelled);
    }
    if Instant::now() >= work.deadline {
        return Err(WorkFailure::TimedOut);
    }
    if work.mutation == TunnelMutation::Connect && result.adoption.is_none() {
        return Err(WorkFailure::EffectFailed);
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
    pub interfaces: BTreeMap<ProfileId, String>,
    pub routes: BTreeMap<ProfileId, BTreeSet<RouteClaim>>,
    pub dns_digest: PolicyDigest,
    pub kill_switch: KillSwitchMode,
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
    pub transition: TopologyTransitionKind,
    pub required_blocking: bool,
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
}

pub trait PolicyExecutor: Send + Sync + 'static {
    fn apply(&self, policy: &TopologyPolicy, barrier: PolicyBarrier) -> Result<(), String>;
    fn compensate(&self, policy: &TopologyPolicy, barrier: PolicyBarrier);
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
    ) {
        self.compensate(policy, barrier);
    }
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
                || (current.generation == policy.generation && current.digest == policy.digest)
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
    for barrier in PolicyBarrier::ORDERED {
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
            if receipt.barrier == PolicyBarrier::Blocking && policy.required_blocking {
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
    PolicyResult {
        generation: policy.generation,
        authority_epoch: policy.authority_epoch,
        digest: policy.digest,
        operation_id: policy.operation_id,
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
    .map_err(|_| WorkFailure::EffectFailed);
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
        executor.compensate_cancellable(policy, barrier, &cancellation);
    }))
    .map_err(|_| WorkFailure::Panicked)
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
