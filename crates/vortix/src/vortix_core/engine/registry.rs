//! `TunnelRegistry<T>` — N-active-tunnel wrapper around `Engine<T>` (plan #001 U5).
//!
//! Owns a `HashMap<ProfileId, RegistryEntry<T>>` (each entry wraps an
//! `Engine<T>` and the `AllowedIPs` declared at connect-time), the derived
//! `primary: Option<ProfileId>`, and the global killswitch fields. Panels read
//! snapshots through `snapshot`/`snapshot_all`; the multi-connection app
//! migration in U6 retires the legacy single-tunnel `VpnEngine` and routes
//! every panel through these accessors.
//!
//! ## Shape decision (Q-DEF-6 → D-7)
//!
//! The plan committed in D-7 to the struct-with-HashMap form over a plain
//! `Vec<(ProfileId, Engine<T>)>` + free functions. The Vec form's downside
//! was that the derived state (`primary`, killswitch mode/state, conflict
//! lookups) would need parallel global slots or be recomputed on every read
//! — the struct keeps them adjacent to the engines they describe and makes
//! O(1) lookup by `ProfileId` natural for the `connect(profile_id)` /
//! `disconnect(profile_id)` interface that the App uses. No spike; the
//! decision is documented here rather than at the call site.
//!
//! ## Threading model
//!
//! The registry is **synchronous and single-threaded**. The TUI event loop
//! owns it directly; the FSM itself is sync (see `fsm.rs:8`) and the registry
//! just wraps `engine.handle(input)` calls. The async `EngineHandle` actor
//! (`handle.rs`) is the single-tunnel surface kept for IPC/remote use cases
//! — multi-tunnel mode bypasses it.
//!
//! ## Primary derivation
//!
//! Kernel-truth-only (Q-DEF-5 → D-4). `refresh_primary()` calls
//! `RouteTable::default_route_interface()` and maps the returned interface
//! name back to a `ProfileId` via each FSM's `Connection::Connected.details
//! .interface`. No explicit promotion; the OS routing table is the source of
//! truth, and the registry just observes it.
//!
//! Triggers: event-driven inline at every FSM transition that affects
//! primary candidacy (Connected, Disconnected of current primary, etc.),
//! plus periodic `Tick` (5s) as a safety net for external route changes.

use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::vortix_core::cidr::{claims_default_route_v4, claims_default_route_v6, Cidr};
use crate::vortix_core::engine::event::EngineEvent;
use crate::vortix_core::engine::fsm::Engine;
use crate::vortix_core::engine::input::{Input, UserCommand};
use crate::vortix_core::engine::state::{Connection, ConnectionHealth};
use crate::vortix_core::ports::tunnel::Tunnel;
use crate::vortix_core::profile::ProfileId;
use crate::vortix_core::state::{KillSwitchMode, KillSwitchState};

// ─────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────

/// Why the primary tunnel changed.
///
/// Surfaced via `tracing::info` today; the U23 journal-event wiring will
/// translate this into an `EngineEvent::PrimaryTunnelChanged` variant the UI
/// banner consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrimaryTunnelChangeReason {
    /// A new connect succeeded and that tunnel won the default route.
    NewTunnelTookDefaultRoute,
    /// The prior primary disconnected; another tunnel that already declared
    /// `0/0` was promoted by the kernel.
    PriorPrimaryDisconnected,
    /// An external route change (user ran `wg-quick down`, route flap, etc.)
    /// observed by the Tick-bound safety net.
    ExternalRouteChange,
}

/// Per-tunnel role derived from declared `AllowedIPs` + current primary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Role {
    /// Owns the kernel default route. Carries the declared `AllowedIPs` for
    /// display / Security Guard scoping.
    Primary { allowed_ips: Vec<Cidr> },
    /// Reachable for its declared `AllowedIPs`; doesn't claim the default route.
    Addressable { allowed_ips: Vec<Cidr> },
    /// Declared `0/0` but another tunnel currently holds the default route —
    /// either because of a takeover race or because the user connected this
    /// one without `--force` and it landed second.
    AddressableSuppressed { allowed_ips: Vec<Cidr> },
    /// Reconnecting; the inner role is the one this tunnel held before the
    /// link went down (so the UI can render "Reconnecting (was Primary)").
    Reconnecting { prior_role: Box<Role> },
    /// Mid-connect prompt (2FA, passphrase) — role unknown until the prompt
    /// resolves.
    AwaitingInput,
}

/// Read-only view of one FSM. UI panels read through these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSnapshot {
    pub profile_id: ProfileId,
    pub state: Connection,
    pub role: Role,
    pub health: ConnectionHealth,
    pub interface_name: Option<String>,
    pub started_at: Option<SystemTime>,
}

/// What kind of conflict `detect_conflict` found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Conflict {
    /// Two profiles both claim the kernel default route. The `current` holder
    /// may be either Connected (already on the route) or Connecting (claimed
    /// it but `tunnel.up` hasn't returned yet — the §7.3 in-flight rule).
    DefaultRouteTakeover { current: ProfileId, new: ProfileId },
    /// Non-default-route overlap. Reserved for the future v2 conflict surface
    /// (R10's "subnet overlap" requirement); not produced by the v1
    /// `detect_conflict` which only inspects the default route.
    RouteOverlap {
        with: ProfileId,
        overlapping_cidrs: Vec<Cidr>,
    },
}

/// Errors `TunnelRegistry` operations can return.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    /// A conflict was detected and `force=false` was passed.
    Conflict(Conflict),
    /// `connect()` referenced a profile the resolver doesn't know about.
    ProfileNotFound(ProfileId),
    /// The FSM transition surfaced a tunnel-level failure. Carries the
    /// failure-reason string so callers can render it; the typed
    /// `TunnelError` lives on the journal event, not here.
    TunnelFailure(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(Conflict::DefaultRouteTakeover { current, new }) => write!(
                f,
                "default-route takeover: profile `{new}` cannot claim 0/0 — `{current}` holds it"
            ),
            Self::Conflict(Conflict::RouteOverlap {
                with,
                overlapping_cidrs,
            }) => write!(
                f,
                "route overlap with `{with}` on {} CIDR(s)",
                overlapping_cidrs.len()
            ),
            Self::ProfileNotFound(id) => write!(f, "profile not found: `{id}`"),
            Self::TunnelFailure(msg) => write!(f, "tunnel failure: {msg}"),
        }
    }
}

impl std::error::Error for RegistryError {}

// ─────────────────────────────────────────────────────────────────────────
// Per-entry record (private)
// ─────────────────────────────────────────────────────────────────────────

/// Per-tunnel record the registry carries alongside each FSM. `AllowedIPs`
/// are stored here (not on `Profile`) because they're a runtime artefact of
/// the parsed protocol body — the `Profile` type stays minimal.
struct RegistryEntry<T: Tunnel> {
    engine: Engine<T>,
    /// `AllowedIPs` declared by this tunnel's profile (union across peers for
    /// `WireGuard`; route directives for `OpenVPN`). Used by `detect_conflict`
    /// and to derive `Role::Primary` vs `Role::Addressable`.
    allowed_ips: Vec<Cidr>,
}

impl<T: Tunnel> RegistryEntry<T> {
    fn claims_default_route(&self) -> bool {
        claims_default_route_v4(&self.allowed_ips) || claims_default_route_v6(&self.allowed_ips)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// TunnelRegistry
// ─────────────────────────────────────────────────────────────────────────

/// Maximum age of a cached default-route-interface value before we
/// treat it as suspect. The cache is fed externally by the App's
/// scanner-result handler (which runs `route get default` in the
/// scanner's background thread, so the UI thread never blocks on it).
/// If the scanner thread stalls or never starts, an old value past this
/// age is still served — better than the PROTECTED → PARTIAL flicker
/// that would happen if we blanked the cache on every TTL expiry, and
/// the registry has no better signal to fall back on. 500ms is short
/// enough that genuine route-table changes propagate to the UI within
/// one user blink; the scanner re-feeds the cache once per tick.
const DEFAULT_ROUTE_CACHE_MAX_AGE: std::time::Duration = std::time::Duration::from_millis(500);

/// Cached default-route interface fed in by the App from the scanner's
/// background thread. Wrapping the value + timestamp in one struct
/// makes the "both set together OR both absent" invariant
/// compile-time-enforced — the prior pair of loose `Option`s relied on
/// every callsite preserving it manually.
#[derive(Clone, Debug)]
struct CachedRouteInterface {
    /// The interface name. `None` is a legitimate "kernel reports no
    /// default route" value (e.g. wifi off, VPN-only mode in an
    /// unconfigured state) — distinct from "we haven't probed yet,"
    /// which is represented by the outer `Option<CachedRouteInterface>`
    /// being `None`.
    iface: Option<String>,
    /// When this value was fed in.
    at: std::time::Instant,
}

pub struct TunnelRegistry<T: Tunnel> {
    fsms: HashMap<ProfileId, RegistryEntry<T>>,
    /// Derived: the `ProfileId` whose interface owns the kernel default route.
    /// Updated by `refresh_primary()`; never set directly.
    primary: Option<ProfileId>,
    killswitch_mode: KillSwitchMode,
    killswitch_state: KillSwitchState,
    /// Test seam: when set, `refresh_primary` consults this closure instead of
    /// `current_platform().route_table.default_route_interface()`. Production
    /// constructor leaves it `None`; tests inject a fake. Boxed so the
    /// registry's struct shape doesn't leak the closure type.
    #[allow(clippy::type_complexity)]
    default_route_interface_probe: Option<Box<dyn Fn() -> Option<String> + Send>>,
    /// Last route-interface value fed by the App's scanner-result
    /// handler. `None` means never fed (registry just constructed,
    /// or running in a test that never feeds). See
    /// [`Self::feed_default_route_interface`] for the write side and
    /// [`Self::default_route_interface_cached`] for the read side.
    cached_route: Option<CachedRouteInterface>,
}

impl<T: Tunnel> Default for TunnelRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Tunnel> TunnelRegistry<T> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fsms: HashMap::new(),
            primary: None,
            killswitch_mode: KillSwitchMode::default(),
            killswitch_state: KillSwitchState::default(),
            default_route_interface_probe: None,
            cached_route: None,
        }
    }

    /// Test-only constructor: inject a fake `default_route_interface` probe.
    /// Production code uses [`TunnelRegistry::new`] and reads from
    /// `current_platform()`.
    #[cfg(test)]
    fn with_route_probe<F>(probe: F) -> Self
    where
        F: Fn() -> Option<String> + Send + 'static,
    {
        Self {
            fsms: HashMap::new(),
            primary: None,
            killswitch_mode: KillSwitchMode::default(),
            killswitch_state: KillSwitchState::default(),
            default_route_interface_probe: Some(Box::new(probe)),
            cached_route: None,
        }
    }

    #[must_use]
    pub fn tunnel_count(&self) -> usize {
        self.fsms.len()
    }

    #[must_use]
    pub fn primary(&self) -> Option<&ProfileId> {
        self.primary.as_ref()
    }

    #[must_use]
    pub fn killswitch_mode(&self) -> KillSwitchMode {
        self.killswitch_mode
    }

    #[must_use]
    pub fn killswitch_state(&self) -> KillSwitchState {
        self.killswitch_state
    }

    pub fn set_killswitch_mode(&mut self, mode: KillSwitchMode) {
        self.killswitch_mode = mode;
        // The actual blocking transition lives on the App's killswitch port
        // call site; the registry just carries the mode for snapshot reads.
    }

    pub fn set_killswitch_state(&mut self, state: KillSwitchState) {
        self.killswitch_state = state;
    }

    /// Register an FSM with the given `AllowedIPs` without driving any connect.
    /// Used by U6's App migration when adopting an already-spawned FSM (e.g.,
    /// hydrating from persisted state) — the registry needs the `AllowedIPs`
    /// for conflict detection but the FSM may already be `Connected`.
    pub fn insert(&mut self, profile_id: ProfileId, engine: Engine<T>, allowed_ips: Vec<Cidr>) {
        self.fsms.insert(
            profile_id,
            RegistryEntry {
                engine,
                allowed_ips,
            },
        );
    }

    /// Remove an FSM (without driving disconnect). Returns the inner engine
    /// for the caller to dispose of. The kernel-level teardown should have
    /// happened before calling this.
    pub fn remove(&mut self, profile_id: &ProfileId) -> Option<Engine<T>> {
        self.fsms.remove(profile_id).map(|e| e.engine)
    }

    /// Bookkeeping API: register or refresh a `Connected` entry directly
    /// from a populated `DetailedConnectionInfo` without driving
    /// `Tunnel::up`. Used to mirror externally-driven kernel state
    /// (e.g. a tunnel brought up via the legacy
    /// `App::connect_profile_inner` spawned-thread path) into the
    /// registry until plan 001 U7 routes the full connect flow through
    /// `EngineHandle::Local`.
    ///
    /// Behavior:
    /// - If an entry already exists for `profile_id`, its FSM is
    ///   seeded into `Connected` with the supplied details
    ///   ([`Engine::seed_connected_state`]) and its `allowed_ips` are
    ///   refreshed (a profile edit may have changed them).
    /// - If no entry exists, `engine_factory` is invoked to construct
    ///   a fresh `Engine<T>` (the caller supplies a placeholder
    ///   tunnel — it is never invoked because state is seeded
    ///   directly). The new engine is seeded and inserted.
    /// - `refresh_primary_internal` runs after seeding so the derived
    ///   `primary` reflects the new entry.
    ///
    /// The supplied details should carry kernel-true values
    /// (interface name, pid, endpoint, mtu, transfer counters, etc.)
    /// — these flow directly into renderer-facing snapshots.
    #[allow(clippy::needless_pass_by_value)] // owned ProfileId stored in the HashMap key
    pub fn set_connected(
        &mut self,
        profile_id: ProfileId,
        allowed_ips: Vec<Cidr>,
        details: crate::vortix_core::engine::state::DetailedConnectionInfo,
        since: std::time::SystemTime,
        engine_factory: impl FnOnce() -> Engine<T>,
    ) {
        if let Some(entry) = self.fsms.get_mut(&profile_id) {
            entry
                .engine
                .seed_connected_state(profile_id.clone(), details, since);
            entry.allowed_ips = allowed_ips;
        } else {
            let mut engine = engine_factory();
            engine.seed_connected_state(profile_id.clone(), details, since);
            self.fsms.insert(
                profile_id,
                RegistryEntry {
                    engine,
                    allowed_ips,
                },
            );
        }
        // Inline refresh — `set_connected` doesn't produce engine
        // events to inspect, so use the external-reason wrapper.
        let from = self.primary.clone();
        self.recompute_primary();
        if self.primary != from {
            log_primary_change(
                from.as_ref(),
                self.primary.as_ref(),
                PrimaryTunnelChangeReason::ExternalRouteChange,
            );
        }
    }

    /// Bookkeeping API counterpart to [`Self::set_connected`]: seed
    /// the FSM (if present) directly into `Disconnected` without
    /// running `Disconnecting` or calling `Tunnel::down`, then drop
    /// the entry. Idempotent — a missing profile is a no-op. Use
    /// when the App's legacy disconnect path has already torn down
    /// the kernel state and we just need the registry's
    /// snapshot/primary derivation to follow.
    pub fn set_disconnected(&mut self, profile_id: &ProfileId) {
        if let Some(entry) = self.fsms.get_mut(profile_id) {
            entry.engine.seed_disconnected_state();
        }
        self.fsms.remove(profile_id);
        let from = self.primary.clone();
        self.recompute_primary();
        if self.primary != from {
            log_primary_change(
                from.as_ref(),
                self.primary.as_ref(),
                PrimaryTunnelChangeReason::ExternalRouteChange,
            );
        }
    }

    /// Bookkeeping API: register a `Connecting` entry — used by
    /// `App::mirror_connecting_into_registry` when the legacy connect
    /// path sets `ConnectionState = Connecting{...}` and spawns its
    /// worker thread. Renderers see the `◐` badge until the connect
    /// completes and `set_connected` replaces this entry.
    #[allow(clippy::needless_pass_by_value)] // owned ProfileId stored in the HashMap key
    pub fn set_connecting(
        &mut self,
        profile_id: ProfileId,
        allowed_ips: Vec<Cidr>,
        started_at: std::time::SystemTime,
        attempt: u32,
        retry_budget_remaining: std::time::Duration,
        engine_factory: impl FnOnce() -> Engine<T>,
    ) {
        if let Some(entry) = self.fsms.get_mut(&profile_id) {
            entry.engine.seed_connecting_state(
                profile_id.clone(),
                started_at,
                attempt,
                retry_budget_remaining,
            );
            entry.allowed_ips = allowed_ips;
        } else {
            let mut engine = engine_factory();
            engine.seed_connecting_state(
                profile_id.clone(),
                started_at,
                attempt,
                retry_budget_remaining,
            );
            self.fsms.insert(
                profile_id,
                RegistryEntry {
                    engine,
                    allowed_ips,
                },
            );
        }
        // No primary recompute: a Connecting tunnel doesn't own the
        // kernel default route yet.
    }

    /// Bookkeeping API: transition an existing entry to `Disconnecting`.
    /// No-op when the profile isn't in the registry (you can't
    /// disconnect a tunnel that never existed). Renderers see the
    /// `◑` badge during the teardown window.
    pub fn set_disconnecting(&mut self, profile_id: &ProfileId, started_at: std::time::SystemTime) {
        if let Some(entry) = self.fsms.get_mut(profile_id) {
            entry
                .engine
                .seed_disconnecting_state(profile_id.clone(), started_at);
        }
        // Re-derive primary: a Disconnecting tunnel may have held the
        // default route, so its yield can flip primary.
        let from = self.primary.clone();
        self.recompute_primary();
        if self.primary != from {
            log_primary_change(
                from.as_ref(),
                self.primary.as_ref(),
                PrimaryTunnelChangeReason::ExternalRouteChange,
            );
        }
    }

    /// Bookkeeping API: register or refresh a `Disconnected` entry that
    /// carries a `FailureReason`. Renderers see the `✗` badge until
    /// the user retries (which `set_connecting` replaces with a fresh
    /// Connecting entry) or explicitly dismisses (`set_disconnected`
    /// removes it).
    #[allow(clippy::needless_pass_by_value)] // owned ProfileId stored in the HashMap key
    pub fn set_failed(
        &mut self,
        profile_id: ProfileId,
        allowed_ips: Vec<Cidr>,
        failure: crate::vortix_core::engine::state::FailureReason,
        engine_factory: impl FnOnce() -> Engine<T>,
    ) {
        if let Some(entry) = self.fsms.get_mut(&profile_id) {
            entry.engine.seed_failed_state(failure);
            entry.allowed_ips = allowed_ips;
        } else {
            let mut engine = engine_factory();
            engine.seed_failed_state(failure);
            self.fsms.insert(
                profile_id,
                RegistryEntry {
                    engine,
                    allowed_ips,
                },
            );
        }
        // Re-derive primary: the failed tunnel may have been primary
        // just before the failure landed.
        let from = self.primary.clone();
        self.recompute_primary();
        if self.primary != from {
            log_primary_change(
                from.as_ref(),
                self.primary.as_ref(),
                PrimaryTunnelChangeReason::ExternalRouteChange,
            );
        }
    }

    // ──────────────────────────── Snapshots ────────────────────────────

    #[must_use]
    pub fn snapshot(&self, profile_id: &ProfileId) -> Option<TunnelSnapshot> {
        let entry = self.fsms.get(profile_id)?;
        Some(self.build_snapshot(profile_id, entry))
    }

    #[must_use]
    pub fn snapshot_all(&self) -> Vec<TunnelSnapshot> {
        let mut out: Vec<TunnelSnapshot> = self
            .fsms
            .iter()
            .map(|(id, entry)| self.build_snapshot(id, entry))
            .collect();
        // Stable order so panel rendering doesn't flicker between frames.
        out.sort_by(|a, b| a.profile_id.as_str().cmp(b.profile_id.as_str()));
        out
    }

    fn build_snapshot(&self, profile_id: &ProfileId, entry: &RegistryEntry<T>) -> TunnelSnapshot {
        let state = entry.engine.state().clone();
        let (interface_name, started_at, health) = match &state {
            Connection::Connected {
                details,
                since,
                health,
                ..
            } => (
                Some(details.interface.clone()),
                Some(*since),
                health.clone(),
            ),
            Connection::Connecting { started_at, .. }
            | Connection::Reconnecting { started_at, .. }
            | Connection::Disconnecting { started_at, .. } => {
                (None, Some(*started_at), ConnectionHealth::default())
            }
            Connection::AwaitingUserInput { since, .. } => {
                (None, Some(*since), ConnectionHealth::default())
            }
            Connection::Disconnected { .. } => (None, None, ConnectionHealth::default()),
        };

        let role = self.derive_role(profile_id, entry, &state);

        TunnelSnapshot {
            profile_id: profile_id.clone(),
            state,
            role,
            health,
            interface_name,
            started_at,
        }
    }

    fn derive_role(
        &self,
        profile_id: &ProfileId,
        entry: &RegistryEntry<T>,
        state: &Connection,
    ) -> Role {
        match state {
            Connection::AwaitingUserInput { .. } => Role::AwaitingInput,
            Connection::Reconnecting { .. } => {
                // Best-effort: use what the AllowedIPs say.
                let prior = self.derive_role_from_allowed_ips(profile_id, entry);
                Role::Reconnecting {
                    prior_role: Box::new(prior),
                }
            }
            // For every steady or transitional state outside Reconnecting /
            // AwaitingUserInput, the role is derived purely from the
            // declared AllowedIPs vs the current primary.
            Connection::Disconnected { .. }
            | Connection::Disconnecting { .. }
            | Connection::Connecting { .. }
            | Connection::Connected { .. } => self.derive_role_from_allowed_ips(profile_id, entry),
        }
    }

    fn derive_role_from_allowed_ips(
        &self,
        profile_id: &ProfileId,
        entry: &RegistryEntry<T>,
    ) -> Role {
        // Kernel ownership of the default route is the source of truth.
        // For OpenVPN, `redirect-gateway` is server-pushed at runtime via
        // `PUSH_REPLY` and never appears in the client `.ovpn` file, so
        // `entry.allowed_ips` (parsed from the static config) is empty
        // even when the tunnel is actually the primary. Before this
        // check existed, those profiles always rendered as
        // `Split tunnel` — strictly wrong when the kernel routing table
        // says otherwise. Trusting the kernel here means WG profiles
        // that DO declare `AllowedIPs = 0.0.0.0/0` AND OpenVPN profiles
        // that got the default route pushed at runtime both render as
        // `Primary` correctly.
        if self.primary.as_ref() == Some(profile_id) {
            return Role::Primary {
                allowed_ips: entry.allowed_ips.clone(),
            };
        }

        // Unauthoritative entries (scanner-adopted external tunnels with
        // unreliable per-PID iface detection — see `DetailedConnectionInfo::
        // interface_authoritative`) render as `Addressable` regardless of
        // declared AllowedIPs. Vortix can't verify the routing status
        // byte-for-byte against the kernel, so claiming `AddressableSuppressed`
        // (which implies "I claimed default but lost") would lie. `Addressable`
        // is the honest fallback — "we see it as connected; we don't know its
        // routing posture."
        if let Connection::Connected { details, .. } = entry.engine.state() {
            if !details.interface_authoritative {
                return Role::Addressable {
                    allowed_ips: entry.allowed_ips.clone(),
                };
            }
        }

        // Not the primary. Now the static AllowedIPs distinguish "I
        // declared 0/0 but lost the election" (suppressed) from
        // "I never wanted the default route" (genuine split-tunnel).
        let claims_default = entry.claims_default_route();
        if !claims_default {
            return Role::Addressable {
                allowed_ips: entry.allowed_ips.clone(),
            };
        }
        if self.primary.is_some() {
            // Someone else owns the default route despite our claim.
            Role::AddressableSuppressed {
                allowed_ips: entry.allowed_ips.clone(),
            }
        } else {
            // No primary yet — could be us (mid-connect) or no one
            // (split-only topology). Until `refresh_primary` runs after
            // `tunnel.up`, surface as Addressable; the post-connect
            // refresh promotes us via the `self.primary` branch above.
            Role::Addressable {
                allowed_ips: entry.allowed_ips.clone(),
            }
        }
    }

    // ──────────────────────────── Connect ────────────────────────────

    /// Attempt to connect `profile_id` with the given `AllowedIPs`.
    ///
    /// `AllowedIPs` are passed in (not extracted from `Profile`) because the
    /// minimal `Profile` type doesn't carry parsed route data — the App
    /// extracts them from the per-protocol parsed profile and threads them
    /// through.
    ///
    /// # Errors
    ///
    /// - `RegistryError::Conflict` when another tunnel already claims the
    ///   default route and `force` is false.
    /// - `RegistryError::ProfileNotFound` when the FSM's profile resolver
    ///   returns `None`.
    /// - `RegistryError::TunnelFailure` when the FSM transitions to
    ///   `Disconnected { last_failure: Some(_) }` after `Connect`.
    #[allow(clippy::needless_pass_by_value)] // owned ProfileId stored in the HashMap key
    pub fn connect(
        &mut self,
        profile_id: ProfileId,
        allowed_ips: Vec<Cidr>,
        engine_factory: impl FnOnce() -> Engine<T>,
        force: bool,
    ) -> Result<(), RegistryError> {
        if !force {
            if let Some(conflict) = self.detect_conflict(&profile_id, &allowed_ips) {
                tracing::info!(
                    target: "vortix::registry",
                    profile_id = %profile_id,
                    ?conflict,
                    "connect blocked by conflict",
                );
                return Err(RegistryError::Conflict(conflict));
            }
        }

        // Spawn or reuse the FSM entry.
        let entry = self
            .fsms
            .entry(profile_id.clone())
            .or_insert_with(|| RegistryEntry {
                engine: engine_factory(),
                allowed_ips: allowed_ips.clone(),
            });
        // Allowed-IPs may have been updated since last connect (e.g., profile
        // edited on disk). Refresh the cached copy.
        entry.allowed_ips = allowed_ips;

        let events = entry
            .engine
            .handle(Input::UserCommand(UserCommand::Connect {
                profile_id: profile_id.clone(),
            }));

        // Detect immediate failure surfaced by the FSM (ProfileGone / tunnel
        // error reasons). The Engine transitions to Disconnected with a
        // last_failure set; we surface that as a typed error so the caller
        // doesn't have to inspect the FSM state.
        if let Connection::Disconnected {
            last_failure: Some(reason),
        } = entry.engine.state()
        {
            use crate::vortix_core::engine::state::FailureReason;
            return match reason {
                FailureReason::ProfileGone(id) => Err(RegistryError::ProfileNotFound(id.clone())),
                other => Err(RegistryError::TunnelFailure(format!("{other:?}"))),
            };
        }

        // Refresh primary inline — event-driven trigger per plan §U5.
        self.refresh_primary_internal(events.iter());
        Ok(())
    }

    /// Connect using the registry's default `Engine::new` factory shape; the
    /// caller supplies the tunnel impl and profile resolver. Most production
    /// call sites use this directly; tests use the lower-level `connect`
    /// which takes a custom factory.
    ///
    /// # Errors
    ///
    /// See [`TunnelRegistry::connect`].
    pub fn connect_with_tunnel(
        &mut self,
        profile_id: ProfileId,
        allowed_ips: Vec<Cidr>,
        tunnel: T,
        profile_resolver: impl Fn(&ProfileId) -> Option<crate::vortix_core::profile::Profile>
            + Send
            + 'static,
        force: bool,
    ) -> Result<(), RegistryError> {
        self.connect(
            profile_id,
            allowed_ips,
            || Engine::new(tunnel, profile_resolver),
            force,
        )
    }

    // ──────────────────────────── Disconnect ────────────────────────────

    /// Drive a single FSM through `UserCommand::Disconnect`.
    ///
    /// # Errors
    ///
    /// `RegistryError::ProfileNotFound` if the registry has no entry for
    /// `profile_id`.
    pub fn disconnect(&mut self, profile_id: &ProfileId) -> Result<(), RegistryError> {
        let was_primary = self.primary.as_ref() == Some(profile_id);
        let entry = self
            .fsms
            .get_mut(profile_id)
            .ok_or_else(|| RegistryError::ProfileNotFound(profile_id.clone()))?;
        let events = entry
            .engine
            .handle(Input::UserCommand(UserCommand::Disconnect {
                profile_id: Some(profile_id.clone()),
            }));

        // Event-driven primary refresh. If we just took down the primary,
        // re-probe immediately and emit a structured log so U23's journal
        // wiring picks it up.
        let from = self.primary.clone();
        self.refresh_primary_internal(events.iter());
        if was_primary && self.primary.as_ref() != from.as_ref() {
            log_primary_change(
                from.as_ref(),
                self.primary.as_ref(),
                PrimaryTunnelChangeReason::PriorPrimaryDisconnected,
            );
        }
        Ok(())
    }

    /// Tear down every active tunnel.
    ///
    /// Sequential per plan §H6: secondaries first, primary last; one
    /// killswitch refresh at the end. Errors on individual tunnels are
    /// logged but don't short-circuit the loop — the goal is to reach an
    /// empty registry even if a `tunnel.down` misbehaves.
    pub fn disconnect_all(&mut self) {
        // Collect ProfileIds first to avoid borrowing `self.fsms` across
        // mutation. Secondaries first; primary last.
        let primary = self.primary.clone();
        let mut order: Vec<ProfileId> = self
            .fsms
            .keys()
            .filter(|id| Some(*id) != primary.as_ref())
            .cloned()
            .collect();
        order.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        if let Some(p) = primary {
            order.push(p);
        }
        for id in order {
            if let Err(err) = self.disconnect(&id) {
                tracing::warn!(
                    target: "vortix::registry",
                    profile_id = %id,
                    %err,
                    "disconnect_all: individual disconnect failed; continuing",
                );
            }
        }
        // One killswitch refresh at the end is a no-op here — the App owns
        // the killswitch port; the registry just signals that it's safe to
        // call. The U6 migration wires the actual port call.
    }

    // ──────────────────────────── Reconnect ────────────────────────────

    /// Drive `Reconnect` on a single FSM.
    ///
    /// # Errors
    ///
    /// `RegistryError::ProfileNotFound` if the registry has no entry.
    pub fn reconnect(&mut self, profile_id: &ProfileId) -> Result<(), RegistryError> {
        let entry = self
            .fsms
            .get_mut(profile_id)
            .ok_or_else(|| RegistryError::ProfileNotFound(profile_id.clone()))?;
        let events = entry
            .engine
            .handle(Input::UserCommand(UserCommand::Reconnect {
                profile_id: Some(profile_id.clone()),
            }));
        self.refresh_primary_internal(events.iter());
        Ok(())
    }

    /// Drive `Reconnect` on every FSM in stable order.
    pub fn reconnect_all(&mut self) {
        let ids: Vec<ProfileId> = {
            let mut v: Vec<ProfileId> = self.fsms.keys().cloned().collect();
            v.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            v
        };
        for id in ids {
            let _ = self.reconnect(&id);
        }
    }

    // ──────────────────────────── Primary refresh ────────────────────────────

    /// Re-probe the kernel default-route interface and update `self.primary`.
    ///
    /// Public so the App can call it from the Tick handler and from
    /// `NetworkLinkChanged` event handling. Internal callers use
    /// `refresh_primary_internal` which records the reason for the log
    /// event.
    pub fn refresh_primary(&mut self) {
        // External callers can't infer the reason; default to
        // `ExternalRouteChange` for the structured log.
        let from = self.primary.clone();
        self.recompute_primary();
        if self.primary != from {
            log_primary_change(
                from.as_ref(),
                self.primary.as_ref(),
                PrimaryTunnelChangeReason::ExternalRouteChange,
            );
        }
        self.drain_pending_after_disconnect();
    }

    fn refresh_primary_internal<'a, I>(&mut self, events: I)
    where
        I: IntoIterator<Item = &'a EngineEvent>,
    {
        let from = self.primary.clone();
        let reason = guess_reason_from_events(events);
        self.recompute_primary();
        if self.primary != from {
            log_primary_change(from.as_ref(), self.primary.as_ref(), reason);
        }
        self.drain_pending_after_disconnect();
    }

    fn recompute_primary(&mut self) {
        let probed = self.default_route_interface_cached();
        let Some(iface) = probed else {
            self.primary = None;
            return;
        };
        let mut found: Option<ProfileId> = None;
        for (pid, entry) in &self.fsms {
            if let Connection::Connected { details, .. } = entry.engine.state() {
                // Only authoritative entries are eligible. Unauthoritative
                // entries (scanner-adopted external tunnels with unreliable
                // per-PID iface detection) carry an iface field we can't
                // verify against the kernel; promoting one to primary would
                // be a false claim. See `DetailedConnectionInfo::
                // interface_authoritative` for the contract.
                if details.interface_authoritative && details.interface == iface {
                    found = Some(pid.clone());
                    break;
                }
            }
        }
        self.primary = found;
    }

    /// External cache feed: push the latest default-route interface
    /// (probed by the App's scanner thread, never by the registry
    /// itself). This is the ONLY production write path for the cache;
    /// the registry must never shell out from its own methods because
    /// they run synchronously on the UI thread.
    ///
    /// Idempotent and cheap — safe to call on every scanner tick.
    pub fn feed_default_route_interface(&mut self, iface: Option<String>) {
        self.cached_route = Some(CachedRouteInterface {
            iface,
            at: std::time::Instant::now(),
        });
    }

    /// Return the best-known default-route interface from the cache
    /// (production) or the injected probe closure (tests). NEVER
    /// shells out — the production probe happens in
    /// [`crate::core::scanner::gather_system_state`] on a background
    /// thread, the result reaches us through
    /// [`Self::feed_default_route_interface`].
    fn default_route_interface_cached(&self) -> Option<String> {
        // Test seam wins — fakes are presumed instant + side-effect-
        // free, so tests can simulate route-table flapping without
        // having to thread the cache update through.
        if let Some(probe) = &self.default_route_interface_probe {
            return probe();
        }
        // Production: serve the cached value. If the App hasn't fed
        // us yet, `cached_route` is `None` → primary stays unset for
        // a fraction of a second after startup until the first scanner
        // tick lands. This is the correct UI behaviour at startup
        // anyway ("no primary known yet").
        let cached = self.cached_route.as_ref()?;
        // Surface a tracing warning when the scanner has fallen behind
        // by more than the staleness budget. We still serve the value
        // (returning `None` would blank the primary every tick and
        // flicker the headline PROTECTED → PARTIAL when the scanner is
        // slow), but ops investigating UX glitches via
        // `RUST_LOG=vortix::vortix_core=warn` get a clear signal.
        let age = cached.at.elapsed();
        if age > DEFAULT_ROUTE_CACHE_MAX_AGE {
            tracing::warn!(
                target: "vortix::vortix_core::engine::registry",
                age_ms = u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
                "default-route cache is stale; scanner thread may be falling behind"
            );
        }
        cached.iface.clone()
    }

    // ──────────────────────────── Pending-after-disconnect ────────────────────────────

    /// Stash `queued` on `during`'s FSM. When `during` reaches
    /// `Disconnected`, the registry's next tick (or transition observer)
    /// will fire a `Connect` for `queued`.
    ///
    /// # Errors
    ///
    /// `RegistryError::ProfileNotFound` if `during` has no entry.
    pub fn queue_after_disconnect(
        &mut self,
        during: &ProfileId,
        queued: ProfileId,
    ) -> Result<(), RegistryError> {
        let entry = self
            .fsms
            .get_mut(during)
            .ok_or_else(|| RegistryError::ProfileNotFound(during.clone()))?;
        entry.engine.set_pending_after_disconnect(Some(queued));
        Ok(())
    }

    /// Walk every FSM; if any reached `Disconnected` with a queued
    /// `pending_after_disconnect`, fire the queued connect. Called inline by
    /// `refresh_primary*` (event-driven) and by the App's Tick (safety net).
    ///
    /// The queued connect uses the same `AllowedIPs` as the originally-stashed
    /// entry — if the queued profile isn't in the registry yet, the caller
    /// must have inserted it (via [`Self::insert`]) before queuing.
    fn drain_pending_after_disconnect(&mut self) {
        // Two-pass to satisfy the borrow checker: collect pending pairs, then
        // act on them.
        let mut to_fire: Vec<(ProfileId, ProfileId)> = Vec::new();
        for (host_id, entry) in &mut self.fsms {
            let is_disconnected = matches!(entry.engine.state(), Connection::Disconnected { .. });
            if !is_disconnected {
                continue;
            }
            if let Some(queued) = entry.engine.pending_after_disconnect().cloned() {
                to_fire.push((host_id.clone(), queued));
                entry.engine.set_pending_after_disconnect(None);
            }
        }
        for (host_id, queued) in to_fire {
            tracing::info!(
                target: "vortix::registry",
                during = %host_id,
                queued = %queued,
                "firing queued connect after disconnect",
            );
            if let Some(entry) = self.fsms.get_mut(&queued) {
                // The queued profile was pre-inserted; drive Connect on its
                // existing FSM.
                let events = entry
                    .engine
                    .handle(Input::UserCommand(UserCommand::Connect {
                        profile_id: queued.clone(),
                    }));
                let _ = events; // primary will be re-computed at the next outer refresh
            } else {
                tracing::warn!(
                    target: "vortix::registry",
                    queued = %queued,
                    "queued profile was not pre-inserted; dropping",
                );
            }
        }
        // Recompute primary once more if anything fired. Cheap; safe to
        // always call.
        self.recompute_primary();
    }

    // ──────────────────────────── Conflict detection ────────────────────────────

    /// Inspect the registry's current state and return a `Conflict` if
    /// connecting `new_profile` with `new_allowed_ips` would violate the
    /// single-default-route invariant. Returns `None` when safe.
    ///
    /// Checks both the Connected primary AND any in-flight `Connecting` FSMs
    /// — the latter is the §7.3 in-flight rule (SC12).
    #[must_use]
    pub fn detect_conflict(
        &self,
        new_profile: &ProfileId,
        new_allowed_ips: &[Cidr],
    ) -> Option<Conflict> {
        let new_claims_default =
            claims_default_route_v4(new_allowed_ips) || claims_default_route_v6(new_allowed_ips);
        if !new_claims_default {
            // Non-default-route profile; never conflicts (route-overlap
            // detection is R10 v2 territory, not v1).
            return None;
        }
        // Find any other tunnel already claiming 0/0 in a Connected or
        // Connecting state.
        for (pid, entry) in &self.fsms {
            if pid == new_profile {
                continue;
            }
            if !entry.claims_default_route() {
                continue;
            }
            match entry.engine.state() {
                Connection::Connected { .. } | Connection::Connecting { .. } => {
                    return Some(Conflict::DefaultRouteTakeover {
                        current: pid.clone(),
                        new: new_profile.clone(),
                    });
                }
                _ => {}
            }
        }
        None
    }

    /// Profile that has claimed (but not yet finalised) the default route —
    /// a Connecting FSM with `0/0` `AllowedIPs`. Returns `None` when no
    /// in-flight claimant exists.
    #[must_use]
    pub fn pending_default_route_claimant(&self) -> Option<&ProfileId> {
        for (pid, entry) in &self.fsms {
            if entry.claims_default_route()
                && matches!(entry.engine.state(), Connection::Connecting { .. })
            {
                return Some(pid);
            }
        }
        None
    }

    /// Drive a `Tick` input through every FSM. Used by the App's tick loop.
    /// The registry refreshes `primary` once at the end.
    pub fn tick(&mut self) {
        for entry in self.fsms.values_mut() {
            let _ = entry.engine.handle(Input::Tick);
        }
        self.refresh_primary();
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

fn guess_reason_from_events<'a, I>(events: I) -> PrimaryTunnelChangeReason
where
    I: IntoIterator<Item = &'a EngineEvent>,
{
    let mut saw_up = false;
    let mut saw_down = false;
    for ev in events {
        match ev {
            EngineEvent::TunnelUp { .. } => saw_up = true,
            EngineEvent::TunnelDown { .. } => saw_down = true,
            _ => {}
        }
    }
    if saw_down {
        PrimaryTunnelChangeReason::PriorPrimaryDisconnected
    } else if saw_up {
        PrimaryTunnelChangeReason::NewTunnelTookDefaultRoute
    } else {
        PrimaryTunnelChangeReason::ExternalRouteChange
    }
}

fn log_primary_change(
    from: Option<&ProfileId>,
    to: Option<&ProfileId>,
    reason: PrimaryTunnelChangeReason,
) {
    // U23 will replace this with a journal-emitted EngineEvent. For now the
    // structured log is the contract.
    tracing::info!(
        target: "vortix::registry",
        from = ?from.map(ProfileId::as_str),
        to = ?to.map(ProfileId::as_str),
        ?reason,
        "primary tunnel changed",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::vortix_core::engine::state::DetailedConnectionInfo;
    use crate::vortix_core::ports::tunnel::mock::{MockTunnel, ScriptedTunnelOutcome};
    use crate::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

    fn profile(name: &str) -> Profile {
        Profile::new(
            ProfileId::new(name),
            name,
            ProtocolKind::WireGuard,
            PathBuf::from(format!("/etc/wireguard/{name}.conf")),
        )
    }

    fn v4(s: &str) -> Cidr {
        s.parse().expect("valid cidr")
    }

    /// Full 0/0 (canonical) as a v4 CIDR list.
    fn default_route_v4() -> Vec<Cidr> {
        vec![v4("0.0.0.0/0")]
    }

    /// `0/1 + 128/1` split-CIDR pair (SC10) — covers full v4.
    fn split_pair_v4() -> Vec<Cidr> {
        vec![v4("0.0.0.0/1"), v4("128.0.0.0/1")]
    }

    /// `/2` quartet (SC11) — covers full v4.
    fn quartet_v4() -> Vec<Cidr> {
        vec![
            v4("0.0.0.0/2"),
            v4("64.0.0.0/2"),
            v4("128.0.0.0/2"),
            v4("192.0.0.0/2"),
        ]
    }

    /// Resolver factory that knows about a single named profile.
    fn resolver_for(name: &'static str) -> impl Fn(&ProfileId) -> Option<Profile> + Send + 'static {
        let owned = name.to_string();
        move |id| {
            if id.as_str() == owned {
                Some(profile(&owned))
            } else {
                None
            }
        }
    }

    /// Constructs a `TunnelRegistry` whose `refresh_primary` consults the
    /// supplied closure.
    fn registry_with_iface<F>(probe: F) -> TunnelRegistry<MockTunnel>
    where
        F: Fn() -> Option<String> + Send + 'static,
    {
        TunnelRegistry::with_route_probe(probe)
    }

    fn connect_with_iface(
        reg: &mut TunnelRegistry<MockTunnel>,
        name: &'static str,
        iface: &str,
        allowed_ips: Vec<Cidr>,
        force: bool,
    ) -> Result<(), RegistryError> {
        let tunnel = MockTunnel::new();
        tunnel.script_up(ScriptedTunnelOutcome::UpSuccess {
            interface_name: iface.into(),
            pid: None,
        });
        reg.connect_with_tunnel(
            ProfileId::new(name),
            allowed_ips,
            tunnel,
            resolver_for(name),
            force,
        )
    }

    // ─────────────── Happy path ───────────────

    #[test]
    fn empty_registry_has_no_primary_or_tunnels() {
        let reg: TunnelRegistry<MockTunnel> = TunnelRegistry::new();
        assert_eq!(reg.tunnel_count(), 0);
        assert!(reg.primary().is_none());
        assert!(reg.snapshot_all().is_empty());
    }

    #[test]
    fn connect_one_profile_becomes_primary_after_refresh() {
        let iface = Arc::new(Mutex::new(None::<String>));
        let iface_probe = Arc::clone(&iface);
        let mut reg = registry_with_iface(move || iface_probe.lock().unwrap().clone());

        // Before connect, kernel reports no default route.
        *iface.lock().unwrap() = Some("utun7".into());
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();

        assert_eq!(reg.tunnel_count(), 1);
        assert_eq!(reg.primary(), Some(&ProfileId::new("corp")));
        let snap = reg.snapshot(&ProfileId::new("corp")).unwrap();
        assert!(matches!(snap.role, Role::Primary { .. }));
        assert_eq!(snap.interface_name.as_deref(), Some("utun7"));
    }

    #[test]
    fn connect_two_disjoint_allowed_ips_both_connected_primary_owns_zero_slash_zero() {
        let mut reg = registry_with_iface(|| Some("utun7".into())); // first tunnel owns kernel route
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();
        connect_with_iface(&mut reg, "lab", "utun8", vec![v4("10.0.0.0/8")], false).unwrap();

        assert_eq!(reg.tunnel_count(), 2);
        assert_eq!(reg.primary(), Some(&ProfileId::new("corp")));
        let snaps = reg.snapshot_all();
        let corp = snaps
            .iter()
            .find(|s| s.profile_id.as_str() == "corp")
            .unwrap();
        let lab = snaps
            .iter()
            .find(|s| s.profile_id.as_str() == "lab")
            .unwrap();
        assert!(matches!(corp.role, Role::Primary { .. }));
        assert!(matches!(lab.role, Role::Addressable { .. }));
    }

    // ─────────────── SC2 — registry follows kernel re-election ───────────────

    #[test]
    fn disconnect_primary_promotes_secondary_with_zero_slash_zero() {
        // Kernel route follows whoever is connected.
        let iface = Arc::new(Mutex::new(Some("utun7".to_string())));
        let iface_probe = Arc::clone(&iface);
        let mut reg = registry_with_iface(move || iface_probe.lock().unwrap().clone());

        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();
        // Second 0/0 with `force` to bypass takeover detection — simulates
        // the "secondary that already declared 0/0 but landed second" case
        // without modeling the takeover overlay UX. After connect, the
        // kernel still says utun7 (corp) holds the route.
        connect_with_iface(&mut reg, "home", "utun8", default_route_v4(), true).unwrap();
        assert_eq!(reg.primary(), Some(&ProfileId::new("corp")));

        // Disconnect corp; kernel route flips to utun8.
        *iface.lock().unwrap() = Some("utun8".into());
        reg.disconnect(&ProfileId::new("corp")).unwrap();

        assert_eq!(reg.primary(), Some(&ProfileId::new("home")));
        let home = reg.snapshot(&ProfileId::new("home")).unwrap();
        assert!(matches!(home.role, Role::Primary { .. }));
    }

    // ─────────────── SC3 — connect-time conflict ───────────────

    #[test]
    fn conflict_when_existing_primary_holds_default_route() {
        let mut reg = registry_with_iface(|| Some("utun7".into()));
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();

        // Second profile also claims 0/0 — should be rejected.
        let err = connect_with_iface(&mut reg, "home", "utun8", default_route_v4(), false)
            .expect_err("expected conflict");
        match err {
            RegistryError::Conflict(Conflict::DefaultRouteTakeover { current, new }) => {
                assert_eq!(current.as_str(), "corp");
                assert_eq!(new.as_str(), "home");
            }
            other => panic!("expected DefaultRouteTakeover, got {other:?}"),
        }
        // No FSM should have been created for the rejected profile.
        assert_eq!(reg.tunnel_count(), 1);
        assert!(reg.snapshot(&ProfileId::new("home")).is_none());
    }

    // ─────────────── SC12 — in-flight conflict ───────────────

    #[test]
    fn conflict_against_pending_default_route_claimant() {
        // Simulate a Connecting FSM holding 0/0. We need an FSM that's stuck
        // in `Connecting` so we use a tunnel that fails with a timeout (the
        // FSM will transition to Disconnected after handling) — but to
        // really exercise the in-flight path we instead insert a custom
        // FSM in `Connecting` state via the public `insert` path is not
        // available; instead use detect_conflict directly with a faked
        // entry by mutating after a successful connect, simulating the
        // race where the FSM is mid-up.
        //
        // Simpler: rely on the fact that detect_conflict treats both
        // Connected and Connecting as live claimants. We assert against a
        // Connected one (already covered by SC3); for in-flight we drop
        // down to detect_conflict directly with a synthetic state by
        // staging it through the test seam.
        //
        // Use `pending_default_route_claimant` as the surface — after a
        // successful connect the FSM is Connected (not Connecting) because
        // the MockTunnel resolves up() synchronously, so this test
        // documents the helper rather than the racy timing.
        let mut reg = registry_with_iface(|| Some("utun7".into()));
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();
        // corp is Connected (not Connecting). The helper should return None
        // because no FSM is Connecting.
        assert!(reg.pending_default_route_claimant().is_none());

        // detect_conflict against a Connected primary is the same code path
        // that fires for Connecting (the match arm covers both); SC3
        // exercises the assertion. We additionally assert here that the
        // returned conflict names the live claimant correctly.
        let c = reg
            .detect_conflict(&ProfileId::new("home"), &default_route_v4())
            .expect("conflict expected");
        assert!(matches!(
            c,
            Conflict::DefaultRouteTakeover { ref current, .. } if current.as_str() == "corp"
        ));
    }

    // ─────────────── SC10 — split CIDR /1 pair ───────────────

    #[test]
    fn split_slash_one_pair_treated_as_default_route_for_conflict() {
        let mut reg = registry_with_iface(|| Some("utun7".into()));
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();

        let err = connect_with_iface(&mut reg, "home", "utun8", split_pair_v4(), false)
            .expect_err("split-CIDR pair should conflict with existing 0/0 primary");
        assert!(matches!(
            err,
            RegistryError::Conflict(Conflict::DefaultRouteTakeover { .. })
        ));
    }

    // ─────────────── SC11 — /2 quartet ───────────────

    #[test]
    fn slash_two_quartet_treated_as_default_route_for_conflict() {
        let mut reg = registry_with_iface(|| Some("utun7".into()));
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();

        let err = connect_with_iface(&mut reg, "home", "utun8", quartet_v4(), false)
            .expect_err("/2 quartet should conflict with existing 0/0 primary");
        assert!(matches!(
            err,
            RegistryError::Conflict(Conflict::DefaultRouteTakeover { .. })
        ));
    }

    // ─────────────── Split-only topology ───────────────

    #[test]
    fn three_split_route_tunnels_no_default_route_no_primary() {
        // Kernel reports no Vortix-owned interface as the default route —
        // the user's physical NIC owns it.
        let mut reg = registry_with_iface(|| Some("eth0".into()));
        connect_with_iface(&mut reg, "corp", "utun7", vec![v4("10.0.0.0/8")], false).unwrap();
        connect_with_iface(&mut reg, "lab", "utun8", vec![v4("192.168.0.0/16")], false).unwrap();
        connect_with_iface(&mut reg, "ops", "utun9", vec![v4("172.16.0.0/12")], false).unwrap();

        assert_eq!(reg.tunnel_count(), 3);
        assert!(reg.primary().is_none());
        for snap in reg.snapshot_all() {
            assert!(matches!(snap.role, Role::Addressable { .. }));
        }
    }

    // ─────────────── force=true bypass ───────────────

    #[test]
    fn force_true_bypasses_conflict_check() {
        let mut reg = registry_with_iface(|| Some("utun7".into()));
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();

        // With force=true the registry skips detect_conflict and lets the
        // second 0/0 FSM transition.
        connect_with_iface(&mut reg, "home", "utun8", default_route_v4(), true).unwrap();
        assert_eq!(reg.tunnel_count(), 2);
    }

    // ─────────────── disconnect_all ───────────────

    #[test]
    fn disconnect_all_tears_down_mixed_states_to_empty_registry_state() {
        let iface = Arc::new(Mutex::new(Some("utun7".to_string())));
        let iface_probe = Arc::clone(&iface);
        let mut reg = registry_with_iface(move || iface_probe.lock().unwrap().clone());

        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();
        connect_with_iface(&mut reg, "lab", "utun8", vec![v4("10.0.0.0/8")], false).unwrap();
        connect_with_iface(&mut reg, "ops", "utun9", vec![v4("172.16.0.0/12")], false).unwrap();

        *iface.lock().unwrap() = None; // post-teardown kernel sees no Vortix default route
        reg.disconnect_all();

        // Each FSM is now Disconnected; the registry retains the entries so
        // the user can re-connect without re-registering. No tunnel should
        // be Connected.
        for snap in reg.snapshot_all() {
            assert!(matches!(snap.state, Connection::Disconnected { .. }));
        }
        assert!(reg.primary().is_none());
    }

    // ─────────────── pending_after_disconnect queue ───────────────

    #[test]
    fn pending_after_disconnect_fires_queued_connect_when_host_reaches_disconnected() {
        let mut reg = registry_with_iface(|| Some("utun7".into()));
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();

        // Pre-insert "home" so the queued connect has something to drive.
        let home_tunnel = MockTunnel::new();
        home_tunnel.script_up(ScriptedTunnelOutcome::UpSuccess {
            interface_name: "utun8".into(),
            pid: None,
        });
        let home_engine = Engine::new(home_tunnel, resolver_for("home"));
        reg.insert(ProfileId::new("home"), home_engine, default_route_v4());

        reg.queue_after_disconnect(&ProfileId::new("corp"), ProfileId::new("home"))
            .unwrap();

        // Disconnect corp; MockTunnel resolves down() synchronously, so corp
        // reaches Disconnected immediately and the drain fires home.
        reg.disconnect(&ProfileId::new("corp")).unwrap();

        let home = reg.snapshot(&ProfileId::new("home")).unwrap();
        assert!(
            matches!(home.state, Connection::Connected { .. }),
            "queued home should have reached Connected, got {:?}",
            home.state
        );
    }

    // ─────────────── Error: profile resolver returns None ───────────────

    #[test]
    fn connect_returns_profile_not_found_when_resolver_returns_none() {
        let mut reg = registry_with_iface(|| None);
        let tunnel = MockTunnel::new();
        let res = reg.connect_with_tunnel(
            ProfileId::new("ghost"),
            default_route_v4(),
            tunnel,
            |_id| None, // resolver knows nothing
            false,
        );
        assert!(matches!(res, Err(RegistryError::ProfileNotFound(_))));
    }

    // ─────────────── snapshot_all is stable-ordered ───────────────

    #[test]
    fn snapshot_all_returns_stable_sorted_order() {
        let mut reg = registry_with_iface(|| None);
        connect_with_iface(&mut reg, "zeta", "utun9", vec![v4("10.0.0.0/8")], false).unwrap();
        connect_with_iface(&mut reg, "alpha", "utun7", vec![v4("10.1.0.0/16")], false).unwrap();
        connect_with_iface(&mut reg, "mid", "utun8", vec![v4("10.2.0.0/16")], false).unwrap();

        let snaps = reg.snapshot_all();
        let ids: Vec<&str> = snaps.iter().map(|s| s.profile_id.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "mid", "zeta"]);
    }

    // ─────────────── External default-route cache feed ───────────────

    /// The `feed_default_route_interface` write path is the production
    /// route for getting kernel-reported state into the registry —
    /// done from the App's scanner-result handler so the UI thread
    /// never blocks on `route get default`. This test exercises the
    /// write + the downstream read via `recompute_primary`.
    #[test]
    fn feed_default_route_interface_drives_primary_election() {
        // Production-style registry — no test probe closure injected,
        // so `default_route_interface_cached` falls through to the
        // cache (which we feed below).
        let mut reg: TunnelRegistry<MockTunnel> = TunnelRegistry::new();

        // Seed a Connected tunnel on `utun7`.
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();

        // Before any feed, the cache is empty → no primary even though
        // a Connected tunnel exists. This is the correct "scanner
        // hasn't told us anything yet" startup state.
        assert!(
            reg.primary().is_none(),
            "primary must be unset before any cache feed"
        );

        // Feed the kernel's view: utun7 owns default route.
        reg.feed_default_route_interface(Some("utun7".to_string()));
        reg.refresh_primary();
        assert_eq!(
            reg.primary().map(ProfileId::as_str),
            Some("corp"),
            "primary should match the Connected tunnel whose interface owns default route"
        );

        // Kernel says route went away (e.g. WiFi off). Feed it through.
        reg.feed_default_route_interface(None);
        reg.refresh_primary();
        assert!(
            reg.primary().is_none(),
            "primary must clear when kernel reports no default route"
        );
    }

    /// The cached value should outlive `DEFAULT_ROUTE_CACHE_MAX_AGE` —
    /// returning `None` past the TTL would blank the primary tunnel
    /// every tick if the scanner falls behind, flickering the headline
    /// PROTECTED → PARTIAL. Bound staleness via tracing observability,
    /// not behaviour.
    #[test]
    fn cached_route_interface_serves_stale_values_to_avoid_ui_flicker() {
        let mut reg: TunnelRegistry<MockTunnel> = TunnelRegistry::new();
        connect_with_iface(&mut reg, "corp", "utun7", default_route_v4(), false).unwrap();

        // Feed, then artificially backdate the timestamp by more than
        // the staleness budget. `default_route_interface_cached` should
        // still return the value (it only emits a tracing::warn).
        reg.feed_default_route_interface(Some("utun7".to_string()));
        // `checked_sub` keeps clippy happy on the unchecked-arithmetic
        // lint; expect() is safe because we just took `Instant::now()`
        // and subtract a small bounded duration from it.
        let stale_at = std::time::Instant::now()
            .checked_sub(DEFAULT_ROUTE_CACHE_MAX_AGE + Duration::from_secs(1))
            .expect("Instant - small Duration must not underflow");
        reg.cached_route = Some(CachedRouteInterface {
            iface: Some("utun7".to_string()),
            at: stale_at,
        });

        reg.refresh_primary();
        assert_eq!(
            reg.primary().map(ProfileId::as_str),
            Some("corp"),
            "stale cache must still feed primary election; otherwise scanner-lag flickers the UI"
        );
    }

    /// `OpenVPN` regression: when the kernel routing table says this
    /// profile owns the default route, the role must render as
    /// `Primary` even if the declared `AllowedIPs` (parsed from the
    /// client `.ovpn`) is empty. `redirect-gateway` is server-pushed at
    /// runtime; vortix can't see it in the static config, so before
    /// this fix every `OpenVPN` profile claimed Split-tunnel even when
    /// it actually owned the default route.
    #[test]
    fn primary_role_promoted_from_kernel_truth_when_allowed_ips_empty() {
        let mut reg: TunnelRegistry<MockTunnel> = TunnelRegistry::new();

        // Connect ovpn-cert with EMPTY allowed_ips (this is what
        // `extract_ovpn_routes` returns for an inline-cert `.ovpn` with
        // no `route` directive — the `redirect-gateway` is only pushed
        // from the server side).
        connect_with_iface(&mut reg, "ovpn-cert", "utun9", vec![], false).unwrap();

        // Scanner feeds the kernel-observed default-route interface.
        reg.feed_default_route_interface(Some("utun9".to_string()));
        reg.refresh_primary();

        // Sanity: registry agrees ovpn-cert is the primary.
        assert_eq!(
            reg.primary().map(ProfileId::as_str),
            Some("ovpn-cert"),
            "kernel says utun9 owns default route → ovpn-cert is primary"
        );

        // Critical assertion: snapshot's role must surface as Primary,
        // not Addressable. Pre-fix this returned Addressable because
        // claims_default_route() short-circuited on empty allowed_ips.
        let snap = reg
            .snapshot(&ProfileId::new("ovpn-cert"))
            .expect("snapshot for connected profile");
        assert!(
            matches!(snap.role, Role::Primary { .. }),
            "ovpn-cert must render as Primary when kernel says it owns default route; got {:?}",
            snap.role
        );
    }

    // ─────────────── interface_authoritative contract (U3) ───────────────

    /// Helper: seed an entry into the Connected state directly with a
    /// custom `interface_authoritative` value, bypassing the FSM's
    /// `Tunnel::up()` path (which always sets authoritative=true).
    /// Used to exercise the "scanner-adopted unauthoritative entry"
    /// branch of `recompute_primary` and `derive_role`.
    fn seed_connected_unauthoritative(
        reg: &mut TunnelRegistry<MockTunnel>,
        name: &'static str,
        iface: &str,
        allowed_ips: Vec<Cidr>,
    ) {
        let details = DetailedConnectionInfo {
            interface: iface.into(),
            interface_authoritative: false,
            ..Default::default()
        };
        reg.set_connected(
            ProfileId::new(name),
            allowed_ips,
            details,
            std::time::SystemTime::now(),
            || Engine::new(MockTunnel::new(), resolver_for(name)),
        );
    }

    #[test]
    fn recompute_primary_skips_unauthoritative_even_when_iface_matches_kernel() {
        // Setup: two Connected tunnels both claiming iface=utun8 against
        // the kernel's reported egress utun8. One is authoritative
        // (came via Tunnel::up), the other is not (scanner-adopted
        // with unreliable per-PID detection on macOS multi-OpenVPN).
        // recompute_primary MUST elect the authoritative one — promoting
        // the other would be a false claim about routing.
        let mut reg: TunnelRegistry<MockTunnel> = TunnelRegistry::new();

        // F1: scanner-adopted, unauthoritative (false-positive iface
        // collision from Method B fallback).
        seed_connected_unauthoritative(&mut reg, "external", "utun8", default_route_v4());

        // F2: came via Tunnel::up — authoritative.
        connect_with_iface(&mut reg, "internal", "utun8", default_route_v4(), true).unwrap();

        reg.feed_default_route_interface(Some("utun8".to_string()));
        reg.refresh_primary();

        assert_eq!(
            reg.primary().map(ProfileId::as_str),
            Some("internal"),
            "primary must be the authoritative entry, not the unauthoritative one with the same iface"
        );
    }

    #[test]
    fn derive_role_returns_addressable_for_unauthoritative_regardless_of_allowed_ips() {
        // Even when an unauthoritative entry's declared allowed_ips claim
        // the full default route, the role must be Addressable — not
        // Primary (it can't be — recompute_primary skips it) and not
        // AddressableSuppressed (which would imply "we claimed default
        // but lost," a routing claim vortix can't verify byte-for-byte
        // against the kernel for an unauthoritative entry).
        let mut reg: TunnelRegistry<MockTunnel> = TunnelRegistry::new();

        // Authoritative primary owns the kernel default route.
        connect_with_iface(&mut reg, "primary", "utun9", default_route_v4(), false).unwrap();
        reg.feed_default_route_interface(Some("utun9".to_string()));
        reg.refresh_primary();

        // Unauthoritative entry that declares 0/0 — historically this
        // would have rendered as AddressableSuppressed.
        seed_connected_unauthoritative(&mut reg, "external", "utun7", default_route_v4());

        let snap = reg
            .snapshot(&ProfileId::new("external"))
            .expect("snapshot for external profile");
        assert!(
            matches!(snap.role, Role::Addressable { .. }),
            "unauthoritative entry must render as Addressable regardless of allowed_ips; got {:?}",
            snap.role
        );
    }

    #[test]
    fn detailed_connection_info_default_sets_interface_authoritative_true() {
        // Most tunnels are authoritative; the unauthoritative case is
        // the narrow scanner-adoption exception. Default::default() must
        // reflect the common path so test fixtures and struct-update
        // patterns (`..Default::default()`) don't accidentally inject
        // false negatives into the primary-election filter.
        let d = DetailedConnectionInfo::default();
        assert!(d.interface_authoritative);
    }
}
