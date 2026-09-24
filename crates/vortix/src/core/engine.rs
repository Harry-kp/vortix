//! Tunnel state vocabulary and the dashboard's render cache.

pub mod registry {
    //! Render cache the dashboard reads: the engine's latest tunnel projection,
    //! plus the route-conflict rule every surface shares.

    use std::collections::BTreeMap;
    use std::time::SystemTime;

    use serde::{Deserialize, Serialize};

    use crate::core::cidr::Cidr;
    use crate::core::engine::state::{Connection, ConnectionHealth};
    use crate::core::profile::ProfileId;
    use crate::core::state::killswitch::{KillSwitchMode, KillSwitchState};

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
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        ///; not produced by the v1
        /// `detect_conflict` which only inspects the default route.
        RouteOverlap {
            with: ProfileId,
            overlapping_cidrs: Vec<Cidr>,
        },
    }

    /// Whether two route sets collide, and how.
    ///
    /// Admission, the dashboard overlay and the CLI gate all have to answer this
    /// identically: if they disagree, one refuses a connect another will not offer
    /// to confirm. They each used to carry their own copy of the rule.
    ///
    /// A default route intersects every other route, so it is only ever compared
    /// against another default. That question is asked first; everything after it
    /// is about specific destinations. A split tunnel alongside a full one is
    /// legitimate — the more specific prefix wins, which is the point of running
    /// both.
    #[must_use]
    pub fn classify_route_conflict(
        requested: &[Cidr],
        existing: &[Cidr],
        existing_profile: &ProfileId,
        requested_profile: &ProfileId,
    ) -> Option<Conflict> {
        let specific = |routes: &[Cidr]| {
            routes
                .iter()
                .filter(|route| route.prefix_len != 0)
                .copied()
                .collect::<Vec<_>>()
        };
        let claims_default = |routes: &[Cidr]| routes.iter().any(|route| route.prefix_len == 0);

        if claims_default(requested) && claims_default(existing) {
            return Some(Conflict::DefaultRouteTakeover {
                current: existing_profile.clone(),
                new: requested_profile.clone(),
            });
        }
        let overlapping_cidrs =
            crate::core::cidr::overlapping_cidrs(&specific(requested), &specific(existing));
        (!overlapping_cidrs.is_empty()).then(|| Conflict::RouteOverlap {
            with: existing_profile.clone(),
            overlapping_cidrs,
        })
    }

    /// What the dashboard renders, fed only by engine snapshots.
    #[derive(Debug, Default)]
    pub struct TunnelRegistry {
        tunnels: BTreeMap<ProfileId, TunnelSnapshot>,
        primary: Option<ProfileId>,
        killswitch_mode: KillSwitchMode,
        killswitch_state: KillSwitchState,
        default_route_interface: Option<String>,
    }

    impl TunnelRegistry {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        #[must_use]
        pub fn tunnel_count(&self) -> usize {
            self.tunnels.len()
        }

        #[must_use]
        pub fn primary(&self) -> Option<&ProfileId> {
            self.primary.as_ref()
        }

        #[must_use]
        pub const fn killswitch_mode(&self) -> KillSwitchMode {
            self.killswitch_mode
        }

        #[must_use]
        pub const fn killswitch_state(&self) -> KillSwitchState {
            self.killswitch_state
        }

        pub fn set_killswitch_mode(&mut self, mode: KillSwitchMode) {
            self.killswitch_mode = mode;
        }

        pub fn set_killswitch_state(&mut self, state: KillSwitchState) {
            self.killswitch_state = state;
        }

        #[must_use]
        pub fn snapshot(&self, profile_id: &ProfileId) -> Option<TunnelSnapshot> {
            self.tunnels.get(profile_id).cloned()
        }

        /// Every tunnel, in stable profile order so panels do not flicker.
        #[must_use]
        pub fn snapshot_all(&self) -> Vec<TunnelSnapshot> {
            self.tunnels.values().cloned().collect()
        }

        pub fn replace_control_projection(
            &mut self,
            tunnels: &BTreeMap<ProfileId, TunnelSnapshot>,
            primary: Option<ProfileId>,
        ) {
            self.tunnels.clone_from(tunnels);
            self.primary = primary;
        }

        pub fn feed_default_route_interface(&mut self, interface: Option<String>) {
            self.default_route_interface = interface;
        }

        #[must_use]
        pub fn default_route_interface(&self) -> Option<&str> {
            self.default_route_interface.as_deref()
        }

        /// Put one tunnel in the cache directly; renderer tests only.
        #[cfg(test)]
        pub fn insert_for_test(&mut self, snapshot: TunnelSnapshot) {
            self.tunnels.insert(snapshot.profile_id.clone(), snapshot);
        }
    }
}
pub mod state {
    //! Engine connection state types.
    //!
    //! Five-variant `Connection` machine plus the supporting health/failure
    //! enums. Matches the brainstorm shape: `Failed` collapses into
    //! `Disconnected { last_failure }` rather than being a sixth variant.

    use std::time::{Duration, SystemTime};

    use serde::{Deserialize, Serialize};

    use crate::core::profile::ProfileId;

    /// Why a previous connect or reconnect attempt ended in `Disconnected`.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum FailureReason {
        /// The retry budget expired with no successful connection.
        RetryBudgetExhausted { attempts: u32, elapsed: Duration },
        /// `Tunnel::up` reported `HandshakeFailed`.
        HandshakeFailed(String),
        /// `Tunnel::up` reported `AuthFailed`.
        AuthFailed(String),
        /// Profile parsing surfaced an unrecoverable error.
        ConfigInvalid(String),
        /// `Tunnel::up` exceeded its configured timeout with no progress.
        Timeout(Duration),
        /// The network link went down and never came back during the retry budget.
        NoNetworkLink,
        /// The profile referenced by the in-flight connect was deleted or renamed
        /// out from under the engine. `ProfileRenamed` updates the FSM in place
        /// when possible; this variant covers the unrecoverable cases.
        ProfileGone(ProfileId),
        /// Anything else surfaced as `TunnelError::Other`.
        Other(String),
    }

    /// Cause for `ConnectionHealth::Degraded`.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum DegradedReason {
        /// `wg show` reports `latest_handshake` exceeding the staleness threshold.
        HandshakeStale { seconds_since_last_handshake: u64 },
        /// One `WireGuard` peer with expected traffic has stale evidence; unrelated
        /// peers/routes do not borrow another peer's health.
        WireGuardPeerStale {
            peer_public_key: String,
            allowed_routes: Vec<String>,
            seconds_since_last_handshake: u64,
        },
        /// A peer with expected traffic has never produced cryptographic evidence.
        WireGuardPeerNeverObserved {
            peer_public_key: String,
            allowed_routes: Vec<String>,
        },
        /// Telemetry reports high packet loss to all configured probe targets.
        HighPacketLoss { loss_percent: f32 },
        /// Telemetry reports ICMP latency above the configured threshold.
        HighLatency { latency_ms: u64 },
    }

    /// Health summary for `Connection::Connected`.
    ///
    /// `Unknown` is the initial state immediately after a successful `up` —
    /// telemetry hasn't reported yet. The TUI renders "Measuring…" in that
    /// window (v0.1.7 ROADMAP item).
    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum ConnectionHealth {
        #[default]
        Unknown,
        Healthy,
        Degraded {
            reason: DegradedReason,
        },
    }

    /// Technical details parsed from the VPN interface (relocated from the
    /// binary-side `crates/vortix/src/state/connection.rs`; a later cleanup prunes
    /// the duplicate).
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct DetailedConnectionInfo {
        pub interface: String,
        pub internal_ip: String,
        pub endpoint: String,
        pub mtu: String,
        /// `WireGuard` public key (empty for `OpenVPN`).
        pub public_key: String,
        pub listen_port: String,
        pub transfer_rx: String,
        pub transfer_tx: String,
        pub latest_handshake: String,
        /// Scanner-derived health carried atomically with refreshed metadata.
        /// Internal-only; the enclosing `Connection` owns the public projection.
        #[serde(skip)]
        pub health_hint: ConnectionHealth,
        pub pid: Option<u32>,
        /// Exact attempt generation that produced this connected state.
        #[serde(skip)]
        pub generation: u64,
        /// Protocol-authoritative handshake evidence for this attempt.
        #[serde(skip)]
        pub handshake: Option<crate::core::ports::tunnel::HandshakeEvidence>,
        /// Per-peer probes actually issued and route-verified for this attempt.
        #[serde(skip)]
        pub probe_receipts: Vec<crate::core::ports::tunnel::ProbeReceipt>,
        /// Exact userspace-child ownership capability. Internal-only and never
        /// exposed through snapshots or JSON.
        #[serde(skip)]
        pub process_ownership: Option<crate::core::ports::process::ManagedProcessId>,
        /// Protocol-requested resolver intent retained for the global policy
        /// worker. Internal-only so existing IPC/JSON snapshots remain stable.
        #[serde(skip)]
        pub dns_request: crate::core::ports::dns::DnsRequest,
        /// Protocol-owned teardown config. Never serialized into snapshots.
        #[serde(skip)]
        pub teardown_config: Option<crate::core::ports::tunnel::TunnelTeardownConfig>,
        /// Whether `interface` came from a reliable per-tunnel source.
        ///
        /// `true` when set by the protocol layer's `Tunnel::up()` result
        /// (`OpenVPN` log scrape, wg-quick output resolved through the
        /// platform port). `false` only when the scanner adopted an
        /// externally-started tunnel on a platform where its per-PID
        /// interface detection is unreliable (current state: macOS
        /// multi-`OpenVPN`, where the ifconfig fallback collides across
        /// PIDs). Tunnels with `false` are excluded from primary-election
        /// candidacy in [`crate::core::engine::registry::TunnelRegistry`]'s
        /// `recompute_primary` and render
        /// as `Role::Addressable` regardless of declared `AllowedIPs`,
        /// because vortix cannot truthfully claim a routing status it
        /// can't verify byte-for-byte against the kernel.
        ///
        /// Defaults to `true` — most tunnels are authoritative; the
        /// adoption path is the narrow exception that must opt out.
        #[serde(default = "default_interface_authoritative")]
        pub interface_authoritative: bool,
    }

    fn default_interface_authoritative() -> bool {
        true
    }

    impl Default for DetailedConnectionInfo {
        fn default() -> Self {
            Self {
                interface: String::new(),
                internal_ip: String::new(),
                endpoint: String::new(),
                mtu: String::new(),
                public_key: String::new(),
                listen_port: String::new(),
                transfer_rx: String::new(),
                transfer_tx: String::new(),
                latest_handshake: String::new(),
                health_hint: ConnectionHealth::default(),
                pid: None,
                generation: 0,
                handshake: None,
                probe_receipts: Vec::new(),
                process_ownership: None,
                dns_request: crate::core::ports::dns::DnsRequest::default(),
                teardown_config: None,
                interface_authoritative: true,
            }
        }
    }

    // U7/U8 compatibility name. Interactive challenge vocabulary is canonical in
    // the control model so credential-bearing flows cannot drift independently.
    /// What a mid-connect prompt asks the user for.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum PromptKind {
        TwoFactorCode,
        Passphrase,
        Generic { label: String },
    }

    /// The connection state machine.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum Connection {
        /// No active VPN connection. Optionally remembers why the previous attempt
        /// failed so the TUI can surface a "Last error: …" hint.
        Disconnected { last_failure: Option<FailureReason> },
        /// Initial connect in progress.
        Connecting {
            profile_id: ProfileId,
            started_at: SystemTime,
            /// 1-based attempt counter for the current connect operation.
            attempt: u32,
            retry_budget_remaining: Duration,
        },
        /// Active VPN connection.
        Connected {
            profile_id: ProfileId,
            since: SystemTime,
            health: ConnectionHealth,
            details: Box<DetailedConnectionInfo>,
        },
        /// Lost the tunnel; trying to bring it back without involving the user.
        Reconnecting {
            profile_id: ProfileId,
            started_at: SystemTime,
            attempt: u32,
            retry_budget_remaining: Duration,
            last_error: Option<String>,
        },
        /// User-initiated disconnect in progress.
        Disconnecting {
            profile_id: ProfileId,
            started_at: SystemTime,
        },
        /// Mid-connect prompt waiting for the user to supply input
        /// (2FA challenge, certificate passphrase, etc.). The slot
        /// reserves the slot for issue #191 (Interactive 2FA/MFA);
        /// no consumer is wired in v0.3.0.
        AwaitingUserInput {
            profile_id: ProfileId,
            prompt_id: String,
            prompt_kind: PromptKind,
            since: SystemTime,
        },
    }

    impl Default for Connection {
        fn default() -> Self {
            Self::Disconnected { last_failure: None }
        }
    }

    impl Connection {
        /// The profile currently in scope (`None` only for `Disconnected`).
        #[must_use]
        pub fn profile_id(&self) -> Option<&ProfileId> {
            match self {
                Self::Disconnected { .. } => None,
                Self::Connecting { profile_id, .. }
                | Self::Connected { profile_id, .. }
                | Self::Reconnecting { profile_id, .. }
                | Self::Disconnecting { profile_id, .. }
                | Self::AwaitingUserInput { profile_id, .. } => Some(profile_id),
            }
        }

        /// `true` when the engine is in a steady-state, non-transitional state.
        #[must_use]
        pub fn is_steady(&self) -> bool {
            matches!(self, Self::Disconnected { .. } | Self::Connected { .. })
        }

        /// `true` when an active tunnel exists (Connected).
        #[must_use]
        pub fn is_connected(&self) -> bool {
            matches!(self, Self::Connected { .. })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn default_is_disconnected_with_no_failure() {
            let s = Connection::default();
            assert!(matches!(s, Connection::Disconnected { last_failure: None }));
        }

        #[test]
        fn profile_id_is_none_for_disconnected() {
            let s = Connection::default();
            assert!(s.profile_id().is_none());
        }

        #[test]
        fn profile_id_is_some_for_other_states() {
            let p = ProfileId::new("corp");
            let s = Connection::Connecting {
                profile_id: p.clone(),
                started_at: SystemTime::now(),
                attempt: 1,
                retry_budget_remaining: Duration::from_secs(300),
            };
            assert_eq!(s.profile_id(), Some(&p));
        }

        #[test]
        fn is_steady_distinguishes_states() {
            let p = ProfileId::new("corp");
            assert!(Connection::default().is_steady());
            assert!(!Connection::Connecting {
                profile_id: p.clone(),
                started_at: SystemTime::now(),
                attempt: 1,
                retry_budget_remaining: Duration::from_secs(300),
            }
            .is_steady());
        }
        #[test]
        fn awaiting_user_input_carries_profile_id() {
            let p = ProfileId::new("corp");
            let s = Connection::AwaitingUserInput {
                profile_id: p.clone(),
                prompt_id: "2fa".into(),
                prompt_kind: PromptKind::TwoFactorCode,
                since: SystemTime::now(),
            };
            assert_eq!(s.profile_id(), Some(&p));
        }

        #[test]
        fn awaiting_user_input_is_not_steady() {
            // Like Connecting/Disconnecting, it's a transitional state.
            let s = Connection::AwaitingUserInput {
                profile_id: ProfileId::new("corp"),
                prompt_id: "2fa".into(),
                prompt_kind: PromptKind::TwoFactorCode,
                since: SystemTime::now(),
            };
            assert!(!s.is_steady());
            assert!(!s.is_connected());
        }

        #[test]
        fn prompt_kind_roundtrips_through_json() {
            let kinds = [
                PromptKind::TwoFactorCode,
                PromptKind::Passphrase,
                PromptKind::Generic {
                    label: "Hardware token PIN".into(),
                },
            ];
            for k in kinds {
                let json = serde_json::to_string(&k).unwrap();
                let back: PromptKind = serde_json::from_str(&json).unwrap();
                assert_eq!(k, back);
            }
        }
    }
}

pub use registry::{classify_route_conflict, Conflict, Role, TunnelRegistry, TunnelSnapshot};
pub use state::{
    Connection, ConnectionHealth, DegradedReason, DetailedConnectionInfo, FailureReason,
};
