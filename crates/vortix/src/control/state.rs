//! The tunnel list: the one piece of state the engine owns.
//!
//! Every transition is a method here and none of them touch the host. The
//! engine performs the side effects a transition asks for and then asks
//! [`State::plan_input`] what the network should look like.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Instant, SystemTime};

use crate::cidr::Cidr;
use crate::control::dns::DnsRequest;
use crate::control::killswitch::KillSwitchMode;
use crate::profile::{ProfileId, ProtocolKind};

use super::plan::{LiveTunnel, PlanInput};

/// What a profile asks of the network, read from its config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub profile_id: ProfileId,
    pub name: String,
    pub protocol: ProtocolKind,
    pub routes: BTreeSet<Cidr>,
    pub server_ips: BTreeSet<IpAddr>,
    pub dns: DnsRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Starting,
    AwaitingCredentials,
    Up,
    /// Between reconnect attempts after an unexpected drop. `None` means
    /// Vortix gave up and waits for the user.
    Waiting {
        retry_at: Option<Instant>,
    },
    Stopping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub spec: Spec,
    pub phase: Phase,
    pub interface: Option<String>,
    /// Larger is newer; the newest full tunnel owns the default route.
    pub rank: u64,
    pub since: SystemTime,
    /// Tunnels to stop once this one is up (a switch).
    pub replaces: BTreeSet<ProfileId>,
    /// Reconnect attempt after an unexpected drop, while recovering.
    pub recovering: Option<u32>,
    /// Start again once stopped (a reconnect).
    pub restart: bool,
    /// A dropped tunnel's teardown is still running; no retry until it ends.
    pub draining: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The profile already has a tunnel.
    Active,
    /// The profile's tunnel is still stopping.
    Busy,
}

#[derive(Debug, Clone, Default)]
pub struct State {
    tunnels: BTreeMap<ProfileId, Tunnel>,
    pub kill_switch: KillSwitchMode,
}

impl State {
    #[must_use]
    pub fn new(kill_switch: KillSwitchMode) -> Self {
        Self {
            tunnels: BTreeMap::new(),
            kill_switch,
        }
    }

    pub fn tunnels(&self) -> impl Iterator<Item = &Tunnel> {
        self.tunnels.values()
    }

    #[must_use]
    pub fn get(&self, profile_id: &ProfileId) -> Option<&Tunnel> {
        self.tunnels.get(profile_id)
    }

    /// Tunnels that cannot coexist with `spec`.
    #[must_use]
    pub fn conflicts(&self, spec: &Spec) -> Vec<Conflict> {
        let requested = spec.routes.iter().copied().collect::<Vec<_>>();
        self.tunnels
            .values()
            .filter(|tunnel| tunnel.spec.profile_id != spec.profile_id)
            .filter(|tunnel| tunnel.phase != Phase::Stopping)
            .filter_map(|tunnel| {
                let existing = tunnel.spec.routes.iter().copied().collect::<Vec<_>>();
                classify_route_conflict(
                    &requested,
                    &existing,
                    &tunnel.spec.profile_id,
                    &spec.profile_id,
                )
            })
            .collect()
    }

    /// Start tracking a new tunnel.
    pub fn begin(
        &mut self,
        spec: Spec,
        rank: u64,
        replaces: BTreeSet<ProfileId>,
        needs_credentials: bool,
    ) -> Result<(), Refusal> {
        if let Some(existing) = self.tunnels.get(&spec.profile_id) {
            return Err(if existing.phase == Phase::Stopping {
                Refusal::Busy
            } else {
                Refusal::Active
            });
        }
        self.tunnels.insert(
            spec.profile_id.clone(),
            Tunnel {
                phase: if needs_credentials {
                    Phase::AwaitingCredentials
                } else {
                    Phase::Starting
                },
                spec,
                interface: None,
                rank,
                since: SystemTime::now(),
                replaces,
                recovering: None,
                restart: false,
                draining: false,
            },
        );
        Ok(())
    }

    /// Adopt a tunnel that was already running when Vortix started.
    pub fn adopt(&mut self, spec: Spec, interface: String, rank: u64, since: SystemTime) {
        self.tunnels.insert(
            spec.profile_id.clone(),
            Tunnel {
                spec,
                phase: Phase::Up,
                interface: Some(interface),
                rank,
                since,
                replaces: BTreeSet::new(),
                recovering: None,
                restart: false,
                draining: false,
            },
        );
    }

    pub fn credentials_given(&mut self, profile_id: &ProfileId) -> bool {
        self.transition(profile_id, Phase::AwaitingCredentials, Phase::Starting)
    }

    /// A start attempt succeeded. Returns the tunnels this one replaces.
    pub fn came_up(
        &mut self,
        profile_id: &ProfileId,
        interface: String,
        pushed_routes: impl IntoIterator<Item = Cidr>,
        pushed_servers: impl IntoIterator<Item = IpAddr>,
        dns: Option<DnsRequest>,
    ) -> BTreeSet<ProfileId> {
        let Some(tunnel) = self
            .tunnels
            .get_mut(profile_id)
            .filter(|tunnel| tunnel.phase == Phase::Starting)
        else {
            return BTreeSet::new();
        };
        tunnel.phase = Phase::Up;
        tunnel.interface = Some(interface);
        tunnel.spec.routes.extend(pushed_routes);
        tunnel.spec.server_ips.extend(pushed_servers);
        if let Some(dns) = dns {
            tunnel.spec.dns = dns;
        }
        tunnel.since = SystemTime::now();
        tunnel.recovering = None;
        let replaces = std::mem::take(&mut tunnel.replaces);
        replaces
            .into_iter()
            .filter(|peer| self.stop(peer))
            .collect()
    }

    /// A start attempt failed. A fresh connect is forgotten; a recovery waits
    /// for `retry_at`. Returns whether the tunnel is still tracked.
    pub fn start_failed(&mut self, profile_id: &ProfileId, retry_at: Option<Instant>) -> bool {
        let Some(tunnel) = self.tunnels.get_mut(profile_id) else {
            return false;
        };
        if !matches!(tunnel.phase, Phase::Starting | Phase::AwaitingCredentials) {
            return true;
        }
        if tunnel.recovering.is_some() {
            tunnel.phase = Phase::Waiting { retry_at };
            true
        } else {
            self.tunnels.remove(profile_id);
            false
        }
    }

    /// The tunnel vanished without being asked to. `draining` when its
    /// teardown is still running.
    pub fn lost(&mut self, profile_id: &ProfileId, retry_at: Option<Instant>, draining: bool) {
        if let Some(tunnel) = self
            .tunnels
            .get_mut(profile_id)
            .filter(|tunnel| tunnel.phase == Phase::Up)
        {
            tunnel.phase = Phase::Waiting { retry_at };
            tunnel.interface = None;
            tunnel.recovering = Some(0);
            tunnel.draining = draining;
        }
    }

    /// A dropped tunnel's teardown finished.
    pub fn drained(&mut self, profile_id: &ProfileId) {
        if let Some(tunnel) = self.tunnels.get_mut(profile_id) {
            tunnel.draining = false;
        }
    }

    /// Begin the next reconnect attempt. Returns the attempt number.
    pub fn retry(&mut self, profile_id: &ProfileId) -> Option<u32> {
        let tunnel = self
            .tunnels
            .get_mut(profile_id)
            .filter(|tunnel| matches!(tunnel.phase, Phase::Waiting { .. }) && !tunnel.draining)?;
        let attempt = tunnel.recovering.unwrap_or(0) + 1;
        tunnel.recovering = Some(attempt);
        tunnel.phase = Phase::Starting;
        Some(attempt)
    }

    /// Ask a tunnel to stop. Returns whether it was running. A stop also
    /// cancels any pending restart: the latest request wins.
    pub fn stop(&mut self, profile_id: &ProfileId) -> bool {
        let Some(tunnel) = self.tunnels.get_mut(profile_id) else {
            return false;
        };
        tunnel.restart = false;
        if tunnel.phase == Phase::Stopping {
            return false;
        }
        tunnel.phase = Phase::Stopping;
        true
    }

    /// Stop and start again. Returns false, and schedules nothing, when the
    /// tunnel is absent or already stopping.
    pub fn restart(&mut self, profile_id: &ProfileId) -> bool {
        let stopped = self.stop(profile_id);
        if stopped {
            if let Some(tunnel) = self.tunnels.get_mut(profile_id) {
                tunnel.restart = true;
            }
        }
        stopped
    }

    /// The tunnel is gone. Returns it when it asked to start again.
    pub fn stopped(&mut self, profile_id: &ProfileId) -> Option<Tunnel> {
        self.tunnels
            .remove(profile_id)
            .filter(|tunnel| tunnel.restart)
    }

    /// Keep a restarted tunnel counted as dropped, so block-on-drop keeps
    /// blocking until the restart actually comes up.
    pub fn resume_recovery(&mut self, profile_id: &ProfileId) {
        if let Some(tunnel) = self.tunnels.get_mut(profile_id) {
            tunnel.recovering = Some(0);
        }
    }

    /// A stop attempt failed; the tunnel is still carrying traffic.
    pub fn stop_failed(&mut self, profile_id: &ProfileId) {
        if let Some(tunnel) = self.tunnels.get_mut(profile_id) {
            tunnel.phase = if tunnel.interface.is_some() {
                Phase::Up
            } else {
                Phase::Waiting { retry_at: None }
            };
            tunnel.restart = false;
        }
    }

    #[must_use]
    pub fn plan_input(&self) -> PlanInput {
        let live = self
            .tunnels
            .values()
            .filter(|tunnel| tunnel.phase == Phase::Up)
            .filter_map(|tunnel| {
                Some(LiveTunnel {
                    profile_id: tunnel.spec.profile_id.clone(),
                    interface: tunnel.interface.clone()?,
                    routes: tunnel.spec.routes.clone(),
                    server_ips: tunnel.spec.server_ips.clone(),
                    dns: tunnel.spec.dns.clone(),
                    rank: tunnel.rank,
                })
            })
            .collect();
        let pending_endpoints = self
            .tunnels
            .values()
            .filter(|tunnel| {
                matches!(
                    tunnel.phase,
                    Phase::Starting | Phase::AwaitingCredentials | Phase::Waiting { .. }
                )
            })
            .flat_map(|tunnel| tunnel.spec.server_ips.iter().copied())
            .collect();
        let pending_full_endpoints = self
            .tunnels
            .values()
            .filter(|tunnel| {
                matches!(
                    tunnel.phase,
                    Phase::Starting | Phase::AwaitingCredentials | Phase::Waiting { .. }
                ) && crate::cidr::is_full(&tunnel.spec.routes)
            })
            .flat_map(|tunnel| tunnel.spec.server_ips.iter().copied())
            .collect();
        let dropped = self
            .tunnels
            .values()
            .any(|tunnel| tunnel.recovering.is_some() && tunnel.phase != Phase::Stopping);
        PlanInput {
            live,
            pending_endpoints,
            pending_full_endpoints,
            dropped,
            kill_switch: self.kill_switch,
        }
    }

    fn transition(&mut self, profile_id: &ProfileId, from: Phase, to: Phase) -> bool {
        match self.tunnels.get_mut(profile_id) {
            Some(tunnel) if tunnel.phase == from => {
                tunnel.phase = to;
                true
            }
            _ => false,
        }
    }
}

/// What kind of conflict `detect_conflict` found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    if crate::cidr::is_full(requested) && crate::cidr::is_full(existing) {
        return Some(Conflict::DefaultRouteTakeover {
            current: existing_profile.clone(),
            new: requested_profile.clone(),
        });
    }
    let overlapping_cidrs =
        crate::cidr::overlapping_cidrs(&specific(requested), &specific(existing));
    (!overlapping_cidrs.is_empty()).then(|| Conflict::RouteOverlap {
        with: existing_profile.clone(),
        overlapping_cidrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::plan::{plan, tests::assert_invariants};

    const PROFILES: [(&str, &str); 3] = [
        ("01", "0.0.0.0/0"),
        ("02", "10.250.0.0/24"),
        ("03", "0.0.0.0/0"),
    ];

    fn spec(id: &str, route: &str) -> Spec {
        Spec {
            profile_id: ProfileId::new(id),
            name: id.into(),
            protocol: ProtocolKind::OpenVpn,
            routes: BTreeSet::from([route.parse().unwrap()]),
            server_ips: BTreeSet::from([IpAddr::from([203, 0, 113, id.as_bytes()[1]])]),
            dns: DnsRequest {
                servers: vec![IpAddr::from([10, 8, 0, 1])],
                search_domains: Vec::new(),
            },
        }
    }

    fn id(value: &str) -> ProfileId {
        ProfileId::new(value)
    }

    #[test]
    fn a_switch_stops_only_what_it_replaces_and_only_once_up() {
        let mut state = State::default();
        state
            .begin(spec("01", "0.0.0.0/0"), 1, BTreeSet::new(), false)
            .unwrap();
        state.came_up(&id("01"), "utun4".into(), [], [], None);
        state
            .begin(spec("02", "10.250.0.0/24"), 2, BTreeSet::new(), false)
            .unwrap();
        state.came_up(&id("02"), "utun5".into(), [], [], None);

        let target = spec("03", "0.0.0.0/0");
        let replaces = state
            .conflicts(&target)
            .into_iter()
            .map(|conflict| match conflict {
                Conflict::DefaultRouteTakeover { current, .. } => current,
                Conflict::RouteOverlap { with, .. } => with,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(replaces, BTreeSet::from([id("01")]));
        state.begin(target, 3, replaces, false).unwrap();
        assert_eq!(
            state.get(&id("01")).unwrap().phase,
            Phase::Up,
            "old tunnel keeps traffic while the new one starts"
        );

        let stop = state.came_up(&id("03"), "utun6".into(), [], [], None);
        assert_eq!(stop, BTreeSet::from([id("01")]));
        assert_eq!(state.get(&id("02")).unwrap().phase, Phase::Up);
        assert_eq!(plan(&state.plan_input()).primary, Some(id("03")));
    }

    #[test]
    fn a_failed_switch_leaves_the_old_tunnel_alone() {
        let mut state = State::default();
        state
            .begin(spec("01", "0.0.0.0/0"), 1, BTreeSet::new(), false)
            .unwrap();
        state.came_up(&id("01"), "utun4".into(), [], [], None);
        state
            .begin(
                spec("03", "0.0.0.0/0"),
                2,
                BTreeSet::from([id("01")]),
                false,
            )
            .unwrap();
        assert!(!state.start_failed(&id("03"), None));
        assert_eq!(state.get(&id("01")).unwrap().phase, Phase::Up);
    }

    #[test]
    fn block_on_drop_holds_through_recovery_and_releases_when_back() {
        let mut state = State {
            kill_switch: KillSwitchMode::Auto,
            ..State::default()
        };
        state
            .begin(spec("01", "0.0.0.0/0"), 1, BTreeSet::new(), false)
            .unwrap();
        state.came_up(&id("01"), "utun4".into(), [], [], None);
        assert!(!state.plan_input().dropped);
        state.lost(&id("01"), Some(Instant::now()), false);
        assert!(state.plan_input().dropped);
        assert_eq!(state.retry(&id("01")), Some(1));
        assert!(
            state.plan_input().dropped,
            "still blocking while the retry runs"
        );
        state.came_up(&id("01"), "utun7".into(), [], [], None);
        assert!(!state.plan_input().dropped);
    }

    /// The dropped tunnel's teardown removes that profile's interface and
    /// ownership files; a retry that starts before it finishes gets its new
    /// tunnel torn down by the old stop.
    #[test]
    fn a_reconnect_waits_for_the_dropped_tunnels_teardown() {
        let mut state = State::default();
        state
            .begin(spec("01", "0.0.0.0/0"), 1, BTreeSet::new(), false)
            .unwrap();
        state.came_up(&id("01"), "wg0".into(), [], [], None);
        state.lost(&id("01"), Some(Instant::now()), true);
        assert!(state.retry(&id("01")).is_none(), "teardown still running");
        state.drained(&id("01"));
        assert_eq!(state.retry(&id("01")), Some(1));
    }

    #[test]
    fn a_disconnect_cancels_a_pending_reconnect() {
        let mut state = State::default();
        state
            .begin(spec("01", "0.0.0.0/0"), 1, BTreeSet::new(), false)
            .unwrap();
        state.came_up(&id("01"), "utun4".into(), [], [], None);
        assert!(state.restart(&id("01")));
        assert!(!state.stop(&id("01")), "already stopping");
        assert!(
            state.stopped(&id("01")).is_none(),
            "the disconnect must win over the earlier reconnect"
        );
    }

    #[test]
    fn a_reconnect_while_stopping_schedules_nothing() {
        let mut state = State::default();
        state
            .begin(spec("01", "0.0.0.0/0"), 1, BTreeSet::new(), false)
            .unwrap();
        state.came_up(&id("01"), "utun4".into(), [], [], None);
        assert!(state.stop(&id("01")));
        assert!(!state.restart(&id("01")));
        assert!(state.stopped(&id("01")).is_none());
    }

    #[test]
    fn a_restarted_dropped_tunnel_keeps_block_on_drop_blocking() {
        let mut state = State {
            kill_switch: KillSwitchMode::Auto,
            ..State::default()
        };
        state
            .begin(spec("01", "0.0.0.0/0"), 1, BTreeSet::new(), false)
            .unwrap();
        state.came_up(&id("01"), "utun4".into(), [], [], None);
        state.lost(&id("01"), None, false);
        assert!(state.restart(&id("01")));
        let old = state.stopped(&id("01")).expect("restart requested");
        assert!(old.recovering.is_some());
        state
            .begin(spec("01", "0.0.0.0/0"), 2, BTreeSet::new(), false)
            .unwrap();
        state.resume_recovery(&id("01"));
        assert!(
            state.plan_input().dropped,
            "still blocking while it restarts"
        );
        assert!(
            state.start_failed(&id("01"), None),
            "a failed restart keeps waiting instead of forgetting the drop"
        );
        assert!(state.plan_input().dropped);
    }

    /// Every sequence of up to five events over three profiles keeps every
    /// planner invariant, whatever order produced the tunnel set.
    #[test]
    fn every_event_sequence_keeps_the_plan_invariants() {
        const EVENTS: usize = 6;
        let steps = PROFILES.len() * EVENTS;
        for mode in [
            KillSwitchMode::Off,
            KillSwitchMode::Auto,
            KillSwitchMode::AlwaysOn,
        ] {
            for sequence in 0..steps.pow(4) {
                let mut state = State {
                    kill_switch: mode,
                    ..State::default()
                };
                let mut rank = 0;
                let mut rest = sequence;
                for _ in 0..4 {
                    let step = rest % steps;
                    rest /= steps;
                    let (name, route) = PROFILES[step / EVENTS];
                    let profile = id(name);
                    match step % EVENTS {
                        0 => {
                            rank += 1;
                            let target = spec(name, route);
                            let replaces = state
                                .conflicts(&target)
                                .into_iter()
                                .map(|conflict| match conflict {
                                    Conflict::DefaultRouteTakeover { current, .. } => current,
                                    Conflict::RouteOverlap { with, .. } => with,
                                })
                                .collect();
                            let _ = state.begin(target, rank, replaces, false);
                        }
                        1 => {
                            let iface = format!("utun{rank}{name}");
                            for peer in state.came_up(&profile, iface, [], [], None) {
                                assert_ne!(peer, profile);
                            }
                        }
                        2 => {
                            state.start_failed(&profile, None);
                        }
                        3 => {
                            state.stop(&profile);
                        }
                        4 => {
                            if state
                                .get(&profile)
                                .is_some_and(|t| t.phase == Phase::Stopping)
                            {
                                state.stopped(&profile);
                            }
                        }
                        _ => state.lost(&profile, None, false),
                    }
                    let input = state.plan_input();
                    assert_invariants(&input, &plan(&input));
                    let full_up = state
                        .tunnels()
                        .filter(|t| t.phase == Phase::Up && crate::cidr::is_full(&t.spec.routes))
                        .count();
                    assert!(full_up <= 1, "two full tunnels are never both up");
                }
            }
        }
    }
}
