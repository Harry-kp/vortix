//! The one place that changes the host network: moves routes, DNS and the
//! firewall from the last applied plan to the next one.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cidr::Cidr;
use crate::control::dns::{DnsEffectiveStatus, DnsOwnedResource, DnsPolicyCoordinator};
use crate::control::killswitch::{KillSwitchMode, KillSwitchState};
use crate::platform::DefaultRouteObservation;
use crate::wireguard::ownership::TunnelOwnershipStore;

use super::plan::{Firewall, NetworkPlan};

pub struct Net {
    config_dir: PathBuf,
    applied: NetworkPlan,
    /// Mode last saved with the firewall; `None` until the first apply.
    saved_mode: Option<KillSwitchMode>,
    dns: DnsPolicyCoordinator,
    store: Arc<TunnelOwnershipStore>,
}

/// What an earlier run left on the host, kept root-owned so a tunnel that
/// died while no Vortix ran is still cleaned up on the next start.
#[derive(Debug, Default, Serialize, Deserialize)]
struct HostState {
    routes: Vec<(Cidr, String)>,
    host_routes: BTreeSet<IpAddr>,
    dns: Vec<DnsOwnedResource>,
}

impl Net {
    /// `applied` is what the host carries for adopted tunnels; whatever the
    /// last run recorded beyond it is added so the first apply removes it.
    #[must_use]
    pub fn new(
        config_dir: PathBuf,
        mut applied: NetworkPlan,
        store: Arc<TunnelOwnershipStore>,
    ) -> Self {
        let mut dns = crate::control::dns::load_policy(&config_dir).unwrap_or_default();
        let recorded = store
            .load_host_state()
            .and_then(|bytes| serde_json::from_slice::<HostState>(&bytes).ok())
            .unwrap_or_default();
        for (cidr, interface) in recorded.routes {
            applied.routes.entry(cidr).or_insert(interface);
        }
        applied.host_routes.extend(recorded.host_routes);
        dns.restore_owned(recorded.dns);
        Self {
            dns,
            config_dir,
            applied,
            saved_mode: None,
            store,
        }
    }

    fn record_host_state(&self) {
        let state = HostState {
            routes: self
                .applied
                .routes
                .iter()
                .map(|(cidr, interface)| (*cidr, interface.clone()))
                .collect(),
            host_routes: self.applied.host_routes.clone(),
            dns: self.dns.effective().owned.clone(),
        };
        let saved = serde_json::to_vec(&state)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                self.store
                    .save_host_state(&bytes)
                    .map_err(|error| error.to_string())
            });
        if let Err(error) = saved {
            tracing::warn!(target: "vortix::net", %error, "could not record applied host state");
        }
    }

    /// Move the host to `target`. Idempotent: after a failure the next call
    /// retries whatever is still missing.
    pub fn apply(&mut self, target: &NetworkPlan, mode: KillSwitchMode) -> Result<(), String> {
        let result = self.apply_all(target, mode);
        self.record_host_state();
        result
    }

    fn apply_all(&mut self, target: &NetworkPlan, mode: KillSwitchMode) -> Result<(), String> {
        let tightening = matches!(target.firewall, Firewall::Block(_));
        if tightening {
            self.apply_firewall(target, mode)?;
        }
        self.apply_routes(target)?;
        self.apply_dns(target)?;
        if !tightening {
            self.apply_firewall(target, mode)?;
        }
        let routes = std::mem::take(&mut self.applied.routes);
        self.applied = target.clone();
        self.applied.routes = routes;
        Self::verify_routes(target)
    }

    fn apply_routes(&mut self, target: &NetworkPlan) -> Result<(), String> {
        use crate::platform::Routes as table;
        // A prefix the target still carries is retargeted in place, never
        // deleted first: that gap leaks traffic onto the real address.
        // A teardown removes its interface's routes; they stay recorded until then.
        let (released, dropped): (Vec<_>, Vec<_>) = self
            .applied
            .routes
            .iter()
            .filter(|(cidr, _)| !target.routes.contains_key(cidr))
            .map(|(cidr, interface)| (*cidr, interface.clone()))
            .partition(|(_, interface)| target.releasing.contains(interface));
        for (cidr, interface) in dropped
            .iter()
            .filter(|(_, interface)| crate::platform::interface_exists(interface))
        {
            if let Err(error) = table::unbind_route(&cidr.to_string(), interface) {
                tracing::warn!(target: "vortix::net", %cidr, %interface, %error, "route removal failed");
            }
        }
        for endpoint in self.applied.host_routes.difference(&target.host_routes) {
            if let Err(error) = table::unbind_host_route(*endpoint) {
                tracing::warn!(target: "vortix::net", %endpoint, %error, "server route removal failed");
            }
        }
        // Recorded before binding, so whatever a failed bind leaves behind is
        // still unbound by the next diff.
        self.applied.routes.clone_from(&target.routes);
        self.applied.routes.extend(released);
        self.applied.host_routes.clone_from(&target.host_routes);
        let mut first_error = None;
        for v4 in [true, false] {
            let endpoints: Vec<_> = target
                .host_routes
                .iter()
                .filter(|ip| ip.is_ipv4() == v4)
                .collect();
            if endpoints.is_empty() {
                continue;
            }
            match table::default_gateway(v4) {
                Some(gateway) => {
                    for endpoint in endpoints {
                        if let Err(error) = table::bind_host_route(*endpoint, &gateway) {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                None if v4 => {
                    first_error.get_or_insert(
                        "no physical default gateway to pin the VPN server route to".into(),
                    );
                }
                // No IPv6 uplink: the server cannot be reached over IPv6 anyway.
                None => {
                    tracing::warn!(target: "vortix::net", "no physical IPv6 gateway; IPv6 server routes not pinned");
                }
            }
        }
        for (cidr, interface) in Self::misrouted(target, &target.routes) {
            if let Err(error) = table::bind_route(&cidr.to_string(), &interface) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn apply_dns(&mut self, target: &NetworkPlan) -> Result<(), String> {
        let _lock = crate::control::dns::acquire_policy_lock(&self.config_dir)
            .map_err(|error| format!("DNS policy lock failed: {error}"))?;
        let config_dir = &self.config_dir;
        let effective = self
            .dns
            .reconcile_durable(&target.dns, &crate::platform::Dns, |state| {
                crate::control::dns::save_policy(config_dir, state)
            })
            .map_err(|error| error.to_string())?;
        match effective.status {
            DnsEffectiveStatus::Applied | DnsEffectiveStatus::Released => Ok(()),
            DnsEffectiveStatus::Degraded => Err(format!(
                "DNS could not be applied: {}",
                effective.errors.join("; ")
            )),
        }
    }

    fn apply_firewall(&mut self, target: &NetworkPlan, mode: KillSwitchMode) -> Result<(), String> {
        if self.saved_mode == Some(mode)
            && self.applied.firewall == target.firewall
            && self.applied.kill_switch_state == target.kill_switch_state
        {
            return Ok(());
        }
        let (allow, applied) = match &target.firewall {
            Firewall::Block(allow) => (
                allow.as_slice(),
                crate::control::killswitch::enable_blocking_multi(allow),
            ),
            Firewall::Open => (&[][..], crate::control::killswitch::disable_blocking()),
        };
        // A failed apply is persisted too, so no later process trusts the
        // previous state on disk.
        let state = if applied.is_err() && mode != KillSwitchMode::Off {
            KillSwitchState::Degraded
        } else {
            target.kill_switch_state
        };
        crate::control::killswitch::save_state(
            mode,
            state,
            crate::control::killswitch::persisted_from_active(allow),
        )
        .map_err(|error| error.to_string())?;
        applied.map_err(|error| error.to_string())?;
        self.applied.firewall = target.firewall.clone();
        self.applied.kill_switch_state = target.kill_switch_state;
        self.saved_mode = Some(mode);
        Ok(())
    }

    fn verify_routes(target: &NetworkPlan) -> Result<(), String> {
        match Self::misrouted(target, &target.routes).first() {
            Some((cidr, interface)) => Err(format!(
                "{cidr} should route through {interface} but does not"
            )),
            None => Ok(()),
        }
    }

    /// The `routes` a packet would not take through their interface.
    fn misrouted<'a>(
        plan: &NetworkPlan,
        routes: impl IntoIterator<Item = (&'a crate::cidr::Cidr, &'a String)>,
    ) -> Vec<(crate::cidr::Cidr, String)> {
        let probed = routes
            .into_iter()
            .filter_map(|(cidr, interface)| {
                plan.probe_address(*cidr)
                    .map(|probe| (*cidr, interface, probe))
            })
            .collect::<Vec<_>>();
        let observed = crate::platform::Routes::route_interfaces_for(
            &probed
                .iter()
                .map(|(_, _, probe)| *probe)
                .collect::<Vec<_>>(),
        );
        probed
            .into_iter()
            .zip(observed)
            .filter(|((_, interface, _), seen)| {
                !matches!(seen, DefaultRouteObservation::Interface(on) if on == *interface)
            })
            .map(|((cidr, interface, _), _)| (cidr, interface.clone()))
            .collect()
    }
}
