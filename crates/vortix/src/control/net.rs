//! The one place that changes the host network: moves routes, DNS and the
//! firewall from the last applied plan to the next one.

use std::path::PathBuf;

use crate::control::dns::{DnsEffectiveStatus, DnsPolicyCoordinator};
use crate::control::killswitch::{KillSwitchMode, KillSwitchState};
use crate::platform::DefaultRouteObservation;

use super::plan::{Firewall, NetworkPlan};

pub struct Net {
    config_dir: PathBuf,
    applied: NetworkPlan,
    /// Mode last saved with the firewall; `None` until the first apply.
    saved_mode: Option<KillSwitchMode>,
    dns: DnsPolicyCoordinator,
}

impl Net {
    /// `applied` is what the host already carries, e.g. for adopted tunnels.
    #[must_use]
    pub fn new(config_dir: PathBuf, applied: NetworkPlan) -> Self {
        Self {
            dns: crate::control::dns::load_policy(&config_dir).unwrap_or_default(),
            config_dir,
            applied,
            saved_mode: None,
        }
    }

    /// Move the host to `target`. Idempotent: after a failure the next call
    /// retries whatever is still missing.
    pub fn apply(&mut self, target: &NetworkPlan, mode: KillSwitchMode) -> Result<(), String> {
        let tightening = matches!(target.firewall, Firewall::Block(_));
        if tightening {
            self.apply_firewall(target, mode)?;
        }
        self.apply_routes(target)?;
        self.apply_dns(target)?;
        if !tightening {
            self.apply_firewall(target, mode)?;
        }
        self.applied = target.clone();
        Self::verify_routes(target)
    }

    /// Put the host back as it was before Vortix touched it.
    pub fn release(&mut self) -> Result<(), String> {
        self.apply(&NetworkPlan::default(), KillSwitchMode::Off)
    }

    fn apply_routes(&mut self, target: &NetworkPlan) -> Result<(), String> {
        use crate::platform::Routes as table;
        // A prefix the target still carries is retargeted in place, never
        // deleted first: that gap leaks traffic onto the real address.
        for (cidr, interface) in &self.applied.routes {
            if !target.routes.contains_key(cidr) {
                if let Err(error) = table::unbind_route(&cidr.to_string(), interface) {
                    tracing::warn!(target: "vortix::net", %cidr, %interface, %error, "route removal failed");
                }
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
        self.applied.host_routes.clone_from(&target.host_routes);
        let mut first_error = None;
        let v4_endpoints: Vec<_> = target
            .host_routes
            .iter()
            .filter(|ip| ip.is_ipv4())
            .collect();
        if !v4_endpoints.is_empty() {
            match table::default_gateway() {
                Some(gateway) => {
                    for endpoint in v4_endpoints {
                        if let Err(error) = table::bind_host_route(*endpoint, &gateway) {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                None => {
                    first_error.get_or_insert(
                        "no physical default gateway to pin the VPN server route to".into(),
                    );
                }
            }
        }
        for endpoint in target.host_routes.iter().filter(|ip| ip.is_ipv6()) {
            // ponytail: only the IPv4 default gateway is read; pinning an
            // IPv6 server needs its IPv6 gateway (#308).
            tracing::warn!(target: "vortix::net", %endpoint, "IPv6 server route not pinned");
        }
        for (cidr, interface) in &target.routes {
            if !Self::routes_through(target, *cidr, interface) {
                if let Err(error) = table::bind_route(&cidr.to_string(), interface) {
                    first_error.get_or_insert(error);
                }
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
        for (cidr, interface) in &target.routes {
            if !Self::routes_through(target, *cidr, interface) {
                return Err(format!(
                    "{cidr} should route through {interface} but does not"
                ));
            }
        }
        Ok(())
    }

    fn routes_through(target: &NetworkPlan, cidr: crate::cidr::Cidr, interface: &str) -> bool {
        let Some(probe) = target.probe_address(cidr) else {
            return true;
        };
        matches!(
            crate::platform::Routes::route_interface_for(probe),
            DefaultRouteObservation::Interface(observed) if observed == interface
        )
    }
}
