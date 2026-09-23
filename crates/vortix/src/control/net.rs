//! The one place that changes the host network: moves routes, DNS and the
//! firewall from the last applied plan to the next one.

use std::path::PathBuf;

use crate::vortix_core::ports::dns::{DnsEffectiveStatus, DnsPolicyCoordinator};
use crate::vortix_core::ports::route_table::DefaultRouteObservation;
use crate::vortix_core::state::killswitch::KillSwitchMode;

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
            dns: crate::core::dns_policy::load(&config_dir).unwrap_or_default(),
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

    fn apply_routes(&self, target: &NetworkPlan) -> Result<(), String> {
        let table = &crate::platform::current_platform().route_table;
        // A prefix the target still carries is retargeted in place, never
        // deleted first: that gap leaks traffic onto the real address.
        for (cidr, interface) in &self.applied.routes {
            if !target.routes.contains_key(cidr) {
                if let Err(error) = table.unbind_route(&cidr.to_string(), interface) {
                    tracing::warn!(target: "vortix::net", %cidr, %interface, %error, "route removal failed");
                }
            }
        }
        for endpoint in self.applied.host_routes.difference(&target.host_routes) {
            if let Err(error) = table.unbind_host_route(*endpoint) {
                tracing::warn!(target: "vortix::net", %endpoint, %error, "server route removal failed");
            }
        }
        if !target.host_routes.is_empty() {
            let gateway = table
                .default_gateway()
                .ok_or("no physical default gateway to pin the VPN server route to")?;
            for endpoint in &target.host_routes {
                table.bind_host_route(*endpoint, &gateway)?;
            }
        }
        for (cidr, interface) in &target.routes {
            if !Self::routes_through(target, *cidr, interface) {
                table.bind_route(&cidr.to_string(), interface)?;
            }
        }
        Ok(())
    }

    fn apply_dns(&mut self, target: &NetworkPlan) -> Result<(), String> {
        let _lock = crate::core::dns_policy::acquire_policy_lock(&self.config_dir)
            .map_err(|error| format!("DNS policy lock failed: {error}"))?;
        let config_dir = &self.config_dir;
        let effective = self
            .dns
            .reconcile_durable(
                &target.dns,
                &crate::platform::current_platform().dns,
                |state| crate::core::dns_policy::save(config_dir, state),
            )
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
        let allow = match &target.firewall {
            Firewall::Block(allow) => {
                crate::core::killswitch::enable_blocking_multi(allow).map_err(|e| e.to_string())?;
                allow.as_slice()
            }
            Firewall::Open => {
                crate::core::killswitch::disable_blocking().map_err(|e| e.to_string())?;
                &[]
            }
        };
        crate::core::killswitch::save_state(
            mode,
            target.kill_switch_state,
            crate::core::killswitch::persisted_from_active(allow),
        )
        .map_err(|error| error.to_string())?;
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

    fn routes_through(
        target: &NetworkPlan,
        cidr: crate::vortix_core::cidr::Cidr,
        interface: &str,
    ) -> bool {
        let Some(probe) = target.probe_address(cidr) else {
            return true;
        };
        matches!(
            crate::platform::current_platform().route_table.route_interface_for(probe),
            DefaultRouteObservation::Interface(observed) if observed == interface
        )
    }
}
