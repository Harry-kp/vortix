//! Validated `OpenVPN` route vocabulary: what a profile configures and what a
//! server pushes, recorded from a completed negotiation.

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv6Addr};

use thiserror::Error;

use crate::core::cidr::Cidr;

/// Upper bound on routes one tunnel may carry.
pub const MAX_ROUTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenVpnRouteError {
    #[error("OpenVPN route gateway must be a same-family unicast address")]
    InvalidGateway,
    #[error("CIDR prefix exceeds its address-family width")]
    InvalidCidr,
    #[error("more than {MAX_ROUTES} OpenVPN routes")]
    TooManyRoutes,
    #[error("OpenVPN route evidence is inconsistent")]
    InvalidEvidence,
}

fn invalid_unicast_ip(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified() || address.is_multicast() || address.is_broadcast()
        }
        IpAddr::V6(address) => address.is_unspecified() || address.is_multicast(),
    }
}

/// How the server challenges for a second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVpnChallengeKind {
    Static,
    Remote,
}

/// Gateway semantics carried by one `OpenVPN` route directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenVpnRouteGateway {
    /// The gateway assigned by the VPN server (`default`/`vpn_gateway`).
    VpnDefault,
    /// The pre-tunnel system gateway (`net_gateway`).
    NetGateway,
    /// The resolved remote-server gateway (`remote_host`).
    RemoteHost,
    Address(IpAddr),
}

/// One explicit IPv4 `route-gateway` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenVpnDefaultGateway {
    Address(IpAddr),
    /// Obtain the gateway from the `OpenVPN` TAP DHCP negotiation.
    Dhcp,
}

/// Default gateway directives for one configured or pushed origin.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenVpnDefaultGateways {
    ipv4: Option<OpenVpnDefaultGateway>,
    ipv6: Option<Ipv6Addr>,
}

impl OpenVpnDefaultGateways {
    pub fn new(
        ipv4: Option<OpenVpnDefaultGateway>,
        ipv6: Option<Ipv6Addr>,
    ) -> Result<Self, OpenVpnRouteError> {
        if matches!(ipv4, Some(OpenVpnDefaultGateway::Address(address)) if {
            !address.is_ipv4() || invalid_unicast_ip(&address)
        }) || ipv6.is_some_and(|address| invalid_unicast_ip(&IpAddr::V6(address)))
        {
            return Err(OpenVpnRouteError::InvalidGateway);
        }
        Ok(Self { ipv4, ipv6 })
    }

    #[must_use]
    pub const fn ipv4(self) -> Option<OpenVpnDefaultGateway> {
        self.ipv4
    }

    #[must_use]
    pub const fn ipv6(self) -> Option<Ipv6Addr> {
        self.ipv6
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ipv4.is_none() && self.ipv6.is_none()
    }
}

/// Gateway and metric applied to routes that omit an explicit value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenVpnRouteDefaults {
    gateways: OpenVpnDefaultGateways,
    metric: Option<u32>,
}

impl OpenVpnRouteDefaults {
    #[must_use]
    pub const fn new(gateways: OpenVpnDefaultGateways, metric: Option<u32>) -> Self {
        Self { gateways, metric }
    }

    #[must_use]
    pub const fn gateways(self) -> OpenVpnDefaultGateways {
        self.gateways
    }

    #[must_use]
    pub const fn metric(self) -> Option<u32> {
        self.metric
    }

    /// Pushed values win over configured ones, per field.
    #[must_use]
    pub fn merged(configured: Self, pushed: Self) -> Self {
        let configured_gateways = configured.gateways();
        let pushed_gateways = pushed.gateways();
        let gateways = OpenVpnDefaultGateways {
            ipv4: pushed_gateways.ipv4().or(configured_gateways.ipv4()),
            ipv6: pushed_gateways.ipv6().or(configured_gateways.ipv6()),
        };
        Self::new(gateways, pushed.metric().or(configured.metric()))
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.gateways.is_empty() && self.metric.is_none()
    }
}

/// One `redirect-gateway` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OpenVpnRedirectFlag {
    Local,
    AutoLocal,
    Def1,
    BypassDhcp,
    BypassDns,
    BlockLocal,
    Ipv6,
    DisableIpv4,
}

/// The flags of one `redirect-gateway` directive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpenVpnRedirectGateway(BTreeSet<OpenVpnRedirectFlag>);

impl OpenVpnRedirectGateway {
    pub fn new(flags: Vec<OpenVpnRedirectFlag>) -> Result<Self, OpenVpnRouteError> {
        let count = flags.len();
        let flags = flags.into_iter().collect::<BTreeSet<_>>();
        if flags.len() != count {
            return Err(OpenVpnRouteError::InvalidGateway);
        }
        Ok(Self(flags))
    }

    #[must_use]
    pub fn flags(&self) -> &BTreeSet<OpenVpnRedirectFlag> {
        &self.0
    }

    #[must_use]
    pub fn ipv4(&self) -> bool {
        !self.0.contains(&OpenVpnRedirectFlag::DisableIpv4)
    }

    #[must_use]
    pub fn ipv6(&self) -> bool {
        self.0.contains(&OpenVpnRedirectFlag::Ipv6)
    }
}

/// One `route` directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenVpnRoute {
    destination: Cidr,
    gateway: OpenVpnRouteGateway,
    metric: Option<u32>,
}

impl OpenVpnRoute {
    pub fn new(
        destination: Cidr,
        gateway: Option<IpAddr>,
        metric: Option<u32>,
    ) -> Result<Self, OpenVpnRouteError> {
        Self::with_gateway(
            destination,
            gateway.map_or(
                OpenVpnRouteGateway::VpnDefault,
                OpenVpnRouteGateway::Address,
            ),
            metric,
        )
    }

    pub fn with_gateway(
        destination: Cidr,
        gateway: OpenVpnRouteGateway,
        metric: Option<u32>,
    ) -> Result<Self, OpenVpnRouteError> {
        if !destination.is_valid() {
            return Err(OpenVpnRouteError::InvalidCidr);
        }
        if matches!(gateway, OpenVpnRouteGateway::Address(address) if {
            invalid_unicast_ip(&address) || address.is_ipv4() != destination.addr.is_ipv4()
        }) {
            return Err(OpenVpnRouteError::InvalidGateway);
        }
        Ok(Self {
            destination,
            gateway,
            metric,
        })
    }

    #[must_use]
    pub const fn destination(self) -> Cidr {
        self.destination
    }

    #[must_use]
    pub const fn gateway(self) -> OpenVpnRouteGateway {
        self.gateway
    }

    #[must_use]
    pub const fn metric(self) -> Option<u32> {
        self.metric
    }
}

/// Routes from one origin: the profile, or the server's push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnRouteSetEvidence {
    routes: Vec<OpenVpnRoute>,
    redirect_gateway: Option<OpenVpnRedirectGateway>,
    route_defaults: OpenVpnRouteDefaults,
}

impl OpenVpnRouteSetEvidence {
    pub fn new(
        routes: Vec<OpenVpnRoute>,
        redirect_gateway: Option<OpenVpnRedirectGateway>,
    ) -> Result<Self, OpenVpnRouteError> {
        Self::with_route_defaults(routes, redirect_gateway, OpenVpnRouteDefaults::default())
    }

    pub fn with_route_defaults(
        routes: Vec<OpenVpnRoute>,
        redirect_gateway: Option<OpenVpnRedirectGateway>,
        route_defaults: OpenVpnRouteDefaults,
    ) -> Result<Self, OpenVpnRouteError> {
        if routes.len() > MAX_ROUTES {
            return Err(OpenVpnRouteError::TooManyRoutes);
        }
        let mut unique = HashSet::with_capacity(routes.len());
        if routes.iter().any(|route| !unique.insert(route)) {
            return Err(OpenVpnRouteError::InvalidEvidence);
        }
        Ok(Self {
            routes,
            redirect_gateway,
            route_defaults,
        })
    }

    #[must_use]
    pub fn routes(&self) -> &[OpenVpnRoute] {
        &self.routes
    }

    #[must_use]
    pub const fn redirect_gateway(&self) -> Option<&OpenVpnRedirectGateway> {
        self.redirect_gateway.as_ref()
    }

    #[must_use]
    pub const fn route_defaults(&self) -> OpenVpnRouteDefaults {
        self.route_defaults
    }
}

/// Configured and pushed routes of one live tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnRouteEvidence {
    configured: OpenVpnRouteSetEvidence,
    pushed: OpenVpnRouteSetEvidence,
    selected_remote: Option<IpAddr>,
}

impl OpenVpnRouteEvidence {
    pub fn new(
        configured: OpenVpnRouteSetEvidence,
        pushed: OpenVpnRouteSetEvidence,
    ) -> Result<Self, OpenVpnRouteError> {
        if configured.routes().len() + pushed.routes().len() > MAX_ROUTES {
            return Err(OpenVpnRouteError::TooManyRoutes);
        }
        Ok(Self {
            configured,
            pushed,
            selected_remote: None,
        })
    }

    /// Record the server address in use; required exactly when a route
    /// depends on it (a default redirect or a `remote_host` gateway).
    pub fn with_selected_remote(
        mut self,
        selected_remote: Option<IpAddr>,
    ) -> Result<Self, OpenVpnRouteError> {
        let requires_selected_remote = self.configured.redirect_gateway().is_some()
            || self.pushed.redirect_gateway().is_some()
            || self
                .configured
                .routes()
                .iter()
                .chain(self.pushed.routes())
                .any(|route| route.gateway() == OpenVpnRouteGateway::RemoteHost);
        if requires_selected_remote != selected_remote.is_some()
            || selected_remote.as_ref().is_some_and(invalid_unicast_ip)
        {
            return Err(OpenVpnRouteError::InvalidEvidence);
        }
        self.selected_remote = selected_remote;
        Ok(self)
    }

    #[must_use]
    pub const fn configured(&self) -> &OpenVpnRouteSetEvidence {
        &self.configured
    }

    #[must_use]
    pub const fn pushed(&self) -> &OpenVpnRouteSetEvidence {
        &self.pushed
    }

    #[must_use]
    pub const fn selected_remote(&self) -> Option<IpAddr> {
        self.selected_remote
    }
}
