use thiserror::Error;

use std::collections::HashSet;
use std::net::IpAddr;

use crate::vortix_core::privileged::{
    OpenVpnDefaultGateways, OpenVpnRedirectFlag, OpenVpnRedirectGateway, OpenVpnRoute,
    OpenVpnRouteDefaults, OpenVpnRouteEvidence, OpenVpnRouteGateway, OpenVpnRouteSetEvidence,
    MAX_RESOURCE_ITEMS,
};

use super::parser::{
    merge_redirect_gateways, parse_default_route_metric, parse_ipv4_default_gateway,
    parse_ipv6_default_gateway, parse_redirect_gateway, parse_route, OvpnParsedProfile, OvpnRoute,
};

const COMPLETED: &str = "Initialization Sequence Completed";
const PUSH_REPLY: &str = "PUSH_REPLY";

/// Route intent authenticated by the latest completed `OpenVPN` negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PushedRouteEvidence {
    routes: Vec<OvpnRoute>,
    redirect_gateway: Option<OpenVpnRedirectGateway>,
    route_defaults: OpenVpnRouteDefaults,
    push_reply_present: bool,
}

impl PushedRouteEvidence {
    pub(crate) fn routes(&self) -> &[OvpnRoute] {
        &self.routes
    }

    pub(crate) const fn redirect_gateway(&self) -> Option<&OpenVpnRedirectGateway> {
        self.redirect_gateway.as_ref()
    }

    pub(crate) const fn push_reply_present(&self) -> bool {
        self.push_reply_present
    }

    pub(crate) const fn route_defaults(&self) -> OpenVpnRouteDefaults {
        self.route_defaults
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum PushReplySelectionError {
    #[error("OpenVPN log has no completed negotiation marker")]
    NoCompletedNegotiation,
    #[error("OpenVPN log contains a newer incomplete negotiation")]
    NewerIncompleteNegotiation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum PushedRouteEvidenceError {
    #[error(transparent)]
    Selection(#[from] PushReplySelectionError),
    #[error("OpenVPN PUSH_REPLY contained malformed route evidence")]
    MalformedRoute,
    #[error("OpenVPN PUSH_REPLY contained unsupported redirect-gateway flags")]
    MalformedRedirect,
    #[error("OpenVPN PUSH_REPLY contained malformed route-gateway evidence")]
    MalformedGateway,
    #[error("OpenVPN PUSH_REPLY route count exceeds the canonical bound")]
    CollectionLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum SelectedRemoteEvidenceError {
    #[error(transparent)]
    Selection(#[from] PushReplySelectionError),
    #[error("OpenVPN log contained malformed selected-remote evidence")]
    MalformedRemote,
}

#[derive(Debug, Error)]
pub(crate) enum OpenVpnRouteEvidenceError {
    #[error("OpenVPN profile contains unsupported route semantics")]
    UnsupportedConfiguredRoute,
    #[error(transparent)]
    Pushed(#[from] PushedRouteEvidenceError),
    #[error(transparent)]
    SelectedRemote(#[from] SelectedRemoteEvidenceError),
    #[error("OpenVPN route evidence was truncated before a PUSH_REPLY was retained")]
    Truncated,
    #[error("OpenVPN route evidence is invalid")]
    Invalid,
}

/// Build complete configured and negotiated route truth from one validated
/// profile parse and one stable runtime-log snapshot.
pub(crate) fn openvpn_route_evidence(
    parsed: &OvpnParsedProfile,
    log: &str,
    log_truncated: bool,
) -> Result<OpenVpnRouteEvidence, OpenVpnRouteEvidenceError> {
    if parsed.unsupported_route_semantics {
        return Err(OpenVpnRouteEvidenceError::UnsupportedConfiguredRoute);
    }
    let configured = parsed
        .routes
        .iter()
        .map(canonical_openvpn_route)
        .collect::<Result<Vec<_>, _>>()?;
    let pushed = pushed_route_evidence(log)?;
    if log_truncated && !pushed.push_reply_present() {
        return Err(OpenVpnRouteEvidenceError::Truncated);
    }
    let pushed_routes = pushed
        .routes()
        .iter()
        .map(canonical_openvpn_route)
        .collect::<Result<Vec<_>, _>>()?;
    let selected_remote_required = configured
        .iter()
        .chain(&pushed_routes)
        .any(|route| route.gateway() == OpenVpnRouteGateway::RemoteHost);
    let selected_remote = if selected_remote_required {
        Some(selected_remote_address(log)?.ok_or(OpenVpnRouteEvidenceError::Invalid)?)
    } else {
        None
    };
    OpenVpnRouteEvidence::new(
        OpenVpnRouteSetEvidence::with_route_defaults(
            configured,
            parsed.redirect_gateway.clone(),
            parsed.route_defaults,
        )
        .map_err(|_| OpenVpnRouteEvidenceError::Invalid)?,
        OpenVpnRouteSetEvidence::with_route_defaults(
            pushed_routes,
            pushed.redirect_gateway().cloned(),
            pushed.route_defaults(),
        )
        .map_err(|_| OpenVpnRouteEvidenceError::Invalid)?,
    )
    .and_then(|evidence| evidence.with_selected_remote(selected_remote))
    .map_err(|_| OpenVpnRouteEvidenceError::Invalid)
}

fn canonical_openvpn_route(route: &OvpnRoute) -> Result<OpenVpnRoute, OpenVpnRouteEvidenceError> {
    let destination =
        crate::vortix_core::cidr::Cidr::new(route.destination.addr, route.destination.prefix_len)
            .ok_or(OpenVpnRouteEvidenceError::Invalid)?;
    OpenVpnRoute::with_gateway(destination, route.gateway, route.metric)
        .map_err(|_| OpenVpnRouteEvidenceError::Invalid)
}

/// Parse route intent from only the latest completed `OpenVPN` negotiation.
///
/// An incomplete newer negotiation invalidates the older evidence rather than
/// being misreported as current. Physical gateway roles are preserved and
/// resolved only at the authenticated OS-effect boundary.
pub(crate) fn pushed_route_evidence(
    log: &str,
) -> Result<PushedRouteEvidence, PushedRouteEvidenceError> {
    let push_reply = latest_completed_push_reply(log)?;
    let mut routes = Vec::new();
    let mut seen_routes = HashSet::new();
    let mut redirect_gateway = None;
    let mut ipv4_gateway = None;
    let mut ipv6_gateway = None;
    let mut default_route_metric = None;
    let Some(push_reply) = push_reply else {
        return Ok(PushedRouteEvidence {
            routes: Vec::new(),
            redirect_gateway,
            route_defaults: OpenVpnRouteDefaults::default(),
            push_reply_present: false,
        });
    };

    for option in push_reply.split(',') {
        let option = option.trim().trim_matches(['\'', '"']);
        let mut tokens = option.split_whitespace();
        let Some(directive) = tokens.next() else {
            continue;
        };
        if directive.eq_ignore_ascii_case("route") || directive.eq_ignore_ascii_case("route-ipv6") {
            let route = parse_route(&mut tokens).ok_or(PushedRouteEvidenceError::MalformedRoute)?;
            if seen_routes.insert(route.clone()) {
                routes.push(route);
            }
            if routes.len() > MAX_RESOURCE_ITEMS {
                return Err(PushedRouteEvidenceError::CollectionLimit);
            }
        } else if directive.eq_ignore_ascii_case("redirect-gateway") {
            let parsed = parse_redirect_gateway(&mut tokens)
                .ok_or(PushedRouteEvidenceError::MalformedRedirect)?;
            redirect_gateway = Some(merge_redirect_gateways(redirect_gateway.as_ref(), &parsed));
        } else if directive.eq_ignore_ascii_case("redirect-gateway-ipv6") {
            if tokens.next().is_some() {
                return Err(PushedRouteEvidenceError::MalformedRedirect);
            }
            let ipv6_only = OpenVpnRedirectGateway::new(vec![
                OpenVpnRedirectFlag::Ipv6,
                OpenVpnRedirectFlag::DisableIpv4,
            ])
            .map_err(|_| PushedRouteEvidenceError::MalformedRedirect)?;
            redirect_gateway = Some(merge_redirect_gateways(
                redirect_gateway.as_ref(),
                &ipv6_only,
            ));
        } else if directive.eq_ignore_ascii_case("route-gateway") {
            ipv4_gateway = Some(
                parse_ipv4_default_gateway(&mut tokens)
                    .ok_or(PushedRouteEvidenceError::MalformedGateway)?,
            );
        } else if directive.eq_ignore_ascii_case("route-ipv6-gateway") {
            ipv6_gateway = Some(
                parse_ipv6_default_gateway(&mut tokens)
                    .ok_or(PushedRouteEvidenceError::MalformedGateway)?,
            );
        } else if directive.eq_ignore_ascii_case("route-metric") {
            default_route_metric = Some(
                parse_default_route_metric(&mut tokens)
                    .ok_or(PushedRouteEvidenceError::MalformedRoute)?,
            );
        }
    }

    let default_gateways = OpenVpnDefaultGateways::new(ipv4_gateway, ipv6_gateway)
        .map_err(|_| PushedRouteEvidenceError::MalformedGateway)?;

    Ok(PushedRouteEvidence {
        routes,
        redirect_gateway,
        route_defaults: OpenVpnRouteDefaults::new(default_gateways, default_route_metric),
        push_reply_present: true,
    })
}

pub(super) fn latest_completed_push_reply(
    log: &str,
) -> Result<Option<&str>, PushReplySelectionError> {
    let session_log = latest_completed_session(log)?;
    let Some(push_at) = session_log.rfind(PUSH_REPLY) else {
        return Ok(None);
    };
    Ok(Some(
        session_log[push_at + PUSH_REPLY.len()..]
            .lines()
            .next()
            .unwrap_or_default(),
    ))
}

/// Return the transport address selected by the latest successful `OpenVPN`
/// client session. Only `OpenVPN`'s fixed `link remote` diagnostic vocabulary is
/// accepted; configured failover order is not connection evidence.
pub(crate) fn selected_remote_address(
    log: &str,
) -> Result<Option<IpAddr>, SelectedRemoteEvidenceError> {
    let session_log = latest_completed_session(log)?;
    for line in session_log.lines().rev() {
        let Some((protocol, remote)) = remote_line_parts(line) else {
            continue;
        };
        if !is_remote_transport(protocol) {
            continue;
        }
        return parse_selected_remote(remote)
            .map(Some)
            .ok_or(SelectedRemoteEvidenceError::MalformedRemote);
    }
    Ok(None)
}

fn latest_completed_session(log: &str) -> Result<&str, PushReplySelectionError> {
    let completed_at = log
        .rfind(COMPLETED)
        .ok_or(PushReplySelectionError::NoCompletedNegotiation)?;
    let suffix = &log[completed_at + COMPLETED.len()..];
    if suffix.contains(PUSH_REPLY) || contains_remote_transport_line(suffix) {
        return Err(PushReplySelectionError::NewerIncompleteNegotiation);
    }
    let completed_log = &log[..completed_at];
    let session_start = completed_log
        .rfind(COMPLETED)
        .map_or(0, |previous| previous + COMPLETED.len());
    Ok(&completed_log[session_start..])
}

fn contains_remote_transport_line(log: &str) -> bool {
    log.lines().any(|line| {
        remote_line_parts(line).is_some_and(|(protocol, _)| is_remote_transport(protocol))
    })
}

fn remote_line_parts(line: &str) -> Option<(&str, &str)> {
    const MARKER: &str = " link remote: ";
    let marker_at = line.rfind(MARKER)?;
    let before = &line[..marker_at];
    let protocol = before.split_whitespace().next_back()?;
    let log_prefix = before[..before.len().checked_sub(protocol.len())?].trim();
    if !valid_openvpn_log_prefix(log_prefix) {
        return None;
    }
    Some((protocol, line[marker_at + MARKER.len()..].trim()))
}

fn valid_openvpn_log_prefix(prefix: &str) -> bool {
    prefix.is_empty()
        || prefix.split_whitespace().all(|token| {
            token.strip_prefix("us=").is_some_and(|micros| {
                !micros.is_empty() && micros.bytes().all(|byte| byte.is_ascii_digit())
            }) || token.bytes().all(|byte| {
                byte.is_ascii_digit()
                    || matches!(byte, b'-' | b':' | b'+' | b'.' | b',' | b'T' | b'Z')
            })
        })
}

fn is_remote_transport(protocol: &str) -> bool {
    matches!(
        protocol,
        "UDP" | "UDPv4" | "UDPv6" | "TCP_CLIENT" | "TCPv4_CLIENT" | "TCPv6_CLIENT"
    )
}

fn parse_selected_remote(remote: &str) -> Option<IpAddr> {
    let (family, address_and_port) = if let Some(value) = remote.strip_prefix("[AF_INET]") {
        (4, value)
    } else if let Some(value) = remote.strip_prefix("[AF_INET6]") {
        (6, value)
    } else {
        return None;
    };
    let (address, port) = address_and_port.rsplit_once(':')?;
    let address = address.parse::<IpAddr>().ok()?;
    let port = port.parse::<u16>().ok()?;
    if port == 0 || family == 4 && !address.is_ipv4() || family == 6 && !address.is_ipv6() {
        return None;
    }
    Some(address)
}

#[cfg(test)]
mod tests {
    use super::{
        openvpn_route_evidence, pushed_route_evidence, selected_remote_address,
        PushReplySelectionError, PushedRouteEvidenceError, SelectedRemoteEvidenceError,
    };
    use crate::vortix_core::privileged::{
        OpenVpnDefaultGateway, OpenVpnRedirectFlag, OpenVpnRouteGateway,
    };

    #[test]
    fn standard_runtime_evidence_preserves_server_pushed_default_route() {
        let parsed = crate::vortix_protocol_openvpn::parser::parse_ovpn_conf(
            "client\nremote 198.51.100.7 1194 udp\n",
        )
        .unwrap();
        let evidence = openvpn_route_evidence(
            &parsed,
            "UDPv4 link remote: [AF_INET]198.51.100.7:1194\n\
             PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 1.1.1.1\n\
             Initialization Sequence Completed\n",
            false,
        )
        .unwrap();

        let redirect = evidence.pushed().redirect_gateway().unwrap();
        assert!(redirect.ipv4());
        assert!(redirect.flags().contains(&OpenVpnRedirectFlag::Def1));
    }

    #[test]
    fn completed_push_reply_preserves_routes_gateways_metrics_and_redirects() {
        let evidence = pushed_route_evidence(
            "PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0 vpn_gateway 7,route-ipv6 2001:db8:42::/48 2001:db8::1 9,redirect-gateway def1,redirect-gateway-ipv6'\nInitialization Sequence Completed\n",
        )
        .unwrap();

        let redirect = evidence.redirect_gateway().unwrap();
        assert!(redirect.ipv4());
        assert!(redirect.ipv6());
        assert!(redirect.flags().contains(&OpenVpnRedirectFlag::Def1));
        assert_eq!(evidence.routes().len(), 2);
        assert_eq!(evidence.routes()[0].destination.prefix_len, 16);
        assert_eq!(
            evidence.routes()[0].gateway,
            OpenVpnRouteGateway::VpnDefault
        );
        assert_eq!(evidence.routes()[0].metric, Some(7));
        assert_eq!(
            evidence.routes()[1].gateway,
            OpenVpnRouteGateway::Address("2001:db8::1".parse().unwrap())
        );
        assert_eq!(evidence.routes()[1].metric, Some(9));
    }

    #[test]
    fn completed_push_reply_preserves_default_gateway_directives() {
        let evidence = pushed_route_evidence(
            "PUSH_REPLY,route-gateway 10.8.0.1,route-ipv6-gateway 2001:db8::1,route-metric 31\nInitialization Sequence Completed\n",
        )
        .unwrap();

        assert_eq!(
            evidence.route_defaults().gateways().ipv4(),
            Some(OpenVpnDefaultGateway::Address("10.8.0.1".parse().unwrap()))
        );
        assert_eq!(
            evidence.route_defaults().gateways().ipv6(),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(evidence.route_defaults().metric(), Some(31));
        assert!(matches!(
            pushed_route_evidence(
                "PUSH_REPLY,route-gateway vpn.example.test\nInitialization Sequence Completed\n"
            ),
            Err(PushedRouteEvidenceError::MalformedGateway)
        ));
    }

    #[test]
    fn route_evidence_uses_only_latest_complete_negotiation() {
        let evidence = pushed_route_evidence(
            "PUSH_REPLY,route 10.1.0.0 255.255.0.0\nInitialization Sequence Completed\nPUSH_REPLY,route 10.2.0.0 255.255.0.0\nInitialization Sequence Completed\n",
        )
        .unwrap();

        assert_eq!(evidence.routes().len(), 1);
        assert_eq!(
            evidence.routes()[0].destination.addr,
            "10.2.0.0".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn incomplete_push_never_becomes_empty_route_truth() {
        assert_eq!(
            pushed_route_evidence("PUSH_REPLY,route 10.0.0.0 255.0.0.0\n").unwrap_err(),
            PushedRouteEvidenceError::Selection(PushReplySelectionError::NoCompletedNegotiation)
        );
        assert_eq!(
            pushed_route_evidence(
                "PUSH_REPLY,route 10.0.0.0 255.0.0.0\nInitialization Sequence Completed\nPUSH_REPLY,route 192.0.2.0 255.255.255.0\n",
            )
            .unwrap_err(),
            PushedRouteEvidenceError::Selection(
                PushReplySelectionError::NewerIncompleteNegotiation
            )
        );
        let physical = pushed_route_evidence(
            "PUSH_REPLY,route 10.0.0.0 255.0.0.0 net_gateway\nInitialization Sequence Completed\n",
        )
        .unwrap();
        assert_eq!(
            physical.routes()[0].gateway,
            OpenVpnRouteGateway::NetGateway
        );
    }

    #[test]
    fn selected_remote_comes_from_the_latest_completed_session() {
        let log = "UDPv4 link remote: [AF_INET]198.51.100.6:1194\nPUSH_REPLY,ping 10\nInitialization Sequence Completed\nUDPv4 link remote: [AF_INET]198.51.100.7:443\nPUSH_REPLY,ping 10\nInitialization Sequence Completed\n";

        assert_eq!(
            selected_remote_address(log).unwrap(),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(
            selected_remote_address(
                "TCPv6_CLIENT link remote: [AF_INET6]2001:db8::7:443\nPUSH_REPLY,ping 10\nInitialization Sequence Completed\n"
            )
            .unwrap(),
            Some("2001:db8::7".parse().unwrap())
        );
    }

    #[test]
    fn selected_remote_rejects_malformed_or_newer_incomplete_sessions() {
        assert_eq!(
            selected_remote_address(
                "UDPv4 link remote: [AF_INET]198.51.100.7:not-a-port\nPUSH_REPLY,ping 10\nInitialization Sequence Completed\n"
            ),
            Err(SelectedRemoteEvidenceError::MalformedRemote)
        );
        assert_eq!(
            selected_remote_address(
                "UDPv4 link remote: [AF_INET]198.51.100.7:1194\nPUSH_REPLY,ping 10\nInitialization Sequence Completed\nUDPv4 link remote: [AF_INET]192.0.2.8:1194\n"
            ),
            Err(SelectedRemoteEvidenceError::Selection(
                PushReplySelectionError::NewerIncompleteNegotiation
            ))
        );
        assert_eq!(
            selected_remote_address(
                "PUSH: Received control message: 'PUSH_REPLY,setenv opt UDPv4 link remote: [AF_INET]192.0.2.99:1194'\nInitialization Sequence Completed\n"
            )
            .unwrap(),
            None
        );
    }
}
