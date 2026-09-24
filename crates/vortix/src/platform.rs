//! The process-wide `Platform` aggregate over the OS adapters.

pub mod aggregate {
    //! Platform aggregate — runtime-selectable per-OS port dispatcher.
    //!
    //! The five capability ports defined in `vortix-core::ports::*` each get a
    //! lightweight `*Kind` enum carrier here. The real variants are unit tags
    //! (zero-cost markers) that dispatch to the static trait impls in
    //! `vortix-platform-{macos,linux}`; the `Mock(...)` variant carries scripted
    //! state for tests.
    //!
    //! ## Why the aggregate lives in `vortix`, not `vortix-core`
    //!
    //! Plan #003 originally located the aggregate in `vortix-core`, but vortix-core
    //! must not depend on the platform impl crates (those crates already depend on
    //! vortix-core for the trait definitions — that's a Cargo dependency cycle).
    //! The binary crate is the natural meeting point: it already depends on
    //! everything, so the aggregate composes cleanly here.

    use std::sync::{Arc, Mutex};

    use crate::core::ports::killswitch::{ActiveTunnelInfo, KillswitchError, Result as KsResult};

    #[cfg(target_os = "linux")]
    use crate::linux as platform_impl;
    #[cfg(target_os = "macos")]
    use crate::macos as platform_impl;

    // ───────────────────────────────────────────────────────────────────────────
    // Mock state shells
    // ───────────────────────────────────────────────────────────────────────────

    /// Scriptable mock for the `Killswitch` port.
    #[derive(Debug, Default, Clone)]
    pub struct MockKillswitch {
        state: Arc<Mutex<MockKillswitchState>>,
    }

    #[derive(Debug, Default)]
    struct MockKillswitchState {
        /// Optional canned error returned by the next `enable_blocking_multi` call.
        pub fail_enable: Option<String>,
        /// Optional canned error returned by the next `disable_blocking` call.
        pub fail_disable: Option<String>,
        /// Whether `enable_blocking_multi` was called at least once.
        pub enabled: bool,
        /// Whether `disable_blocking` was called at least once.
        pub disabled: bool,
        /// Number of `ActiveTunnelInfo` entries in the most recent
        /// `enable_blocking_multi` call.
        pub last_active_count: usize,
    }

    impl MockKillswitch {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Script `enable_blocking_multi` to fail with the given message.
        ///
        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned.
        pub fn fail_next_enable(&self, msg: impl Into<String>) {
            self.state.lock().unwrap().fail_enable = Some(msg.into());
        }

        /// Returns whether `enable_blocking_multi` was called at least once.
        ///
        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned.
        #[must_use]
        pub fn was_enabled(&self) -> bool {
            self.state.lock().unwrap().enabled
        }

        /// Returns whether `disable_blocking` was called at least once.
        ///
        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned.
        #[must_use]
        pub fn was_disabled(&self) -> bool {
            self.state.lock().unwrap().disabled
        }

        /// Returns the active-tunnel count from the most recent
        /// `enable_blocking_multi` call, or zero if never called.
        ///
        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned.
        #[must_use]
        pub fn last_active_count(&self) -> usize {
            self.state.lock().unwrap().last_active_count
        }

        fn enable_blocking_multi(&self, active: &[ActiveTunnelInfo]) -> KsResult<()> {
            let mut s = self.state.lock().unwrap();
            if let Some(msg) = s.fail_enable.take() {
                return Err(KillswitchError::CommandFailed(msg));
            }
            s.enabled = true;
            s.last_active_count = active.len();
            Ok(())
        }

        fn disable_blocking(&self) -> KsResult<()> {
            let mut s = self.state.lock().unwrap();
            if let Some(msg) = s.fail_disable.take() {
                return Err(KillswitchError::CommandFailed(msg));
            }
            s.disabled = true;
            Ok(())
        }

        fn verify_blocking(&self, active: &[ActiveTunnelInfo]) -> KsResult<()> {
            let state = self.state.lock().unwrap();
            if state.enabled && state.last_active_count == active.len() {
                Ok(())
            } else {
                Err(KillswitchError::CommandFailed(
                    "mock blocking policy does not match".into(),
                ))
            }
        }

        fn verify_disabled(&self) -> KsResult<()> {
            let state = self.state.lock().unwrap();
            if state.disabled {
                Ok(())
            } else {
                Err(KillswitchError::CommandFailed(
                    "mock policy has not been disabled".into(),
                ))
            }
        }
    }

    /// Scriptable mock for the `DnsResolver` port.
    #[derive(Debug, Default, Clone)]
    pub struct MockDns {
        /// Canned response from `get_dns_server`. `None` returns `None`.
        pub dns: Option<String>,
    }

    /// Scriptable mock for the `Interface` port.
    #[derive(Debug, Default, Clone)]
    pub struct MockInterface {
        /// If true, resolution falls back to the requested profile name.
        pub wg_present: bool,
        /// Override the value returned by `resolve_wireguard_interface`.
        /// `Some("utun7")` simulates the macOS case where wg-quick maps
        /// the config-basename to a kernel utun device that differs from
        /// the basename. Falls back to `Some(name)` when `wg_present` is
        /// true and this is `None` (the historical default), or `None`
        /// otherwise.
        pub wg_kernel_iface: Option<String>,
    }

    /// Scriptable mock for the `NetworkStats` port.
    #[derive(Debug, Default, Clone)]
    pub struct MockNetworkStats {
        pub bytes_in: u64,
        pub bytes_out: u64,
    }

    /// Scriptable mock for the `RouteTable` port.
    #[derive(Debug, Default, Clone)]
    pub struct MockRouteTable {
        pub gateway: Option<String>,
        /// Canned interface name for `default_route_interface()`.
        pub interface: Option<String>,
        /// Distinguish an unavailable probe from a successful no-route result.
        pub probe_failed: bool,
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Per-port enum carriers
    // ───────────────────────────────────────────────────────────────────────────

    /// Static-dispatch carrier for the `Killswitch` port.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum KillswitchKind {
        #[cfg(target_os = "macos")]
        Macos,
        #[cfg(target_os = "linux")]
        Linux,
        Mock(MockKillswitch),
    }

    impl KillswitchKind {
        /// Engage the kill switch with a per-tunnel ruleset.
        ///
        /// # Errors
        ///
        /// See [`KillswitchError`].
        ///
        /// # Panics
        ///
        /// The mock variant may panic if its internal mutex is poisoned.
        pub fn enable_blocking_multi(&self, active: &[ActiveTunnelInfo]) -> KsResult<()> {
            use crate::core::ports::killswitch::Killswitch;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::PfFirewall::enable_blocking_multi(active),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::IptablesFirewall::enable_blocking_multi(active),
                Self::Mock(m) => m.enable_blocking_multi(active),
            }
        }

        /// Disengage the kill switch.
        ///
        /// # Errors
        ///
        /// See [`KillswitchError`].
        ///
        /// # Panics
        ///
        /// The mock variant may panic if its internal mutex is poisoned.
        pub fn disable_blocking(&self) -> KsResult<()> {
            use crate::core::ports::killswitch::Killswitch;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::PfFirewall::disable_blocking(),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::IptablesFirewall::disable_blocking(),
                Self::Mock(m) => m.disable_blocking(),
            }
        }

        /// Read back an exact blocking policy without mutating it.
        pub fn verify_blocking(&self, active: &[ActiveTunnelInfo]) -> KsResult<()> {
            use crate::core::ports::killswitch::Killswitch;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::PfFirewall::verify_blocking(active),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::IptablesFirewall::verify_blocking(active),
                Self::Mock(mock) => mock.verify_blocking(active),
            }
        }

        /// Prove that Vortix-owned firewall state is absent without mutating it.
        pub fn verify_disabled(&self) -> KsResult<()> {
            use crate::core::ports::killswitch::Killswitch;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::PfFirewall::verify_disabled(),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::IptablesFirewall::verify_disabled(),
                Self::Mock(mock) => mock.verify_disabled(),
            }
        }
    }

    /// Static-dispatch carrier for the `DnsResolver` port.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum DnsResolverKind {
        #[cfg(target_os = "macos")]
        Macos,
        #[cfg(target_os = "linux")]
        Linux,
        Mock(MockDns),
    }

    impl DnsResolverKind {
        /// Get the current system DNS server.
        #[must_use]
        pub fn get_dns_server(&self) -> Option<String> {
            use crate::core::ports::dns::DnsResolver;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacDns::get_dns_server(),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxDns::get_dns_server(),
                Self::Mock(m) => m.dns.clone(),
            }
        }
    }

    impl crate::core::ports::dns::DnsPolicyAdapter for DnsResolverKind {
        fn capabilities(&self) -> crate::core::ports::dns::DnsPlatformCapabilities {
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacDns.capabilities(),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxDns.capabilities(),
                Self::Mock(_) => crate::core::ports::dns::DnsPlatformCapabilities {
                    scoped_domains: true,
                },
            }
        }

        fn apply(
            &self,
            desired: &crate::core::ports::dns::DnsPolicy,
            previous_desired: Option<&crate::core::ports::dns::DnsPolicy>,
            previous_effective: &crate::core::ports::dns::DnsEffectiveState,
        ) -> crate::core::ports::dns::DnsEffectiveState {
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => {
                    platform_impl::MacDns.apply(desired, previous_desired, previous_effective)
                }
                #[cfg(target_os = "linux")]
                Self::Linux => {
                    platform_impl::LinuxDns.apply(desired, previous_desired, previous_effective)
                }
                Self::Mock(_) => crate::core::ports::dns::DnsEffectiveState {
                    requested_generation: desired.generation,
                    applied_generation: Some(desired.generation),
                    status: if desired.assignments.iter().all(|assignment| {
                        matches!(
                            assignment.scope,
                            crate::core::ports::dns::DnsScope::Suppressed
                        )
                    }) {
                        crate::core::ports::dns::DnsEffectiveStatus::Released
                    } else {
                        crate::core::ports::dns::DnsEffectiveStatus::Applied
                    },
                    owned: desired
                        .assignments
                        .iter()
                        .filter(|assignment| {
                            !matches!(
                                assignment.scope,
                                crate::core::ports::dns::DnsScope::Suppressed
                            )
                        })
                        .map(|assignment| crate::core::ports::dns::DnsOwnedResource {
                            generation: desired.generation,
                            id: format!("mock:{}", assignment.interface),
                            profile_id: assignment.profile_id.clone(),
                            interface: assignment.interface.clone(),
                        })
                        .collect(),
                    errors: Vec::new(),
                },
            }
        }

        fn verify(
            &self,
            desired: &crate::core::ports::dns::DnsPolicy,
            effective: &crate::core::ports::dns::DnsEffectiveState,
        ) -> Result<(), Vec<String>> {
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacDns.verify(desired, effective),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxDns.verify(desired, effective),
                Self::Mock(_) => Ok(()),
            }
        }
    }

    /// Static-dispatch carrier for the `Interface` port.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum InterfaceKind {
        #[cfg(target_os = "macos")]
        Macos,
        #[cfg(target_os = "linux")]
        Linux,
        Mock(MockInterface),
    }

    impl InterfaceKind {
        /// Resolve the real interface name for a `WireGuard` profile.
        #[must_use]
        pub fn resolve_wireguard_interface(&self, name: &str) -> Option<String> {
            use crate::core::ports::interface::Interface;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacInterface::resolve_wireguard_interface(name),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxInterface::resolve_wireguard_interface(name),
                Self::Mock(m) => {
                    if let Some(iface) = m.wg_kernel_iface.clone() {
                        Some(iface)
                    } else if m.wg_present {
                        Some(name.to_string())
                    } else {
                        None
                    }
                }
            }
        }

        /// PID of the `WireGuard` user-space process managing the interface.
        #[must_use]
        pub fn get_wireguard_pid(&self, interface: &str) -> Option<u32> {
            use crate::core::ports::interface::Interface;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacInterface::get_wireguard_pid(interface),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxInterface::get_wireguard_pid(interface),
                Self::Mock(_) => None,
            }
        }

        /// `(ip, mtu)` for the interface.
        #[must_use]
        pub fn get_interface_info(&self, interface: &str) -> (String, String) {
            use crate::core::ports::interface::Interface;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacInterface::get_interface_info(interface),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxInterface::get_interface_info(interface),
                Self::Mock(_) => (String::new(), String::new()),
            }
        }
    }

    /// Static-dispatch carrier for the `NetworkStats` port.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum NetworkStatsKind {
        #[cfg(target_os = "macos")]
        Macos,
        #[cfg(target_os = "linux")]
        Linux,
        Mock(MockNetworkStats),
    }

    impl NetworkStatsKind {
        /// Total bytes received and transmitted across all non-loopback interfaces.
        #[must_use]
        pub fn get_total_bytes(&self) -> (u64, u64) {
            use crate::core::ports::network_stats::NetworkStats;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacNetworkStats::get_total_bytes(),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxNetworkStats::get_total_bytes(),
                Self::Mock(m) => (m.bytes_in, m.bytes_out),
            }
        }
    }

    /// Static-dispatch carrier for the `RouteTable` port.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum RouteTableKind {
        #[cfg(target_os = "macos")]
        Macos,
        #[cfg(target_os = "linux")]
        Linux,
        Mock(MockRouteTable),
    }

    impl RouteTableKind {
        /// IP of the current default gateway, if any.
        #[must_use]
        pub fn default_gateway(&self) -> Option<String> {
            use crate::core::ports::route_table::RouteTable;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacRouteTable::default_gateway(),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxRouteTable::default_gateway(),
                Self::Mock(m) => m.gateway.clone(),
            }
        }

        /// Which interface actually carries public traffic, preserving probe
        /// failures.
        ///
        /// `redirect-gateway def1` installs `0.0.0.0/1` and `128.0.0.0/1` instead
        /// of replacing the default route, so reading the `default` entry names
        /// the ISP link while every packet leaves through the tunnel. Vortix then
        /// reported a fully tunnelled `OpenVPN` session as "no exit". Ask the kernel
        /// to select a route instead, which is the question being asked.
        #[must_use]
        pub fn default_route_observation(
            &self,
        ) -> crate::core::ports::route_table::DefaultRouteObservation {
            use crate::core::ports::route_table::RouteTable;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacRouteTable::default_route_observation(),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxRouteTable::default_route_observation(),
                Self::Mock(m) if m.probe_failed => {
                    crate::core::ports::route_table::DefaultRouteObservation::ProbeFailed
                }
                Self::Mock(m) => m.interface.clone().map_or(
                    crate::core::ports::route_table::DefaultRouteObservation::NoDefaultRoute,
                    crate::core::ports::route_table::DefaultRouteObservation::Interface,
                ),
            }
        }

        /// Compatibility view for callers that do not need freshness semantics.
        #[must_use]
        pub fn default_route_interface(&self) -> Option<String> {
            self.default_route_observation()
                .interface()
                .map(ToOwned::to_owned)
        }

        /// Bind `cidr` to `interface`.
        pub fn bind_route(&self, cidr: &str, interface: &str) -> Result<(), String> {
            use crate::core::ports::route_table::RouteTable;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacRouteTable::bind_route(cidr, interface),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxRouteTable::bind_route(cidr, interface),
                Self::Mock(_) => Ok(()),
            }
        }

        /// Keep a VPN server outside the tunnel's default-route claim.
        pub fn bind_host_route(
            &self,
            destination: std::net::IpAddr,
            gateway: &str,
        ) -> Result<(), String> {
            use crate::core::ports::route_table::RouteTable;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacRouteTable::bind_host_route(destination, gateway),
                #[cfg(target_os = "linux")]
                Self::Linux => {
                    platform_impl::LinuxRouteTable::bind_host_route(destination, gateway)
                }
                Self::Mock(_) => Ok(()),
            }
        }

        /// Remove an interface-scoped route installed by Vortix.
        pub fn unbind_route(&self, cidr: &str, interface: &str) -> Result<(), String> {
            use crate::core::ports::route_table::RouteTable;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacRouteTable::unbind_route(cidr, interface),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxRouteTable::unbind_route(cidr, interface),
                Self::Mock(_) => Ok(()),
            }
        }

        /// Remove a VPN-server escape route installed by Vortix.
        pub fn unbind_host_route(&self, destination: std::net::IpAddr) -> Result<(), String> {
            use crate::core::ports::route_table::RouteTable;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacRouteTable::unbind_host_route(destination),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxRouteTable::unbind_host_route(destination),
                Self::Mock(_) => Ok(()),
            }
        }

        /// Tri-state route selected by the kernel for one concrete destination.
        #[must_use]
        pub fn route_interface_for(
            &self,
            target: std::net::IpAddr,
        ) -> crate::core::ports::route_table::DefaultRouteObservation {
            use crate::core::ports::route_table::RouteTable;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::MacRouteTable::route_interface_for(target),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::LinuxRouteTable::route_interface_for(target),
                Self::Mock(m) if m.probe_failed => {
                    crate::core::ports::route_table::DefaultRouteObservation::ProbeFailed
                }
                Self::Mock(m) => m.interface.clone().map_or(
                    crate::core::ports::route_table::DefaultRouteObservation::NoDefaultRoute,
                    crate::core::ports::route_table::DefaultRouteObservation::Interface,
                ),
            }
        }
    }

    /// Scriptable mock for the `SocketAudit` port.
    #[derive(Debug, Default, Clone)]
    pub struct MockSocketAudit {
        pub canned: Vec<crate::core::ports::socket_audit::SocketSnapshot>,
    }

    /// Static-dispatch carrier for the `SocketAudit` port.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum SocketAuditKind {
        #[cfg(target_os = "macos")]
        Macos,
        #[cfg(target_os = "linux")]
        Linux,
        Mock(MockSocketAudit),
    }

    impl SocketAuditKind {
        /// Snapshot the current socket inventory.
        ///
        /// # Errors
        ///
        /// See `crate::core::ports::socket_audit::SocketAuditError`.
        pub fn snapshot(
            &self,
        ) -> crate::core::ports::socket_audit::SocketAuditResult<
            Vec<crate::core::ports::socket_audit::SocketSnapshot>,
        > {
            use crate::core::ports::socket_audit::SocketAudit;
            match self {
                #[cfg(target_os = "macos")]
                Self::Macos => platform_impl::LsofSocketAudit::snapshot(),
                #[cfg(target_os = "linux")]
                Self::Linux => platform_impl::ProcSocketAudit::snapshot(),
                Self::Mock(m) => Ok(m.canned.clone()),
            }
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // The aggregate
    // ───────────────────────────────────────────────────────────────────────────

    /// The platform aggregate — one field per capability port.
    ///
    /// Constructed once at startup via [`Platform::detect_current`] and threaded
    /// through the engine and CLI. Tests construct [`Platform::for_test`] which
    /// uses `Mock(...)` variants for every port.
    #[derive(Debug, Clone)]
    pub struct Platform {
        pub killswitch: KillswitchKind,
        pub dns: DnsResolverKind,
        pub interface: InterfaceKind,
        pub network_stats: NetworkStatsKind,
        pub route_table: RouteTableKind,
        pub socket_audit: SocketAuditKind,
    }

    impl Platform {
        /// Construct the platform aggregate for the current OS.
        ///
        /// Today this just picks the right unit-tag variants for each port. Later
        /// units may need to run backend-detection probes here (e.g. iptables vs
        /// nftables) — currently those probes run inside the impl methods.
        #[must_use]
        pub fn detect_current() -> Self {
            #[cfg(target_os = "macos")]
            {
                Self {
                    killswitch: KillswitchKind::Macos,
                    dns: DnsResolverKind::Macos,
                    interface: InterfaceKind::Macos,
                    network_stats: NetworkStatsKind::Macos,
                    route_table: RouteTableKind::Macos,
                    socket_audit: SocketAuditKind::Macos,
                }
            }
            #[cfg(target_os = "linux")]
            {
                Self {
                    killswitch: KillswitchKind::Linux,
                    dns: DnsResolverKind::Linux,
                    interface: InterfaceKind::Linux,
                    network_stats: NetworkStatsKind::Linux,
                    route_table: RouteTableKind::Linux,
                    socket_audit: SocketAuditKind::Linux,
                }
            }
        }

        /// Live network-interface enumeration.
        ///
        /// Dispatches to the per-OS free function — Linux reads
        /// `/sys/class/net/`, macOS parses `ifconfig -l`, Windows currently
        /// returns an empty list (stub). Used by the killswitch
        /// `PersistedState` V2 migration to drop phantom tunnel entries
        /// whose interface no longer exists in the kernel.
        ///
        /// Returns an empty `Vec` when enumeration fails or the platform
        /// has no implementation. Callers should treat an empty list as
        /// "unknown" rather than "no interfaces present" — see
        /// `core::killswitch::filter_phantom_tunnels`.
        #[must_use]
        pub fn available_network_interfaces(&self) -> Vec<String> {
            #[cfg(target_os = "linux")]
            {
                platform_impl::interface_list::available_network_interfaces()
            }
            #[cfg(target_os = "macos")]
            {
                platform_impl::interface_list::available_network_interfaces()
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                Vec::new()
            }
        }

        /// Construct an all-mock platform for unit tests.
        #[must_use]
        pub fn for_test() -> Self {
            Self {
                killswitch: KillswitchKind::Mock(MockKillswitch::new()),
                dns: DnsResolverKind::Mock(MockDns::default()),
                interface: InterfaceKind::Mock(MockInterface::default()),
                network_stats: NetworkStatsKind::Mock(MockNetworkStats::default()),
                route_table: RouteTableKind::Mock(MockRouteTable::default()),
                socket_audit: SocketAuditKind::Mock(MockSocketAudit::default()),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn for_test_uses_mock_variants() {
            let p = Platform::for_test();
            assert!(matches!(p.killswitch, KillswitchKind::Mock(_)));
            assert!(matches!(p.dns, DnsResolverKind::Mock(_)));
            assert!(matches!(p.interface, InterfaceKind::Mock(_)));
            assert!(matches!(p.network_stats, NetworkStatsKind::Mock(_)));
            assert!(matches!(p.route_table, RouteTableKind::Mock(_)));
        }

        #[test]
        fn mock_killswitch_records_calls() {
            let mock = MockKillswitch::new();
            assert!(!mock.was_enabled());
            let ks = KillswitchKind::Mock(mock.clone());
            let active = vec![ActiveTunnelInfo {
                interface: "wg0".into(),
                server_ips: vec!["1.2.3.4".parse().unwrap()],
                declared_cidrs: Vec::new(),
                is_primary: true,
            }];
            ks.enable_blocking_multi(&active).unwrap();
            assert!(mock.was_enabled());
            assert_eq!(mock.last_active_count(), 1);
            ks.disable_blocking().unwrap();
            assert!(mock.was_disabled());
        }

        #[test]
        fn mock_killswitch_records_empty_active_set() {
            let mock = MockKillswitch::new();
            let ks = KillswitchKind::Mock(mock.clone());
            ks.enable_blocking_multi(&[]).unwrap();
            assert!(mock.was_enabled());
            assert_eq!(mock.last_active_count(), 0);
        }

        #[test]
        fn mock_killswitch_scripts_failure() {
            let mock = MockKillswitch::new();
            mock.fail_next_enable("simulated iptables error");
            let ks = KillswitchKind::Mock(mock);
            let err = ks.enable_blocking_multi(&[]).unwrap_err();
            assert!(matches!(err, KillswitchError::CommandFailed(_)));
        }

        #[test]
        fn mock_dns_returns_canned_value() {
            let dns = DnsResolverKind::Mock(MockDns {
                dns: Some("1.1.1.1".into()),
            });
            assert_eq!(dns.get_dns_server(), Some("1.1.1.1".into()));
        }

        #[test]
        fn mock_route_table_returns_canned_gateway() {
            let rt = RouteTableKind::Mock(MockRouteTable {
                gateway: Some("192.168.1.1".into()),
                interface: None,
                probe_failed: false,
            });
            assert_eq!(rt.default_gateway(), Some("192.168.1.1".into()));
        }

        #[test]
        fn mock_route_table_returns_canned_interface() {
            let rt = RouteTableKind::Mock(MockRouteTable {
                gateway: None,
                interface: Some("utun3".into()),
                probe_failed: false,
            });
            assert_eq!(rt.default_route_interface(), Some("utun3".into()));
        }

        #[test]
        fn mock_route_table_interface_defaults_to_none() {
            let rt = RouteTableKind::Mock(MockRouteTable::default());
            assert_eq!(rt.default_route_interface(), None);
        }
    }
}
#[cfg(target_os = "macos")]
// xtask:allow-platform-cfg: the only remaining caller is the macOS DNS adapter
pub(crate) mod fixed_root_command {
    //! Bounded execution for fixed, package-owned privileged commands.

    #![allow(
        unsafe_code,
        reason = "bounded privileged children require private process-group containment"
    )]

    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
    const INITIAL_WAIT_INTERVAL: Duration = Duration::from_millis(1);
    const MAX_WAIT_INTERVAL: Duration = Duration::from_millis(20);
    const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum FixedCommandError {
        FailedBeforeSpawn,
        OutcomeUnknown,
    }

    pub(crate) struct FixedCommandOutput {
        pub(crate) status: ExitStatus,
        #[allow(
            dead_code,
            reason = "drained to avoid pipe deadlock; only status is inspected today"
        )]
        pub(crate) stdout: String,
        #[allow(
            dead_code,
            reason = "drained to avoid pipe deadlock; only status is inspected today"
        )]
        pub(crate) stderr: String,
    }

    pub(crate) fn run(
        candidates: &[&str],
        arguments: &[&str],
        stdin: Option<&[u8]>,
        max_input_bytes: usize,
    ) -> Result<FixedCommandOutput, FixedCommandError> {
        run_with_timeout(
            candidates,
            arguments,
            stdin,
            max_input_bytes,
            COMMAND_TIMEOUT,
        )
    }

    pub(crate) fn run_with_timeout(
        candidates: &[&str],
        arguments: &[&str],
        stdin: Option<&[u8]>,
        max_input_bytes: usize,
        timeout: Duration,
    ) -> Result<FixedCommandOutput, FixedCommandError> {
        if timeout.is_zero() || timeout > COMMAND_TIMEOUT {
            return Err(FixedCommandError::FailedBeforeSpawn);
        }
        if stdin.is_some_and(|body| body.len() > max_input_bytes) {
            return Err(FixedCommandError::FailedBeforeSpawn);
        }
        let binary = verified_fixed_binary(candidates)?;
        run_bounded(&binary, arguments, stdin, timeout)
    }

    fn verified_fixed_binary(candidates: &[&str]) -> Result<PathBuf, FixedCommandError> {
        candidates
            .iter()
            .map(Path::new)
            .find_map(|candidate| {
                let metadata = std::fs::symlink_metadata(candidate).ok()?;
                if !metadata.is_file()
                    || metadata.uid() != 0
                    || metadata.permissions().mode() & 0o022 != 0
                    || metadata.permissions().mode() & 0o111 == 0
                    || !candidate
                        .parent()
                        .is_some_and(root_owned_nonwritable_directory)
                {
                    return None;
                }
                Some(candidate.to_owned())
            })
            .ok_or(FixedCommandError::FailedBeforeSpawn)
    }

    fn root_owned_nonwritable_directory(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.file_type().is_dir()
                && metadata.uid() == 0
                && metadata.permissions().mode() & 0o022 == 0
        })
    }

    fn run_bounded(
        binary: &Path,
        arguments: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<FixedCommandOutput, FixedCommandError> {
        let mut command = Command::new(binary);
        command
            .args(arguments)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.process_group(0);
        let mut child = command
            .spawn()
            .map_err(|_| FixedCommandError::FailedBeforeSpawn)?;
        thread::scope(|scope| {
            let input_writer = child.stdin.take().map(|mut pipe| {
                scope.spawn(move || stdin.is_none_or(|body| pipe.write_all(body).is_ok()))
            });
            let stdout_reader = child
                .stdout
                .take()
                .map(|pipe| scope.spawn(move || read_bounded(pipe)));
            let stderr_reader = child
                .stderr
                .take()
                .map(|pipe| scope.spawn(move || read_bounded(pipe)));
            let deadline = Instant::now() + timeout;
            let mut wait_interval = INITIAL_WAIT_INTERVAL;
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(wait_interval);
                        wait_interval = (wait_interval * 2).min(MAX_WAIT_INTERVAL);
                    }
                    Ok(None) | Err(_) => {
                        terminate_process_group(&mut child);
                        join_discard(input_writer, stdout_reader, stderr_reader);
                        return Err(FixedCommandError::OutcomeUnknown);
                    }
                }
            };
            let input_ok = input_writer.is_none_or(|writer| writer.join().ok() == Some(true));
            let stdout = join_output(stdout_reader);
            let stderr = join_output(stderr_reader);
            if !input_ok {
                return Err(FixedCommandError::OutcomeUnknown);
            }
            Ok(FixedCommandOutput {
                status,
                stdout: stdout?,
                stderr: stderr?,
            })
        })
    }

    fn read_bounded(mut reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_OUTPUT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "privileged command output exceeded limit",
            ));
        }
        Ok(bytes)
    }

    fn join_output(
        reader: Option<thread::ScopedJoinHandle<'_, std::io::Result<Vec<u8>>>>,
    ) -> Result<String, FixedCommandError> {
        let bytes = reader
            .ok_or(FixedCommandError::OutcomeUnknown)?
            .join()
            .map_err(|_| FixedCommandError::OutcomeUnknown)?
            .map_err(|_| FixedCommandError::OutcomeUnknown)?;
        String::from_utf8(bytes).map_err(|_| FixedCommandError::OutcomeUnknown)
    }

    fn join_discard<'scope>(
        input: Option<thread::ScopedJoinHandle<'scope, bool>>,
        stdout: Option<thread::ScopedJoinHandle<'scope, std::io::Result<Vec<u8>>>>,
        stderr: Option<thread::ScopedJoinHandle<'scope, std::io::Result<Vec<u8>>>>,
    ) {
        let _ = input.map(thread::ScopedJoinHandle::join);
        let _ = stdout.map(thread::ScopedJoinHandle::join);
        let _ = stderr.map(thread::ScopedJoinHandle::join);
    }

    fn terminate_process_group(child: &mut std::process::Child) {
        kill_process_group(child.id());
        let _ = child.wait();
    }

    fn kill_process_group(child_id: u32) {
        if let Ok(pid) = libc::pid_t::try_from(child_id) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::Cursor;

        use super::*;

        #[test]
        fn bounded_reader_rejects_oversized_output() {
            let bytes = vec![b'x'; usize::try_from(MAX_OUTPUT_BYTES).unwrap() + 1];
            assert_eq!(
                read_bounded(Cursor::new(bytes)).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }

        #[test]
        fn caller_timeout_must_stay_within_the_fixed_command_ceiling() {
            for timeout in [Duration::ZERO, COMMAND_TIMEOUT + Duration::from_millis(1)] {
                assert!(matches!(
                    run_with_timeout(&[], &[], None, 0, timeout),
                    Err(FixedCommandError::FailedBeforeSpawn)
                ));
            }
        }
    }
}
pub(crate) mod route_probe {
    //! Shared failure backoff for platform route-table probes.

    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use crate::process::CommandSpec;

    pub(crate) enum ProbeOutcome {
        BackedOff,
        Success(String),
        Failed {
            consecutive_failures: u32,
            cooldown: Duration,
        },
    }

    struct ProbeBackoff {
        consecutive_failures: u32,
        next_allowed: Instant,
    }

    /// Process-wide state for one platform route probe.
    pub(crate) struct RouteProbe {
        state: OnceLock<Mutex<ProbeBackoff>>,
    }

    impl RouteProbe {
        pub(crate) const fn new() -> Self {
            Self {
                state: OnceLock::new(),
            }
        }

        pub(crate) fn run(&self, spec: CommandSpec) -> ProbeOutcome {
            let state = self.state.get_or_init(|| {
                Mutex::new(ProbeBackoff {
                    consecutive_failures: 0,
                    next_allowed: Instant::now(),
                })
            });

            {
                let state = state.lock().expect("backoff state mutex poisoned");
                if Instant::now() < state.next_allowed {
                    return ProbeOutcome::BackedOff;
                }
            }

            let result = crate::process::run_to_output(spec);
            let mut state = state.lock().expect("backoff state mutex poisoned");
            if let Ok(output) = result {
                state.consecutive_failures = 0;
                state.next_allowed = Instant::now();
                return ProbeOutcome::Success(String::from_utf8_lossy(&output.stdout).into_owned());
            }

            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            let cooldown = cooldown_for_failures(state.consecutive_failures);
            state.next_allowed = Instant::now() + cooldown;
            ProbeOutcome::Failed {
                consecutive_failures: state.consecutive_failures,
                cooldown,
            }
        }
    }

    fn cooldown_for_failures(failures: u32) -> Duration {
        Duration::from_secs(match failures {
            0..=2 => 0,
            3..=5 => 5,
            6..=10 => 15,
            _ => 60,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cooldown_ladder_escalates_then_caps() {
            assert_eq!(cooldown_for_failures(0), Duration::ZERO);
            assert_eq!(cooldown_for_failures(2), Duration::ZERO);
            assert_eq!(cooldown_for_failures(3), Duration::from_secs(5));
            assert_eq!(cooldown_for_failures(5), Duration::from_secs(5));
            assert_eq!(cooldown_for_failures(6), Duration::from_secs(15));
            assert_eq!(cooldown_for_failures(10), Duration::from_secs(15));
            assert_eq!(cooldown_for_failures(11), Duration::from_secs(60));
            assert_eq!(cooldown_for_failures(1_000_000), Duration::from_secs(60));
        }
    }
}

pub use aggregate::{
    DnsResolverKind, InterfaceKind, KillswitchKind, MockDns, MockInterface, MockKillswitch,
    MockNetworkStats, MockRouteTable, NetworkStatsKind, Platform, RouteTableKind,
};

// ───────────────────────────────────────────────────────────────────────────
// Process-global platform — the consumer-migration seam.
//
// Plan #003 originally threaded the Platform aggregate through every consumer.
// We instead install a process-wide singleton, matching the runner's
// `crate::process::global_runner()` pattern. `main.rs` initialises it once at
// startup; consumers reach for `current_platform()` instead of branching on
// `cfg(target_os)`. The async engine refactor swaps this back to
// explicit dependency injection.
// ───────────────────────────────────────────────────────────────────────────

use std::sync::OnceLock;

static GLOBAL_PLATFORM: OnceLock<Platform> = OnceLock::new();

/// Install the process-wide platform aggregate. First call wins.
///
/// `main()` calls this with `Platform::detect_current()`. Tests can call it
/// earlier with `Platform::for_test()` to redirect platform-port calls.
pub fn set_global_platform(platform: Platform) {
    let _ = GLOBAL_PLATFORM.set(platform);
}

/// Get the process-wide platform aggregate. Lazily initialises with
/// `Platform::for_test()` (all-mock variants) when no explicit platform has
/// been installed — the right behaviour for tests that don't touch
/// platform-port paths.
#[must_use]
pub fn current_platform() -> &'static Platform {
    GLOBAL_PLATFORM.get_or_init(Platform::for_test)
}

/// Directory a confined `wg-quick` is permitted to read configs from, when
/// the platform confines it at all.
///
/// Debian and Ubuntu ship an `AppArmor` profile for wg-quick granting no read
/// access outside `/etc/wireguard`, so a lifecycle copy staged anywhere else
/// is refused by the kernel before wg-quick even runs. The profile's rule is
/// `file rw @{etc_rw}/wireguard/{,**}` — the `{,**}` covers the tree
/// recursively, so Vortix takes its own subdirectory rather than writing
/// beside configs the user manages. Nothing there is ever theirs, so there is
/// no file to avoid clobbering and none of its contents outlive a teardown.
///
/// `None` means the platform does not confine wg-quick and the caller may
/// stage wherever it likes.
pub(crate) fn wireguard_staging_dir() -> Option<&'static std::path::Path> {
    #[cfg(target_os = "linux")] // xtask:allow-platform-cfg: AppArmor confines wg-quick on Linux only
    const STAGING_DIR: Option<&str> = Some("/etc/wireguard/vortix");
    #[cfg(not(target_os = "linux"))] // xtask:allow-platform-cfg: see above
    const STAGING_DIR: Option<&str> = None;

    STAGING_DIR.map(std::path::Path::new)
}

#[cfg(target_os = "linux")]
pub(crate) fn process_group_has_live_members(group_id: u32) -> std::io::Result<Option<bool>> {
    crate::linux::process_identity::process_group_has_live_members(group_id)
}

#[cfg(target_os = "macos")]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the Linux platform probe so the process layer stays OS-agnostic"
)]
pub(crate) fn process_group_has_live_members(_group_id: u32) -> std::io::Result<Option<bool>> {
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("Vortix currently only supports macOS and Linux");

// Re-export platform constants from the centralized constants module for convenience.
pub use crate::constants::KILLSWITCH_EMERGENCY_MSG;

// Capability ports now live in `vortix-core::ports::*`.
// Keep the legacy trait names as aliases so existing call sites keep working.
pub use crate::core::ports::dns::DnsResolver;
pub use crate::core::ports::interface::Interface as InterfaceDetector;
pub use crate::core::ports::killswitch::Killswitch as Firewall;
pub use crate::core::ports::network_stats::NetworkStats as NetworkStatsProvider;
pub use crate::core::ports::route_table::RouteTable;

fn syscall_result(result: libc::c_int) -> std::io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Replace the current process's supplementary groups on macOS.
///
/// This is called from a `pre_exec` closure, so it performs only bounded
/// scalar conversion and the async-signal-safe `setgroups` syscall.
#[cfg(target_os = "macos")]
pub(crate) fn set_process_supplementary_groups(groups: &[u32]) -> std::io::Result<()> {
    let count =
        i32::try_from(groups.len()).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `groups` remains valid for the duration of the syscall.
    #[allow(unsafe_code)]
    let result = unsafe { libc::setgroups(count, groups.as_ptr()) };
    syscall_result(result)
}

/// Linux variant of [`set_process_supplementary_groups`].
#[cfg(target_os = "linux")]
pub(crate) fn set_process_supplementary_groups(groups: &[u32]) -> std::io::Result<()> {
    // SAFETY: `groups` remains valid for the duration of the syscall.
    #[allow(unsafe_code)]
    let result = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    syscall_result(result)
}

/// Resolve a user's complete OS group list without invoking an external
/// command. The libc signature differs between macOS and Linux, so the
/// normalization belongs at this platform boundary.
#[cfg(target_os = "macos")]
pub(crate) fn supplementary_groups_for_user(
    user: &std::ffi::CStr,
    gid: u32,
    max_groups: usize,
) -> Option<Vec<u32>> {
    let base_group = i32::try_from(gid).ok()?;
    let mut group_count = i32::try_from(max_groups).ok()?;
    let mut groups = vec![0_i32; max_groups];
    // SAFETY: the call uses the stable C string and a buffer whose length is
    // supplied through `group_count`.
    #[allow(unsafe_code)]
    unsafe {
        if libc::getgrouplist(
            user.as_ptr(),
            base_group,
            groups.as_mut_ptr(),
            &raw mut group_count,
        ) < 0
        {
            return None;
        }
        groups.truncate(usize::try_from(group_count).ok()?);
        if groups.is_empty() {
            return None;
        }
        groups
            .into_iter()
            .map(|group| u32::try_from(group).ok())
            .collect()
    }
}

/// Linux variant of [`supplementary_groups_for_user`].
#[cfg(target_os = "linux")]
pub(crate) fn supplementary_groups_for_user(
    user: &std::ffi::CStr,
    gid: u32,
    max_groups: usize,
) -> Option<Vec<u32>> {
    let mut group_count = i32::try_from(max_groups).ok()?;
    let mut groups = vec![0_u32; max_groups];
    // SAFETY: the call uses the stable C string and a buffer whose length is
    // supplied through `group_count`.
    #[allow(unsafe_code)]
    unsafe {
        if libc::getgrouplist(
            user.as_ptr(),
            gid,
            groups.as_mut_ptr(),
            &raw mut group_count,
        ) < 0
        {
            return None;
        }
        groups.truncate(usize::try_from(group_count).ok()?);
        if groups.is_empty() {
            return None;
        }
        Some(groups)
    }
}

/// The command that shows this platform's Vortix-owned firewall rules, so a
/// reader who is told Vortix cannot confirm them can look for themselves.
#[cfg(target_os = "macos")]
#[must_use]
pub fn firewall_inspect_hint() -> &'static str {
    "sudo pfctl -a com.apple/vortix.killswitch -sr"
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn firewall_inspect_hint() -> &'static str {
    "sudo nft list table inet vortix_killswitch"
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[must_use]
pub fn firewall_inspect_hint() -> &'static str {
    "(no firewall inspection command on this platform)"
}

/// Platform-appropriate install hint for a package.
#[cfg(target_os = "macos")]
#[must_use]
pub fn install_hint(pkg: &str) -> String {
    format!("brew install {pkg}")
}

/// The install command for this machine's package manager.
///
/// Read from `/etc/os-release`: `ID` first, then `ID_LIKE`, so derivatives
/// resolve to the family they are built on -- `CachyOS` and `EndeavourOS` report
/// `ID_LIKE=arch`, Nobara reports `fedora`, Mint reports `debian`. A distro
/// that matches nothing falls back to listing every family, which is what
/// this function used to print unconditionally.
#[cfg(target_os = "linux")]
fn install_command(pkg: &str) -> Option<String> {
    let release = std::fs::read_to_string("/etc/os-release").ok()?;
    let field = |key: &str| -> Option<String> {
        release.lines().find_map(|line| {
            let value = line.strip_prefix(key)?.strip_prefix('=')?;
            Some(value.trim_matches('"').to_lowercase())
        })
    };
    let ids = [field("ID"), field("ID_LIKE")];
    let families = ids.iter().flatten().flat_map(|v| {
        v.split_whitespace()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>()
    });
    for family in families {
        match family.as_str() {
            "debian" | "ubuntu" => return Some(format!("sudo apt install {pkg}")),
            "arch" | "archlinux" | "cachyos" | "manjaro" => {
                return Some(format!("sudo pacman -S {pkg}"))
            }
            "fedora" | "rhel" | "centos" => return Some(format!("sudo dnf install {pkg}")),
            _ => {}
        }
    }
    None
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn install_hint(pkg: &str) -> String {
    // A package whose name differs per family, or which is not a package at
    // all, keeps its hand-written block below.
    let uniform = matches!(pkg, "wg" | "wg-quick" | "wireguard-tools" | "openvpn");
    if uniform {
        let package = if pkg == "openvpn" {
            "openvpn"
        } else {
            "wireguard-tools"
        };
        if let Some(command) = install_command(package) {
            return command;
        }
    }
    match pkg {
        // systemd-resolved is managing DNS — need the systemd-provided shim.
        // `openresolv` will NOT work here (causes "signature mismatch").
        "resolvconf (systemd)" => "\
sudo apt install systemd-resolved  # Debian/Ubuntu (provides resolvconf shim)\n\
sudo pacman -S systemd-resolvconf  # Arch\n\
sudo dnf install systemd-resolved  # Fedora"
            .to_string(),
        // Non-systemd system — standalone openresolv works fine.
        "resolvconf" => "\
sudo apt install openresolv  # Debian/Ubuntu\n\
sudo pacman -S openresolv    # Arch\n\
sudo dnf install openresolv  # Fedora"
            .to_string(),
        // Not a package (#242) — the fix is a sysctl, boot-param, or profile edit.
        "host IPv6 (kernel disabled)" => "\
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0\n\
# if that reports 'unknown oid': remove ipv6.disable=1 from the kernel cmdline\n\
# or: remove the IPv6 entry from the profile's Address line"
            .to_string(),
        // WireGuard binaries (wg, wg-quick) and the package itself all
        // share the same install hint — both binaries ship in the
        // wireguard-tools package on every supported distro.
        "wg" | "wg-quick" | "wireguard-tools" => "\
sudo apt install wireguard-tools  # Debian/Ubuntu\n\
sudo pacman -S wireguard-tools    # Arch\n\
sudo dnf install wireguard-tools  # Fedora"
            .to_string(),
        // OpenVPN ships under its eponymous package everywhere.
        "openvpn" => "\
sudo apt install openvpn  # Debian/Ubuntu\n\
sudo pacman -S openvpn    # Arch\n\
sudo dnf install openvpn  # Fedora"
            .to_string(),
        // Unknown package: best-effort generic hint (the calling code
        // should add a specific case above before relying on this).
        _ => format!(
            "\
sudo apt install {pkg}  # Debian/Ubuntu\n\
sudo pacman -S {pkg}    # Arch\n\
sudo dnf install {pkg}  # Fedora"
        ),
    }
}

#[cfg(test)]
mod external_interface_tests {}
