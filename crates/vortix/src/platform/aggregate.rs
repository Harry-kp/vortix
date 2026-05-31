//! Platform aggregate — runtime-selectable per-OS port dispatcher (plan 003 U3/U5).
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

use crate::vortix_core::ports::killswitch::{
    ActiveTunnelInfo, KillswitchError, Result as KsResult,
};

#[cfg(target_os = "linux")]
use crate::vortix_platform_linux as platform_impl;
#[cfg(target_os = "macos")]
use crate::vortix_platform_macos as platform_impl;
#[cfg(target_os = "windows")]
use crate::vortix_platform_windows as platform_impl;

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
    /// If true, `check_wireguard_interface` always returns true.
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
    /// Canned interface name for `default_route_interface()` (plan #001 U4).
    pub interface: Option<String>,
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
    #[cfg(target_os = "windows")]
    Windows,
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
        use crate::vortix_core::ports::killswitch::Killswitch;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::PfFirewall::enable_blocking_multi(active),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::IptablesFirewall::enable_blocking_multi(active),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsFirewall::enable_blocking_multi(active),
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
        use crate::vortix_core::ports::killswitch::Killswitch;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::PfFirewall::disable_blocking(),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::IptablesFirewall::disable_blocking(),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsFirewall::disable_blocking(),
            Self::Mock(m) => m.disable_blocking(),
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
    #[cfg(target_os = "windows")]
    Windows,
    Mock(MockDns),
}

impl DnsResolverKind {
    /// Get the current system DNS server.
    #[must_use]
    pub fn get_dns_server(&self) -> Option<String> {
        use crate::vortix_core::ports::dns::DnsResolver;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::MacDns::get_dns_server(),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::LinuxDns::get_dns_server(),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsDns::get_dns_server(),
            Self::Mock(m) => m.dns.clone(),
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
    #[cfg(target_os = "windows")]
    Windows,
    Mock(MockInterface),
}

impl InterfaceKind {
    /// Whether a `WireGuard` interface exists for this profile name.
    #[must_use]
    pub fn check_wireguard_interface(&self, name: &str) -> bool {
        use crate::vortix_core::ports::interface::Interface;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::MacInterface::check_wireguard_interface(name),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::LinuxInterface::check_wireguard_interface(name),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsInterface::check_wireguard_interface(name),
            Self::Mock(m) => m.wg_present,
        }
    }

    /// Resolve the real interface name for a `WireGuard` profile.
    #[must_use]
    pub fn resolve_wireguard_interface(&self, name: &str) -> Option<String> {
        use crate::vortix_core::ports::interface::Interface;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::MacInterface::resolve_wireguard_interface(name),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::LinuxInterface::resolve_wireguard_interface(name),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsInterface::resolve_wireguard_interface(name),
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
        use crate::vortix_core::ports::interface::Interface;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::MacInterface::get_wireguard_pid(interface),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::LinuxInterface::get_wireguard_pid(interface),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsInterface::get_wireguard_pid(interface),
            Self::Mock(_) => None,
        }
    }

    /// `(ip, mtu)` for the interface.
    #[must_use]
    pub fn get_interface_info(&self, interface: &str) -> (String, String) {
        use crate::vortix_core::ports::interface::Interface;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::MacInterface::get_interface_info(interface),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::LinuxInterface::get_interface_info(interface),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsInterface::get_interface_info(interface),
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
    #[cfg(target_os = "windows")]
    Windows,
    Mock(MockNetworkStats),
}

impl NetworkStatsKind {
    /// Total bytes received and transmitted across all non-loopback interfaces.
    #[must_use]
    pub fn get_total_bytes(&self) -> (u64, u64) {
        use crate::vortix_core::ports::network_stats::NetworkStats;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::MacNetworkStats::get_total_bytes(),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::LinuxNetworkStats::get_total_bytes(),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsNetworkStats::get_total_bytes(),
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
    #[cfg(target_os = "windows")]
    Windows,
    Mock(MockRouteTable),
}

impl RouteTableKind {
    /// IP of the current default gateway, if any.
    #[must_use]
    pub fn default_gateway(&self) -> Option<String> {
        use crate::vortix_core::ports::route_table::RouteTable;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::MacRouteTable::default_gateway(),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::LinuxRouteTable::default_gateway(),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsRouteTable::default_gateway(),
            Self::Mock(m) => m.gateway.clone(),
        }
    }

    /// Name of the interface carrying the current default route, if any
    /// (plan #001 U4).
    #[must_use]
    pub fn default_route_interface(&self) -> Option<String> {
        use crate::vortix_core::ports::route_table::RouteTable;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::MacRouteTable::default_route_interface(),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::LinuxRouteTable::default_route_interface(),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsRouteTable::default_route_interface(),
            Self::Mock(m) => m.interface.clone(),
        }
    }
}

/// Scriptable mock for the `SocketAudit` port (plan 015 phase C).
#[derive(Debug, Default, Clone)]
pub struct MockSocketAudit {
    pub canned: Vec<crate::vortix_core::ports::socket_audit::SocketSnapshot>,
}

/// Static-dispatch carrier for the `SocketAudit` port (plan 015 phase C).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SocketAuditKind {
    #[cfg(target_os = "macos")]
    Macos,
    #[cfg(target_os = "linux")]
    Linux,
    #[cfg(target_os = "windows")]
    Windows,
    Mock(MockSocketAudit),
}

impl SocketAuditKind {
    /// Snapshot the current socket inventory.
    ///
    /// # Errors
    ///
    /// See `crate::vortix_core::ports::socket_audit::SocketAuditError`.
    pub fn snapshot(
        &self,
    ) -> crate::vortix_core::ports::socket_audit::SocketAuditResult<
        Vec<crate::vortix_core::ports::socket_audit::SocketSnapshot>,
    > {
        use crate::vortix_core::ports::socket_audit::SocketAudit;
        match self {
            #[cfg(target_os = "macos")]
            Self::Macos => platform_impl::LsofSocketAudit::snapshot(),
            #[cfg(target_os = "linux")]
            Self::Linux => platform_impl::ProcSocketAudit::snapshot(),
            #[cfg(target_os = "windows")]
            Self::Windows => platform_impl::WindowsSocketAudit::snapshot(),
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
        #[cfg(target_os = "windows")]
        {
            Self {
                killswitch: KillswitchKind::Windows,
                dns: DnsResolverKind::Windows,
                interface: InterfaceKind::Windows,
                network_stats: NetworkStatsKind::Windows,
                route_table: RouteTableKind::Windows,
                socket_audit: SocketAuditKind::Windows,
            }
        }
    }

    /// Live network-interface enumeration (plan multi-connection U11).
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
        #[cfg(target_os = "windows")]
        {
            platform_impl::interface_list::available_network_interfaces()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
        });
        assert_eq!(rt.default_gateway(), Some("192.168.1.1".into()));
    }

    #[test]
    fn mock_route_table_returns_canned_interface() {
        let rt = RouteTableKind::Mock(MockRouteTable {
            gateway: None,
            interface: Some("utun3".into()),
        });
        assert_eq!(rt.default_route_interface(), Some("utun3".into()));
    }

    #[test]
    fn mock_route_table_interface_defaults_to_none() {
        let rt = RouteTableKind::Mock(MockRouteTable::default());
        assert_eq!(rt.default_route_interface(), None);
    }
}
