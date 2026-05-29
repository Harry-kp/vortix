//! macOS DNS resolver via the `SystemConfiguration` framework.
//!
//! Plan 002 U7: replaced `scutil --dns` and `networksetup -getdnsservers`
//! shell-outs with direct queries against `SCDynamicStore`. Both shell-outs
//! ultimately read the same `State:/Network/Global/DNS` /
//! `Setup:/Network/Service/<uuid>/DNS` keys we read directly; the previous
//! string-parsing of their stdout is gone.

use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::base::{TCFType, ToVoid};
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::propertylist::CFPropertyList;
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use system_configuration::sys::schema_definitions::kSCPropNetDNSServerAddresses;

use crate::vortix_core::ports::dns::DnsResolver;

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const SC_STORE_NAME: &str = "vortix.dns";
const GLOBAL_DNS_KEY: &str = "State:/Network/Global/DNS";
const SETUP_SERVICES_PATTERN: &str = "Setup:/Network/Service/.*/DNS";

/// macOS DNS resolution via `SCDynamicStore` + `/etc/resolv.conf`.
pub struct MacDns;

impl DnsResolver for MacDns {
    fn get_dns_server() -> Option<String> {
        // Global DNS aggregates the active interface's configured nameservers
        // (the same view `scutil --dns` summarises). resolv.conf is kept as
        // the cross-system fallback for parity with the prior chain; the
        // service-level walk replaces the old `networksetup -getdnsservers`
        // last-resort lookup.
        try_global_dns()
            .or_else(try_resolv_conf)
            .or_else(try_service_dns)
    }
}

/// Try to get DNS from `/etc/resolv.conf`.
fn try_resolv_conf() -> Option<String> {
    let content = std::fs::read_to_string(RESOLV_CONF_PATH).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let dns = rest.trim().to_string();
            if !dns.is_empty() {
                return Some(dns);
            }
        }
    }
    None
}

/// Read the primary nameserver from `State:/Network/Global/DNS`.
///
/// Replaces `scutil --dns`'s `nameserver[0]:` line.
fn try_global_dns() -> Option<String> {
    let store = SCDynamicStoreBuilder::new(SC_STORE_NAME).build()?;
    first_server_address(&store, GLOBAL_DNS_KEY)
}

/// Walk every per-service DNS configuration and return the first populated one.
///
/// Replaces the prior `networksetup -listallnetworkservices` +
/// `networksetup -getdnsservers <service>` last-resort fallback. The
/// service-keyed config (Wi-Fi, Ethernet, USB LAN, …) lives under
/// `Setup:/Network/Service/<uuid>/DNS`; we don't need to know the
/// human-readable name to read it.
fn try_service_dns() -> Option<String> {
    let store = SCDynamicStoreBuilder::new(SC_STORE_NAME).build()?;
    let pattern = CFString::new(SETUP_SERVICES_PATTERN);
    let keys = store.get_keys(pattern)?;
    for i in 0..keys.len() {
        let key = keys.get(i)?;
        let key_str = key.to_string();
        if let Some(server) = first_server_address(&store, &key_str) {
            return Some(server);
        }
    }
    None
}

/// Look up `key` in the dynamic store, downcast the value to a
/// `CFDictionary`, then read the first entry of its `ServerAddresses`
/// array as a string.
fn first_server_address(store: &SCDynamicStore, key: &str) -> Option<String> {
    let dict = store
        .get(key)
        .and_then(CFPropertyList::downcast_into::<CFDictionary>)?;
    // SAFETY: `kSCPropNetDNSServerAddresses` is a static CFString symbol
    // exported by the SystemConfiguration framework; `.to_void()` produces
    // its const-void key pointer for the dictionary lookup. `find` returns
    // a borrowed `*const c_void` whose deref points at a `CFArrayRef`;
    // `wrap_under_get_rule` increments the retain count for safe ownership.
    #[allow(unsafe_code)]
    let array: CFArray<CFString> = unsafe {
        let key_ref = kSCPropNetDNSServerAddresses;
        let ptr = dict.find(key_ref.to_void())?;
        CFArray::<CFString>::wrap_under_get_rule((*ptr).cast())
    };
    if array.is_empty() {
        return None;
    }
    let first = array.get(0)?;
    let value = first.to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}
