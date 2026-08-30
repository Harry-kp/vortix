//! macOS DNS policy via the `SystemConfiguration` framework and scoped
//! `/private/etc/resolver` files.
//!
//! replaced `scutil --dns` and `networksetup -getdnsservers`
//! shell-outs with direct queries against `SCDynamicStore`. Both shell-outs
//! ultimately read the same `State:/Network/Global/DNS` /
//! `Setup:/Network/Service/<uuid>/DNS` keys we read directly; the previous
//! string-parsing of their stdout is gone.

use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::base::{CFType, TCFType, ToVoid};
use system_configuration::core_foundation::data::CFData;
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::number::CFNumber;
use system_configuration::core_foundation::propertylist::{
    create_data, create_with_data, kCFPropertyListBinaryFormat_v1_0, kCFPropertyListImmutable,
    CFPropertyList, CFPropertyListSubClass,
};
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use system_configuration::sys::schema_definitions::{
    kSCDynamicStorePropNetPrimaryService, kSCPropNetDNSSearchDomains, kSCPropNetDNSSearchOrder,
    kSCPropNetDNSServerAddresses,
};

use crate::vortix_core::ports::dns::DnsResolver;
use crate::vortix_core::ports::dns::{
    DnsAssignment, DnsEffectiveState, DnsEffectiveStatus, DnsOwnedResource,
    DnsPlatformCapabilities, DnsPolicy, DnsPolicyAdapter, DnsScope,
};
use crate::vortix_core::ports::owned_dns::{
    ExpectedDnsState, OwnedDns, OwnedDnsBackend, OwnedDnsError,
};

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const SC_STORE_NAME: &str = "vortix.dns";
const GLOBAL_DNS_KEY: &str = "State:/Network/Global/DNS";
const GLOBAL_IPV4_KEY: &str = "State:/Network/Global/IPv4";
const SETUP_SERVICES_PATTERN: &str = "Setup:/Network/Service/.*/DNS";
const VORTIX_PRIMARY_DNS_BACKUP_KEY: &str = "State:/Network/Service/vortix/DnsBackup";
const VORTIX_PRIMARY_DNS_OWNER_KEY: &str = "State:/Network/Service/vortix/DnsOwner";
const VORTIX_PRIMARY_DNS_RESOURCE_ID: &str = "macos:system-configuration:primary-dns";
const MAX_DYNAMIC_STORE_VALUE_BYTES: usize = 128 * 1024;
const MANAGED_DNS_PREFERENCES_DOMAIN: &str = "com.apple.dnsSettings.managed";
const MANAGED_DNS_SETTINGS_KEY: &str = "DNSSettings";
const MANAGED_DNS_PROTOCOL_KEY: &str = "DNSProtocol";

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

const VORTIX_RESOLVER_MARKER: &str = "# managed-by: vortix dns";
const MAX_RESOLVER_FILES: usize = 256;
const MAX_RESOLVER_BYTES: u64 = 64 * 1024;

impl DnsPolicyAdapter for MacDns {
    fn capabilities(&self) -> DnsPlatformCapabilities {
        DnsPlatformCapabilities {
            scoped_domains: true,
        }
    }

    fn apply(
        &self,
        desired: &DnsPolicy,
        previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> DnsEffectiveState {
        MacDnsPolicy::system().apply(desired, previous_desired, previous_effective)
    }

    fn verify(
        &self,
        desired: &DnsPolicy,
        effective: &DnsEffectiveState,
    ) -> Result<(), Vec<String>> {
        MacDnsPolicy::system().verify(desired, effective)
    }
}

/// Vortix-owned macOS DNS adapter. Catch-all policy follows the active primary
/// service with an exact dynamic-store backup; scoped domains use resolver
/// files. A configurable test backend exercises ownership and crash recovery
/// without touching the developer's resolver configuration.
#[derive(Debug, Clone)]
pub struct MacDnsPolicy {
    resolver_dir: std::path::PathBuf,
    expected_owner_uid: u32,
    dynamic_store: MacDynamicStore,
    managed_dns: ManagedDnsSource,
    #[cfg(test)]
    fail_readback_at: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
enum ManagedDnsSource {
    SystemPreferences,
    #[cfg(test)]
    Fixed(bool),
}

#[derive(Debug, Clone)]
enum MacDynamicStore {
    System,
    #[cfg(test)]
    Memory(std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>>),
}

#[allow(
    unsafe_code,
    reason = "CoreFoundation exposes managed preference ownership through its C API"
)]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFPreferencesAppValueIsForced(
        key: *const std::ffi::c_void,
        application_id: *const std::ffi::c_void,
    ) -> u8;
    fn CFPreferencesCopyAppValue(
        key: *const std::ffi::c_void,
        application_id: *const std::ffi::c_void,
    ) -> *const std::ffi::c_void;
}

impl ManagedDnsSource {
    fn forced_encrypted_dns(self) -> Result<bool, String> {
        match self {
            Self::SystemPreferences => system_forced_encrypted_dns(),
            #[cfg(test)]
            Self::Fixed(value) => Ok(value),
        }
    }
}

#[allow(
    unsafe_code,
    reason = "the copied CoreFoundation preference is transferred into a retained safe wrapper"
)]
fn system_forced_encrypted_dns() -> Result<bool, String> {
    let key = CFString::new(MANAGED_DNS_SETTINGS_KEY);
    let domain = CFString::new(MANAGED_DNS_PREFERENCES_DOMAIN);
    // SAFETY: both pointers are retained CFStrings for the duration of each
    // CoreFoundation call.
    let forced = unsafe { CFPreferencesAppValueIsForced(key.to_void(), domain.to_void()) != 0 };
    if !forced {
        return Ok(false);
    }
    // SAFETY: CopyAppValue follows the create rule. A non-null result is one
    // owned property-list reference transferred into the safe wrapper.
    let raw = unsafe { CFPreferencesCopyAppValue(key.to_void(), domain.to_void()) };
    if raw.is_null() {
        return Err("managed DNS ownership is forced but its settings are unavailable".into());
    }
    let settings = unsafe { CFPropertyList::wrap_under_create_rule(raw.cast()) };
    managed_dns_protocol(&settings).map(|protocol| {
        protocol.eq_ignore_ascii_case("HTTPS") || protocol.eq_ignore_ascii_case("TLS")
    })
}

#[allow(
    unsafe_code,
    reason = "the typed wrapper validates a value borrowed from a CoreFoundation dictionary"
)]
fn managed_dns_protocol(settings: &CFPropertyList) -> Result<String, String> {
    let dictionary = settings
        .clone()
        .downcast_into::<CFDictionary>()
        .ok_or_else(|| "managed DNS settings are not a dictionary".to_string())?;
    let key = CFString::new(MANAGED_DNS_PROTOCOL_KEY);
    let value = dictionary
        .find(key.to_void())
        .ok_or_else(|| "managed DNS settings have no DNSProtocol".to_string())?;
    // SAFETY: the dictionary retains the borrowed value while the wrapper is
    // constructed, and downcast validates that it is a CFString.
    unsafe { CFPropertyList::wrap_under_get_rule((*value).cast()) }
        .downcast_into::<CFString>()
        .map(|value| value.to_string())
        .ok_or_else(|| "managed DNS protocol is not a string".to_string())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrimaryDnsOwner {
    generation: u64,
    profile_id: String,
    interface: String,
    service_key: String,
    servers: Vec<String>,
    search_domains: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PrimaryDnsBackup {
    service_key: String,
    encoded_value: String,
}

#[derive(Debug)]
struct PlannedResolver {
    resource: DnsOwnedResource,
    path: std::path::PathBuf,
    name: std::ffi::CString,
    body: String,
    original: Option<Vec<u8>>,
}

impl MacDynamicStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::System => {
                let store = SCDynamicStoreBuilder::new(SC_STORE_NAME)
                    .build()
                    .ok_or_else(|| "cannot open the macOS dynamic store".to_string())?;
                store.get(key).map(|value| encode_plist(&value)).transpose()
            }
            #[cfg(test)]
            Self::Memory(values) => values
                .lock()
                .map_err(|_| "test dynamic store lock poisoned".to_string())
                .map(|values| values.get(key).cloned()),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), String> {
        if value.is_empty() || value.len() > MAX_DYNAMIC_STORE_VALUE_BYTES {
            return Err("macOS dynamic-store value is empty or too large".to_string());
        }
        match self {
            Self::System => {
                let store = SCDynamicStoreBuilder::new(SC_STORE_NAME)
                    .build()
                    .ok_or_else(|| "cannot open the macOS dynamic store".to_string())?;
                let value = decode_plist(value)?;
                if store.set_raw(key, &value) {
                    Ok(())
                } else {
                    Err(format!("cannot set macOS dynamic-store key {key}"))
                }
            }
            #[cfg(test)]
            Self::Memory(values) => values
                .lock()
                .map_err(|_| "test dynamic store lock poisoned".to_string())
                .map(|mut values| {
                    values.insert(key.to_string(), value.to_vec());
                }),
        }
    }

    fn remove(&self, key: &str) -> Result<(), String> {
        match self {
            Self::System => {
                let store = SCDynamicStoreBuilder::new(SC_STORE_NAME)
                    .build()
                    .ok_or_else(|| "cannot open the macOS dynamic store".to_string())?;
                if store.get(key).is_none() || store.remove(key) {
                    Ok(())
                } else {
                    Err(format!("cannot remove macOS dynamic-store key {key}"))
                }
            }
            #[cfg(test)]
            Self::Memory(values) => values
                .lock()
                .map_err(|_| "test dynamic store lock poisoned".to_string())
                .map(|mut values| {
                    values.remove(key);
                }),
        }
    }

    fn flush_dns_cache(&self) -> Result<(), String> {
        match self {
            Self::System => {
                let output = crate::platform::fixed_root_command::run(
                    &["/usr/bin/dscacheutil"],
                    &["-flushcache"],
                    None,
                    0,
                )
                .map_err(|_| "cannot run the macOS DNS cache flush".to_string())?;
                if output.status.success() {
                    Ok(())
                } else {
                    Err("macOS DNS cache flush failed".to_string())
                }
            }
            #[cfg(test)]
            Self::Memory(_) => Ok(()),
        }
    }

    #[cfg(test)]
    fn memory() -> Self {
        let service_id = "test-primary-service";
        let service_key = format!("Setup:/Network/Service/{service_id}/DNS");
        let values = std::collections::BTreeMap::from([
            (
                GLOBAL_IPV4_KEY.to_string(),
                primary_service_value(service_id).expect("test primary service value is valid"),
            ),
            (
                service_key,
                primary_dns_value(&["192.0.2.53".to_string()], &[])
                    .expect("test DNS value is valid"),
            ),
        ]);
        Self::Memory(std::sync::Arc::new(std::sync::Mutex::new(values)))
    }
}

fn encode_plist(value: &CFPropertyList) -> Result<Vec<u8>, String> {
    let data = create_data(value.as_CFTypeRef(), kCFPropertyListBinaryFormat_v1_0)
        .map_err(|error| format!("cannot encode macOS dynamic-store value: {error:?}"))?;
    let length = usize::try_from(data.len())
        .map_err(|_| "macOS dynamic-store value has a negative length".to_string())?;
    if length > MAX_DYNAMIC_STORE_VALUE_BYTES {
        return Err("macOS dynamic-store value exceeds its fixed limit".to_string());
    }
    Ok(data.bytes().to_vec())
}

#[allow(
    unsafe_code,
    reason = "CoreFoundation create-rule ownership must be transferred into the safe wrapper"
)]
fn decode_plist(value: &[u8]) -> Result<CFPropertyList, String> {
    if value.is_empty() || value.len() > MAX_DYNAMIC_STORE_VALUE_BYTES {
        return Err("macOS dynamic-store value is empty or too large".to_string());
    }
    let (value, _) = create_with_data(CFData::from_buffer(value), kCFPropertyListImmutable)
        .map_err(|error| format!("cannot decode macOS dynamic-store value: {error:?}"))?;
    // SAFETY: `create_with_data` returned one retained property-list object.
    Ok(unsafe { CFPropertyList::wrap_under_create_rule(value.cast()) })
}

fn encode_cf_value(value: impl CFPropertyListSubClass) -> Result<Vec<u8>, String> {
    encode_plist(&value.into_CFPropertyList())
}

#[allow(
    unsafe_code,
    reason = "SystemConfiguration exports process-lifetime CoreFoundation string symbols"
)]
#[cfg(test)]
fn primary_service_value(service_id: &str) -> Result<Vec<u8>, String> {
    // SAFETY: the SystemConfiguration symbol is a process-lifetime CFString.
    let key = unsafe { CFString::wrap_under_get_rule(kSCDynamicStorePropNetPrimaryService) };
    let value = CFString::new(service_id);
    let typed = CFDictionary::from_CFType_pairs(&[(key, value)]);
    let value = unsafe { CFDictionary::wrap_under_get_rule(typed.as_concrete_TypeRef()) };
    encode_cf_value(value)
}

#[allow(
    unsafe_code,
    reason = "SystemConfiguration exports process-lifetime CoreFoundation string symbols"
)]
fn primary_dns_value(servers: &[String], search_domains: &[String]) -> Result<Vec<u8>, String> {
    // SAFETY: the SystemConfiguration symbols are process-lifetime CFStrings.
    let server_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
    let search_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSearchDomains) };
    let order_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSearchOrder) };
    let servers = CFArray::from_CFTypes(
        &servers
            .iter()
            .map(|server| CFString::new(server))
            .collect::<Vec<_>>(),
    );
    let search_domains = CFArray::from_CFTypes(
        &search_domains
            .iter()
            .map(|domain| CFString::new(domain))
            .collect::<Vec<_>>(),
    );
    let order = CFNumber::from(5000_i32);
    let mut pairs: Vec<(CFType, CFType)> = vec![
        (server_key.as_CFType(), servers.as_CFType()),
        (order_key.as_CFType(), order.as_CFType()),
    ];
    if !search_domains.is_empty() {
        pairs.push((search_key.as_CFType(), search_domains.as_CFType()));
    }
    let typed = CFDictionary::from_CFType_pairs(&pairs);
    let value = unsafe { CFDictionary::wrap_under_get_rule(typed.as_concrete_TypeRef()) };
    encode_cf_value(value)
}

fn encode_json_string(value: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    let json = serde_json::to_string(value)
        .map_err(|error| format!("cannot encode Vortix DNS ownership: {error}"))?;
    encode_cf_value(CFString::new(&json))
}

fn decode_json_string<T: serde::de::DeserializeOwned>(value: &[u8]) -> Result<T, String> {
    let value = decode_plist(value)?
        .downcast_into::<CFString>()
        .ok_or_else(|| "Vortix DNS ownership value is not a string".to_string())?;
    serde_json::from_str(&value.to_string())
        .map_err(|error| format!("cannot decode Vortix DNS ownership: {error}"))
}

fn plist_values_equal(left: &[u8], right: &[u8]) -> Result<bool, String> {
    Ok(decode_plist(left)? == decode_plist(right)?)
}

#[allow(
    unsafe_code,
    reason = "typed wrappers validate values obtained through CoreFoundation dictionary pointers"
)]
#[cfg(test)]
fn dns_server_addresses(value: &[u8]) -> Result<Vec<String>, String> {
    let dictionary = decode_plist(value)?
        .downcast_into::<CFDictionary>()
        .ok_or_else(|| "macOS DNS value is not a dictionary".to_string())?;
    // SAFETY: the SystemConfiguration symbol is a process-lifetime CFString.
    let key = unsafe { kSCPropNetDNSServerAddresses };
    let value = dictionary
        .find(key.to_void())
        .ok_or_else(|| "macOS DNS value has no ServerAddresses".to_string())?;
    // SAFETY: this value was validated as an array by `downcast_into`; the
    // dictionary retains it for the lifetime of this wrapper.
    let array = unsafe {
        CFPropertyList::wrap_under_get_rule((*value).cast())
            .downcast_into::<CFArray>()
            .ok_or_else(|| "macOS DNS ServerAddresses is not an array".to_string())?
    };
    let capacity = usize::try_from(array.len())
        .map_err(|_| "macOS DNS ServerAddresses has a negative length".to_string())?;
    let mut addresses = Vec::with_capacity(capacity);
    for index in 0..array.len() {
        let value = array
            .get(index)
            .ok_or_else(|| "macOS DNS ServerAddresses changed while reading".to_string())?;
        // SAFETY: the DNS dictionary contract requires string array entries.
        let value = unsafe { CFString::wrap_under_get_rule((*value).cast()) };
        addresses.push(value.to_string());
    }
    Ok(addresses)
}

impl MacDnsPolicy {
    fn directory(&self, create: bool) -> Result<Option<ResolverDirectory>, String> {
        ResolverDirectory::open(&self.resolver_dir, self.expected_owner_uid, create)
    }

    fn resolver_name(path: &std::path::Path) -> Result<std::ffi::CString, String> {
        let name = path
            .file_name()
            .ok_or_else(|| "resolver path has no basename".to_string())?;
        std::ffi::CString::new(name.as_encoded_bytes())
            .map_err(|_| "resolver basename contains NUL".to_string())
    }

    fn read_owned_resolver(&self, path: &std::path::Path) -> Result<Option<Vec<u8>>, String> {
        let Some(directory) = self.directory(false)? else {
            return Ok(None);
        };
        let body = directory.read(&Self::resolver_name(path)?)?;
        if let Some(body) = body.as_ref() {
            if !body.starts_with(VORTIX_RESOLVER_MARKER.as_bytes()) {
                return Err(format!(
                    "refusing to replace foreign DNS resolver {}",
                    path.display()
                ));
            }
        }
        Ok(body)
    }

    fn write_owned_resolver(&self, resolver: &PlannedResolver, body: &[u8]) -> Result<(), String> {
        let directory = self
            .directory(true)?
            .ok_or_else(|| "resolver directory was not created".to_string())?;
        directory.write(&resolver.name, body)
    }

    #[must_use]
    pub fn system() -> Self {
        Self {
            // `/etc` is a compatibility symlink on macOS. The privileged
            // writer opens every component with `O_NOFOLLOW`, so use the
            // canonical root-owned location directly.
            resolver_dir: std::path::PathBuf::from("/private/etc/resolver"),
            expected_owner_uid: 0,
            dynamic_store: MacDynamicStore::System,
            managed_dns: ManagedDnsSource::SystemPreferences,
            #[cfg(test)]
            fail_readback_at: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn at(resolver_dir: std::path::PathBuf) -> Self {
        let resolver_dir = canonical_test_resolver_dir(resolver_dir);
        Self {
            resolver_dir,
            expected_owner_uid: crate::utils::effective_user_group_ids().0,
            dynamic_store: MacDynamicStore::memory(),
            managed_dns: ManagedDnsSource::Fixed(false),
            fail_readback_at: None,
        }
    }

    #[cfg(test)]
    fn at_with_managed_encrypted_dns(resolver_dir: std::path::PathBuf) -> Self {
        let mut policy = Self::at(resolver_dir);
        policy.managed_dns = ManagedDnsSource::Fixed(true);
        policy
    }

    #[cfg(test)]
    fn at_failing_readback(resolver_dir: std::path::PathBuf, write_number: usize) -> Self {
        let resolver_dir = canonical_test_resolver_dir(resolver_dir);
        Self {
            resolver_dir,
            expected_owner_uid: crate::utils::effective_user_group_ids().0,
            dynamic_store: MacDynamicStore::memory(),
            managed_dns: ManagedDnsSource::Fixed(false),
            fail_readback_at: Some(write_number),
        }
    }

    fn ensure_catch_all_dns_is_available(&self) -> Result<(), String> {
        match self.managed_dns.forced_encrypted_dns() {
            Ok(false) => Ok(()),
            Ok(true) => Err(
                "macOS managed encrypted DNS owns system resolution; refusing catch-all DNS because overriding device-management policy can leave networking unusable"
                    .to_string(),
            ),
            Err(error) => Err(format!(
                "cannot prove macOS managed DNS ownership before applying catch-all DNS: {error}"
            )),
        }
    }

    fn primary_assignment(policy: &DnsPolicy) -> Result<Option<&DnsAssignment>, String> {
        let mut assignments = policy
            .assignments
            .iter()
            .filter(|assignment| matches!(assignment.scope, DnsScope::CatchAll));
        let assignment = assignments.next();
        if assignments.next().is_some() {
            return Err("macOS DNS policy contains more than one catch-all owner".to_string());
        }
        Ok(assignment)
    }

    fn primary_resource(generation: u64, assignment: &DnsAssignment) -> DnsOwnedResource {
        DnsOwnedResource {
            generation,
            id: VORTIX_PRIMARY_DNS_RESOURCE_ID.to_string(),
            profile_id: assignment.profile_id.clone(),
            interface: assignment.interface.clone(),
        }
    }

    fn primary_owner(
        generation: u64,
        assignment: &DnsAssignment,
        service_key: String,
    ) -> PrimaryDnsOwner {
        PrimaryDnsOwner {
            generation,
            profile_id: assignment.profile_id.as_str().to_string(),
            interface: assignment.interface.clone(),
            service_key,
            servers: assignment.servers.iter().map(ToString::to_string).collect(),
            search_domains: assignment.search_domains.clone(),
        }
    }

    #[allow(
        unsafe_code,
        reason = "typed wrapper validates the process-lifetime SystemConfiguration dictionary value"
    )]
    fn primary_service_key(&self) -> Result<String, String> {
        let value = self
            .dynamic_store
            .get(GLOBAL_IPV4_KEY)?
            .ok_or_else(|| "macOS has no active primary network service".to_string())?;
        let dictionary = decode_plist(&value)?
            .downcast_into::<CFDictionary>()
            .ok_or_else(|| "macOS primary-service state is not a dictionary".to_string())?;
        // SAFETY: the SystemConfiguration symbol is a process-lifetime CFString.
        let key = unsafe { kSCDynamicStorePropNetPrimaryService };
        let service = dictionary
            .find(key.to_void())
            .map(|value| unsafe { CFString::wrap_under_get_rule((*value).cast()) })
            .ok_or_else(|| "macOS primary-service state has no PrimaryService".to_string())?;
        let service = service.to_string();
        if service.is_empty() || service.contains('/') || service.contains('\0') {
            return Err("macOS primary service identifier is unsafe".to_string());
        }
        Ok(format!("Setup:/Network/Service/{service}/DNS"))
    }

    fn primary_owner_state(&self) -> Result<Option<PrimaryDnsOwner>, String> {
        self.dynamic_store
            .get(VORTIX_PRIMARY_DNS_OWNER_KEY)?
            .map(|value| decode_json_string(&value))
            .transpose()
    }

    fn primary_backup_state(&self) -> Result<Option<PrimaryDnsBackup>, String> {
        self.dynamic_store
            .get(VORTIX_PRIMARY_DNS_BACKUP_KEY)?
            .map(|value| decode_json_string(&value))
            .transpose()
    }

    fn set_primary_owner(&self, owner: &PrimaryDnsOwner) -> Result<(), String> {
        let encoded = encode_json_string(owner)?;
        self.dynamic_store
            .set(VORTIX_PRIMARY_DNS_OWNER_KEY, &encoded)?;
        match self.primary_owner_state()? {
            Some(read_back) if read_back == *owner => Ok(()),
            _ => Err("macOS primary DNS ownership read-back mismatch".to_string()),
        }
    }

    fn set_primary_backup(&self, backup: &PrimaryDnsBackup) -> Result<(), String> {
        let encoded = encode_json_string(backup)?;
        self.dynamic_store
            .set(VORTIX_PRIMARY_DNS_BACKUP_KEY, &encoded)?;
        match self.primary_backup_state()? {
            Some(read_back) if read_back == *backup => Ok(()),
            _ => Err("macOS primary DNS backup read-back mismatch".to_string()),
        }
    }

    fn owner_dns_value(owner: &PrimaryDnsOwner) -> Result<Vec<u8>, String> {
        primary_dns_value(&owner.servers, &owner.search_domains)
    }

    fn backup_value(backup: &PrimaryDnsBackup) -> Result<Vec<u8>, String> {
        use base64::Engine as _;

        base64::engine::general_purpose::STANDARD
            .decode(&backup.encoded_value)
            .map_err(|_| "macOS primary DNS backup is not valid base64".to_string())
            .and_then(|value| {
                decode_plist(&value)?;
                Ok(value)
            })
    }

    fn new_backup(service_key: String, value: &[u8]) -> PrimaryDnsBackup {
        use base64::Engine as _;

        PrimaryDnsBackup {
            service_key,
            encoded_value: base64::engine::general_purpose::STANDARD.encode(value),
        }
    }

    fn restore_dynamic_value(&self, key: &str, value: Option<&[u8]>) -> Result<(), String> {
        value.map_or_else(
            || self.dynamic_store.remove(key),
            |value| self.dynamic_store.set(key, value),
        )
    }

    fn apply_primary(
        &self,
        generation: u64,
        assignment: &DnsAssignment,
        previous: Option<(u64, &DnsAssignment)>,
    ) -> Result<(), String> {
        let old_owner = self.dynamic_store.get(VORTIX_PRIMARY_DNS_OWNER_KEY)?;
        let old_backup = self.dynamic_store.get(VORTIX_PRIMARY_DNS_BACKUP_KEY)?;
        let parsed_owner = old_owner
            .as_deref()
            .map(decode_json_string::<PrimaryDnsOwner>)
            .transpose()?;
        let parsed_backup = old_backup
            .as_deref()
            .map(decode_json_string::<PrimaryDnsBackup>)
            .transpose()?;

        let service_key = match (&parsed_owner, &parsed_backup) {
            (Some(owner), Some(backup)) if owner.service_key == backup.service_key => {
                owner.service_key.clone()
            }
            (None, Some(backup)) => backup.service_key.clone(),
            (None, None) => self.primary_service_key()?,
            _ => return Err("macOS primary DNS ownership and backup disagree".to_string()),
        };
        let old_service = self.dynamic_store.get(&service_key)?;
        let old_service = old_service
            .ok_or_else(|| "macOS primary network service has no DNS configuration".to_string())?;
        let owner = Self::primary_owner(generation, assignment, service_key.clone());
        let desired = Self::owner_dns_value(&owner)?;

        let needs_backup = parsed_owner.is_none() && parsed_backup.is_none();
        if let Some(current_owner) = parsed_owner.as_ref() {
            let owner_is_desired = current_owner == &owner;
            let owner_is_prior = previous.is_some_and(|(prior_generation, prior_assignment)| {
                current_owner
                    == &Self::primary_owner(prior_generation, prior_assignment, service_key.clone())
            });
            if !owner_is_desired && !owner_is_prior {
                return Err("macOS primary DNS is owned by another generation".to_string());
            }
            let current_expected = Self::owner_dns_value(current_owner)?;
            if !plist_values_equal(&old_service, &current_expected)?
                && !plist_values_equal(&old_service, &desired)?
            {
                return Err("macOS primary DNS changed during replacement".to_string());
            }
        } else if parsed_backup.is_some() {
            let backup = parsed_backup
                .as_ref()
                .ok_or_else(|| "macOS primary DNS backup disappeared".to_string())?;
            let prior = Self::backup_value(backup)?;
            let desired_owner = Self::primary_owner(generation, assignment, service_key.clone());
            let desired = Self::owner_dns_value(&desired_owner)?;
            if !plist_values_equal(&old_service, &prior)?
                && !plist_values_equal(&old_service, &desired)?
            {
                return Err("macOS primary DNS changed during interrupted apply".to_string());
            }
        }

        let result = (|| {
            if needs_backup {
                self.set_primary_backup(&Self::new_backup(service_key.clone(), &old_service))?;
            }
            self.dynamic_store.set(&service_key, &desired)?;
            let read_back = self
                .dynamic_store
                .get(&service_key)?
                .ok_or_else(|| "macOS primary DNS disappeared after apply".to_string())?;
            if !plist_values_equal(&read_back, &desired)? {
                return Err("macOS primary DNS read-back mismatch".to_string());
            }
            self.set_primary_owner(&owner)?;
            self.dynamic_store.flush_dns_cache()
        })();
        if let Err(error) = result {
            let mut rollback_errors = Vec::new();
            if let Err(rollback) = self.restore_dynamic_value(&service_key, Some(&old_service)) {
                rollback_errors.push(rollback);
            }
            if let Err(rollback) =
                self.restore_dynamic_value(VORTIX_PRIMARY_DNS_OWNER_KEY, old_owner.as_deref())
            {
                rollback_errors.push(rollback);
            }
            if let Err(rollback) =
                self.restore_dynamic_value(VORTIX_PRIMARY_DNS_BACKUP_KEY, old_backup.as_deref())
            {
                rollback_errors.push(rollback);
            }
            if let Err(rollback) = self.dynamic_store.flush_dns_cache() {
                rollback_errors.push(rollback);
            }
            return if rollback_errors.is_empty() {
                Err(error)
            } else {
                Err(format!(
                    "{error}; primary DNS rollback failed: {}",
                    rollback_errors.join("; ")
                ))
            };
        }
        Ok(())
    }

    fn verify_primary(&self, generation: u64, assignment: &DnsAssignment) -> Result<(), String> {
        let owner = self
            .primary_owner_state()?
            .ok_or_else(|| "macOS primary DNS has no Vortix owner".to_string())?;
        let expected = Self::primary_owner(generation, assignment, owner.service_key.clone());
        if owner != expected {
            return Err("macOS primary DNS ownership does not match policy".to_string());
        }
        let backup = self
            .primary_backup_state()?
            .ok_or_else(|| "macOS primary DNS has no Vortix backup".to_string())?;
        if backup.service_key != owner.service_key {
            return Err("macOS primary DNS ownership and backup disagree".to_string());
        }
        let actual = self
            .dynamic_store
            .get(&owner.service_key)?
            .ok_or_else(|| "macOS primary DNS configuration is absent".to_string())?;
        if plist_values_equal(&actual, &Self::owner_dns_value(&owner)?)? {
            Ok(())
        } else {
            Err("macOS primary DNS configuration does not match policy".to_string())
        }
    }

    fn release_primary(&self, resource: &DnsOwnedResource) -> Result<(), String> {
        let owner = self.primary_owner_state()?;
        let backup = self.primary_backup_state()?;
        let Some(backup) = backup else {
            return if owner.is_none() {
                Ok(())
            } else {
                Err("macOS primary DNS backup is absent".to_string())
            };
        };
        let prior = Self::backup_value(&backup)?;

        let Some(owner) = owner else {
            let actual = self
                .dynamic_store
                .get(&backup.service_key)?
                .ok_or_else(|| "macOS primary DNS configuration is absent".to_string())?;
            if !plist_values_equal(&actual, &prior)? {
                return Err("macOS primary DNS changed during interrupted release".to_string());
            }
            return self.dynamic_store.remove(VORTIX_PRIMARY_DNS_BACKUP_KEY);
        };
        if owner.service_key != backup.service_key {
            return Err("macOS primary DNS ownership and backup disagree".to_string());
        }
        if owner.generation != resource.generation
            || owner.profile_id != resource.profile_id.as_str()
            || owner.interface != resource.interface
        {
            return Ok(());
        }
        let actual = self
            .dynamic_store
            .get(&owner.service_key)?
            .ok_or_else(|| "macOS primary DNS configuration is absent".to_string())?;
        if !plist_values_equal(&actual, &Self::owner_dns_value(&owner)?)? {
            return Err("refusing to overwrite externally changed macOS DNS".to_string());
        }
        self.dynamic_store.set(&owner.service_key, &prior)?;
        let restored = self
            .dynamic_store
            .get(&owner.service_key)?
            .ok_or_else(|| "restored macOS primary DNS disappeared".to_string())?;
        if !plist_values_equal(&restored, &prior)? {
            return Err("macOS primary DNS restoration read-back mismatch".to_string());
        }
        self.dynamic_store.flush_dns_cache()?;
        self.dynamic_store.remove(VORTIX_PRIMARY_DNS_OWNER_KEY)?;
        self.dynamic_store.remove(VORTIX_PRIMARY_DNS_BACKUP_KEY)
    }

    fn primary_resource_is_present(&self, resource: &DnsOwnedResource) -> bool {
        self.primary_owner_state()
            .ok()
            .flatten()
            .is_some_and(|owner| {
                owner.generation == resource.generation
                    && owner.profile_id == resource.profile_id.as_str()
                    && owner.interface == resource.interface
                    && self
                        .dynamic_store
                        .get(&owner.service_key)
                        .ok()
                        .flatten()
                        .and_then(|actual| {
                            Self::owner_dns_value(&owner)
                                .ok()
                                .and_then(|expected| plist_values_equal(&actual, &expected).ok())
                        })
                        == Some(true)
            })
    }

    #[cfg(test)]
    fn test_primary_dns_servers(&self) -> Vec<String> {
        let service_key = self.primary_service_key().unwrap();
        let value = self.dynamic_store.get(&service_key).unwrap().unwrap();
        dns_server_addresses(&value).unwrap()
    }

    fn resources_for(
        &self,
        generation: u64,
        assignment: &DnsAssignment,
    ) -> Result<Vec<(DnsOwnedResource, std::path::PathBuf)>, String> {
        let names = match &assignment.scope {
            DnsScope::CatchAll | DnsScope::Suppressed => Vec::new(),
            DnsScope::Scoped { domains } => domains
                .iter()
                .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect(),
        };
        names
            .into_iter()
            .map(|name| {
                if name.is_empty()
                    || name == "."
                    || name == ".."
                    || name.contains('/')
                    || name.contains('\0')
                {
                    return Err(format!("unsafe DNS resolver scope {name:?}"));
                }
                if name == "default" {
                    return Err(
                        "scoped DNS domain \"default\" collides with the catch-all resolver"
                            .to_string(),
                    );
                }
                let path = self.resolver_dir.join(&name);
                Ok((
                    DnsOwnedResource {
                        generation,
                        id: format!("macos:{}", path.display()),
                        profile_id: assignment.profile_id.clone(),
                        interface: assignment.interface.clone(),
                    },
                    path,
                ))
            })
            .collect()
    }

    fn plan(&self, desired: &DnsPolicy) -> Result<Vec<PlannedResolver>, String> {
        Self::primary_assignment(desired)?;
        let mut planned = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for assignment in desired
            .assignments
            .iter()
            .filter(|assignment| matches!(assignment.scope, DnsScope::Scoped { .. }))
        {
            let body = resolver_body(desired.generation, assignment);
            for (resource, path) in self.resources_for(desired.generation, assignment)? {
                if !ids.insert(resource.id.clone()) {
                    return Err(format!(
                        "duplicate DNS resolver resource {}",
                        path.display()
                    ));
                }
                planned.push(PlannedResolver {
                    resource,
                    name: std::ffi::CString::new(
                        path.file_name()
                            .ok_or_else(|| "resolver path has no basename".to_string())?
                            .as_encoded_bytes(),
                    )
                    .map_err(|_| "resolver basename contains NUL".to_string())?,
                    path,
                    body: body.clone(),
                    original: None,
                });
            }
        }

        // Snapshot and validate every destination before the first mutation.
        // This prevents a late foreign/colliding resource from turning an
        // otherwise valid policy into a partial apply.
        for resolver in &mut planned {
            resolver.original = self.read_owned_resolver(&resolver.path)?;
        }
        Ok(planned)
    }

    pub(crate) fn has_active_assignments(policy: &DnsPolicy) -> bool {
        policy
            .assignments
            .iter()
            .any(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
    }

    pub(crate) fn effective_state_for(
        &self,
        policy: &DnsPolicy,
    ) -> Result<DnsEffectiveState, String> {
        self.plan(policy)?;
        let owned = self.resources_for_policy(policy)?;
        Ok(DnsEffectiveState {
            requested_generation: policy.generation,
            applied_generation: Some(policy.generation),
            status: if owned.is_empty() {
                DnsEffectiveStatus::Released
            } else {
                DnsEffectiveStatus::Applied
            },
            owned,
            errors: Vec::new(),
        })
    }

    pub(crate) fn verify_exclusive(&self, policy: &DnsPolicy) -> Result<(), String> {
        self.verify(policy, &self.effective_state_for(policy)?)
            .map_err(|errors| errors.join("; "))?;
        let expected = self
            .resources_for_policy(policy)?
            .into_iter()
            .map(|resource| resource.id)
            .collect::<std::collections::BTreeSet<_>>();
        let observed = self.managed_resource_ids()?;
        if observed == expected {
            Ok(())
        } else {
            Err("managed DNS resolver inventory does not match policy".to_string())
        }
    }

    pub(crate) fn audit_absent(&self) -> Result<(), String> {
        if self.managed_resource_ids()?.is_empty() {
            Ok(())
        } else {
            Err("managed DNS resolver inventory is not empty".to_string())
        }
    }

    fn resources_for_policy(&self, policy: &DnsPolicy) -> Result<Vec<DnsOwnedResource>, String> {
        let mut resources: Vec<DnsOwnedResource> = policy
            .assignments
            .iter()
            .filter(|assignment| matches!(assignment.scope, DnsScope::Scoped { .. }))
            .map(|assignment| self.resources_for(policy.generation, assignment))
            .collect::<Result<Vec<_>, _>>()
            .map(|groups| {
                groups
                    .into_iter()
                    .flatten()
                    .map(|(resource, _)| resource)
                    .collect()
            })?;
        if let Some(primary) = Self::primary_assignment(policy)? {
            resources.push(Self::primary_resource(policy.generation, primary));
        }
        Ok(resources)
    }

    fn managed_resource_ids(&self) -> Result<std::collections::BTreeSet<String>, String> {
        use std::os::unix::ffi::OsStrExt as _;

        let mut managed = std::collections::BTreeSet::new();
        if let Some(directory) = self.directory(false)? {
            for name in directory.entry_names()? {
                let Some(body) = directory.read_managed(&name)? else {
                    continue;
                };
                debug_assert!(body.starts_with(VORTIX_RESOLVER_MARKER.as_bytes()));
                let path = self
                    .resolver_dir
                    .join(std::ffi::OsStr::from_bytes(name.to_bytes()));
                managed.insert(format!("macos:{}", path.display()));
            }
        }
        match (self.primary_owner_state()?, self.primary_backup_state()?) {
            (None, None) => {}
            (Some(owner), Some(backup)) if owner.service_key == backup.service_key => {
                managed.insert(VORTIX_PRIMARY_DNS_RESOURCE_ID.to_string());
            }
            (None, Some(_)) => {
                // A crash after the backup write still represents owned state
                // and must not be treated as an absent platform.
                managed.insert(VORTIX_PRIMARY_DNS_RESOURCE_ID.to_string());
            }
            _ => return Err("macOS primary DNS ownership and backup disagree".to_string()),
        }
        Ok(managed)
    }

    fn actual_owned<'a>(
        &self,
        candidates: impl IntoIterator<Item = &'a DnsOwnedResource>,
    ) -> Vec<DnsOwnedResource> {
        let mut ids = std::collections::HashSet::new();
        candidates
            .into_iter()
            .filter(|resource| self.resource_is_present(resource))
            .filter(|resource| ids.insert(resource.id.clone()))
            .cloned()
            .collect()
    }

    fn rollback(&self, written: &[&PlannedResolver]) -> Vec<String> {
        let mut errors = Vec::new();
        for resolver in written.iter().rev() {
            let result = if let Some(original) = &resolver.original {
                self.write_owned_resolver(resolver, original)
            } else {
                self.release(&resolver.resource)
            };
            if let Err(error) = result {
                errors.push(format!(
                    "failed to roll back DNS resolver {}: {error}",
                    resolver.path.display()
                ));
            }
        }
        errors
    }

    fn release(&self, resource: &DnsOwnedResource) -> Result<(), String> {
        if resource.id == VORTIX_PRIMARY_DNS_RESOURCE_ID {
            return self.release_primary(resource);
        }
        let Some(path) = resource.id.strip_prefix("macos:") else {
            return Ok(());
        };
        let path = std::path::Path::new(path);
        let Some(directory) = self.directory(false)? else {
            return Ok(());
        };
        let name = Self::resolver_name(path)?;
        let Some(body) = directory.read(&name)? else {
            return Ok(());
        };
        if !body.starts_with(VORTIX_RESOLVER_MARKER.as_bytes())
            || !body_has_generation(&String::from_utf8_lossy(&body), resource.generation)
        {
            return Ok(());
        }
        directory.remove(&name)
    }

    fn resource_is_present(&self, resource: &DnsOwnedResource) -> bool {
        if resource.id == VORTIX_PRIMARY_DNS_RESOURCE_ID {
            return self.primary_resource_is_present(resource);
        }
        let Some(path) = resource.id.strip_prefix("macos:") else {
            return false;
        };
        let Ok(Some(body)) = self.read_owned_resolver(std::path::Path::new(path)) else {
            return false;
        };
        body_has_generation(&String::from_utf8_lossy(&body), resource.generation)
    }

    fn expected_resolver_bodies(
        &self,
        policy: &DnsPolicy,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, String> {
        let mut expected = std::collections::BTreeMap::new();
        for assignment in policy
            .assignments
            .iter()
            .filter(|assignment| matches!(assignment.scope, DnsScope::Scoped { .. }))
        {
            let body = resolver_body(policy.generation, assignment).into_bytes();
            for (_, path) in self.resources_for(policy.generation, assignment)? {
                let name = Self::resolver_name(&path)?.into_bytes();
                if expected.insert(name, body.clone()).is_some() {
                    return Err("duplicate DNS resolver recovery resource".to_string());
                }
            }
        }
        Ok(expected)
    }

    fn validate_pending_inventory(
        &self,
        desired: &DnsPolicy,
        prior: Option<&DnsPolicy>,
    ) -> Result<(), String> {
        self.validate_pending_primary(desired, prior)?;
        let desired = self.expected_resolver_bodies(desired)?;
        let prior = prior
            .map(|policy| self.expected_resolver_bodies(policy))
            .transpose()?
            .unwrap_or_default();
        let Some(directory) = self.directory(false)? else {
            return Ok(());
        };
        for name in directory.entry_names()? {
            let Some(body) = directory.read_managed(&name)? else {
                continue;
            };
            let name = name.to_bytes();
            let matches_desired = desired.get(name) == Some(&body);
            let matches_prior = prior.get(name) == Some(&body);
            if !matches_desired && !matches_prior {
                return Err(
                    "managed DNS inventory is not an exact intended/prior generation member"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    fn validate_pending_primary(
        &self,
        desired: &DnsPolicy,
        prior: Option<&DnsPolicy>,
    ) -> Result<(), String> {
        let owner = self.primary_owner_state()?;
        let backup = self.primary_backup_state()?;
        let (owner, backup) = match (owner, backup) {
            (None, None) => return Ok(()),
            (owner, Some(backup)) => (owner, backup),
            (Some(_), None) => {
                return Err("macOS primary DNS owner has no recovery backup".to_string())
            }
        };
        if owner
            .as_ref()
            .is_some_and(|owner| owner.service_key != backup.service_key)
        {
            return Err("macOS primary DNS ownership and backup disagree".to_string());
        }
        let actual = self
            .dynamic_store
            .get(&backup.service_key)?
            .ok_or_else(|| "macOS primary DNS configuration is absent".to_string())?;
        let mut allowed = vec![Self::backup_value(&backup)?];
        if let Some(assignment) = Self::primary_assignment(desired)? {
            allowed.push(Self::owner_dns_value(&Self::primary_owner(
                desired.generation,
                assignment,
                backup.service_key.clone(),
            ))?);
        }
        if let Some(prior) = prior {
            if let Some(assignment) = Self::primary_assignment(prior)? {
                allowed.push(Self::owner_dns_value(&Self::primary_owner(
                    prior.generation,
                    assignment,
                    backup.service_key.clone(),
                ))?);
            }
        }
        if !allowed
            .iter()
            .any(|candidate| plist_values_equal(&actual, candidate).unwrap_or(false))
        {
            return Err(
                "macOS primary DNS is not an exact intended/prior/backup value".to_string(),
            );
        }
        if let Some(owner) = owner {
            let owner_matches_desired =
                Self::primary_assignment(desired)?.is_some_and(|assignment| {
                    owner
                        == Self::primary_owner(
                            desired.generation,
                            assignment,
                            backup.service_key.clone(),
                        )
                });
            let owner_matches_prior = prior.is_some_and(|prior| {
                Self::primary_assignment(prior)
                    .ok()
                    .flatten()
                    .is_some_and(|assignment| {
                        owner
                            == Self::primary_owner(
                                prior.generation,
                                assignment,
                                backup.service_key.clone(),
                            )
                    })
            });
            if !owner_matches_desired && !owner_matches_prior {
                return Err(
                    "macOS primary DNS owner is not an intended/prior generation".to_string(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn canonical_test_resolver_dir(mut path: std::path::PathBuf) -> std::path::PathBuf {
    let name = path
        .file_name()
        .expect("test resolver directory has a basename")
        .to_owned();
    assert!(path.pop(), "test resolver directory has a parent");
    std::fs::canonicalize(path)
        .expect("test resolver parent is present")
        .join(name)
}

impl DnsPolicyAdapter for MacDnsPolicy {
    fn capabilities(&self) -> DnsPlatformCapabilities {
        DnsPlatformCapabilities {
            scoped_domains: true,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the DNS transaction keeps preflight, ordered effects, rollback, and ownership publication together"
    )]
    fn apply(
        &self,
        desired: &DnsPolicy,
        previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> DnsEffectiveState {
        let desired_primary = match Self::primary_assignment(desired) {
            Ok(primary) => primary,
            Err(error) => {
                return DnsEffectiveState {
                    requested_generation: desired.generation,
                    applied_generation: previous_effective.applied_generation,
                    status: DnsEffectiveStatus::Degraded,
                    owned: self.actual_owned(&previous_effective.owned),
                    errors: vec![error],
                };
            }
        };
        if desired_primary.is_some() {
            if let Err(error) = self.ensure_catch_all_dns_is_available() {
                return DnsEffectiveState {
                    requested_generation: desired.generation,
                    applied_generation: previous_effective.applied_generation,
                    status: DnsEffectiveStatus::Degraded,
                    owned: self.actual_owned(&previous_effective.owned),
                    errors: vec![error],
                };
            }
        }
        let planned = match self.plan(desired) {
            Ok(planned) => planned,
            Err(error) => {
                let actual = self.actual_owned(&previous_effective.owned);
                let previous_still_applied = actual == previous_effective.owned;
                return DnsEffectiveState {
                    requested_generation: desired.generation,
                    applied_generation: previous_still_applied
                        .then_some(previous_effective.applied_generation)
                        .flatten(),
                    status: DnsEffectiveStatus::Degraded,
                    owned: actual,
                    errors: vec![error],
                };
            }
        };
        let previous_primary = previous_desired
            .and_then(|policy| Self::primary_assignment(policy).ok().flatten())
            .map(|assignment| {
                (
                    previous_desired.expect("policy exists").generation,
                    assignment,
                )
            });
        if let Some(primary) = desired_primary {
            if let Err(error) = self.apply_primary(desired.generation, primary, previous_primary) {
                return DnsEffectiveState {
                    requested_generation: desired.generation,
                    applied_generation: previous_effective.applied_generation,
                    status: DnsEffectiveStatus::Degraded,
                    owned: self.actual_owned(&previous_effective.owned),
                    errors: vec![error],
                };
            }
        }
        let mut written = Vec::new();
        let apply_error = planned.iter().enumerate().find_map(|(index, resolver)| {
            #[cfg(not(test))]
            let _ = index;
            if let Err(error) = self.write_owned_resolver(resolver, resolver.body.as_bytes()) {
                return Some(error);
            }
            written.push(resolver);
            #[cfg(test)]
            if self.fail_readback_at == Some(index + 1) {
                return Some(format!(
                    "injected DNS resolver read-back failure for {}",
                    resolver.path.display()
                ));
            }
            let read_back = match self.read_owned_resolver(&resolver.path) {
                Ok(Some(read_back)) => read_back,
                Ok(None) => return Some("resolver disappeared after write".to_string()),
                Err(error) => return Some(error),
            };
            (read_back != resolver.body.as_bytes()).then(|| {
                format!(
                    "DNS resolver read-back mismatch for {}",
                    resolver.path.display()
                )
            })
        });

        if let Some(error) = apply_error {
            let mut errors = vec![error];
            errors.extend(self.rollback(&written));
            if let Some(primary) = desired_primary {
                let primary_rollback = previous_primary.map_or_else(
                    || self.release_primary(&Self::primary_resource(desired.generation, primary)),
                    |(generation, assignment)| {
                        self.apply_primary(
                            generation,
                            assignment,
                            Some((desired.generation, primary)),
                        )
                    },
                );
                if let Err(error) = primary_rollback {
                    errors.push(format!("failed to roll back macOS primary DNS: {error}"));
                }
            }
            let desired_resources = planned.iter().map(|resolver| &resolver.resource);
            let actual =
                self.actual_owned(desired_resources.chain(previous_effective.owned.iter()));
            let rollback_succeeded = errors.len() == 1;
            let previous_restored = rollback_succeeded && actual == previous_effective.owned;
            return DnsEffectiveState {
                requested_generation: desired.generation,
                applied_generation: previous_restored
                    .then_some(previous_effective.applied_generation)
                    .flatten(),
                status: DnsEffectiveStatus::Degraded,
                owned: actual,
                errors,
            };
        }

        let mut owned = planned
            .iter()
            .map(|resolver| resolver.resource.clone())
            .collect::<Vec<_>>();
        if let Some(primary) = desired_primary {
            owned.push(Self::primary_resource(desired.generation, primary));
        }

        let desired_ids = owned
            .iter()
            .map(|resource| resource.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        for resource in &previous_effective.owned {
            if !desired_ids.contains(resource.id.as_str()) {
                if let Err(error) = self.release(resource) {
                    let desired_resources = owned.iter();
                    return DnsEffectiveState {
                        requested_generation: desired.generation,
                        applied_generation: None,
                        status: DnsEffectiveStatus::Degraded,
                        owned: self
                            .actual_owned(desired_resources.chain(previous_effective.owned.iter())),
                        errors: vec![error],
                    };
                }
            }
        }

        DnsEffectiveState {
            requested_generation: desired.generation,
            applied_generation: Some(desired.generation),
            status: if owned.is_empty() {
                DnsEffectiveStatus::Released
            } else {
                DnsEffectiveStatus::Applied
            },
            owned,
            errors: Vec::new(),
        }
    }

    fn verify(
        &self,
        desired: &DnsPolicy,
        _effective: &DnsEffectiveState,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for assignment in desired
            .assignments
            .iter()
            .filter(|assignment| matches!(assignment.scope, DnsScope::Scoped { .. }))
        {
            let expected = resolver_body(desired.generation, assignment);
            match self.resources_for(desired.generation, assignment) {
                Ok(resources) => {
                    for (_, path) in resources {
                        match self.read_owned_resolver(&path) {
                            Ok(Some(actual)) if actual == expected.as_bytes() => {}
                            Ok(Some(_)) => errors.push(format!(
                                "DNS resolver read-back mismatch for {}",
                                path.display()
                            )),
                            Ok(None) => errors.push(format!(
                                "cannot read DNS resolver {}: not found",
                                path.display()
                            )),
                            Err(error) => errors.push(format!(
                                "cannot read DNS resolver {}: {error}",
                                path.display()
                            )),
                        }
                    }
                }
                Err(error) => errors.push(error),
            }
        }
        match Self::primary_assignment(desired) {
            Ok(Some(primary)) => {
                if let Err(error) = self.ensure_catch_all_dns_is_available() {
                    errors.push(error);
                }
                if let Err(error) = self.verify_primary(desired.generation, primary) {
                    errors.push(error);
                }
            }
            Ok(None) => {}
            Err(error) => errors.push(error),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl OwnedDns for MacDnsPolicy {
    fn backend(&self) -> OwnedDnsBackend {
        OwnedDnsBackend::MacOsResolverFiles
    }

    fn apply(
        &mut self,
        desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
    ) -> Result<(), OwnedDnsError> {
        let previous_desired = match expected {
            ExpectedDnsState::Absent => {
                self.audit_absent()
                    .map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
                None
            }
            ExpectedDnsState::Applied(policy) => {
                self.verify_exclusive(policy)
                    .map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
                Some(policy)
            }
        };
        let previous_effective = previous_desired
            .map(|policy| self.effective_state_for(policy))
            .transpose()
            .map_err(|_| OwnedDnsError::FailedBeforeEffect)?
            .unwrap_or_default();
        // Classify destination collisions, links, and unsafe ownership before
        // entering the mutation adapter. Once the first resolver write is
        // attempted, failures must conservatively become EffectMayHaveApplied.
        self.plan(desired)
            .map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
        let result = DnsPolicyAdapter::apply(self, desired, previous_desired, &previous_effective);
        let expected_status = if Self::has_active_assignments(desired) {
            DnsEffectiveStatus::Applied
        } else {
            DnsEffectiveStatus::Released
        };
        if result.status != expected_status
            || result.applied_generation != Some(desired.generation)
            || self.verify_exclusive(desired).is_err()
        {
            return Err(OwnedDnsError::EffectMayHaveApplied);
        }
        Ok(())
    }

    fn audit(&mut self, desired: &DnsPolicy) -> Result<(), OwnedDnsError> {
        self.verify_exclusive(desired)
            .map_err(|_| OwnedDnsError::EffectMayHaveApplied)
    }

    fn audit_absent(&mut self) -> Result<(), OwnedDnsError> {
        MacDnsPolicy::audit_absent(self).map_err(|_| OwnedDnsError::EffectMayHaveApplied)
    }

    fn recover_pending(
        &mut self,
        desired: &DnsPolicy,
        prior: Option<&DnsPolicy>,
    ) -> Result<(), OwnedDnsError> {
        self.validate_pending_inventory(desired, prior)
            .map_err(|_| OwnedDnsError::EffectMayHaveApplied)?;
        let previous_effective = prior
            .map(|policy| self.effective_state_for(policy))
            .transpose()
            .map_err(|_| OwnedDnsError::EffectMayHaveApplied)?
            .unwrap_or_default();
        let result = DnsPolicyAdapter::apply(self, desired, prior, &previous_effective);
        let expected_status = if Self::has_active_assignments(desired) {
            DnsEffectiveStatus::Applied
        } else {
            DnsEffectiveStatus::Released
        };
        if result.status != expected_status
            || result.applied_generation != Some(desired.generation)
            || self.verify_exclusive(desired).is_err()
        {
            return Err(OwnedDnsError::EffectMayHaveApplied);
        }
        Ok(())
    }

    fn audit_recovery(
        &mut self,
        candidates: &[DnsPolicy],
        allow_absent: bool,
    ) -> Result<(), OwnedDnsError> {
        if allow_absent && MacDnsPolicy::audit_absent(self).is_ok() {
            return Ok(());
        }
        if candidates
            .iter()
            .any(|candidate| self.verify_exclusive(candidate).is_ok())
        {
            Ok(())
        } else {
            Err(OwnedDnsError::EffectMayHaveApplied)
        }
    }
}

/// Pinned, root-owned resolver directory used for every privileged file
/// mutation. All entry operations are descriptor-relative and refuse links.
struct ResolverDirectory {
    directory: std::fs::File,
    expected_owner_uid: u32,
}

#[allow(
    unsafe_code,
    reason = "descriptor-relative resolver storage requires openat/mkdirat/renameat/unlinkat"
)]
impl ResolverDirectory {
    fn open(
        path: &std::path::Path,
        expected_owner_uid: u32,
        create: bool,
    ) -> Result<Option<Self>, String> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::fs::MetadataExt as _;

        if !path.is_absolute() {
            return Err("resolver directory must be absolute".to_string());
        }
        let mut components = path.components().peekable();
        if components.next() != Some(std::path::Component::RootDir) {
            return Err("resolver directory must be absolute".to_string());
        }
        let root = std::ffi::CString::new("/").expect("root path contains no NUL");
        // SAFETY: the fixed C string is valid and a successful fd is owned by
        // the returned File exactly once.
        let root_fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: `open` returned a new descriptor owned by this call.
        let mut directory = unsafe { std::fs::File::from_raw_fd(root_fd) };
        let mut saw_component = false;
        while let Some(component) = components.next() {
            let std::path::Component::Normal(component) = component else {
                return Err("resolver directory contains an unsafe component".to_string());
            };
            saw_component = true;
            let name = std::ffi::CString::new(component.as_encoded_bytes())
                .map_err(|_| "resolver directory component contains NUL".to_string())?;
            let is_leaf = components.peek().is_none();
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: the parent descriptor and component C string remain
            // live for the call; successful ownership moves into File.
            let mut fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 && is_leaf && create {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::NotFound {
                    // SAFETY: descriptor and component are valid. EEXIST is
                    // handled by the following no-follow open.
                    let created =
                        unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) };
                    if created != 0
                        && std::io::Error::last_os_error().kind()
                            != std::io::ErrorKind::AlreadyExists
                    {
                        return Err(std::io::Error::last_os_error().to_string());
                    }
                    // SAFETY: same validated arguments as the first openat.
                    fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
                }
            }
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if is_leaf && !create && error.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(error.to_string());
            }
            // SAFETY: `openat` returned a new descriptor owned by this call.
            directory = unsafe { std::fs::File::from_raw_fd(fd) };

            if is_leaf {
                let metadata = directory.metadata().map_err(|error| error.to_string())?;
                if !metadata.is_dir()
                    || metadata.uid() != expected_owner_uid
                    || metadata.mode() & 0o022 != 0
                {
                    return Err("resolver directory owner or mode is unsafe".to_string());
                }
            }
        }
        if !saw_component {
            return Err("resolver directory cannot be filesystem root".to_string());
        }
        Ok(Some(Self {
            directory,
            expected_owner_uid,
        }))
    }

    fn read(&self, name: &std::ffi::CStr) -> Result<Option<Vec<u8>>, String> {
        self.read_entry(name, true)
    }

    fn read_managed(&self, name: &std::ffi::CStr) -> Result<Option<Vec<u8>>, String> {
        let body = self.read_entry(name, false)?;
        match body {
            Some(body) if body.starts_with(VORTIX_RESOLVER_MARKER.as_bytes()) => {
                self.read_entry(name, true)
            }
            _ => Ok(None),
        }
    }

    fn read_entry(
        &self,
        name: &std::ffi::CStr,
        require_owned: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        use std::io::Read as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::fs::MetadataExt as _;

        // SAFETY: the pinned directory and validated C string are live; a
        // successful descriptor is transferred into File exactly once.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound
                || (!require_owned && error.raw_os_error() == Some(libc::ELOOP))
            {
                Ok(None)
            } else {
                Err(error.to_string())
            };
        }
        // SAFETY: `openat` returned a new descriptor owned by this call.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() > MAX_RESOLVER_BYTES {
            return if require_owned {
                Err("resolver entry type or size is unsafe".to_string())
            } else {
                Ok(None)
            };
        }
        if require_owned
            && (metadata.uid() != self.expected_owner_uid
                || metadata.mode() & 0o022 != 0
                || metadata.nlink() != 1)
        {
            return Err("resolver entry owner, mode, size, or link count is unsafe".to_string());
        }
        let mut body = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.by_ref()
            .take(MAX_RESOLVER_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|error| error.to_string())?;
        if body.len() as u64 > MAX_RESOLVER_BYTES {
            return Err("resolver entry exceeds its fixed size".to_string());
        }
        Ok(Some(body))
    }

    fn write(&self, name: &std::ffi::CStr, body: &[u8]) -> Result<(), String> {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use std::sync::atomic::{AtomicU64, Ordering};

        static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

        if body.is_empty() || body.len() as u64 > MAX_RESOLVER_BYTES {
            return Err("resolver body is empty or exceeds its fixed size".to_string());
        }
        if let Some(existing) = self.read(name)? {
            if !existing.starts_with(VORTIX_RESOLVER_MARKER.as_bytes()) {
                return Err("refusing to replace foreign DNS resolver".to_string());
            }
        }
        let (temporary_name, mut temporary) = (0..64)
            .find_map(|_| {
                let candidate = std::ffi::CString::new(format!(
                    ".vortix-resolver.{}.{}.tmp",
                    std::process::id(),
                    TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ))
                .expect("fixed resolver temporary name contains no NUL");
                // SAFETY: the pinned directory and C string are live. The
                // returned descriptor, if any, is uniquely owned here.
                let fd = unsafe {
                    libc::openat(
                        self.directory.as_raw_fd(),
                        candidate.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o644,
                    )
                };
                if fd >= 0 {
                    // SAFETY: `openat` returned a new owned descriptor.
                    Some(Ok((candidate, unsafe { std::fs::File::from_raw_fd(fd) })))
                } else if std::io::Error::last_os_error().kind()
                    == std::io::ErrorKind::AlreadyExists
                {
                    None
                } else {
                    Some(Err(std::io::Error::last_os_error().to_string()))
                }
            })
            .transpose()?
            .ok_or_else(|| "resolver temporary namespace exhausted".to_string())?;

        let result = (|| {
            temporary
                .set_permissions(std::fs::Permissions::from_mode(0o644))
                .map_err(|error| error.to_string())?;
            let metadata = temporary.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file()
                || metadata.uid() != self.expected_owner_uid
                || metadata.mode() & 0o777 != 0o644
                || metadata.nlink() != 1
            {
                return Err("resolver temporary file ownership is unsafe".to_string());
            }
            temporary
                .write_all(body)
                .and_then(|()| temporary.sync_all())
                .map_err(|error| error.to_string())?;
            // SAFETY: both names are valid and both directory descriptors are
            // the same pinned directory.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            self.directory
                .sync_all()
                .map_err(|error| error.to_string())?;
            match self.read(name)? {
                Some(installed) if installed == body => Ok(()),
                _ => Err("resolver atomic install read-back mismatch".to_string()),
            }
        })();
        if result.is_err() {
            // SAFETY: the pinned directory and temporary C string are valid.
            let _ =
                unsafe { libc::unlinkat(self.directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
        }
        result
    }

    fn remove(&self, name: &std::ffi::CStr) -> Result<(), String> {
        use std::os::fd::AsRawFd as _;

        // SAFETY: the pinned directory and C string are valid.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.to_string());
            }
        }
        self.directory.sync_all().map_err(|error| error.to_string())
    }

    fn entry_names(&self) -> Result<Vec<std::ffi::CString>, String> {
        use std::os::fd::AsRawFd as _;

        // SAFETY: fcntl creates a close-on-exec descriptor consumed by
        // fdopendir. The DIR stream is closed exactly once below.
        let duplicate =
            unsafe { libc::fcntl(self.directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: `duplicate` is a valid directory descriptor.
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            // SAFETY: fdopendir failed and did not consume the descriptor.
            let _ = unsafe { libc::close(duplicate) };
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut names = Vec::new();
        loop {
            // SAFETY: macOS exposes thread-local errno through `__error`.
            unsafe { *libc::__error() = 0 };
            // SAFETY: the DIR stream remains valid until closed below.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    // SAFETY: closes the valid stream and its descriptor.
                    let _ = unsafe { libc::closedir(stream) };
                    return Err(error.to_string());
                }
                break;
            }
            // SAFETY: POSIX guarantees d_name is NUL-terminated.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            if names.len() >= MAX_RESOLVER_FILES {
                // SAFETY: closes the valid stream and its descriptor.
                let _ = unsafe { libc::closedir(stream) };
                return Err("DNS resolver inventory exceeds its fixed limit".to_string());
            }
            names.push(name.to_owned());
        }
        // SAFETY: closes the valid stream and its descriptor.
        if unsafe { libc::closedir(stream) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(names)
    }
}

fn resolver_body(generation: u64, assignment: &DnsAssignment) -> String {
    use std::fmt::Write as _;

    let mut body = format!(
        "{VORTIX_RESOLVER_MARKER}\n# generation: {generation}\n# interface: {}\n",
        assignment.interface
    );
    for server in &assignment.servers {
        let _ = writeln!(body, "nameserver {server}");
    }
    for domain in &assignment.search_domains {
        let _ = writeln!(body, "search {domain}");
    }
    body
}

fn body_has_generation(body: &str, generation: u64) -> bool {
    body.lines()
        .any(|line| line == format!("# generation: {generation}"))
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

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::vortix_core::ports::dns::{DnsRequest, DnsTunnelIntent, DnsTunnelRole};
    use crate::vortix_core::profile::ProfileId;

    fn policy(generation: u64, server: &str) -> DnsPolicy {
        DnsPolicy::compute(
            generation,
            &[DnsTunnelIntent {
                profile_id: ProfileId::new("corp"),
                interface: "utun7".into(),
                role: DnsTunnelRole::Primary,
                request: DnsRequest {
                    servers: vec![server.parse().unwrap()],
                    search_domains: Vec::new(),
                },
            }],
            DnsPlatformCapabilities {
                scoped_domains: true,
            },
        )
        .unwrap()
    }

    fn scoped_policy(generation: u64, server: &str, domains: &[&str]) -> DnsPolicy {
        DnsPolicy {
            generation,
            assignments: vec![DnsAssignment {
                profile_id: ProfileId::new("corp"),
                interface: "utun7".into(),
                servers: vec![server.parse().unwrap()],
                search_domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
                scope: DnsScope::Scoped {
                    domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
                },
            }],
        }
    }

    #[test]
    fn catch_all_uses_primary_service_and_restores_it_on_release() {
        let temp = tempfile::tempdir().unwrap();
        let adapter = MacDnsPolicy::at(temp.path().join("resolver"));
        let original = adapter.test_primary_dns_servers();
        let first = policy(1, "1.1.1.1");
        let applied = adapter.apply(&first, None, &DnsEffectiveState::default());
        assert_eq!(applied.status, DnsEffectiveStatus::Applied);
        assert_eq!(adapter.test_primary_dns_servers(), vec!["1.1.1.1"]);
        assert!(!temp.path().join("resolver/default").exists());
        let repeated = adapter.apply(&first, Some(&first), &applied);
        assert_eq!(repeated.status, DnsEffectiveStatus::Applied);

        let released_policy = DnsPolicy {
            generation: 2,
            assignments: Vec::new(),
        };
        let released = adapter.apply(&released_policy, Some(&first), &repeated);
        assert_eq!(released.status, DnsEffectiveStatus::Released);
        assert_eq!(adapter.test_primary_dns_servers(), original);
        assert!(!temp.path().join("resolver/default").exists());
        let repeated_release = adapter.apply(&released_policy, Some(&released_policy), &released);
        assert_eq!(repeated_release.status, DnsEffectiveStatus::Released);
    }

    #[test]
    fn managed_encrypted_dns_refuses_catch_all_before_mutating_primary_dns() {
        let temp = tempfile::tempdir().unwrap();
        let adapter = MacDnsPolicy::at_with_managed_encrypted_dns(temp.path().join("resolver"));
        let original = adapter.test_primary_dns_servers();

        let effective = adapter.apply(&policy(1, "10.80.0.1"), None, &DnsEffectiveState::default());

        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert!(effective.owned.is_empty());
        assert!(effective.errors.iter().any(|error| {
            error.contains("managed encrypted DNS") && error.contains("refusing catch-all DNS")
        }));
        assert_eq!(adapter.test_primary_dns_servers(), original);
        assert!(adapter.primary_owner_state().unwrap().is_none());
        assert!(adapter.primary_backup_state().unwrap().is_none());
    }

    #[test]
    fn foreign_default_resolver_is_never_overwritten() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let resolver_dir = temp.path().join("resolver");
        std::fs::create_dir_all(&resolver_dir).unwrap();
        std::fs::write(resolver_dir.join("default"), "nameserver 9.9.9.9\n").unwrap();
        std::fs::set_permissions(
            resolver_dir.join("default"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        let mut adapter = MacDnsPolicy::at(resolver_dir.clone());
        assert_eq!(OwnedDns::audit_absent(&mut adapter), Ok(()));
        let effective = adapter.apply(&policy(1, "1.1.1.1"), None, &DnsEffectiveState::default());
        assert_eq!(effective.status, DnsEffectiveStatus::Applied);
        assert_eq!(adapter.test_primary_dns_servers(), vec!["1.1.1.1"]);
        assert_eq!(
            std::fs::read_to_string(resolver_dir.join("default")).unwrap(),
            "nameserver 9.9.9.9\n"
        );
    }

    #[test]
    fn prior_generation_release_cannot_delete_new_generation_resource() {
        let temp = tempfile::tempdir().unwrap();
        let adapter = MacDnsPolicy::at(temp.path().join("resolver"));
        let first_policy = policy(1, "1.1.1.1");
        let first = adapter.apply(&first_policy, None, &DnsEffectiveState::default());
        let second_policy = policy(2, "8.8.8.8");
        let second = adapter.apply(&second_policy, Some(&first_policy), &first);
        assert_eq!(second.status, DnsEffectiveStatus::Applied);
        adapter.release(&first.owned[0]).unwrap();
        assert_eq!(adapter.test_primary_dns_servers(), vec!["8.8.8.8"]);
    }

    #[test]
    fn interrupted_primary_apply_resumes_from_the_exact_backup() {
        let temp = tempfile::tempdir().unwrap();
        let mut adapter = MacDnsPolicy::at(temp.path().join("resolver"));
        let service_key = adapter.primary_service_key().unwrap();
        let original = adapter.dynamic_store.get(&service_key).unwrap().unwrap();
        adapter
            .set_primary_backup(&MacDnsPolicy::new_backup(service_key, &original))
            .unwrap();

        let desired = policy(7, "1.1.1.1");
        OwnedDns::recover_pending(&mut adapter, &desired, None).unwrap();
        assert_eq!(OwnedDns::audit(&mut adapter, &desired), Ok(()));
        assert_eq!(adapter.test_primary_dns_servers(), vec!["1.1.1.1"]);

        let resource = MacDnsPolicy::primary_resource(7, &desired.assignments[0]);
        adapter.release(&resource).unwrap();
        assert_eq!(adapter.test_primary_dns_servers(), vec!["192.0.2.53"]);
    }

    #[test]
    fn interrupted_primary_replacement_accepts_only_the_intended_next_value() {
        let temp = tempfile::tempdir().unwrap();
        let mut adapter = MacDnsPolicy::at(temp.path().join("resolver"));
        let prior = policy(4, "1.1.1.1");
        OwnedDns::apply(&mut adapter, &prior, ExpectedDnsState::Absent).unwrap();
        let desired = policy(5, "8.8.8.8");
        let service_key = adapter.primary_service_key().unwrap();

        // Model a crash after replacing the service DNS but before advancing
        // the Vortix owner marker from generation 4 to generation 5.
        adapter
            .dynamic_store
            .set(
                &service_key,
                &primary_dns_value(&["8.8.8.8".to_string()], &[]).unwrap(),
            )
            .unwrap();

        OwnedDns::recover_pending(&mut adapter, &desired, Some(&prior)).unwrap();
        assert_eq!(OwnedDns::audit(&mut adapter, &desired), Ok(()));
        assert_eq!(adapter.test_primary_dns_servers(), vec!["8.8.8.8"]);
    }

    #[test]
    fn external_primary_dns_change_is_never_overwritten_on_release() {
        let temp = tempfile::tempdir().unwrap();
        let adapter = MacDnsPolicy::at(temp.path().join("resolver"));
        let desired = policy(3, "1.1.1.1");
        let effective = adapter.apply(&desired, None, &DnsEffectiveState::default());
        assert_eq!(effective.status, DnsEffectiveStatus::Applied);
        let service_key = adapter.primary_service_key().unwrap();
        adapter
            .dynamic_store
            .set(
                &service_key,
                &primary_dns_value(&["9.9.9.9".to_string()], &[]).unwrap(),
            )
            .unwrap();

        assert!(adapter.release(&effective.owned[0]).is_err());
        assert_eq!(adapter.test_primary_dns_servers(), vec!["9.9.9.9"]);
        assert!(adapter.primary_owner_state().unwrap().is_some());
        assert!(adapter.primary_backup_state().unwrap().is_some());
    }

    #[test]
    fn later_readback_failure_restores_and_removes_all_earlier_writes() {
        let temp = tempfile::tempdir().unwrap();
        let resolver_dir = temp.path().join("resolver");
        let normal = MacDnsPolicy::at(resolver_dir.clone());
        let previous_policy = scoped_policy(1, "1.1.1.1", &["a.example"]);
        let previous = normal.apply(&previous_policy, None, &DnsEffectiveState::default());
        let original = std::fs::read_to_string(resolver_dir.join("a.example")).unwrap();

        let failing = MacDnsPolicy::at_failing_readback(resolver_dir.clone(), 2);
        let desired = scoped_policy(2, "8.8.8.8", &["a.example", "b.example"]);
        let effective = failing.apply(&desired, Some(&previous_policy), &previous);

        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert_eq!(effective.applied_generation, Some(1));
        assert_eq!(effective.owned, previous.owned);
        assert_eq!(
            std::fs::read_to_string(resolver_dir.join("a.example")).unwrap(),
            original
        );
        assert!(!resolver_dir.join("b.example").exists());
    }

    #[test]
    fn reserved_and_duplicate_scopes_fail_before_any_write() {
        let temp = tempfile::tempdir().unwrap();
        let reserved_dir = temp.path().join("reserved");
        let adapter = MacDnsPolicy::at(reserved_dir.clone());
        let mut reserved = policy(1, "1.1.1.1");
        reserved.assignments.push(DnsAssignment {
            profile_id: ProfileId::new("secondary"),
            interface: "utun8".into(),
            servers: vec!["8.8.8.8".parse().unwrap()],
            search_domains: vec!["default".into()],
            scope: DnsScope::Scoped {
                domains: vec![" DEFAULT. ".into()],
            },
        });
        let effective = adapter.apply(&reserved, None, &DnsEffectiveState::default());
        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert!(!reserved_dir.join("default").exists());

        let duplicate_dir = temp.path().join("duplicate");
        let adapter = MacDnsPolicy::at(duplicate_dir.clone());
        let duplicate = scoped_policy(1, "1.1.1.1", &["Corp.Example.", " corp.example "]);
        let effective = adapter.apply(&duplicate, None, &DnsEffectiveState::default());
        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert!(!duplicate_dir.join("corp.example").exists());
    }

    #[test]
    fn helper_replacement_requires_exact_prior_and_keeps_one_owned_projection() {
        let temp = tempfile::tempdir().unwrap();
        let mut adapter = MacDnsPolicy::at(temp.path().join("resolver"));
        let first = policy(1, "1.1.1.1");
        let second = policy(2, "9.9.9.9");

        OwnedDns::apply(&mut adapter, &first, ExpectedDnsState::Absent).unwrap();
        OwnedDns::apply(&mut adapter, &second, ExpectedDnsState::Applied(&first)).unwrap();

        assert_eq!(OwnedDns::audit(&mut adapter, &second), Ok(()));
        assert_eq!(
            OwnedDns::audit(&mut adapter, &first),
            Err(OwnedDnsError::EffectMayHaveApplied)
        );
    }

    #[test]
    fn helper_audit_rejects_an_unexpected_managed_resolver() {
        let temp = tempfile::tempdir().unwrap();
        let resolver_dir = temp.path().join("resolver");
        let mut adapter = MacDnsPolicy::at(resolver_dir.clone());
        let expected = policy(1, "1.1.1.1");
        OwnedDns::apply(&mut adapter, &expected, ExpectedDnsState::Absent).unwrap();
        std::fs::create_dir_all(&resolver_dir).unwrap();
        std::fs::write(
            resolver_dir.join("stale.example"),
            "# managed-by: vortix dns\n# generation: 9\nnameserver 8.8.8.8\n",
        )
        .unwrap();

        assert_eq!(
            OwnedDns::audit(&mut adapter, &expected),
            Err(OwnedDnsError::EffectMayHaveApplied)
        );
        assert_eq!(
            OwnedDns::audit_absent(&mut adapter),
            Err(OwnedDnsError::EffectMayHaveApplied)
        );
    }

    #[test]
    fn helper_pending_recovery_converges_only_exact_intended_prior_members() {
        let temp = tempfile::tempdir().unwrap();
        let resolver_dir = temp.path().join("resolver");
        let mut adapter = MacDnsPolicy::at(resolver_dir.clone());
        let prior = scoped_policy(1, "1.1.1.1", &["a.example"]);
        let desired = scoped_policy(2, "9.9.9.9", &["a.example", "b.example"]);
        OwnedDns::apply(&mut adapter, &prior, ExpectedDnsState::Absent).unwrap();

        let desired_a = resolver_body(desired.generation, &desired.assignments[0]);
        std::fs::write(resolver_dir.join("a.example"), desired_a).unwrap();
        OwnedDns::recover_pending(&mut adapter, &desired, Some(&prior)).unwrap();
        assert_eq!(OwnedDns::audit(&mut adapter, &desired), Ok(()));

        std::fs::write(
            resolver_dir.join("unexpected.example"),
            "# managed-by: vortix dns\n# generation: 99\nnameserver 8.8.8.8\n",
        )
        .unwrap();
        assert_eq!(
            OwnedDns::recover_pending(&mut adapter, &desired, Some(&prior)),
            Err(OwnedDnsError::EffectMayHaveApplied)
        );
        assert!(resolver_dir.join("unexpected.example").exists());
    }

    #[test]
    fn helper_writer_rejects_linked_directory_entries_and_hardlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let resolver_dir = temp.path().join("resolver");
        let foreign_dir = temp.path().join("foreign");
        std::fs::create_dir_all(&foreign_dir).unwrap();
        symlink(&foreign_dir, &resolver_dir).unwrap();
        let mut linked_directory = MacDnsPolicy::at(resolver_dir.clone());
        assert_eq!(
            OwnedDns::apply(
                &mut linked_directory,
                &scoped_policy(1, "1.1.1.1", &["a.example"]),
                ExpectedDnsState::Absent
            ),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert!(std::fs::read_dir(&foreign_dir).unwrap().next().is_none());

        std::fs::remove_file(&resolver_dir).unwrap();
        std::fs::create_dir_all(&resolver_dir).unwrap();
        let foreign = temp.path().join("foreign-resolver");
        std::fs::write(&foreign, "nameserver 9.9.9.9\n").unwrap();
        symlink(&foreign, resolver_dir.join("a.example")).unwrap();
        let mut linked_entry = MacDnsPolicy::at(resolver_dir.clone());
        assert_eq!(
            OwnedDns::apply(
                &mut linked_entry,
                &scoped_policy(1, "1.1.1.1", &["a.example"]),
                ExpectedDnsState::Absent
            ),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert_eq!(
            std::fs::read_to_string(&foreign).unwrap(),
            "nameserver 9.9.9.9\n"
        );

        std::fs::remove_file(resolver_dir.join("a.example")).unwrap();
        std::fs::write(
            resolver_dir.join("a.example"),
            "# managed-by: vortix dns\n# generation: 1\nnameserver 1.1.1.1\n",
        )
        .unwrap();
        std::fs::hard_link(
            resolver_dir.join("a.example"),
            resolver_dir.join("duplicate"),
        )
        .unwrap();
        let mut hardlinked = MacDnsPolicy::at(resolver_dir);
        assert_eq!(
            OwnedDns::audit(
                &mut hardlinked,
                &scoped_policy(1, "1.1.1.1", &["a.example"])
            ),
            Err(OwnedDnsError::EffectMayHaveApplied)
        );
    }
}
