//! macOS DNS resolver via the `SystemConfiguration` framework.
//!
//! replaced `scutil --dns` and `networksetup -getdnsservers`
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
use crate::vortix_core::ports::dns::{
    DnsAssignment, DnsEffectiveState, DnsEffectiveStatus, DnsOwnedResource,
    DnsPlatformCapabilities, DnsPolicy, DnsPolicyAdapter, DnsScope,
};

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

const VORTIX_RESOLVER_MARKER: &str = "# managed-by: vortix dns";

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

/// Vortix-owned `/etc/resolver` adapter. A configurable root keeps ownership,
/// idempotency, and partial-failure behavior testable without touching the
/// developer's resolver configuration.
#[derive(Debug, Clone)]
pub struct MacDnsPolicy {
    resolver_dir: std::path::PathBuf,
    #[cfg(test)]
    fail_readback_at: Option<usize>,
}

#[derive(Debug)]
struct PlannedResolver {
    resource: DnsOwnedResource,
    path: std::path::PathBuf,
    body: String,
    original: Option<Vec<u8>>,
}

impl MacDnsPolicy {
    #[must_use]
    pub fn system() -> Self {
        Self {
            resolver_dir: std::path::PathBuf::from("/etc/resolver"),
            #[cfg(test)]
            fail_readback_at: None,
        }
    }

    #[cfg(test)]
    fn at(resolver_dir: std::path::PathBuf) -> Self {
        Self {
            resolver_dir,
            fail_readback_at: None,
        }
    }

    #[cfg(test)]
    fn at_failing_readback(resolver_dir: std::path::PathBuf, write_number: usize) -> Self {
        Self {
            resolver_dir,
            fail_readback_at: Some(write_number),
        }
    }

    fn resources_for(
        &self,
        generation: u64,
        assignment: &DnsAssignment,
    ) -> Result<Vec<(DnsOwnedResource, std::path::PathBuf)>, String> {
        let names = match &assignment.scope {
            DnsScope::CatchAll => vec![("default".to_string(), false)],
            DnsScope::Scoped { domains } => domains
                .iter()
                .map(|domain| {
                    (
                        domain.trim().trim_end_matches('.').to_ascii_lowercase(),
                        true,
                    )
                })
                .collect(),
            DnsScope::Suppressed => Vec::new(),
        };
        names
            .into_iter()
            .map(|(name, is_scoped)| {
                if name.is_empty()
                    || name == "."
                    || name == ".."
                    || name.contains('/')
                    || name.contains('\0')
                {
                    return Err(format!("unsafe DNS resolver scope {name:?}"));
                }
                if is_scoped && name == "default" {
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
        let mut planned = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for assignment in desired
            .assignments
            .iter()
            .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
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
            resolver.original = read_owned_resolver(&resolver.path)?;
        }
        Ok(planned)
    }

    fn actual_owned<'a>(
        candidates: impl IntoIterator<Item = &'a DnsOwnedResource>,
    ) -> Vec<DnsOwnedResource> {
        let mut ids = std::collections::HashSet::new();
        candidates
            .into_iter()
            .filter(|resource| resource_is_present(resource))
            .filter(|resource| ids.insert(resource.id.clone()))
            .cloned()
            .collect()
    }

    fn rollback(written: &[&PlannedResolver]) -> Vec<String> {
        let mut errors = Vec::new();
        for resolver in written.iter().rev() {
            let result = if let Some(original) = &resolver.original {
                write_owned_resolver(&resolver.path, original)
            } else {
                Self::release(&resolver.resource)
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

    fn release(resource: &DnsOwnedResource) -> Result<(), String> {
        let Some(path) = resource.id.strip_prefix("macos:") else {
            return Ok(());
        };
        let path = std::path::Path::new(path);
        let Ok(body) = std::fs::read_to_string(path) else {
            return Ok(());
        };
        if !body.starts_with(VORTIX_RESOLVER_MARKER)
            || !body_has_generation(&body, resource.generation)
        {
            return Ok(());
        }
        std::fs::remove_file(path).map_err(|error| error.to_string())
    }
}

impl DnsPolicyAdapter for MacDnsPolicy {
    fn capabilities(&self) -> DnsPlatformCapabilities {
        DnsPlatformCapabilities {
            scoped_domains: true,
        }
    }

    fn apply(
        &self,
        desired: &DnsPolicy,
        _previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> DnsEffectiveState {
        let planned = match self.plan(desired) {
            Ok(planned) => planned,
            Err(error) => {
                let actual = Self::actual_owned(&previous_effective.owned);
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
        let mut written = Vec::new();
        let apply_error = planned.iter().enumerate().find_map(|(index, resolver)| {
            #[cfg(not(test))]
            let _ = index;
            if let Err(error) = write_owned_resolver(&resolver.path, resolver.body.as_bytes()) {
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
            let read_back = match std::fs::read_to_string(&resolver.path) {
                Ok(read_back) => read_back,
                Err(error) => return Some(error.to_string()),
            };
            (read_back != resolver.body).then(|| {
                format!(
                    "DNS resolver read-back mismatch for {}",
                    resolver.path.display()
                )
            })
        });

        if let Some(error) = apply_error {
            let mut errors = vec![error];
            errors.extend(Self::rollback(&written));
            let desired_resources = planned.iter().map(|resolver| &resolver.resource);
            let actual =
                Self::actual_owned(desired_resources.chain(previous_effective.owned.iter()));
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

        let owned = planned
            .iter()
            .map(|resolver| resolver.resource.clone())
            .collect::<Vec<_>>();

        let desired_ids = owned
            .iter()
            .map(|resource| resource.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        for resource in &previous_effective.owned {
            if !desired_ids.contains(resource.id.as_str()) {
                if let Err(error) = Self::release(resource) {
                    let desired_resources = owned.iter();
                    return DnsEffectiveState {
                        requested_generation: desired.generation,
                        applied_generation: None,
                        status: DnsEffectiveStatus::Degraded,
                        owned: Self::actual_owned(
                            desired_resources.chain(previous_effective.owned.iter()),
                        ),
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
            .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
        {
            let expected = resolver_body(desired.generation, assignment);
            match self.resources_for(desired.generation, assignment) {
                Ok(resources) => {
                    for (_, path) in resources {
                        match std::fs::read_to_string(&path) {
                            Ok(actual) if actual == expected => {}
                            Ok(_) => errors.push(format!(
                                "DNS resolver read-back mismatch for {}",
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
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
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

fn read_owned_resolver(path: &std::path::Path) -> Result<Option<Vec<u8>>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if !metadata.file_type().is_file() {
        return Err(format!(
            "refusing to replace non-file DNS resolver {}",
            path.display()
        ));
    }
    let body = std::fs::read(path).map_err(|error| error.to_string())?;
    if !body.starts_with(VORTIX_RESOLVER_MARKER.as_bytes()) {
        return Err(format!(
            "refusing to replace foreign DNS resolver {}",
            path.display()
        ));
    }
    Ok(Some(body))
}

fn resource_is_present(resource: &DnsOwnedResource) -> bool {
    let Some(path) = resource.id.strip_prefix("macos:") else {
        return false;
    };
    let Ok(Some(body)) = read_owned_resolver(std::path::Path::new(path)) else {
        return false;
    };
    body_has_generation(&String::from_utf8_lossy(&body), resource.generation)
}

fn body_has_generation(body: &str, generation: u64) -> bool {
    body.lines()
        .any(|line| line == format!("# generation: {generation}"))
}

fn write_owned_resolver(path: &std::path::Path, body: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let _ = read_owned_resolver(path)?;
    std::fs::create_dir_all(path.parent().ok_or("resolver path has no parent")?)
        .map_err(|error| error.to_string())?;
    let temp = path.with_extension(format!("vortix-{}", std::process::id()));
    if read_owned_resolver(&temp)?.is_some() {
        std::fs::remove_file(&temp).map_err(|error| error.to_string())?;
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&temp).map_err(|error| error.to_string())?;
    let result = file
        .write_all(body)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temp, path))
        .map_err(|error| error.to_string());
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
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
    fn repeated_apply_and_release_are_idempotent_and_generation_owned() {
        let temp = tempfile::tempdir().unwrap();
        let adapter = MacDnsPolicy::at(temp.path().join("resolver"));
        let first = policy(1, "1.1.1.1");
        let applied = adapter.apply(&first, None, &DnsEffectiveState::default());
        assert_eq!(applied.status, DnsEffectiveStatus::Applied);
        let repeated = adapter.apply(&first, Some(&first), &applied);
        assert_eq!(repeated.status, DnsEffectiveStatus::Applied);

        let released_policy = DnsPolicy {
            generation: 2,
            assignments: Vec::new(),
        };
        let released = adapter.apply(&released_policy, Some(&first), &repeated);
        assert_eq!(released.status, DnsEffectiveStatus::Released);
        assert!(!temp.path().join("resolver/default").exists());
        let repeated_release = adapter.apply(&released_policy, Some(&released_policy), &released);
        assert_eq!(repeated_release.status, DnsEffectiveStatus::Released);
    }

    #[test]
    fn foreign_default_resolver_is_never_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let resolver_dir = temp.path().join("resolver");
        std::fs::create_dir_all(&resolver_dir).unwrap();
        std::fs::write(resolver_dir.join("default"), "nameserver 9.9.9.9\n").unwrap();
        let adapter = MacDnsPolicy::at(resolver_dir.clone());
        let effective = adapter.apply(&policy(1, "1.1.1.1"), None, &DnsEffectiveState::default());
        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
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
        MacDnsPolicy::release(&first.owned[0]).unwrap();
        let body = std::fs::read_to_string(temp.path().join("resolver/default")).unwrap();
        assert!(body.contains("generation: 2"));
        assert!(body.contains("nameserver 8.8.8.8"));
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
}
