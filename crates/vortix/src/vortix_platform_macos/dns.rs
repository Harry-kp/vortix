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
use crate::vortix_core::ports::owned_dns::{
    ExpectedDnsState, OwnedDns, OwnedDnsBackend, OwnedDnsError,
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

/// Vortix-owned `/etc/resolver` adapter. A configurable root keeps ownership,
/// idempotency, and partial-failure behavior testable without touching the
/// developer's resolver configuration.
#[derive(Debug, Clone)]
pub struct MacDnsPolicy {
    resolver_dir: std::path::PathBuf,
    expected_owner_uid: u32,
    #[cfg(test)]
    fail_readback_at: Option<usize>,
}

#[derive(Debug)]
struct PlannedResolver {
    resource: DnsOwnedResource,
    path: std::path::PathBuf,
    name: std::ffi::CString,
    body: String,
    original: Option<Vec<u8>>,
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
            fail_readback_at: None,
        }
    }

    #[cfg(test)]
    fn at_failing_readback(resolver_dir: std::path::PathBuf, write_number: usize) -> Self {
        let resolver_dir = canonical_test_resolver_dir(resolver_dir);
        Self {
            resolver_dir,
            expected_owner_uid: crate::utils::effective_user_group_ids().0,
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
        let owned = self
            .plan(policy)?
            .into_iter()
            .map(|resolver| resolver.resource)
            .collect::<Vec<_>>();
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
        policy
            .assignments
            .iter()
            .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
            .map(|assignment| self.resources_for(policy.generation, assignment))
            .collect::<Result<Vec<_>, _>>()
            .map(|groups| {
                groups
                    .into_iter()
                    .flatten()
                    .map(|(resource, _)| resource)
                    .collect()
            })
    }

    fn managed_resource_ids(&self) -> Result<std::collections::BTreeSet<String>, String> {
        use std::os::unix::ffi::OsStrExt as _;

        let Some(directory) = self.directory(false)? else {
            return Ok(std::collections::BTreeSet::new());
        };
        let mut managed = std::collections::BTreeSet::new();
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
            .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
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

    fn apply(
        &self,
        desired: &DnsPolicy,
        _previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> DnsEffectiveState {
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
            .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
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
        adapter.release(&first.owned[0]).unwrap();
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
                &policy(1, "1.1.1.1"),
                ExpectedDnsState::Absent
            ),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert!(std::fs::read_dir(&foreign_dir).unwrap().next().is_none());

        std::fs::remove_file(&resolver_dir).unwrap();
        std::fs::create_dir_all(&resolver_dir).unwrap();
        let foreign = temp.path().join("foreign-resolver");
        std::fs::write(&foreign, "nameserver 9.9.9.9\n").unwrap();
        symlink(&foreign, resolver_dir.join("default")).unwrap();
        let mut linked_entry = MacDnsPolicy::at(resolver_dir.clone());
        assert_eq!(
            OwnedDns::apply(
                &mut linked_entry,
                &policy(1, "1.1.1.1"),
                ExpectedDnsState::Absent
            ),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert_eq!(
            std::fs::read_to_string(&foreign).unwrap(),
            "nameserver 9.9.9.9\n"
        );

        std::fs::remove_file(resolver_dir.join("default")).unwrap();
        std::fs::write(
            resolver_dir.join("default"),
            "# managed-by: vortix dns\n# generation: 1\nnameserver 1.1.1.1\n",
        )
        .unwrap();
        std::fs::hard_link(resolver_dir.join("default"), resolver_dir.join("duplicate")).unwrap();
        let mut hardlinked = MacDnsPolicy::at(resolver_dir);
        assert_eq!(
            OwnedDns::audit(&mut hardlinked, &policy(1, "1.1.1.1")),
            Err(OwnedDnsError::EffectMayHaveApplied)
        );
    }
}
