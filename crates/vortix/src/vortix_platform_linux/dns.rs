//! Linux DNS resolver using resolvectl, nmcli, and /etc/resolv.conf.
//!
//! Read-only inspection and generation-owned mutation both live behind DNS
//! ports. Protocol adapters never invoke resolver commands directly.

use crate::vortix_core::ports::dns::{
    DnsAssignment, DnsEffectiveState, DnsEffectiveStatus, DnsOwnedResource,
    DnsPlatformCapabilities, DnsPolicy, DnsPolicyAdapter, DnsResolver, DnsScope,
};
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Timeout for each resolver mutation/read-back invocation.
///
/// 5s is generous for a healthy resolved (typical roundtrip is ~10ms over
/// the local `DBus` / `Varlink` socket). Caps the failure window when
/// resolved is wedged or `DBus` is stuck — the caller's fail-open posture
/// surfaces the timeout as degraded effective DNS rather than blocking the
/// tunnel data path.
const RESOLVECTL_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Linux DNS resolution with fallback chain:
/// 1. `resolvectl` (systemd-resolved)
/// 2. `nmcli` (`NetworkManager`)
/// 3. `/etc/resolv.conf` (universal fallback)
pub struct LinuxDns;

#[derive(Debug)]
struct DnsCommandOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait DnsCommandRunner {
    fn run(&mut self, spec: CommandSpec) -> Result<DnsCommandOutput, String>;
}

#[derive(Debug, Default)]
struct RealDnsCommandRunner;

impl DnsCommandRunner for RealDnsCommandRunner {
    fn run(&mut self, spec: CommandSpec) -> Result<DnsCommandOutput, String> {
        let output =
            crate::vortix_process::run_to_output(spec).map_err(|error| error.to_string())?;
        Ok(DnsCommandOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResolvedLinkState {
    servers: Vec<String>,
    domains: Vec<String>,
    default_route: Option<bool>,
}

#[derive(Debug, Clone)]
struct ResolvedOwnership {
    resource: DnsOwnedResource,
    prior: ResolvedLinkState,
    applied: ResolvedLinkState,
}

#[derive(Debug, Clone)]
struct ResolvconfOwnership {
    resource: DnsOwnedResource,
    prior: Option<Vec<u8>>,
    applied: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
struct LinuxDnsOwnership {
    resolved: HashMap<String, ResolvedOwnership>,
    resolvconf: HashMap<String, ResolvconfOwnership>,
}

struct LinuxDnsPolicyEngine<R> {
    runner: R,
    ownership: LinuxDnsOwnership,
    mutated_resolved: HashSet<String>,
    mutated_resolvconf: HashSet<String>,
}

impl<R> LinuxDnsPolicyEngine<R> {
    fn new(runner: R) -> Self {
        Self {
            runner,
            ownership: LinuxDnsOwnership::default(),
            mutated_resolved: HashSet::new(),
            mutated_resolvconf: HashSet::new(),
        }
    }
}

static POLICY_ENGINE: OnceLock<Mutex<LinuxDnsPolicyEngine<RealDnsCommandRunner>>> = OnceLock::new();

fn policy_engine() -> &'static Mutex<LinuxDnsPolicyEngine<RealDnsCommandRunner>> {
    POLICY_ENGINE.get_or_init(|| Mutex::new(LinuxDnsPolicyEngine::new(RealDnsCommandRunner)))
}

impl DnsResolver for LinuxDns {
    fn get_dns_server() -> Option<String> {
        try_get_dns_resolvectl()
            .or_else(try_get_dns_nmcli)
            .or_else(try_get_dns_resolv_conf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxDnsBackend {
    Resolved,
    Resolvconf,
    Unavailable,
}

fn selected_backend() -> LinuxDnsBackend {
    if crate::utils::use_resolvectl_path() {
        LinuxDnsBackend::Resolved
    } else if crate::utils::resolvconf_works() {
        LinuxDnsBackend::Resolvconf
    } else {
        LinuxDnsBackend::Unavailable
    }
}

impl DnsPolicyAdapter for LinuxDns {
    fn capabilities(&self) -> DnsPlatformCapabilities {
        DnsPlatformCapabilities {
            scoped_domains: selected_backend() == LinuxDnsBackend::Resolved,
        }
    }

    fn apply(
        &self,
        desired: &DnsPolicy,
        previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> DnsEffectiveState {
        let Ok(mut engine) = policy_engine().lock() else {
            return degraded(
                desired.generation,
                previous_effective,
                "Linux DNS ownership ledger is unavailable".into(),
            );
        };
        engine.apply(
            selected_backend(),
            desired,
            previous_desired,
            previous_effective,
        )
    }

    fn verify(
        &self,
        desired: &DnsPolicy,
        _effective: &DnsEffectiveState,
    ) -> Result<(), Vec<String>> {
        let Ok(mut engine) = policy_engine().lock() else {
            return Err(vec!["Linux DNS ownership ledger is unavailable".into()]);
        };
        engine.verify_policy(selected_backend(), desired)
    }
}

fn active_assignments(policy: &DnsPolicy) -> impl Iterator<Item = &DnsAssignment> {
    policy
        .assignments
        .iter()
        .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
}

impl<R: DnsCommandRunner> LinuxDnsPolicyEngine<R> {
    fn apply(
        &mut self,
        backend: LinuxDnsBackend,
        desired: &DnsPolicy,
        previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> DnsEffectiveState {
        self.mutated_resolved.clear();
        self.mutated_resolvconf.clear();
        if backend == LinuxDnsBackend::Unavailable && active_assignments(desired).next().is_some() {
            return degraded(
                desired.generation,
                previous_effective,
                "no supported Linux DNS mutation backend (resolved or resolvconf)".into(),
            );
        }

        let before = self.ownership.clone();
        let effective =
            match self.apply_transaction(backend, desired, previous_desired, previous_effective) {
                Ok(()) => {
                    let owned = self.owned_resources();
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
                Err(error) => {
                    let rollback_errors = self.restore_ownership_snapshot(&before);
                    let rollback_complete = rollback_errors.is_empty();
                    let mut errors = vec![error];
                    errors.extend(rollback_errors);
                    DnsEffectiveState {
                        requested_generation: desired.generation,
                        applied_generation: rollback_complete
                            .then_some(previous_effective.applied_generation)
                            .flatten(),
                        status: DnsEffectiveStatus::Degraded,
                        owned: self.owned_resources(),
                        errors,
                    }
                }
            };
        self.mutated_resolved.clear();
        self.mutated_resolvconf.clear();
        effective
    }

    fn verify_policy(
        &mut self,
        backend: LinuxDnsBackend,
        desired: &DnsPolicy,
    ) -> Result<(), Vec<String>> {
        if backend == LinuxDnsBackend::Unavailable && active_assignments(desired).next().is_some() {
            return Err(vec![
                "no supported Linux DNS read-back backend (resolved or resolvconf)".into(),
            ]);
        }
        let errors = active_assignments(desired)
            .filter_map(|assignment| self.verify_assignment(backend, assignment).err())
            .collect::<Vec<_>>();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn verify_assignment(
        &mut self,
        backend: LinuxDnsBackend,
        assignment: &DnsAssignment,
    ) -> Result<(), String> {
        match backend {
            LinuxDnsBackend::Resolved => verify_resolved_state(
                &mut self.runner,
                &assignment.interface,
                &resolved_state_for(assignment),
            ),
            LinuxDnsBackend::Resolvconf => verify_resolvconf_record(&mut self.runner, assignment),
            LinuxDnsBackend::Unavailable => Ok(()),
        }
    }

    fn apply_transaction(
        &mut self,
        backend: LinuxDnsBackend,
        desired: &DnsPolicy,
        previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> Result<(), String> {
        let desired_assignments = active_assignments(desired).collect::<Vec<_>>();
        let new_primary = desired_assignments
            .iter()
            .copied()
            .find(|assignment| matches!(assignment.scope, DnsScope::CatchAll));
        let old_primary_interface = previous_desired.and_then(|policy| {
            active_assignments(policy)
                .find(|assignment| matches!(assignment.scope, DnsScope::CatchAll))
                .map(|assignment| assignment.interface.as_str())
        });
        let promoted_interface = new_primary
            .filter(|primary| Some(primary.interface.as_str()) != old_primary_interface)
            .map(|primary| primary.interface.as_str());

        // Establish and exactly verify the new catch-all before narrowing or
        // releasing the old one. Any later failure restores the snapshot.
        if let Some(primary) =
            new_primary.filter(|primary| Some(primary.interface.as_str()) != old_primary_interface)
        {
            self.apply_assignment(backend, desired.generation, primary)?;
        }
        for assignment in desired_assignments {
            if Some(assignment.interface.as_str()) == promoted_interface {
                continue;
            }
            self.apply_assignment(backend, desired.generation, assignment)?;
        }
        self.release_stale(backend, desired, previous_effective)
    }

    fn apply_assignment(
        &mut self,
        backend: LinuxDnsBackend,
        generation: u64,
        assignment: &DnsAssignment,
    ) -> Result<(), String> {
        match backend {
            LinuxDnsBackend::Resolved => self.apply_resolved(generation, assignment),
            LinuxDnsBackend::Resolvconf => self.apply_resolvconf(generation, assignment),
            LinuxDnsBackend::Unavailable => Ok(()),
        }
    }

    fn apply_resolved(
        &mut self,
        generation: u64,
        assignment: &DnsAssignment,
    ) -> Result<(), String> {
        let interface = assignment.interface.as_str();
        let expected = resolved_state_for(assignment);
        let current = read_resolved_state(&mut self.runner, interface)?;
        if let Some(owned) = self.ownership.resolved.get(interface) {
            if current != owned.applied {
                return Err(format!(
                    "refusing to overwrite DNS on {interface}: current resolved state no longer matches Vortix ownership"
                ));
            }
            if current == expected {
                self.ownership
                    .resolved
                    .get_mut(interface)
                    .expect("checked")
                    .resource = resource_for(LinuxDnsBackend::Resolved, generation, assignment);
                return Ok(());
            }
        } else {
            self.ownership.resolved.insert(
                interface.to_string(),
                ResolvedOwnership {
                    resource: resource_for(LinuxDnsBackend::Resolved, generation, assignment),
                    prior: current.clone(),
                    applied: current,
                },
            );
        }

        self.mutated_resolved.insert(interface.to_string());
        for spec in build_resolved_apply_specs(assignment) {
            run_spec(&mut self.runner, spec)?;
        }
        verify_resolved_state(&mut self.runner, interface, &expected)?;
        let owned = self
            .ownership
            .resolved
            .get_mut(interface)
            .expect("inserted");
        owned.resource = resource_for(LinuxDnsBackend::Resolved, generation, assignment);
        owned.applied = expected;
        Ok(())
    }

    fn apply_resolvconf(
        &mut self,
        generation: u64,
        assignment: &DnsAssignment,
    ) -> Result<(), String> {
        if !matches!(assignment.scope, DnsScope::CatchAll) {
            return Ok(());
        }
        let interface = assignment.interface.as_str();
        let expected = resolvconf_body(generation, assignment);
        let current = read_resolvconf_record(&mut self.runner, interface)?;
        if let Some(owned) = self.ownership.resolvconf.get(interface) {
            if current.as_deref().map(normalized_record) != Some(normalized_record(&owned.applied))
            {
                return Err(format!(
                    "refusing to overwrite DNS record vortix.{interface}: current record no longer matches Vortix ownership"
                ));
            }
            if normalized_record(current.as_deref().unwrap_or_default())
                == normalized_record(&expected)
            {
                self.ownership
                    .resolvconf
                    .get_mut(interface)
                    .expect("checked")
                    .resource = resource_for(LinuxDnsBackend::Resolvconf, generation, assignment);
                return Ok(());
            }
        } else {
            self.ownership.resolvconf.insert(
                interface.to_string(),
                ResolvconfOwnership {
                    resource: resource_for(LinuxDnsBackend::Resolvconf, generation, assignment),
                    prior: current,
                    applied: Vec::new(),
                },
            );
        }

        self.mutated_resolvconf.insert(interface.to_string());
        run_spec(
            &mut self.runner,
            build_resolvconf_apply_spec(interface, expected.clone()),
        )?;
        verify_resolvconf_record(&mut self.runner, assignment)?;
        let owned = self
            .ownership
            .resolvconf
            .get_mut(interface)
            .expect("inserted");
        owned.resource = resource_for(LinuxDnsBackend::Resolvconf, generation, assignment);
        owned.applied = expected;
        Ok(())
    }

    fn release_stale(
        &mut self,
        backend: LinuxDnsBackend,
        desired: &DnsPolicy,
        previous_effective: &DnsEffectiveState,
    ) -> Result<(), String> {
        let desired_resolved = if backend == LinuxDnsBackend::Resolved {
            active_assignments(desired)
                .map(|assignment| format!("resolved:{}", assignment.interface))
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        };
        let desired_resolvconf = if backend == LinuxDnsBackend::Resolvconf {
            active_assignments(desired)
                .filter(|assignment| matches!(assignment.scope, DnsScope::CatchAll))
                .map(|assignment| format!("resolvconf:{}", assignment.interface))
                .collect::<HashSet<_>>()
        } else {
            HashSet::new()
        };
        let authorized_ids = self
            .ownership
            .resolved
            .values()
            .map(|owned| owned.resource.id.clone())
            .chain(
                self.ownership
                    .resolvconf
                    .values()
                    .map(|owned| owned.resource.id.clone()),
            )
            .collect::<HashSet<_>>();

        let stale_resolved = self
            .ownership
            .resolved
            .values()
            .filter(|owned| !desired_resolved.contains(&owned.resource.id))
            .map(|owned| owned.resource.interface.clone())
            .collect::<Vec<_>>();
        for interface in stale_resolved {
            self.release_resolved(&interface)?;
        }
        let stale_resolvconf = self
            .ownership
            .resolvconf
            .values()
            .filter(|owned| !desired_resolvconf.contains(&owned.resource.id))
            .map(|owned| owned.resource.interface.clone())
            .collect::<Vec<_>>();
        for interface in stale_resolvconf {
            self.release_resolvconf(&interface)?;
        }

        for resource in &previous_effective.owned {
            let desired = desired_resolved.contains(&resource.id)
                || desired_resolvconf.contains(&resource.id);
            if desired || authorized_ids.contains(&resource.id) {
                continue;
            }
            return Err(format!(
                "refusing to release {} from persisted DNS ownership alone; current process did not create or verify it",
                resource.id
            ));
        }
        Ok(())
    }

    fn release_resolved(&mut self, interface: &str) -> Result<(), String> {
        let owned = self
            .ownership
            .resolved
            .get(interface)
            .cloned()
            .ok_or_else(|| format!("resolved DNS on {interface} is not owned by this process"))?;
        let current = read_resolved_state(&mut self.runner, interface)?;
        if current != owned.applied {
            return Err(format!(
                "refusing to restore DNS on {interface}: current resolved state no longer matches Vortix ownership"
            ));
        }
        self.mutated_resolved.insert(interface.to_string());
        write_resolved_state(&mut self.runner, interface, &owned.prior)?;
        verify_resolved_state(&mut self.runner, interface, &owned.prior)?;
        self.ownership.resolved.remove(interface);
        Ok(())
    }

    fn release_resolvconf(&mut self, interface: &str) -> Result<(), String> {
        let owned = self
            .ownership
            .resolvconf
            .get(interface)
            .cloned()
            .ok_or_else(|| {
                format!("resolvconf record on {interface} is not owned by this process")
            })?;
        let current = read_resolvconf_record(&mut self.runner, interface)?;
        if current.as_deref().map(normalized_record) != Some(normalized_record(&owned.applied)) {
            return Err(format!(
                "refusing to restore DNS record vortix.{interface}: current record no longer matches Vortix ownership"
            ));
        }
        self.mutated_resolvconf.insert(interface.to_string());
        write_resolvconf_record(&mut self.runner, interface, owned.prior.as_deref())?;
        let restored = read_resolvconf_record(&mut self.runner, interface)?;
        if restored.as_deref().map(normalized_record)
            != owned.prior.as_deref().map(normalized_record)
        {
            return Err(format!(
                "restored DNS record vortix.{interface} does not match the captured prior record"
            ));
        }
        self.ownership.resolvconf.remove(interface);
        Ok(())
    }

    fn restore_ownership_snapshot(&mut self, before: &LinuxDnsOwnership) -> Vec<String> {
        let mut errors = Vec::new();
        let current_resolved = self.ownership.resolved.clone();
        for (interface, owned) in &current_resolved {
            if !self.mutated_resolved.contains(interface) {
                continue;
            }
            let target = before
                .resolved
                .get(interface)
                .map_or(&owned.prior, |previous| &previous.applied);
            if let Err(error) = write_resolved_state(&mut self.runner, interface, target)
                .and_then(|()| verify_resolved_state(&mut self.runner, interface, target))
            {
                errors.push(format!("rollback DNS on {interface}: {error}"));
            }
        }
        for (interface, previous) in &before.resolved {
            if current_resolved.contains_key(interface)
                || !self.mutated_resolved.contains(interface)
            {
                continue;
            }
            if let Err(error) = write_resolved_state(&mut self.runner, interface, &previous.applied)
                .and_then(|()| {
                    verify_resolved_state(&mut self.runner, interface, &previous.applied)
                })
            {
                errors.push(format!("rollback released DNS on {interface}: {error}"));
            }
        }

        let current_resolvconf = self.ownership.resolvconf.clone();
        for (interface, owned) in &current_resolvconf {
            if !self.mutated_resolvconf.contains(interface) {
                continue;
            }
            let target = before
                .resolvconf
                .get(interface)
                .map_or(owned.prior.as_deref(), |previous| {
                    Some(previous.applied.as_slice())
                });
            if let Err(error) = write_resolvconf_record(&mut self.runner, interface, target) {
                errors.push(format!("rollback DNS record vortix.{interface}: {error}"));
            }
        }
        for (interface, previous) in &before.resolvconf {
            if current_resolvconf.contains_key(interface)
                || !self.mutated_resolvconf.contains(interface)
            {
                continue;
            }
            if let Err(error) = write_resolvconf_record(
                &mut self.runner,
                interface,
                Some(previous.applied.as_slice()),
            ) {
                errors.push(format!(
                    "rollback released DNS record vortix.{interface}: {error}"
                ));
            }
        }

        if errors.is_empty() {
            self.ownership = before.clone();
        } else {
            for (interface, owned) in &before.resolved {
                self.ownership
                    .resolved
                    .entry(interface.clone())
                    .or_insert_with(|| owned.clone());
            }
            for (interface, owned) in &before.resolvconf {
                self.ownership
                    .resolvconf
                    .entry(interface.clone())
                    .or_insert_with(|| owned.clone());
            }
        }
        errors
    }

    fn owned_resources(&self) -> Vec<DnsOwnedResource> {
        let mut resources = self
            .ownership
            .resolved
            .values()
            .map(|owned| owned.resource.clone())
            .chain(
                self.ownership
                    .resolvconf
                    .values()
                    .map(|owned| owned.resource.clone()),
            )
            .collect::<Vec<_>>();
        resources.sort_by(|a, b| a.id.cmp(&b.id));
        resources
    }
}

fn degraded(generation: u64, previous: &DnsEffectiveState, error: String) -> DnsEffectiveState {
    DnsEffectiveState {
        requested_generation: generation,
        applied_generation: previous.applied_generation,
        status: DnsEffectiveStatus::Degraded,
        owned: previous.owned.clone(),
        errors: vec![error],
    }
}

fn resource_for(
    backend: LinuxDnsBackend,
    generation: u64,
    assignment: &DnsAssignment,
) -> DnsOwnedResource {
    let prefix = match backend {
        LinuxDnsBackend::Resolved => "resolved",
        LinuxDnsBackend::Resolvconf => "resolvconf",
        LinuxDnsBackend::Unavailable => "unavailable",
    };
    DnsOwnedResource {
        generation,
        id: format!("{prefix}:{}", assignment.interface),
        profile_id: assignment.profile_id.clone(),
        interface: assignment.interface.clone(),
    }
}

fn run_spec<R: DnsCommandRunner>(runner: &mut R, spec: CommandSpec) -> Result<(), String> {
    let output = runner.run(spec)?;
    if output.success {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn resolved_state_for(assignment: &DnsAssignment) -> ResolvedLinkState {
    let mut servers = assignment
        .servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    servers.sort();
    servers.dedup();

    let mut domains = assignment.search_domains.clone();
    match &assignment.scope {
        DnsScope::CatchAll => domains.push("~.".into()),
        DnsScope::Scoped { domains: scoped } => domains.extend(scoped.iter().cloned()),
        DnsScope::Suppressed => {}
    }
    domains.sort();
    domains.dedup();

    ResolvedLinkState {
        servers,
        domains,
        default_route: match assignment.scope {
            DnsScope::CatchAll => Some(true),
            DnsScope::Scoped { .. } => Some(false),
            DnsScope::Suppressed => None,
        },
    }
}

fn read_resolved_state<R: DnsCommandRunner>(
    runner: &mut R,
    interface: &str,
) -> Result<ResolvedLinkState, String> {
    let mut servers = read_resolvectl_values(runner, "dns", interface)?;
    let mut domains = read_resolvectl_values(runner, "domain", interface)?;
    servers.sort();
    servers.dedup();
    domains.sort();
    domains.dedup();

    let values = read_resolvectl_values(runner, "default-route", interface)?;
    let default_route = match values.as_slice() {
        [] => None,
        [value] if value.eq_ignore_ascii_case("yes") || value == "1" => Some(true),
        [value] if value.eq_ignore_ascii_case("no") || value == "0" => Some(false),
        _ => {
            return Err(format!(
                "unrecognized resolved default-route read-back for {interface}: {values:?}"
            ));
        }
    };
    Ok(ResolvedLinkState {
        servers,
        domains,
        default_route,
    })
}

fn read_resolvectl_values<R: DnsCommandRunner>(
    runner: &mut R,
    property: &str,
    interface: &str,
) -> Result<Vec<String>, String> {
    let output = runner.run(
        CommandSpec::oneshot("resolvectl", vec![property.into(), interface.to_string()])
            .timeout(RESOLVECTL_CALL_TIMEOUT),
    )?;
    if !output.success {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut values = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let value_text = if index == 0 {
            line.split_once(':').map_or(line, |(_, values)| values)
        } else {
            line
        };
        values.extend(value_text.split_whitespace().map(ToOwned::to_owned));
    }
    Ok(values)
}

fn write_resolved_state<R: DnsCommandRunner>(
    runner: &mut R,
    interface: &str,
    state: &ResolvedLinkState,
) -> Result<(), String> {
    let mut dns_args = vec!["dns".into(), interface.to_string()];
    if state.servers.is_empty() {
        dns_args.push(String::new());
    } else {
        dns_args.extend(state.servers.iter().cloned());
    }
    let mut domain_args = vec!["domain".into(), interface.to_string()];
    if state.domains.is_empty() {
        domain_args.push(String::new());
    } else {
        domain_args.extend(state.domains.iter().cloned());
    }
    let default_route = state
        .default_route
        .map_or_else(String::new, |value| if value { "yes" } else { "no" }.into());
    for spec in [
        CommandSpec::oneshot("resolvectl", dns_args)
            .timeout(RESOLVECTL_CALL_TIMEOUT)
            .privilege(PrivilegeReq::Root),
        CommandSpec::oneshot("resolvectl", domain_args)
            .timeout(RESOLVECTL_CALL_TIMEOUT)
            .privilege(PrivilegeReq::Root),
        CommandSpec::oneshot(
            "resolvectl",
            vec!["default-route".into(), interface.to_string(), default_route],
        )
        .timeout(RESOLVECTL_CALL_TIMEOUT)
        .privilege(PrivilegeReq::Root),
    ] {
        run_spec(runner, spec)?;
    }
    Ok(())
}

fn verify_resolved_state<R: DnsCommandRunner>(
    runner: &mut R,
    interface: &str,
    expected: &ResolvedLinkState,
) -> Result<(), String> {
    let actual = read_resolved_state(runner, interface)?;
    if actual == *expected {
        Ok(())
    } else {
        Err(format!(
            "DNS read-back for {interface} differs from the complete requested resolved policy: expected {expected:?}, got {actual:?}"
        ))
    }
}

fn resolvconf_body(generation: u64, assignment: &DnsAssignment) -> Vec<u8> {
    let mut body = format!("# managed-by: vortix dns generation {generation}\n").into_bytes();
    for server in &assignment.servers {
        body.extend(format!("nameserver {server}\n").into_bytes());
    }
    if !assignment.search_domains.is_empty() {
        body.extend(format!("search {}\n", assignment.search_domains.join(" ")).into_bytes());
    }
    body
}

fn read_resolvconf_record<R: DnsCommandRunner>(
    runner: &mut R,
    interface: &str,
) -> Result<Option<Vec<u8>>, String> {
    let output = runner.run(
        CommandSpec::oneshot(
            "resolvconf",
            vec!["-l".into(), format!("vortix.{interface}")],
        )
        .timeout(RESOLVECTL_CALL_TIMEOUT),
    )?;
    if output.success {
        return Ok((!output.stdout.is_empty()).then_some(output.stdout));
    }
    let error = String::from_utf8_lossy(&output.stderr).into_owned();
    let lower = error.to_ascii_lowercase();
    if lower.is_empty() || lower.contains("not found") || lower.contains("no such") {
        Ok(None)
    } else {
        Err(error)
    }
}

fn verify_resolvconf_record<R: DnsCommandRunner>(
    runner: &mut R,
    assignment: &DnsAssignment,
) -> Result<(), String> {
    let Some(record) = read_resolvconf_record(runner, &assignment.interface)? else {
        return Err(format!(
            "Vortix resolvconf record for {} is missing",
            assignment.interface
        ));
    };
    let text = String::from_utf8_lossy(&record);
    let mut servers = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver "))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let mut expected_servers = assignment
        .servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    servers.sort();
    servers.dedup();
    expected_servers.sort();
    expected_servers.dedup();

    let mut search_domains = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("search "))
        .flat_map(str::split_whitespace)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let mut expected_search_domains = assignment.search_domains.clone();
    search_domains.sort();
    search_domains.dedup();
    expected_search_domains.sort();
    expected_search_domains.dedup();
    if servers == expected_servers && search_domains == expected_search_domains {
        Ok(())
    } else {
        Err(format!(
            "Vortix resolvconf record for {} differs from requested servers/search domains",
            assignment.interface
        ))
    }
}

fn normalized_record(record: &[u8]) -> String {
    String::from_utf8_lossy(record)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_resolvconf_record<R: DnsCommandRunner>(
    runner: &mut R,
    interface: &str,
    record: Option<&[u8]>,
) -> Result<(), String> {
    if let Some(record) = record {
        return run_spec(
            runner,
            build_resolvconf_apply_spec(interface, record.to_vec()),
        );
    }
    let output = runner.run(
        CommandSpec::oneshot(
            "resolvconf",
            vec!["-d".into(), format!("vortix.{interface}"), "-f".into()],
        )
        .timeout(RESOLVECTL_CALL_TIMEOUT)
        .privilege(PrivilegeReq::Root),
    )?;
    if output.success {
        Ok(())
    } else {
        let error = String::from_utf8_lossy(&output.stderr).into_owned();
        let lower = error.to_ascii_lowercase();
        if lower.is_empty() || lower.contains("not found") || lower.contains("no such") {
            Ok(())
        } else {
            Err(error)
        }
    }
}

fn build_resolved_apply_specs(assignment: &DnsAssignment) -> Vec<CommandSpec> {
    let mut dns_args = vec!["dns".into(), assignment.interface.clone()];
    dns_args.extend(assignment.servers.iter().map(ToString::to_string));
    let mut domains = assignment.search_domains.clone();
    match &assignment.scope {
        DnsScope::CatchAll => domains.push("~.".to_string()),
        DnsScope::Scoped { domains: scoped } => {
            // A systemd-resolved search domain is also a per-link routing
            // domain, so the plain suffix preserves both semantics.
            for domain in scoped {
                if !domains.contains(domain) {
                    domains.push(domain.clone());
                }
            }
        }
        DnsScope::Suppressed => return Vec::new(),
    }
    let mut domain_args = vec!["domain".into(), assignment.interface.clone()];
    domain_args.extend(domains);
    let default_route = if matches!(assignment.scope, DnsScope::CatchAll) {
        "yes"
    } else {
        "no"
    };
    vec![
        CommandSpec::oneshot("resolvectl", dns_args)
            .timeout(RESOLVECTL_CALL_TIMEOUT)
            .privilege(PrivilegeReq::Root),
        CommandSpec::oneshot("resolvectl", domain_args)
            .timeout(RESOLVECTL_CALL_TIMEOUT)
            .privilege(PrivilegeReq::Root),
        CommandSpec::oneshot(
            "resolvectl",
            vec![
                "default-route".into(),
                assignment.interface.clone(),
                default_route.into(),
            ],
        )
        .timeout(RESOLVECTL_CALL_TIMEOUT)
        .privilege(PrivilegeReq::Root),
    ]
}

fn build_resolvconf_apply_spec(interface: &str, body: Vec<u8>) -> CommandSpec {
    CommandSpec::oneshot(
        "resolvconf",
        vec![
            "-a".into(),
            format!("vortix.{interface}"),
            "-m".into(),
            "0".into(),
            "-x".into(),
        ],
    )
    .stdin(body)
    .timeout(RESOLVECTL_CALL_TIMEOUT)
    .privilege(PrivilegeReq::Root)
}

/// Try to get DNS from resolvectl (systemd-resolved, most modern distros).
fn try_get_dns_resolvectl() -> Option<String> {
    let output = crate::vortix_process::run_to_output(CommandSpec::oneshot(
        "resolvectl",
        vec!["status".into()],
    ))
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Look for "DNS Servers:" or "Current DNS Server:" line
        if trimmed.starts_with("DNS Servers:") || trimmed.starts_with("Current DNS Server:") {
            if let Some(dns) = trimmed.split(':').nth(1) {
                let dns = dns.trim().to_string();
                // May have multiple servers, take the first one
                let first = dns.split_whitespace().next().unwrap_or("").to_string();
                if !first.is_empty() {
                    return Some(first);
                }
            }
        }
    }
    None
}

/// Try to get DNS from `nmcli` (`NetworkManager` distros).
fn try_get_dns_nmcli() -> Option<String> {
    let output = crate::vortix_process::run_to_output(CommandSpec::oneshot(
        "nmcli",
        vec!["dev".into(), "show".into()],
    ))
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("IP4.DNS") {
            // Format: "IP4.DNS[1]:                             1.1.1.1"
            if let Some(dns) = trimmed.split(':').nth(1) {
                let dns = dns.trim().to_string();
                if !dns.is_empty() {
                    return Some(dns);
                }
            }
        }
    }
    None
}

/// Try to get DNS from /etc/resolv.conf (universal fallback).
fn try_get_dns_resolv_conf() -> Option<String> {
    let content = std::fs::read_to_string(RESOLV_CONF_PATH).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver") {
            let dns = trimmed.trim_start_matches("nameserver").trim().to_string();
            if !dns.is_empty() {
                return Some(dns);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::profile::ProfileId;
    use std::collections::VecDeque;

    #[derive(Debug)]
    struct FailureRule {
        program: String,
        args: Vec<String>,
        skip_matches: usize,
    }

    #[derive(Debug, Default)]
    struct FakeDnsCommandRunner {
        resolved: HashMap<String, ResolvedLinkState>,
        resolvconf: HashMap<String, Vec<u8>>,
        calls: Vec<CommandSpec>,
        failures: VecDeque<FailureRule>,
    }

    impl FakeDnsCommandRunner {
        fn fail(&mut self, program: &str, args: &[&str], skip_matches: usize) {
            self.failures.push_back(FailureRule {
                program: program.into(),
                args: args.iter().map(|arg| (*arg).into()).collect(),
                skip_matches,
            });
        }

        fn mutations(&self) -> Vec<Vec<String>> {
            self.calls
                .iter()
                .filter(|spec| {
                    (spec.program == "resolvectl" && spec.args.len() > 2)
                        || (spec.program == "resolvconf"
                            && matches!(spec.args.first().map(String::as_str), Some("-a" | "-d")))
                })
                .map(|spec| spec.args.clone())
                .collect()
        }

        fn output(stdout: impl Into<Vec<u8>>) -> DnsCommandOutput {
            DnsCommandOutput {
                success: true,
                stdout: stdout.into(),
                stderr: Vec::new(),
            }
        }
    }

    impl DnsCommandRunner for FakeDnsCommandRunner {
        fn run(&mut self, spec: CommandSpec) -> Result<DnsCommandOutput, String> {
            self.calls.push(spec.clone());
            if let Some(rule) = self.failures.front_mut() {
                if rule.program == spec.program && rule.args == spec.args {
                    if rule.skip_matches == 0 {
                        self.failures.pop_front();
                        return Ok(DnsCommandOutput {
                            success: false,
                            stdout: Vec::new(),
                            stderr: b"injected failure".to_vec(),
                        });
                    }
                    rule.skip_matches -= 1;
                }
            }

            match (spec.program.as_str(), spec.args.as_slice()) {
                ("resolvectl", [property, interface]) => {
                    let state = self.resolved.entry(interface.clone()).or_default();
                    let values = match property.as_str() {
                        "dns" => state.servers.join(" "),
                        "domain" => state.domains.join(" "),
                        "default-route" => state
                            .default_route
                            .map(|value| if value { "yes" } else { "no" })
                            .unwrap_or_default()
                            .into(),
                        _ => return Err(format!("unsupported resolvectl query: {spec:?}")),
                    };
                    Ok(Self::output(
                        format!("Link 7 ({interface}): {values}\n").into_bytes(),
                    ))
                }
                ("resolvectl", [property, interface, values @ ..]) => {
                    let state = self.resolved.entry(interface.clone()).or_default();
                    match property.as_str() {
                        "dns" => {
                            state.servers = values
                                .iter()
                                .filter(|value| !value.is_empty())
                                .cloned()
                                .collect();
                        }
                        "domain" => {
                            state.domains = values
                                .iter()
                                .filter(|value| !value.is_empty())
                                .cloned()
                                .collect();
                        }
                        "default-route" => {
                            state.default_route = match values.first().map(String::as_str) {
                                Some("yes") => Some(true),
                                Some("no") => Some(false),
                                Some("") | None => None,
                                other => return Err(format!("invalid default route: {other:?}")),
                            };
                        }
                        _ => return Err(format!("unsupported resolvectl mutation: {spec:?}")),
                    }
                    Ok(Self::output(Vec::new()))
                }
                ("resolvconf", [flag, record]) if flag == "-l" => Ok(Self::output(
                    self.resolvconf.get(record).cloned().unwrap_or_default(),
                )),
                ("resolvconf", [flag, record, ..]) if flag == "-a" => {
                    self.resolvconf
                        .insert(record.clone(), spec.stdin_bytes.unwrap_or_default());
                    Ok(Self::output(Vec::new()))
                }
                ("resolvconf", [flag, record, ..]) if flag == "-d" => {
                    self.resolvconf.remove(record);
                    Ok(Self::output(Vec::new()))
                }
                _ => Err(format!("unsupported command: {spec:?}")),
            }
        }
    }

    fn args_of(spec: &CommandSpec) -> Vec<String> {
        spec.args.clone()
    }

    fn assignment(scope: DnsScope) -> DnsAssignment {
        DnsAssignment {
            profile_id: ProfileId::new("corp"),
            interface: "wg0".into(),
            servers: vec!["1.1.1.1".parse().unwrap()],
            search_domains: Vec::new(),
            scope,
        }
    }

    fn assignment_for(interface: &str, server: &str, scope: DnsScope) -> DnsAssignment {
        DnsAssignment {
            profile_id: ProfileId::new(interface),
            interface: interface.into(),
            servers: vec![server.parse().unwrap()],
            search_domains: match &scope {
                DnsScope::Scoped { domains } => domains.clone(),
                DnsScope::CatchAll | DnsScope::Suppressed => Vec::new(),
            },
            scope,
        }
    }

    fn policy(generation: u64, assignments: Vec<DnsAssignment>) -> DnsPolicy {
        DnsPolicy {
            generation,
            assignments,
        }
    }

    #[test]
    fn resolved_primary_is_complete_per_link_policy() {
        let specs = build_resolved_apply_specs(&assignment(DnsScope::CatchAll));
        assert_eq!(args_of(&specs[0]), vec!["dns", "wg0", "1.1.1.1"]);
        assert_eq!(args_of(&specs[1]), vec!["domain", "wg0", "~."]);
        assert_eq!(args_of(&specs[2]), vec!["default-route", "wg0", "yes"]);
    }

    #[test]
    fn resolved_secondary_uses_only_explicit_search_domains() {
        let mut assignment = assignment(DnsScope::Scoped {
            domains: vec!["corp.example".into()],
        });
        assignment.search_domains = vec!["corp.example".into()];
        let specs = build_resolved_apply_specs(&assignment);
        assert_eq!(args_of(&specs[1]), vec!["domain", "wg0", "corp.example"]);
        assert!(!args_of(&specs[1]).iter().any(|argument| argument == "~."));
    }

    #[test]
    fn resolved_primary_keeps_search_domains_with_catch_all_route() {
        let mut assignment = assignment(DnsScope::CatchAll);
        assignment.search_domains = vec!["corp.example".into()];
        let specs = build_resolved_apply_specs(&assignment);
        assert_eq!(
            args_of(&specs[1]),
            vec!["domain", "wg0", "corp.example", "~."]
        );
    }

    #[test]
    fn resolvconf_uses_vortix_owned_record_and_stdin() {
        let mut engine = LinuxDnsPolicyEngine::new(FakeDnsCommandRunner::default());
        engine
            .apply_assignment(
                LinuxDnsBackend::Resolvconf,
                7,
                &assignment(DnsScope::CatchAll),
            )
            .unwrap();
        let spec = engine
            .runner
            .calls
            .iter()
            .find(|spec| {
                spec.program == "resolvconf" && spec.args.first().is_some_and(|arg| arg == "-a")
            })
            .expect("production apply path must write the Vortix-owned record");
        assert_eq!(args_of(spec), vec!["-a", "vortix.wg0", "-m", "0", "-x"]);
        assert_eq!(
            spec.stdin_bytes.as_deref(),
            Some(b"# managed-by: vortix dns generation 7\nnameserver 1.1.1.1\n".as_slice())
        );
    }

    #[test]
    fn suppressed_secondary_has_no_platform_commands() {
        assert!(build_resolved_apply_specs(&assignment(DnsScope::Suppressed)).is_empty());
        let mut engine = LinuxDnsPolicyEngine::new(FakeDnsCommandRunner::default());
        engine
            .apply_assignment(
                LinuxDnsBackend::Resolvconf,
                7,
                &assignment(DnsScope::Suppressed),
            )
            .unwrap();
        assert!(engine.runner.calls.is_empty());
    }

    #[test]
    fn primary_transfer_verifies_new_catchall_first_and_rolls_back_on_failure() {
        let mut runner = FakeDnsCommandRunner::default();
        runner.resolved.insert(
            "wg0".into(),
            ResolvedLinkState {
                servers: vec!["9.9.9.9".into()],
                domains: vec!["foreign.example".into()],
                default_route: Some(false),
            },
        );
        let previous = policy(
            1,
            vec![assignment_for("wg0", "1.1.1.1", DnsScope::CatchAll)],
        );
        let mut engine = LinuxDnsPolicyEngine::new(runner);
        let previous_effective = engine.apply(
            LinuxDnsBackend::Resolved,
            &previous,
            None,
            &DnsEffectiveState::default(),
        );
        assert_eq!(previous_effective.status, DnsEffectiveStatus::Applied);

        engine.runner.calls.clear();
        engine
            .runner
            .fail("resolvectl", &["domain", "wg0", "corp.example"], 0);
        let desired = policy(
            2,
            vec![
                assignment_for(
                    "wg0",
                    "1.1.1.1",
                    DnsScope::Scoped {
                        domains: vec!["corp.example".into()],
                    },
                ),
                assignment_for("wg1", "8.8.8.8", DnsScope::CatchAll),
            ],
        );
        let effective = engine.apply(
            LinuxDnsBackend::Resolved,
            &desired,
            Some(&previous),
            &previous_effective,
        );

        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert_eq!(
            engine.runner.resolved["wg0"],
            resolved_state_for(&previous.assignments[0])
        );
        assert_eq!(engine.runner.resolved["wg1"], ResolvedLinkState::default());
        let promote_call = engine
            .runner
            .calls
            .iter()
            .position(|spec| spec.args == ["dns", "wg1", "8.8.8.8"])
            .unwrap();
        let verify_new_call = engine
            .runner
            .calls
            .iter()
            .enumerate()
            .skip(promote_call + 1)
            .find(|(_, spec)| spec.args == ["dns", "wg1"])
            .map(|(index, _)| index)
            .unwrap();
        let narrow_call = engine
            .runner
            .calls
            .iter()
            .position(|spec| spec.args == ["dns", "wg0", "1.1.1.1"])
            .unwrap();
        assert!(promote_call < verify_new_call && verify_new_call < narrow_call);
        let mutations = engine.runner.mutations();
        let promote = mutations
            .iter()
            .position(|args| args == &["dns", "wg1", "8.8.8.8"])
            .unwrap();
        let narrow = mutations
            .iter()
            .position(|args| args == &["dns", "wg0", "1.1.1.1"])
            .unwrap();
        assert!(promote < narrow);
    }

    #[test]
    fn resolved_readback_rejects_extra_servers_and_catchall_on_scoped_link() {
        let mut engine = LinuxDnsPolicyEngine::new(FakeDnsCommandRunner::default());
        let desired = policy(
            1,
            vec![assignment_for(
                "wg0",
                "1.1.1.1",
                DnsScope::Scoped {
                    domains: vec!["corp.example".into()],
                },
            )],
        );
        let effective = engine.apply(
            LinuxDnsBackend::Resolved,
            &desired,
            None,
            &DnsEffectiveState::default(),
        );
        assert_eq!(effective.status, DnsEffectiveStatus::Applied);
        let state = engine.runner.resolved.get_mut("wg0").unwrap();
        state.servers.push("8.8.8.8".into());
        state.domains.push("~.".into());
        assert!(engine
            .verify_policy(LinuxDnsBackend::Resolved, &desired)
            .is_err());
    }

    #[test]
    fn readback_failure_restores_preexisting_foreign_state() {
        let prior = ResolvedLinkState {
            servers: vec!["9.9.9.9".into()],
            domains: vec!["lan.example".into()],
            default_route: Some(false),
        };
        let mut runner = FakeDnsCommandRunner::default();
        runner.resolved.insert("wg0".into(), prior.clone());
        // Skip the initial ownership snapshot query, then fail exact read-back.
        runner.fail("resolvectl", &["dns", "wg0"], 1);
        let mut engine = LinuxDnsPolicyEngine::new(runner);
        let desired = policy(
            1,
            vec![assignment_for("wg0", "1.1.1.1", DnsScope::CatchAll)],
        );
        let effective = engine.apply(
            LinuxDnsBackend::Resolved,
            &desired,
            None,
            &DnsEffectiveState::default(),
        );
        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert_eq!(engine.runner.resolved["wg0"], prior);
        assert!(effective.owned.is_empty());
    }

    #[test]
    fn release_failure_is_degraded_and_retains_truthful_ownership() {
        let prior = ResolvedLinkState {
            servers: vec!["9.9.9.9".into()],
            domains: vec!["lan.example".into()],
            default_route: Some(false),
        };
        let mut runner = FakeDnsCommandRunner::default();
        runner.resolved.insert("wg0".into(), prior);
        let mut engine = LinuxDnsPolicyEngine::new(runner);
        let desired = policy(
            1,
            vec![assignment_for("wg0", "1.1.1.1", DnsScope::CatchAll)],
        );
        let applied = engine.apply(
            LinuxDnsBackend::Resolved,
            &desired,
            None,
            &DnsEffectiveState::default(),
        );
        engine
            .runner
            .fail("resolvectl", &["dns", "wg0", "9.9.9.9"], 0);
        let released = policy(2, Vec::new());
        let effective = engine.apply(
            LinuxDnsBackend::Resolved,
            &released,
            Some(&desired),
            &applied,
        );
        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert_eq!(effective.owned.len(), 1);
        assert_eq!(effective.owned[0].id, "resolved:wg0");
    }

    #[test]
    fn successful_release_restores_exact_preexisting_link_state() {
        let prior = ResolvedLinkState {
            servers: vec!["149.112.112.112".into(), "9.9.9.9".into()],
            domains: vec!["lan.example".into(), "~internal.example".into()],
            default_route: Some(false),
        };
        let mut runner = FakeDnsCommandRunner::default();
        runner.resolved.insert("wg0".into(), prior.clone());
        let mut engine = LinuxDnsPolicyEngine::new(runner);
        let desired = policy(
            1,
            vec![assignment_for("wg0", "1.1.1.1", DnsScope::CatchAll)],
        );
        let applied = engine.apply(
            LinuxDnsBackend::Resolved,
            &desired,
            None,
            &DnsEffectiveState::default(),
        );
        let effective = engine.apply(
            LinuxDnsBackend::Resolved,
            &policy(2, Vec::new()),
            Some(&desired),
            &applied,
        );
        assert_eq!(effective.status, DnsEffectiveStatus::Released);
        assert!(effective.owned.is_empty());
        assert_eq!(engine.runner.resolved["wg0"], prior);
    }

    #[test]
    fn ownership_mismatch_is_left_untouched_and_reported_degraded() {
        let mut engine = LinuxDnsPolicyEngine::new(FakeDnsCommandRunner::default());
        let desired = policy(
            1,
            vec![assignment_for("wg0", "1.1.1.1", DnsScope::CatchAll)],
        );
        let applied = engine.apply(
            LinuxDnsBackend::Resolved,
            &desired,
            None,
            &DnsEffectiveState::default(),
        );
        let foreign = ResolvedLinkState {
            servers: vec!["4.4.4.4".into()],
            domains: vec!["~foreign.example".into()],
            default_route: Some(false),
        };
        engine.runner.resolved.insert("wg0".into(), foreign.clone());
        let effective = engine.apply(
            LinuxDnsBackend::Resolved,
            &policy(2, Vec::new()),
            Some(&desired),
            &applied,
        );
        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert_eq!(engine.runner.resolved["wg0"], foreign);
        assert_eq!(effective.owned.len(), 1);
    }

    #[test]
    fn persisted_ownership_never_authorizes_destructive_cleanup() {
        let runner = FakeDnsCommandRunner::default();
        let mut engine = LinuxDnsPolicyEngine::new(runner);
        let previous = DnsEffectiveState {
            requested_generation: 1,
            applied_generation: Some(1),
            status: DnsEffectiveStatus::Applied,
            owned: vec![DnsOwnedResource {
                generation: 1,
                id: "resolved:wg0".into(),
                profile_id: ProfileId::new("corp"),
                interface: "wg0".into(),
            }],
            errors: Vec::new(),
        };
        let effective = engine.apply(
            LinuxDnsBackend::Resolved,
            &policy(2, Vec::new()),
            None,
            &previous,
        );
        assert_eq!(effective.status, DnsEffectiveStatus::Degraded);
        assert!(effective.owned.is_empty());
        assert!(engine.runner.mutations().is_empty());
    }

    #[test]
    fn retry_of_identical_resolved_policy_is_idempotent() {
        let mut engine = LinuxDnsPolicyEngine::new(FakeDnsCommandRunner::default());
        let desired = policy(
            1,
            vec![assignment_for("wg0", "1.1.1.1", DnsScope::CatchAll)],
        );
        let applied = engine.apply(
            LinuxDnsBackend::Resolved,
            &desired,
            None,
            &DnsEffectiveState::default(),
        );
        engine.runner.calls.clear();
        let retry = engine.apply(
            LinuxDnsBackend::Resolved,
            &policy(2, desired.assignments.clone()),
            Some(&desired),
            &applied,
        );
        assert_eq!(retry.status, DnsEffectiveStatus::Applied);
        assert!(engine.runner.mutations().is_empty());
    }

    #[test]
    fn resolvconf_readback_is_exact_and_queries_only_the_vortix_record() {
        let mut engine = LinuxDnsPolicyEngine::new(FakeDnsCommandRunner::default());
        let desired = policy(
            7,
            vec![assignment_for("wg0", "1.1.1.1", DnsScope::CatchAll)],
        );
        let applied = engine.apply(
            LinuxDnsBackend::Resolvconf,
            &desired,
            None,
            &DnsEffectiveState::default(),
        );
        assert_eq!(applied.status, DnsEffectiveStatus::Applied);
        assert!(engine
            .runner
            .calls
            .iter()
            .any(|spec| { spec.program == "resolvconf" && spec.args == ["-l", "vortix.wg0"] }));
        engine.runner.resolvconf.insert(
            "vortix.wg0".into(),
            b"# managed-by: vortix dns generation 7\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"
                .to_vec(),
        );
        assert!(engine
            .verify_policy(LinuxDnsBackend::Resolvconf, &desired)
            .is_err());
    }

    // ── existing read-only resolver tests ────────────────────────────────

    #[test]
    fn test_parse_resolv_conf() {
        // Simulate the parsing logic
        let content = "# Generated by NetworkManager\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        let mut result = None;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                let dns = trimmed.trim_start_matches("nameserver").trim().to_string();
                if !dns.is_empty() {
                    result = Some(dns);
                    break;
                }
            }
        }
        assert_eq!(result, Some("1.1.1.1".to_string()));
    }
}
