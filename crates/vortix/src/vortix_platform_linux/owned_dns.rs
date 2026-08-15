//! Restart-safe Linux DNS effects for the privileged helper.

use std::collections::BTreeMap;

use crate::platform::fixed_root_command::{self, FixedCommandError, FixedCommandOutput};
use crate::vortix_core::ports::dns::{DnsAssignment, DnsPolicy, DnsScope};
use crate::vortix_core::ports::owned_dns::{
    ExpectedDnsState, OwnedDns, OwnedDnsBackend, OwnedDnsError, OwnedDnsLink,
    OwnedDnsRecoveryCandidate, PreparedOwnedDns,
};
use crate::vortix_core::privileged::{PhysicalDnsBackend, PhysicalDnsPrior, PhysicalDnsValue};

use super::dns::{
    normalized_record, parse_resolvectl_values, resolvconf_body, resolved_state_for,
    ResolvedLinkState,
};

const RESOLVECTL_CANDIDATES: &[&str] = &["/usr/bin/resolvectl", "/bin/resolvectl"];
const RESOLVCONF_CANDIDATES: &[&str] = &["/usr/sbin/resolvconf", "/sbin/resolvconf"];
const MAX_DNS_INPUT_BYTES: usize = 64 * 1024;

pub(crate) struct LinuxOwnedDns<R = FixedDnsRunner> {
    runner: R,
}

impl LinuxOwnedDns {
    pub(crate) const fn new() -> Self {
        Self {
            runner: FixedDnsRunner,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunError {
    Unavailable,
    OutcomeUnknown,
}

pub(crate) trait DnsRunner: Send {
    fn run(
        &mut self,
        candidates: &[&str],
        arguments: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<FixedCommandOutput, RunError>;
}

pub(crate) struct FixedDnsRunner;

impl DnsRunner for FixedDnsRunner {
    fn run(
        &mut self,
        candidates: &[&str],
        arguments: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<FixedCommandOutput, RunError> {
        fixed_root_command::run(candidates, arguments, stdin, MAX_DNS_INPUT_BYTES).map_err(
            |error| match error {
                FixedCommandError::FailedBeforeSpawn => RunError::Unavailable,
                FixedCommandError::OutcomeUnknown => RunError::OutcomeUnknown,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterError {
    Unavailable,
    Invalid,
    OutcomeUnknown,
}

impl From<RunError> for AdapterError {
    fn from(error: RunError) -> Self {
        match error {
            RunError::Unavailable => Self::Unavailable,
            RunError::OutcomeUnknown => Self::OutcomeUnknown,
        }
    }
}

impl<R: DnsRunner> OwnedDns for LinuxOwnedDns<R> {
    fn backend(&self) -> OwnedDnsBackend {
        OwnedDnsBackend::LinuxPendingPhysicalLedger
    }

    fn apply(
        &mut self,
        _desired: &DnsPolicy,
        _expected: ExpectedDnsState<'_>,
    ) -> Result<(), OwnedDnsError> {
        Err(OwnedDnsError::FailedBeforeEffect)
    }

    fn audit(&mut self, _desired: &DnsPolicy) -> Result<(), OwnedDnsError> {
        Err(OwnedDnsError::FailedBeforeEffect)
    }

    fn audit_absent(&mut self) -> Result<(), OwnedDnsError> {
        Err(OwnedDnsError::FailedBeforeEffect)
    }

    fn recover_pending(
        &mut self,
        _desired: &DnsPolicy,
        _prior: Option<&DnsPolicy>,
    ) -> Result<(), OwnedDnsError> {
        Err(OwnedDnsError::EffectMayHaveApplied)
    }

    fn audit_recovery(
        &mut self,
        _candidates: &[DnsPolicy],
        _allow_absent: bool,
    ) -> Result<(), OwnedDnsError> {
        Err(OwnedDnsError::EffectMayHaveApplied)
    }

    fn prepare_physical(
        &mut self,
        desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
        inherited: &[OwnedDnsLink],
    ) -> Result<PreparedOwnedDns, OwnedDnsError> {
        self.prepare(desired, expected, inherited)
            .map_err(|_| OwnedDnsError::FailedBeforeEffect)
    }

    fn apply_physical(
        &mut self,
        desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
        prepared: &PreparedOwnedDns,
        recovered: &[PreparedOwnedDns],
    ) -> Result<(), OwnedDnsError> {
        self.converge(desired, expected, prepared, recovered, false)
    }

    fn audit_physical(
        &mut self,
        desired: &DnsPolicy,
        prepared: &PreparedOwnedDns,
    ) -> Result<(), OwnedDnsError> {
        self.verify_policy(desired, prepared)
            .map_err(|_| OwnedDnsError::EffectMayHaveApplied)
    }

    fn recover_pending_physical(
        &mut self,
        desired: &DnsPolicy,
        prior: Option<&DnsPolicy>,
        prepared: &PreparedOwnedDns,
        recovered: &[PreparedOwnedDns],
    ) -> Result<(), OwnedDnsError> {
        let expected = prior.map_or(ExpectedDnsState::Absent, ExpectedDnsState::Applied);
        self.converge(desired, expected, prepared, recovered, true)
    }

    fn audit_recovery_physical(
        &mut self,
        candidates: &[OwnedDnsRecoveryCandidate],
        allow_absent: bool,
    ) -> Result<(), OwnedDnsError> {
        if candidates.is_empty() {
            return allow_absent
                .then_some(())
                .ok_or(OwnedDnsError::EffectMayHaveApplied);
        }
        if candidates
            .iter()
            .any(|candidate| !linux_backend(candidate.physical().backend()))
        {
            return Err(OwnedDnsError::EffectMayHaveApplied);
        }
        if candidates.iter().any(|candidate| {
            self.verify_policy(candidate.policy(), candidate.physical())
                .is_ok()
        }) {
            Ok(())
        } else {
            Err(OwnedDnsError::EffectMayHaveApplied)
        }
    }
}

impl<R: DnsRunner> LinuxOwnedDns<R> {
    fn prepare(
        &mut self,
        desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
        inherited: &[OwnedDnsLink],
    ) -> Result<PreparedOwnedDns, AdapterError> {
        validate_interfaces(desired)?;
        let forced = inherited_backend(inherited)?;
        if let Some(backend) = forced {
            return self.prepare_backend(backend, desired, expected, inherited);
        }
        if active_assignments(desired).next().is_none() {
            return Ok(PreparedOwnedDns::new(
                PhysicalDnsBackend::LinuxResolved,
                Vec::new(),
            ));
        }
        match self.prepare_backend(
            PhysicalDnsBackend::LinuxResolved,
            desired,
            expected,
            inherited,
        ) {
            Err(AdapterError::Unavailable) => self.prepare_backend(
                PhysicalDnsBackend::LinuxResolvconf,
                desired,
                expected,
                inherited,
            ),
            result => result,
        }
    }

    fn prepare_backend(
        &mut self,
        backend: PhysicalDnsBackend,
        desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
        inherited: &[OwnedDnsLink],
    ) -> Result<PreparedOwnedDns, AdapterError> {
        let desired_states = policy_states(backend, desired)?;
        let expected_states = match expected {
            ExpectedDnsState::Absent => BTreeMap::new(),
            ExpectedDnsState::Applied(policy) => policy_states(backend, policy)?,
        };
        let inherited = inherited_links(backend, inherited)?;
        let mut observed = BTreeMap::new();
        for (interface, prior) in &inherited {
            let current = self.read_state(backend, interface)?;
            let expected = expected_states
                .get(interface)
                .or_else(|| desired_states.contains_key(interface).then_some(prior));
            let Some(expected) = expected else {
                return Err(AdapterError::Invalid);
            };
            if !state_eq(&current, expected) || !prior_matches_backend(backend, prior) {
                return Err(AdapterError::Invalid);
            }
            observed.insert(interface.clone(), current);
        }
        let mut links = Vec::with_capacity(desired_states.len());
        for interface in desired_states.keys() {
            let current = match observed.remove(interface) {
                Some(current) => current,
                None => self.read_state(backend, interface)?,
            };
            let prior = if let Some(prior) = inherited.get(interface) {
                let expected = expected_states
                    .get(interface)
                    .ok_or(AdapterError::Invalid)?;
                if !state_eq(&current, expected) {
                    return Err(AdapterError::Invalid);
                }
                prior.clone()
            } else {
                if let Some(expected) = expected_states.get(interface) {
                    if !state_eq(&current, expected) {
                        return Err(AdapterError::Invalid);
                    }
                }
                current
            };
            links.push(OwnedDnsLink::new(interface.clone(), prior));
        }
        Ok(PreparedOwnedDns::new(backend, links))
    }

    fn converge(
        &mut self,
        desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
        prepared: &PreparedOwnedDns,
        recovered: &[PreparedOwnedDns],
        allow_converged_members: bool,
    ) -> Result<(), OwnedDnsError> {
        let backend = prepared.backend();
        if !linux_backend(backend)
            || recovered
                .iter()
                .any(|candidate| candidate.backend() != backend)
        {
            return Err(OwnedDnsError::FailedBeforeEffect);
        }
        let desired_states =
            policy_states(backend, desired).map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
        let expected_states = match expected {
            ExpectedDnsState::Absent => Ok(BTreeMap::new()),
            ExpectedDnsState::Applied(policy) => policy_states(backend, policy),
        }
        .map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
        let prepared_priors = inherited_links(backend, prepared.links())
            .map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
        if prepared_priors.len() != desired_states.len()
            || desired_states
                .keys()
                .any(|interface| !prepared_priors.contains_key(interface))
        {
            return Err(OwnedDnsError::FailedBeforeEffect);
        }
        let all_priors = recovered
            .iter()
            .flat_map(PreparedOwnedDns::links)
            .chain(prepared.links())
            .cloned()
            .collect::<Vec<_>>();
        let all_priors =
            inherited_links(backend, &all_priors).map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
        let actions = build_actions(
            &desired_states,
            &expected_states,
            &prepared_priors,
            &all_priors,
        )
        .map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
        self.execute_actions(backend, &actions, allow_converged_members)
    }

    fn execute_actions(
        &mut self,
        backend: PhysicalDnsBackend,
        actions: &[DnsAction],
        allow_target: bool,
    ) -> Result<(), OwnedDnsError> {
        let mut current = Vec::with_capacity(actions.len());
        for action in actions {
            let observed = self
                .read_state(backend, &action.interface)
                .map_err(|_| OwnedDnsError::FailedBeforeEffect)?;
            if !(state_eq(&observed, &action.expected)
                || allow_target && state_eq(&observed, &action.target))
            {
                return Err(OwnedDnsError::FailedBeforeEffect);
            }
            current.push(observed);
        }
        let mut mutated = Vec::new();
        for (index, action) in actions.iter().enumerate() {
            if state_eq(&current[index], &action.target) {
                continue;
            }
            mutated.push(index);
            if self
                .write_state(backend, &action.interface, &action.target)
                .and_then(|()| self.verify_state(backend, &action.interface, &action.target))
                .is_err()
            {
                return self.rollback_actions(backend, actions, &current, &mutated);
            }
        }
        Ok(())
    }

    fn rollback_actions(
        &mut self,
        backend: PhysicalDnsBackend,
        actions: &[DnsAction],
        original: &[PhysicalDnsPrior],
        mutated: &[usize],
    ) -> Result<(), OwnedDnsError> {
        let mut rollback_ok = true;
        for index in mutated.iter().rev() {
            let restored = self
                .write_state(backend, &actions[*index].interface, &original[*index])
                .and_then(|()| {
                    self.verify_state(backend, &actions[*index].interface, &original[*index])
                })
                .is_ok();
            rollback_ok &= restored;
        }
        if rollback_ok {
            Err(OwnedDnsError::FailedBeforeEffect)
        } else {
            Err(OwnedDnsError::EffectMayHaveApplied)
        }
    }

    fn verify_policy(
        &mut self,
        policy: &DnsPolicy,
        prepared: &PreparedOwnedDns,
    ) -> Result<(), AdapterError> {
        let expected = policy_states(prepared.backend(), policy)?;
        let prepared_interfaces = prepared
            .links()
            .iter()
            .map(OwnedDnsLink::interface)
            .collect::<std::collections::BTreeSet<_>>();
        if prepared_interfaces.len() != prepared.links().len()
            || prepared_interfaces.len() != expected.len()
            || expected
                .keys()
                .any(|interface| !prepared_interfaces.contains(interface.as_str()))
        {
            return Err(AdapterError::Invalid);
        }
        for (interface, expected) in expected {
            self.verify_state(prepared.backend(), &interface, &expected)?;
        }
        Ok(())
    }

    fn verify_state(
        &mut self,
        backend: PhysicalDnsBackend,
        interface: &str,
        expected: &PhysicalDnsPrior,
    ) -> Result<(), AdapterError> {
        let actual = self.read_state(backend, interface)?;
        state_eq(&actual, expected)
            .then_some(())
            .ok_or(AdapterError::Invalid)
    }

    fn read_state(
        &mut self,
        backend: PhysicalDnsBackend,
        interface: &str,
    ) -> Result<PhysicalDnsPrior, AdapterError> {
        match backend {
            PhysicalDnsBackend::LinuxResolved => self.read_resolved(interface),
            PhysicalDnsBackend::LinuxResolvconf => self.read_resolvconf(interface),
            PhysicalDnsBackend::MacOsResolverFiles => Err(AdapterError::Invalid),
        }
    }

    fn write_state(
        &mut self,
        backend: PhysicalDnsBackend,
        interface: &str,
        state: &PhysicalDnsPrior,
    ) -> Result<(), AdapterError> {
        match (backend, state) {
            (
                PhysicalDnsBackend::LinuxResolved,
                PhysicalDnsPrior::Resolved {
                    servers,
                    domains,
                    default_route,
                },
            ) => self.write_resolved(interface, servers, domains, *default_route),
            (PhysicalDnsBackend::LinuxResolvconf, PhysicalDnsPrior::Resolvconf { record }) => {
                self.write_resolvconf(interface, record.as_deref())
            }
            _ => Err(AdapterError::Invalid),
        }
    }

    fn read_resolved(&mut self, interface: &str) -> Result<PhysicalDnsPrior, AdapterError> {
        let servers = self.resolvectl_values("dns", interface)?;
        let domains = self.resolvectl_values("domain", interface)?;
        let route = self.resolvectl_values("default-route", interface)?;
        let default_route = match route.as_slice() {
            [] => None,
            [value] if value.eq_ignore_ascii_case("yes") || value == "1" => Some(true),
            [value] if value.eq_ignore_ascii_case("no") || value == "0" => Some(false),
            _ => return Err(AdapterError::Invalid),
        };
        Ok(PhysicalDnsPrior::Resolved {
            servers: values(servers)?,
            domains: values(domains)?,
            default_route,
        })
    }

    fn resolvectl_values(
        &mut self,
        property: &str,
        interface: &str,
    ) -> Result<Vec<String>, AdapterError> {
        let output = self
            .runner
            .run(RESOLVECTL_CANDIDATES, &[property, interface], None)?;
        if !output.status.success() {
            return Err(AdapterError::Invalid);
        }
        let mut values = parse_resolvectl_values(&output.stdout);
        values.sort();
        values.dedup();
        Ok(values)
    }

    fn write_resolved(
        &mut self,
        interface: &str,
        servers: &[PhysicalDnsValue],
        domains: &[PhysicalDnsValue],
        default_route: Option<bool>,
    ) -> Result<(), AdapterError> {
        let servers = servers
            .iter()
            .map(PhysicalDnsValue::as_str)
            .collect::<Vec<_>>();
        let domains = domains
            .iter()
            .map(PhysicalDnsValue::as_str)
            .collect::<Vec<_>>();
        let mut dns = vec!["dns", interface];
        dns.extend(servers.iter().copied());
        if servers.is_empty() {
            dns.push("");
        }
        let mut domain = vec!["domain", interface];
        domain.extend(domains.iter().copied());
        if domains.is_empty() {
            domain.push("");
        }
        let route = default_route.map_or("", |value| if value { "yes" } else { "no" });
        for arguments in [dns, domain, vec!["default-route", interface, route]] {
            let output = self.runner.run(RESOLVECTL_CANDIDATES, &arguments, None)?;
            if !output.status.success() {
                return Err(AdapterError::OutcomeUnknown);
            }
        }
        Ok(())
    }

    fn read_resolvconf(&mut self, interface: &str) -> Result<PhysicalDnsPrior, AdapterError> {
        let name = format!("vortix.{interface}");
        let output = self
            .runner
            .run(RESOLVCONF_CANDIDATES, &["-l", &name], None)?;
        let record = if output.status.success() {
            Some(output.stdout.into_bytes())
        } else if missing_record(&output.stderr) {
            None
        } else {
            return Err(AdapterError::Invalid);
        };
        Ok(PhysicalDnsPrior::Resolvconf { record })
    }

    fn write_resolvconf(
        &mut self,
        interface: &str,
        record: Option<&[u8]>,
    ) -> Result<(), AdapterError> {
        let name = format!("vortix.{interface}");
        let (arguments, stdin) = record.map_or_else(
            || (vec!["-d", name.as_str(), "-f"], None),
            |record| (vec!["-a", name.as_str()], Some(record)),
        );
        let output = self.runner.run(RESOLVCONF_CANDIDATES, &arguments, stdin)?;
        if output.status.success() || (record.is_none() && missing_record(&output.stderr)) {
            Ok(())
        } else {
            Err(AdapterError::OutcomeUnknown)
        }
    }
}

#[derive(Debug)]
struct DnsAction {
    interface: String,
    expected: PhysicalDnsPrior,
    target: PhysicalDnsPrior,
}

fn build_actions(
    desired: &BTreeMap<String, PhysicalDnsPrior>,
    expected: &BTreeMap<String, PhysicalDnsPrior>,
    prepared_priors: &BTreeMap<String, PhysicalDnsPrior>,
    all_priors: &BTreeMap<String, PhysicalDnsPrior>,
) -> Result<Vec<DnsAction>, AdapterError> {
    let mut actions = Vec::new();
    for (interface, target) in desired {
        let before = expected
            .get(interface)
            .or_else(|| prepared_priors.get(interface))
            .ok_or(AdapterError::Invalid)?;
        actions.push(DnsAction {
            interface: interface.clone(),
            expected: before.clone(),
            target: target.clone(),
        });
    }
    for (interface, before) in expected {
        if desired.contains_key(interface) {
            continue;
        }
        let target = all_priors.get(interface).ok_or(AdapterError::Invalid)?;
        actions.push(DnsAction {
            interface: interface.clone(),
            expected: before.clone(),
            target: target.clone(),
        });
    }
    Ok(actions)
}

fn policy_states(
    backend: PhysicalDnsBackend,
    policy: &DnsPolicy,
) -> Result<BTreeMap<String, PhysicalDnsPrior>, AdapterError> {
    validate_interfaces(policy)?;
    let active = active_assignments(policy).collect::<Vec<_>>();
    if backend == PhysicalDnsBackend::LinuxResolvconf
        && (active.len() > 1
            || active
                .iter()
                .any(|assignment| !matches!(assignment.scope, DnsScope::CatchAll)))
    {
        return Err(AdapterError::Invalid);
    }
    active
        .into_iter()
        .map(|assignment| {
            let state = match backend {
                PhysicalDnsBackend::LinuxResolved => {
                    let ResolvedLinkState {
                        servers,
                        domains,
                        default_route,
                    } = resolved_state_for(assignment);
                    PhysicalDnsPrior::Resolved {
                        servers: values(servers)?,
                        domains: values(domains)?,
                        default_route,
                    }
                }
                PhysicalDnsBackend::LinuxResolvconf => PhysicalDnsPrior::Resolvconf {
                    record: Some(resolvconf_body(policy.generation, assignment)),
                },
                PhysicalDnsBackend::MacOsResolverFiles => return Err(AdapterError::Invalid),
            };
            Ok((assignment.interface.clone(), state))
        })
        .collect()
}

fn inherited_backend(links: &[OwnedDnsLink]) -> Result<Option<PhysicalDnsBackend>, AdapterError> {
    let mut backend = None;
    for link in links {
        let candidate = match link.prior() {
            PhysicalDnsPrior::Resolved { .. } => PhysicalDnsBackend::LinuxResolved,
            PhysicalDnsPrior::Resolvconf { .. } => PhysicalDnsBackend::LinuxResolvconf,
            PhysicalDnsPrior::MacOsResolverFiles => return Err(AdapterError::Invalid),
        };
        if backend.is_some_and(|backend| backend != candidate) {
            return Err(AdapterError::Invalid);
        }
        backend = Some(candidate);
    }
    Ok(backend)
}

fn inherited_links(
    backend: PhysicalDnsBackend,
    links: &[OwnedDnsLink],
) -> Result<BTreeMap<String, PhysicalDnsPrior>, AdapterError> {
    let mut inherited = BTreeMap::new();
    for link in links {
        if !valid_interface(link.interface()) || !prior_matches_backend(backend, link.prior()) {
            return Err(AdapterError::Invalid);
        }
        if let Some(existing) = inherited.insert(link.interface().to_string(), link.prior().clone())
        {
            if !state_eq(&existing, link.prior()) {
                return Err(AdapterError::Invalid);
            }
        }
    }
    Ok(inherited)
}

fn prior_matches_backend(backend: PhysicalDnsBackend, prior: &PhysicalDnsPrior) -> bool {
    matches!(
        (backend, prior),
        (
            PhysicalDnsBackend::LinuxResolved,
            PhysicalDnsPrior::Resolved { .. }
        ) | (
            PhysicalDnsBackend::LinuxResolvconf,
            PhysicalDnsPrior::Resolvconf { .. }
        )
    )
}

fn state_eq(left: &PhysicalDnsPrior, right: &PhysicalDnsPrior) -> bool {
    match (left, right) {
        (
            PhysicalDnsPrior::Resolvconf { record: left },
            PhysicalDnsPrior::Resolvconf { record: right },
        ) => left.as_deref().map(normalized_record) == right.as_deref().map(normalized_record),
        _ => left == right,
    }
}

fn values(values: Vec<String>) -> Result<Vec<PhysicalDnsValue>, AdapterError> {
    values
        .into_iter()
        .map(|value| PhysicalDnsValue::new(value).map_err(|_| AdapterError::Invalid))
        .collect()
}

fn active_assignments(policy: &DnsPolicy) -> impl Iterator<Item = &DnsAssignment> {
    policy
        .assignments
        .iter()
        .filter(|assignment| !matches!(assignment.scope, DnsScope::Suppressed))
}

fn validate_interfaces(policy: &DnsPolicy) -> Result<(), AdapterError> {
    policy
        .assignments
        .iter()
        .all(|assignment| valid_interface(&assignment.interface))
        .then_some(())
        .ok_or(AdapterError::Invalid)
}

fn valid_interface(interface: &str) -> bool {
    interface.starts_with("vx")
        && interface.len() <= 15
        && interface.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

const fn linux_backend(backend: PhysicalDnsBackend) -> bool {
    matches!(
        backend,
        PhysicalDnsBackend::LinuxResolved | PhysicalDnsBackend::LinuxResolvconf
    )
}

fn missing_record(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("not found") || lower.contains("no such")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::ExitStatus;

    use super::*;
    use crate::vortix_core::profile::ProfileId;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Call {
        program: &'static str,
        arguments: Vec<String>,
    }

    #[derive(Default)]
    struct FakeRunner {
        resolved_available: bool,
        resolvconf_available: bool,
        resolved: BTreeMap<String, PhysicalDnsPrior>,
        resolvconf: BTreeMap<String, Vec<u8>>,
        calls: Vec<Call>,
        write_count: usize,
        fail_after_write: BTreeSet<usize>,
        fail_before_write: BTreeSet<usize>,
    }

    impl FakeRunner {
        fn available() -> Self {
            Self {
                resolved_available: true,
                resolvconf_available: true,
                ..Self::default()
            }
        }

        fn resolved_state(&self, interface: &str) -> PhysicalDnsPrior {
            self.resolved
                .get(interface)
                .cloned()
                .unwrap_or_else(empty_resolved)
        }

        fn record_call(&mut self, program: &'static str, arguments: &[&str]) {
            self.calls.push(Call {
                program,
                arguments: arguments
                    .iter()
                    .map(|argument| (*argument).to_string())
                    .collect(),
            });
        }

        fn begin_write(&mut self) -> Result<bool, RunError> {
            self.write_count += 1;
            if self.fail_before_write.contains(&self.write_count) {
                return Err(RunError::OutcomeUnknown);
            }
            Ok(self.fail_after_write.contains(&self.write_count))
        }

        fn run_resolved(&mut self, arguments: &[&str]) -> Result<FixedCommandOutput, RunError> {
            if !self.resolved_available {
                return Err(RunError::Unavailable);
            }
            let [property, interface, rest @ ..] = arguments else {
                return Ok(command_output(false, "", "invalid arguments"));
            };
            if rest.is_empty() {
                let state = self.resolved_state(interface);
                let PhysicalDnsPrior::Resolved {
                    servers,
                    domains,
                    default_route,
                } = state
                else {
                    return Ok(command_output(false, "", "wrong backend"));
                };
                let values = match *property {
                    "dns" => servers
                        .iter()
                        .map(PhysicalDnsValue::as_str)
                        .collect::<Vec<_>>(),
                    "domain" => domains
                        .iter()
                        .map(PhysicalDnsValue::as_str)
                        .collect::<Vec<_>>(),
                    "default-route" => default_route
                        .map(|value| if value { "yes" } else { "no" })
                        .into_iter()
                        .collect(),
                    _ => return Ok(command_output(false, "", "unknown property")),
                };
                return Ok(command_output(
                    true,
                    &format!("Link: {}", values.join(" ")),
                    "",
                ));
            }

            let fail_after = self.begin_write()?;
            let state = self
                .resolved
                .entry((*interface).to_string())
                .or_insert_with(empty_resolved);
            let PhysicalDnsPrior::Resolved {
                servers,
                domains,
                default_route,
            } = state
            else {
                return Ok(command_output(false, "", "wrong backend"));
            };
            match *property {
                "dns" => *servers = physical_values(rest),
                "domain" => *domains = physical_values(rest),
                "default-route" => {
                    *default_route = match rest {
                        ["yes"] => Some(true),
                        ["no"] => Some(false),
                        [""] => None,
                        _ => return Ok(command_output(false, "", "invalid route")),
                    };
                }
                _ => return Ok(command_output(false, "", "unknown property")),
            }
            if fail_after {
                Err(RunError::OutcomeUnknown)
            } else {
                Ok(command_output(true, "", ""))
            }
        }

        fn run_resolvconf(
            &mut self,
            arguments: &[&str],
            stdin: Option<&[u8]>,
        ) -> Result<FixedCommandOutput, RunError> {
            if !self.resolvconf_available {
                return Err(RunError::Unavailable);
            }
            match arguments {
                ["-l", name] => Ok(self.resolvconf.get(*name).map_or_else(
                    || command_output(false, "", "not found"),
                    |record| command_output(true, std::str::from_utf8(record).unwrap(), ""),
                )),
                ["-a", name] => {
                    let fail_after = self.begin_write()?;
                    self.resolvconf
                        .insert((*name).to_string(), stdin.unwrap_or_default().to_vec());
                    if fail_after {
                        Err(RunError::OutcomeUnknown)
                    } else {
                        Ok(command_output(true, "", ""))
                    }
                }
                ["-d", name, "-f"] => {
                    let fail_after = self.begin_write()?;
                    self.resolvconf.remove(*name);
                    if fail_after {
                        Err(RunError::OutcomeUnknown)
                    } else {
                        Ok(command_output(true, "", ""))
                    }
                }
                _ => Ok(command_output(false, "", "invalid arguments")),
            }
        }
    }

    impl DnsRunner for FakeRunner {
        fn run(
            &mut self,
            candidates: &[&str],
            arguments: &[&str],
            stdin: Option<&[u8]>,
        ) -> Result<FixedCommandOutput, RunError> {
            let program = if candidates == RESOLVECTL_CANDIDATES {
                "resolvectl"
            } else if candidates == RESOLVCONF_CANDIDATES {
                "resolvconf"
            } else {
                return Err(RunError::Unavailable);
            };
            self.record_call(program, arguments);
            match program {
                "resolvectl" => self.run_resolved(arguments),
                "resolvconf" => self.run_resolvconf(arguments, stdin),
                _ => unreachable!(),
            }
        }
    }

    fn command_output(success: bool, stdout: &str, stderr: &str) -> FixedCommandOutput {
        FixedCommandOutput {
            status: ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    fn physical_values(values: &[&str]) -> Vec<PhysicalDnsValue> {
        values
            .iter()
            .filter(|value| !value.is_empty())
            .map(|value| PhysicalDnsValue::new(value).unwrap())
            .collect()
    }

    fn empty_resolved() -> PhysicalDnsPrior {
        resolved(&[], &[], None)
    }

    fn resolved(
        servers: &[&str],
        domains: &[&str],
        default_route: Option<bool>,
    ) -> PhysicalDnsPrior {
        PhysicalDnsPrior::Resolved {
            servers: physical_values(servers),
            domains: physical_values(domains),
            default_route,
        }
    }

    fn assignment(interface: &str, server: &str, scope: DnsScope) -> DnsAssignment {
        DnsAssignment {
            profile_id: ProfileId::new(interface),
            interface: interface.to_string(),
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

    fn prepared_resolved(priors: &[(&str, PhysicalDnsPrior)]) -> PreparedOwnedDns {
        PreparedOwnedDns::new(
            PhysicalDnsBackend::LinuxResolved,
            priors
                .iter()
                .map(|(interface, prior)| {
                    OwnedDnsLink::new((*interface).to_string(), prior.clone())
                })
                .collect(),
        )
    }

    #[test]
    fn prepare_captures_exact_resolved_prior_without_mutation() {
        let prior = resolved(&["9.9.9.9"], &["~legacy.example"], Some(false));
        let mut runner = FakeRunner::available();
        runner.resolved.insert("vxcorp1".into(), prior.clone());
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            1,
            vec![assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll)],
        );

        let prepared = dns
            .prepare_physical(&desired, ExpectedDnsState::Absent, &[])
            .unwrap();

        assert_eq!(prepared.backend(), PhysicalDnsBackend::LinuxResolved);
        assert_eq!(
            prepared.links(),
            &[OwnedDnsLink::new("vxcorp1".into(), prior)]
        );
        assert_eq!(dns.runner.write_count, 0);
    }

    #[test]
    fn unavailable_resolved_fallback_rejects_unrepresentable_scoped_policy() {
        let mut runner = FakeRunner::available();
        runner.resolved_available = false;
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            1,
            vec![assignment(
                "vxcorp1",
                "1.1.1.1",
                DnsScope::Scoped {
                    domains: vec!["corp.example".into()],
                },
            )],
        );

        assert_eq!(
            dns.prepare_physical(&desired, ExpectedDnsState::Absent, &[]),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert_eq!(dns.runner.write_count, 0);
    }

    #[test]
    fn inherited_backend_is_pinned_without_cross_backend_fallback() {
        let mut runner = FakeRunner::available();
        runner.resolvconf_available = false;
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            2,
            vec![assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll)],
        );
        let inherited = OwnedDnsLink::new(
            "vxcorp1".into(),
            PhysicalDnsPrior::Resolvconf { record: None },
        );

        assert_eq!(
            dns.prepare_physical(&desired, ExpectedDnsState::Applied(&desired), &[inherited]),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert!(dns
            .runner
            .calls
            .iter()
            .all(|call| call.program == "resolvconf"));
    }

    #[test]
    fn prepared_retry_reuses_exact_current_generation_capture() {
        let prior = resolved(&["9.9.9.9"], &[], Some(false));
        let mut runner = FakeRunner::available();
        runner.resolved.insert("vxcorp1".into(), prior.clone());
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            2,
            vec![assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll)],
        );
        let inherited = OwnedDnsLink::new("vxcorp1".into(), prior.clone());

        let prepared = dns
            .prepare_physical(&desired, ExpectedDnsState::Absent, &[inherited])
            .unwrap();

        assert_eq!(prepared.links()[0].prior(), &prior);
        assert_eq!(dns.runner.calls.len(), 3);
        assert_eq!(dns.runner.write_count, 0);
    }

    #[test]
    fn apply_rejects_pre_effect_drift_without_mutation() {
        let prior = resolved(&["9.9.9.9"], &[], Some(false));
        let foreign = resolved(&["8.8.8.8"], &[], Some(false));
        let mut runner = FakeRunner::available();
        runner.resolved.insert("vxcorp1".into(), foreign);
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            1,
            vec![assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll)],
        );

        assert_eq!(
            dns.apply_physical(
                &desired,
                ExpectedDnsState::Absent,
                &prepared_resolved(&[("vxcorp1", prior)]),
                &[]
            ),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert_eq!(dns.runner.write_count, 0);
    }

    #[test]
    fn partial_apply_rolls_back_current_and_prior_actions() {
        let first_prior = resolved(&["9.9.9.9"], &[], Some(false));
        let second_prior = resolved(&["8.8.8.8"], &[], Some(false));
        let mut runner = FakeRunner::available();
        runner
            .resolved
            .insert("vxcorp1".into(), first_prior.clone());
        runner
            .resolved
            .insert("vxcorp2".into(), second_prior.clone());
        runner.fail_after_write.insert(4);
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            1,
            vec![
                assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll),
                assignment(
                    "vxcorp2",
                    "10.0.0.53",
                    DnsScope::Scoped {
                        domains: vec!["corp.example".into()],
                    },
                ),
            ],
        );

        assert_eq!(
            dns.apply_physical(
                &desired,
                ExpectedDnsState::Absent,
                &prepared_resolved(&[
                    ("vxcorp1", first_prior.clone()),
                    ("vxcorp2", second_prior.clone()),
                ]),
                &[]
            ),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert_eq!(dns.runner.resolved_state("vxcorp1"), first_prior);
        assert_eq!(dns.runner.resolved_state("vxcorp2"), second_prior);
        assert!(dns.runner.write_count >= 10);
    }

    #[test]
    fn failed_rollback_reports_ambiguous_effect() {
        let prior = resolved(&["9.9.9.9"], &[], Some(false));
        let mut runner = FakeRunner::available();
        runner.resolved.insert("vxcorp1".into(), prior.clone());
        runner.fail_after_write.insert(1);
        runner.fail_before_write.insert(2);
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            1,
            vec![assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll)],
        );

        assert_eq!(
            dns.apply_physical(
                &desired,
                ExpectedDnsState::Absent,
                &prepared_resolved(&[("vxcorp1", prior)]),
                &[]
            ),
            Err(OwnedDnsError::EffectMayHaveApplied)
        );
    }

    #[test]
    fn recovery_accepts_only_prior_or_target_members_then_converges() {
        let first_prior = resolved(&["9.9.9.9"], &[], Some(false));
        let second_prior = resolved(&["8.8.8.8"], &[], Some(false));
        let desired = policy(
            1,
            vec![
                assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll),
                assignment(
                    "vxcorp2",
                    "10.0.0.53",
                    DnsScope::Scoped {
                        domains: vec!["corp.example".into()],
                    },
                ),
            ],
        );
        let targets = policy_states(PhysicalDnsBackend::LinuxResolved, &desired).unwrap();
        let mut runner = FakeRunner::available();
        runner
            .resolved
            .insert("vxcorp1".into(), targets["vxcorp1"].clone());
        runner
            .resolved
            .insert("vxcorp2".into(), second_prior.clone());
        let mut dns = LinuxOwnedDns { runner };
        let prepared = prepared_resolved(&[("vxcorp1", first_prior), ("vxcorp2", second_prior)]);

        dns.recover_pending_physical(&desired, None, &prepared, &[])
            .unwrap();

        assert_eq!(dns.runner.resolved_state("vxcorp1"), targets["vxcorp1"]);
        assert_eq!(dns.runner.resolved_state("vxcorp2"), targets["vxcorp2"]);
    }

    #[test]
    fn recovery_rejects_foreign_member_before_any_write() {
        let prior = resolved(&["9.9.9.9"], &[], Some(false));
        let mut runner = FakeRunner::available();
        runner.resolved.insert(
            "vxcorp1".into(),
            resolved(&["203.0.113.53"], &[], Some(false)),
        );
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            1,
            vec![assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll)],
        );

        assert_eq!(
            dns.recover_pending_physical(
                &desired,
                None,
                &prepared_resolved(&[("vxcorp1", prior)]),
                &[]
            ),
            Err(OwnedDnsError::FailedBeforeEffect)
        );
        assert_eq!(dns.runner.write_count, 0);
    }

    #[test]
    fn resolvconf_prepare_preserves_present_empty_record() {
        let mut runner = FakeRunner::available();
        runner.resolved_available = false;
        runner
            .resolvconf
            .insert("vortix.vxcorp1".into(), Vec::new());
        let mut dns = LinuxOwnedDns { runner };
        let desired = policy(
            1,
            vec![assignment("vxcorp1", "1.1.1.1", DnsScope::CatchAll)],
        );

        let prepared = dns
            .prepare_physical(&desired, ExpectedDnsState::Absent, &[])
            .unwrap();

        assert_eq!(prepared.backend(), PhysicalDnsBackend::LinuxResolvconf);
        assert_eq!(
            prepared.links()[0].prior(),
            &PhysicalDnsPrior::Resolvconf {
                record: Some(Vec::new())
            }
        );
        assert_eq!(dns.runner.write_count, 0);
    }
}
