//! Fixed-vocabulary PF adapter used by the root helper.

use super::firewall::{PfFirewall, PF_ANCHOR, PF_APPLY_ARGS, PF_RELEASE_ARGS};
use crate::platform::fixed_root_command::{self, FixedCommandError, FixedCommandOutput};
use crate::vortix_core::ports::killswitch::ActiveTunnelInfo;
use crate::vortix_core::ports::owned_firewall::{
    ExpectedFirewallState, OwnedFirewall, OwnedFirewallError,
};
use crate::vortix_core::privileged::PhysicalFirewallBackend;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const PFCTL_CANDIDATES: &[&str] = &["/sbin/pfctl", "/usr/sbin/pfctl"];

pub(crate) struct MacOsOwnedFirewall {
    runner: Box<dyn FirewallCommandRunner>,
}

impl MacOsOwnedFirewall {
    pub(crate) fn new() -> Self {
        Self {
            runner: Box::new(FixedFirewallCommandRunner),
        }
    }

    #[cfg(test)]
    fn with_runner(runner: impl FirewallCommandRunner + 'static) -> Self {
        Self {
            runner: Box::new(runner),
        }
    }

    fn read_state(&mut self) -> Result<PfState, OwnedFirewallError> {
        let root = self.runner.run(PfCommand::RootRules, None)?;
        let anchor = self.runner.run(PfCommand::AnchorRules, None)?;
        let status = self.runner.run(PfCommand::Status, None)?;
        if !root.status.success() || !anchor.status.success() || !status.status.success() {
            return Err(OwnedFirewallError::EffectMayHaveApplied);
        }
        Ok(PfState {
            root_traverses_anchor: PfFirewall::root_traverses_anchor(&root.stdout),
            enabled: pf_is_enabled(&status.stdout),
            anchor_rules: anchor.stdout,
        })
    }

    fn require_root_traversal(&mut self) -> Result<(), OwnedFirewallError> {
        let root = self
            .runner
            .run(PfCommand::RootRules, None)
            .map_err(|_| OwnedFirewallError::FailedBeforeEffect)?;
        if root.status.success() && PfFirewall::root_traverses_anchor(&root.stdout) {
            Ok(())
        } else {
            Err(OwnedFirewallError::FailedBeforeEffect)
        }
    }

    fn require_prior(
        &mut self,
        expected: ExpectedFirewallState<'_>,
    ) -> Result<(), OwnedFirewallError> {
        match expected {
            ExpectedFirewallState::Blocking(active) => self.audit_blocking(active),
            ExpectedFirewallState::Absent => {
                self.require_root_traversal()?;
                self.audit_absent()
            }
        }
        .map_err(|_| OwnedFirewallError::FailedBeforeEffect)
    }
}

impl OwnedFirewall for MacOsOwnedFirewall {
    fn backend(&self) -> PhysicalFirewallBackend {
        PhysicalFirewallBackend::MacOsPf
    }

    fn apply_blocking(
        &mut self,
        active: &[ActiveTunnelInfo],
        expected: ExpectedFirewallState<'_>,
    ) -> Result<(), OwnedFirewallError> {
        self.require_prior(expected)?;
        let rules = PfFirewall::generate_pf_rules(active);
        if !self
            .runner
            .run(PfCommand::Load, Some(rules.as_bytes()))?
            .status
            .success()
        {
            return Err(OwnedFirewallError::EffectMayHaveApplied);
        }
        let enabled = self.runner.run(PfCommand::Enable, None)?;
        if !enabled.status.success() {
            // `pfctl -e` may report failure when another owner raced to enable
            // PF. Exact read-back, not diagnostic text, decides success.
            return self.audit_blocking(active);
        }
        self.audit_blocking(active)
    }

    fn clear(&mut self, expected: ExpectedFirewallState<'_>) -> Result<(), OwnedFirewallError> {
        self.require_prior(expected)?;
        if matches!(expected, ExpectedFirewallState::Absent) {
            return Ok(());
        }
        let _output = self.runner.run(PfCommand::Flush, None)?;
        // Both success and an already-absent non-zero result require the same
        // exact postcondition; diagnostic text never decides ownership.
        self.audit_absent()
    }

    fn audit_blocking(&mut self, active: &[ActiveTunnelInfo]) -> Result<(), OwnedFirewallError> {
        let state = self.read_state()?;
        if state.root_traverses_anchor
            && state.enabled
            && PfFirewall::snapshot_matches_policy(active, &state.anchor_rules)
        {
            Ok(())
        } else {
            Err(OwnedFirewallError::EffectMayHaveApplied)
        }
    }

    fn audit_absent(&mut self) -> Result<(), OwnedFirewallError> {
        let anchor = self.runner.run(PfCommand::AnchorRules, None)?;
        if anchor.status.success() && PfFirewall::canonical_pf_rules(&anchor.stdout).is_empty() {
            Ok(())
        } else {
            Err(OwnedFirewallError::EffectMayHaveApplied)
        }
    }

    fn audit_recovery(
        &mut self,
        blocking_candidates: &[Vec<ActiveTunnelInfo>],
        allow_absent: bool,
    ) -> Result<(), OwnedFirewallError> {
        let state = self.read_state()?;
        if allow_absent && PfFirewall::canonical_pf_rules(&state.anchor_rules).is_empty() {
            return Ok(());
        }
        if state.root_traverses_anchor && state.enabled && {
            let observed = PfFirewall::canonical_pf_rules(&state.anchor_rules);
            blocking_candidates
                .iter()
                .any(|active| PfFirewall::canonical_snapshot_matches(active, &observed))
        } {
            Ok(())
        } else {
            Err(OwnedFirewallError::EffectMayHaveApplied)
        }
    }
}

struct PfState {
    root_traverses_anchor: bool,
    enabled: bool,
    anchor_rules: String,
}

fn pf_is_enabled(status: &str) -> bool {
    status.lines().any(|line| {
        line.split_once(':').is_some_and(|(key, value)| {
            key.trim() == "Status" && value.split_ascii_whitespace().next() == Some("Enabled")
        })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PfCommand {
    RootRules,
    AnchorRules,
    Status,
    Load,
    Enable,
    Flush,
}

impl PfCommand {
    fn invocation(self) -> (&'static [&'static str], &'static [&'static str]) {
        let arguments: &'static [&'static str] = match self {
            Self::RootRules => &["-sr"],
            Self::AnchorRules => &["-a", PF_ANCHOR, "-sr"],
            Self::Status => &["-s", "info"],
            Self::Load => &PF_APPLY_ARGS,
            Self::Enable => &["-e"],
            Self::Flush => &PF_RELEASE_ARGS,
        };
        (PFCTL_CANDIDATES, arguments)
    }
}

trait FirewallCommandRunner: Send {
    fn run(
        &mut self,
        command: PfCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FixedCommandOutput, OwnedFirewallError>;
}

struct FixedFirewallCommandRunner;

impl FirewallCommandRunner for FixedFirewallCommandRunner {
    fn run(
        &mut self,
        command: PfCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FixedCommandOutput, OwnedFirewallError> {
        let (candidates, arguments) = command.invocation();
        fixed_root_command::run(candidates, arguments, stdin, MAX_INPUT_BYTES)
            .map_err(map_command_error)
    }
}

const fn map_command_error(error: FixedCommandError) -> OwnedFirewallError {
    match error {
        FixedCommandError::FailedBeforeSpawn => OwnedFirewallError::FailedBeforeEffect,
        FixedCommandError::OutcomeUnknown => OwnedFirewallError::EffectMayHaveApplied,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::ExitStatus;

    use super::*;

    struct ScriptedRunner {
        steps: VecDeque<(PfCommand, Option<Vec<u8>>, FixedCommandOutput)>,
    }

    impl ScriptedRunner {
        fn new(steps: Vec<(PfCommand, Option<Vec<u8>>, FixedCommandOutput)>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }

    impl Drop for ScriptedRunner {
        fn drop(&mut self) {
            assert!(self.steps.is_empty(), "firewall script was not exhausted");
        }
    }

    impl FirewallCommandRunner for ScriptedRunner {
        fn run(
            &mut self,
            command: PfCommand,
            stdin: Option<&[u8]>,
        ) -> Result<FixedCommandOutput, OwnedFirewallError> {
            let (expected_command, expected_stdin, output) = self.steps.pop_front().unwrap();
            assert_eq!(command, expected_command);
            assert_eq!(stdin.map(<[u8]>::to_vec), expected_stdin);
            Ok(output)
        }
    }

    fn output(stdout: impl Into<String>) -> FixedCommandOutput {
        FixedCommandOutput {
            status: ExitStatus::from_raw(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn status_parser_requires_exact_enabled_field() {
        assert!(pf_is_enabled("Status: Enabled for 0 days\n"));
        assert!(!pf_is_enabled("Status: Disabled\n"));
        assert!(!pf_is_enabled("note: Enabled\n"));
    }

    #[test]
    fn blocking_loads_only_after_traversal_and_requires_exact_readback() {
        let active = vec![ActiveTunnelInfo::endpoint_allowlist(vec!["198.51.100.7"
            .parse()
            .unwrap()])];
        let rules = PfFirewall::generate_pf_rules(&active);
        let runner = ScriptedRunner::new(vec![
            (
                PfCommand::RootRules,
                None,
                output("anchor \"com.apple/*\"\n"),
            ),
            (PfCommand::AnchorRules, None, output("")),
            (PfCommand::Load, Some(rules.as_bytes().to_vec()), output("")),
            (PfCommand::Enable, None, output("")),
            (
                PfCommand::RootRules,
                None,
                output("anchor \"com.apple/*\"\n"),
            ),
            (PfCommand::AnchorRules, None, output(rules)),
            (
                PfCommand::Status,
                None,
                output("Status: Enabled for 0 days\n"),
            ),
        ]);

        assert_eq!(
            MacOsOwnedFirewall::with_runner(runner)
                .apply_blocking(&active, ExpectedFirewallState::Absent),
            Ok(())
        );
    }

    #[test]
    fn missing_root_traversal_fails_before_first_effect() {
        let runner =
            ScriptedRunner::new(vec![(PfCommand::RootRules, None, output("pass out all\n"))]);

        assert_eq!(
            MacOsOwnedFirewall::with_runner(runner)
                .apply_blocking(&[], ExpectedFirewallState::Absent),
            Err(OwnedFirewallError::FailedBeforeEffect)
        );
    }

    #[test]
    fn clear_mutates_only_anchor_and_proves_absence() {
        let prior = Vec::new();
        let prior_rules = PfFirewall::generate_pf_rules(&prior);
        let runner = ScriptedRunner::new(vec![
            (
                PfCommand::RootRules,
                None,
                output("anchor \"com.apple/*\"\n"),
            ),
            (PfCommand::AnchorRules, None, output(prior_rules)),
            (
                PfCommand::Status,
                None,
                output("Status: Enabled for 0 days\n"),
            ),
            (PfCommand::Flush, None, output("")),
            (PfCommand::AnchorRules, None, output("")),
            (PfCommand::AnchorRules, None, output("")),
        ]);
        let mut subject = MacOsOwnedFirewall::with_runner(runner);

        subject
            .clear(ExpectedFirewallState::Blocking(&prior))
            .unwrap();
        assert_eq!(subject.audit_absent(), Ok(()));
    }

    #[test]
    fn recovery_matches_all_candidates_against_one_kernel_snapshot() {
        let first = vec![ActiveTunnelInfo::endpoint_allowlist(vec!["198.51.100.7"
            .parse()
            .unwrap()])];
        let second = vec![ActiveTunnelInfo::endpoint_allowlist(vec!["203.0.113.9"
            .parse()
            .unwrap()])];
        let second_rules = PfFirewall::generate_pf_rules(&second);
        let runner = ScriptedRunner::new(vec![
            (
                PfCommand::RootRules,
                None,
                output("anchor \"com.apple/*\"\n"),
            ),
            (PfCommand::AnchorRules, None, output(second_rules)),
            (
                PfCommand::Status,
                None,
                output("Status: Enabled for 0 days\n"),
            ),
        ]);

        assert_eq!(
            MacOsOwnedFirewall::with_runner(runner).audit_recovery(&[first, second], false),
            Ok(())
        );
    }
}
