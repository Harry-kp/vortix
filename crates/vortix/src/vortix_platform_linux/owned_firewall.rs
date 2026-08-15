//! Fixed-vocabulary nftables adapter used by the root helper.
//!
//! The iptables backend remains unavailable until its guarded dual-family
//! transaction and restart read-back are implemented.

use super::nft_policy::{self, BatchMode, ExpectedPolicy, ObservedPolicy};
use crate::platform::fixed_root_command::{self, FixedCommandError, FixedCommandOutput};
use crate::vortix_core::ports::killswitch::ActiveTunnelInfo;
use crate::vortix_core::ports::owned_firewall::{
    ExpectedFirewallState, OwnedFirewall, OwnedFirewallError,
};
use crate::vortix_core::privileged::PhysicalFirewallBackend;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const NFT_CANDIDATES: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];

pub(crate) struct LinuxOwnedFirewall {
    runner: Box<dyn NftCommandRunner>,
}

impl LinuxOwnedFirewall {
    pub(crate) fn new() -> Self {
        Self {
            runner: Box::new(FixedNftCommandRunner),
        }
    }

    #[cfg(test)]
    fn with_runner(runner: impl NftCommandRunner + 'static) -> Self {
        Self {
            runner: Box::new(runner),
        }
    }

    fn snapshot(&mut self) -> Result<NftSnapshot, OwnedFirewallError> {
        let output = self.runner.run(NftCommand::ListTable, None)?;
        if output.status.success() {
            return Ok(NftSnapshot::Present(output.stdout));
        }
        if output.stderr.contains(nft_policy::MISSING_ERROR) {
            Ok(NftSnapshot::Absent)
        } else {
            Err(OwnedFirewallError::EffectMayHaveApplied)
        }
    }

    fn require_prior(
        &mut self,
        expected: ExpectedFirewallState<'_>,
    ) -> Result<(), OwnedFirewallError> {
        let matches = match (expected, self.snapshot()) {
            (ExpectedFirewallState::Blocking(active), Ok(NftSnapshot::Present(snapshot))) => {
                nft_policy::snapshot_matches(active, &snapshot)
            }
            (ExpectedFirewallState::Absent, Ok(NftSnapshot::Absent)) => true,
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(OwnedFirewallError::FailedBeforeEffect)
        }
    }
}

impl OwnedFirewall for LinuxOwnedFirewall {
    fn backend(&self) -> PhysicalFirewallBackend {
        PhysicalFirewallBackend::LinuxNft
    }

    fn apply_blocking(
        &mut self,
        active: &[ActiveTunnelInfo],
        expected: ExpectedFirewallState<'_>,
    ) -> Result<(), OwnedFirewallError> {
        self.require_prior(expected)?;
        let mode = if matches!(expected, ExpectedFirewallState::Blocking(_)) {
            BatchMode::Replace
        } else {
            BatchMode::Create
        };
        let rules = nft_policy::ruleset(active, mode);
        let output = self.runner.run(NftCommand::Batch, Some(rules.as_bytes()))?;
        if !output.status.success() {
            return Err(OwnedFirewallError::EffectMayHaveApplied);
        }
        self.audit_blocking(active)
    }

    fn clear(&mut self, expected: ExpectedFirewallState<'_>) -> Result<(), OwnedFirewallError> {
        self.require_prior(expected)?;
        if matches!(expected, ExpectedFirewallState::Absent) {
            return Ok(());
        }
        let _output = self.runner.run(NftCommand::DeleteTable, None)?;
        self.audit_absent()
    }

    fn audit_blocking(&mut self, active: &[ActiveTunnelInfo]) -> Result<(), OwnedFirewallError> {
        match self.snapshot()? {
            NftSnapshot::Present(snapshot) if nft_policy::snapshot_matches(active, &snapshot) => {
                Ok(())
            }
            NftSnapshot::Present(_) | NftSnapshot::Absent => {
                Err(OwnedFirewallError::EffectMayHaveApplied)
            }
        }
    }

    fn audit_absent(&mut self) -> Result<(), OwnedFirewallError> {
        match self.snapshot()? {
            NftSnapshot::Absent => Ok(()),
            NftSnapshot::Present(_) => Err(OwnedFirewallError::EffectMayHaveApplied),
        }
    }

    fn audit_recovery(
        &mut self,
        blocking_candidates: &[Vec<ActiveTunnelInfo>],
        allow_absent: bool,
    ) -> Result<(), OwnedFirewallError> {
        match self.snapshot()? {
            NftSnapshot::Absent if allow_absent => Ok(()),
            NftSnapshot::Present(snapshot) => {
                let observed = ObservedPolicy::parse(&snapshot);
                if blocking_candidates
                    .iter()
                    .map(|active| ExpectedPolicy::new(active, BatchMode::Create))
                    .any(|expected| expected.matches(&observed))
                {
                    Ok(())
                } else {
                    Err(OwnedFirewallError::EffectMayHaveApplied)
                }
            }
            NftSnapshot::Absent => Err(OwnedFirewallError::EffectMayHaveApplied),
        }
    }
}

enum NftSnapshot {
    Absent,
    Present(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NftCommand {
    ListTable,
    Batch,
    DeleteTable,
}

impl NftCommand {
    fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::ListTable => &[
                "-n",
                "list",
                "table",
                "inet",
                crate::constants::NFT_TABLE_NAME,
            ],
            Self::Batch => &["-f", "-"],
            Self::DeleteTable => &["delete", "table", "inet", crate::constants::NFT_TABLE_NAME],
        }
    }
}

trait NftCommandRunner: Send {
    fn run(
        &mut self,
        command: NftCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FixedCommandOutput, OwnedFirewallError>;
}

struct FixedNftCommandRunner;

impl NftCommandRunner for FixedNftCommandRunner {
    fn run(
        &mut self,
        command: NftCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FixedCommandOutput, OwnedFirewallError> {
        fixed_root_command::run(NFT_CANDIDATES, command.arguments(), stdin, MAX_INPUT_BYTES)
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
        steps: VecDeque<(NftCommand, Option<Vec<u8>>, FixedCommandOutput)>,
    }

    impl ScriptedRunner {
        fn new(steps: Vec<(NftCommand, Option<Vec<u8>>, FixedCommandOutput)>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }

    impl Drop for ScriptedRunner {
        fn drop(&mut self) {
            assert!(
                self.steps.is_empty(),
                "nft command script was not exhausted"
            );
        }
    }

    impl NftCommandRunner for ScriptedRunner {
        fn run(
            &mut self,
            command: NftCommand,
            stdin: Option<&[u8]>,
        ) -> Result<FixedCommandOutput, OwnedFirewallError> {
            let (expected_command, expected_stdin, output) = self.steps.pop_front().unwrap();
            assert_eq!(command, expected_command);
            assert_eq!(stdin.map(<[u8]>::to_vec), expected_stdin);
            Ok(output)
        }
    }

    fn success(stdout: impl Into<String>) -> FixedCommandOutput {
        FixedCommandOutput {
            status: ExitStatus::from_raw(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn missing() -> FixedCommandOutput {
        FixedCommandOutput {
            status: ExitStatus::from_raw(1 << 8),
            stdout: String::new(),
            stderr: nft_policy::MISSING_ERROR.to_string(),
        }
    }

    fn active(endpoint: &str) -> Vec<ActiveTunnelInfo> {
        vec![ActiveTunnelInfo::endpoint_allowlist(vec![endpoint
            .parse()
            .unwrap()])]
    }

    #[test]
    fn create_is_one_batch_and_requires_exact_readback() {
        let active = active("198.51.100.7");
        let rules = nft_policy::ruleset(&active, BatchMode::Create);
        let runner = ScriptedRunner::new(vec![
            (NftCommand::ListTable, None, missing()),
            (
                NftCommand::Batch,
                Some(rules.as_bytes().to_vec()),
                success(""),
            ),
            (NftCommand::ListTable, None, success(rules)),
        ]);

        assert_eq!(
            LinuxOwnedFirewall::with_runner(runner)
                .apply_blocking(&active, ExpectedFirewallState::Absent),
            Ok(())
        );
    }

    #[test]
    fn replace_rejects_drift_before_effect() {
        let prior = active("198.51.100.7");
        let foreign = nft_policy::ruleset(&active("203.0.113.9"), BatchMode::Create);
        let runner = ScriptedRunner::new(vec![(NftCommand::ListTable, None, success(foreign))]);

        assert_eq!(
            LinuxOwnedFirewall::with_runner(runner)
                .apply_blocking(&prior, ExpectedFirewallState::Blocking(&prior)),
            Err(OwnedFirewallError::FailedBeforeEffect)
        );
    }

    #[test]
    fn replace_uses_one_atomic_batch_and_exact_readback() {
        let prior = active("198.51.100.7");
        let intended = active("203.0.113.9");
        let prior_rules = nft_policy::ruleset(&prior, BatchMode::Create);
        let replacement = nft_policy::ruleset(&intended, BatchMode::Replace);
        let intended_rules = nft_policy::ruleset(&intended, BatchMode::Create);
        let runner = ScriptedRunner::new(vec![
            (NftCommand::ListTable, None, success(prior_rules)),
            (
                NftCommand::Batch,
                Some(replacement.as_bytes().to_vec()),
                success(""),
            ),
            (NftCommand::ListTable, None, success(intended_rules)),
        ]);

        assert_eq!(
            LinuxOwnedFirewall::with_runner(runner)
                .apply_blocking(&intended, ExpectedFirewallState::Blocking(&prior)),
            Ok(())
        );
    }

    #[test]
    fn clear_requires_exact_prior_and_confirms_absence() {
        let prior = active("198.51.100.7");
        let prior_rules = nft_policy::ruleset(&prior, BatchMode::Create);
        let runner = ScriptedRunner::new(vec![
            (NftCommand::ListTable, None, success(prior_rules)),
            (NftCommand::DeleteTable, None, success("")),
            (NftCommand::ListTable, None, missing()),
        ]);

        assert_eq!(
            LinuxOwnedFirewall::with_runner(runner).clear(ExpectedFirewallState::Blocking(&prior)),
            Ok(())
        );
    }

    #[test]
    fn recovery_matches_candidates_against_one_snapshot() {
        let first = active("198.51.100.7");
        let second = active("203.0.113.9");
        let second_rules = nft_policy::ruleset(&second, BatchMode::Create);
        let runner =
            ScriptedRunner::new(vec![(NftCommand::ListTable, None, success(second_rules))]);

        assert_eq!(
            LinuxOwnedFirewall::with_runner(runner).audit_recovery(&[first, second], false),
            Ok(())
        );
    }
}
