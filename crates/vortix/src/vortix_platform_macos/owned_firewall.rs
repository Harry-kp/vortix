//! Fixed-vocabulary PF adapter used by the root helper.

#![allow(
    unsafe_code,
    reason = "bounded firewall children require private process-group containment"
)]

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::firewall::{PfFirewall, PF_ANCHOR, PF_APPLY_ARGS, PF_RELEASE_ARGS};
use crate::vortix_core::ports::killswitch::ActiveTunnelInfo;
use crate::vortix_core::ports::owned_firewall::{OwnedFirewall, OwnedFirewallError};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_INTERVAL: Duration = Duration::from_millis(20);
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
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
}

impl OwnedFirewall for MacOsOwnedFirewall {
    fn apply_blocking(&mut self, active: &[ActiveTunnelInfo]) -> Result<(), OwnedFirewallError> {
        self.require_root_traversal()?;
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

    fn clear(&mut self) -> Result<(), OwnedFirewallError> {
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
        if state.root_traverses_anchor
            && state.enabled
            && blocking_candidates
                .iter()
                .any(|active| PfFirewall::snapshot_matches_policy(active, &state.anchor_rules))
        {
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

struct FirewallCommandOutput {
    status: ExitStatus,
    stdout: String,
}

trait FirewallCommandRunner: Send {
    fn run(
        &mut self,
        command: PfCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FirewallCommandOutput, OwnedFirewallError>;
}

struct FixedFirewallCommandRunner;

impl FirewallCommandRunner for FixedFirewallCommandRunner {
    fn run(
        &mut self,
        command: PfCommand,
        stdin: Option<&[u8]>,
    ) -> Result<FirewallCommandOutput, OwnedFirewallError> {
        if stdin.is_some_and(|body| body.len() > MAX_INPUT_BYTES) {
            return Err(OwnedFirewallError::FailedBeforeEffect);
        }
        let (candidates, arguments) = command.invocation();
        let binary = verified_fixed_binary(candidates)?;
        run_bounded(&binary, arguments, stdin)
    }
}

fn verified_fixed_binary(candidates: &[&str]) -> Result<PathBuf, OwnedFirewallError> {
    candidates
        .iter()
        .map(Path::new)
        .find_map(|candidate| {
            let metadata = std::fs::symlink_metadata(candidate).ok()?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
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
        .ok_or(OwnedFirewallError::FailedBeforeEffect)
}

fn root_owned_nonwritable_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o022 == 0
    })
}

fn run_bounded(
    binary: &Path,
    arguments: &[&str],
    stdin: Option<&[u8]>,
) -> Result<FirewallCommandOutput, OwnedFirewallError> {
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
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut child = command
        .spawn()
        .map_err(|_| OwnedFirewallError::FailedBeforeEffect)?;
    let input = stdin.map(<[u8]>::to_vec);
    let input_writer = child.stdin.take().map(|mut pipe| {
        thread::spawn(move || input.is_none_or(|body| pipe.write_all(&body).is_ok()))
    });
    let stdout_reader = child
        .stdout
        .take()
        .map(|pipe| thread::spawn(move || read_bounded(pipe)));
    let stderr_reader = child
        .stderr
        .take()
        .map(|pipe| thread::spawn(move || read_bounded(pipe)));
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(WAIT_INTERVAL),
            Ok(None) | Err(_) => {
                terminate_process_group(&mut child);
                join_discard(input_writer, stdout_reader, stderr_reader);
                return Err(OwnedFirewallError::EffectMayHaveApplied);
            }
        }
    };
    kill_process_group(child.id());
    let input_ok = input_writer.is_none_or(|writer| writer.join().ok() == Some(true));
    let stdout = join_output(stdout_reader);
    let stderr = join_output(stderr_reader);
    if !input_ok {
        return Err(OwnedFirewallError::EffectMayHaveApplied);
    }
    // stderr is deliberately bounded and drained even though policy decisions
    // never depend on human-readable diagnostics.
    let stdout = stdout?;
    let _stderr = stderr?;
    Ok(FirewallCommandOutput { status, stdout })
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
            "firewall output exceeded limit",
        ));
    }
    Ok(bytes)
}

fn join_output(
    reader: Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
) -> Result<String, OwnedFirewallError> {
    let bytes = reader
        .ok_or(OwnedFirewallError::EffectMayHaveApplied)?
        .join()
        .map_err(|_| OwnedFirewallError::EffectMayHaveApplied)?
        .map_err(|_| OwnedFirewallError::EffectMayHaveApplied)?;
    String::from_utf8(bytes).map_err(|_| OwnedFirewallError::EffectMayHaveApplied)
}

fn join_discard(
    input: Option<thread::JoinHandle<bool>>,
    stdout: Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<thread::JoinHandle<std::io::Result<Vec<u8>>>>,
) {
    let _ = input.map(thread::JoinHandle::join);
    let _ = stdout.map(thread::JoinHandle::join);
    let _ = stderr.map(thread::JoinHandle::join);
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
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::os::unix::process::ExitStatusExt as _;

    use super::*;

    struct ScriptedRunner {
        steps: VecDeque<(PfCommand, Option<Vec<u8>>, FirewallCommandOutput)>,
    }

    impl ScriptedRunner {
        fn new(steps: Vec<(PfCommand, Option<Vec<u8>>, FirewallCommandOutput)>) -> Self {
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
        ) -> Result<FirewallCommandOutput, OwnedFirewallError> {
            let (expected_command, expected_stdin, output) = self.steps.pop_front().unwrap();
            assert_eq!(command, expected_command);
            assert_eq!(stdin.map(<[u8]>::to_vec), expected_stdin);
            Ok(output)
        }
    }

    fn output(stdout: impl Into<String>) -> FirewallCommandOutput {
        FirewallCommandOutput {
            status: ExitStatus::from_raw(0),
            stdout: stdout.into(),
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
            MacOsOwnedFirewall::with_runner(runner).apply_blocking(&active),
            Ok(())
        );
    }

    #[test]
    fn missing_root_traversal_fails_before_first_effect() {
        let runner =
            ScriptedRunner::new(vec![(PfCommand::RootRules, None, output("pass out all\n"))]);

        assert_eq!(
            MacOsOwnedFirewall::with_runner(runner).apply_blocking(&[]),
            Err(OwnedFirewallError::FailedBeforeEffect)
        );
    }

    #[test]
    fn clear_mutates_only_anchor_and_proves_absence() {
        let runner = ScriptedRunner::new(vec![
            (PfCommand::Flush, None, output("")),
            (PfCommand::AnchorRules, None, output("")),
            (PfCommand::AnchorRules, None, output("")),
        ]);
        let mut subject = MacOsOwnedFirewall::with_runner(runner);

        subject.clear().unwrap();
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

    #[test]
    fn bounded_reader_rejects_oversized_output() {
        let bytes = vec![b'x'; usize::try_from(MAX_OUTPUT_BYTES).unwrap() + 1];
        assert_eq!(
            read_bounded(Cursor::new(bytes)).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
}
