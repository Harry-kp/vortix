//! Runtime-only `NetworkManager` integration for helper-created interfaces.

use std::thread;
use std::time::Duration;

use crate::platform::fixed_root_command::{self, FixedCommandError, FixedCommandOutput};
use crate::platform::DesktopNetworkError;

const NMCLI_CANDIDATES: &[&str] = &["/usr/bin/nmcli", "/bin/nmcli"];
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY_DELAYS: &[Duration] = &[
    Duration::from_millis(25),
    Duration::from_millis(50),
    Duration::from_millis(100),
];

trait NetworkManagerRunner {
    fn run(&mut self, arguments: &[&str]) -> Result<FixedCommandOutput, FixedCommandError>;
}

struct FixedNetworkManagerRunner;

impl NetworkManagerRunner for FixedNetworkManagerRunner {
    fn run(&mut self, arguments: &[&str]) -> Result<FixedCommandOutput, FixedCommandError> {
        fixed_root_command::run_with_timeout(NMCLI_CANDIDATES, arguments, None, 0, COMMAND_TIMEOUT)
    }
}

pub(crate) fn detach(interface: &str) -> Result<(), DesktopNetworkError> {
    detach_with(interface, &mut FixedNetworkManagerRunner, thread::sleep)
}

fn detach_with(
    interface: &str,
    runner: &mut impl NetworkManagerRunner,
    mut pause: impl FnMut(Duration),
) -> Result<(), DesktopNetworkError> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(DesktopNetworkError);
    }

    let status = match runner.run(&["-t", "-f", "RUNNING", "general"]) {
        Ok(output) => output,
        Err(FixedCommandError::FailedBeforeSpawn) => {
            return Ok(());
        }
        Err(FixedCommandError::OutcomeUnknown) => {
            return Err(DesktopNetworkError);
        }
    };
    if !status.status.success() || status.stdout.trim() != "running" {
        return Ok(());
    }

    for delay in RETRY_DELAYS.iter().copied().chain([Duration::ZERO]) {
        match runner.run(&["--wait", "1", "device", "set", interface, "managed", "no"]) {
            Ok(output) if output.status.success() => {
                return Ok(());
            }
            Err(FixedCommandError::OutcomeUnknown) => {
                return Err(DesktopNetworkError);
            }
            Ok(_) | Err(FixedCommandError::FailedBeforeSpawn) => {}
        }
        if delay.is_zero() {
            return Err(DesktopNetworkError);
        }
        pause(delay);
    }
    Err(DesktopNetworkError)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::process::ExitStatusExt as _;

    use super::*;

    struct FakeRunner {
        outputs: VecDeque<Result<FixedCommandOutput, FixedCommandError>>,
        calls: Vec<Vec<String>>,
    }

    impl FakeRunner {
        fn new(
            outputs: impl IntoIterator<Item = Result<FixedCommandOutput, FixedCommandError>>,
        ) -> Self {
            Self {
                outputs: outputs.into_iter().collect(),
                calls: Vec::new(),
            }
        }
    }

    impl NetworkManagerRunner for FakeRunner {
        fn run(&mut self, arguments: &[&str]) -> Result<FixedCommandOutput, FixedCommandError> {
            self.calls.push(
                arguments
                    .iter()
                    .map(|argument| (*argument).to_owned())
                    .collect(),
            );
            self.outputs.pop_front().unwrap()
        }
    }

    fn output(success: bool, stdout: &str) -> FixedCommandOutput {
        FixedCommandOutput {
            status: std::process::ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    #[test]
    fn active_network_manager_detaches_only_the_exact_runtime_interface() {
        let mut runner = FakeRunner::new([Ok(output(true, "running\n")), Ok(output(true, ""))]);

        detach_with("vxabcdefghijk", &mut runner, |_| {}).unwrap();
        assert_eq!(
            runner.calls,
            [
                vec!["-t", "-f", "RUNNING", "general"],
                vec![
                    "--wait",
                    "1",
                    "device",
                    "set",
                    "vxabcdefghijk",
                    "managed",
                    "no"
                ]
            ]
        );
    }

    #[test]
    fn absent_network_manager_is_not_a_connection_failure() {
        let mut runner = FakeRunner::new([Err(FixedCommandError::FailedBeforeSpawn)]);

        detach_with("vxabcdefghijk", &mut runner, |_| {}).unwrap();
    }

    #[test]
    fn inactive_network_manager_is_not_a_connection_failure() {
        let mut runner = FakeRunner::new([Ok(output(false, ""))]);

        detach_with("vxabcdefghijk", &mut runner, |_| {}).unwrap();
        assert_eq!(runner.calls.len(), 1);
    }

    #[test]
    fn device_discovery_is_retried_before_giving_up() {
        let mut runner = FakeRunner::new([
            Ok(output(true, "running\n")),
            Ok(output(false, "")),
            Ok(output(true, "")),
        ]);
        let mut pauses = Vec::new();

        detach_with("vxabcdefghijk", &mut runner, |delay| pauses.push(delay)).unwrap();

        assert_eq!(runner.calls.len(), 3);
        assert_eq!(pauses, [Duration::from_millis(25)]);
    }

    #[test]
    fn option_shaped_or_overlong_interface_never_reaches_nmcli() {
        for interface in ["--help", "vx-interface-name-is-too-long"] {
            let mut runner = FakeRunner::new([]);
            assert_eq!(
                detach_with(interface, &mut runner, |_| {}),
                Err(DesktopNetworkError)
            );
            assert!(runner.calls.is_empty());
        }
    }

    #[test]
    fn active_network_manager_refusal_is_not_silently_ignored() {
        let mut runner = FakeRunner::new(
            std::iter::once(Ok(output(true, "running\n")))
                .chain((0..4).map(|_| Ok(output(false, "")))),
        );

        assert_eq!(
            detach_with("vxabcdefghijk", &mut runner, |_| {}),
            Err(DesktopNetworkError)
        );
        assert_eq!(runner.calls.len(), 5);
    }
}
