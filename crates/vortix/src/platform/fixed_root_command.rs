//! Bounded execution for fixed, package-owned privileged commands.

#![allow(
    unsafe_code,
    reason = "bounded privileged children require private process-group containment"
)]

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_WAIT_INTERVAL: Duration = Duration::from_millis(1);
const MAX_WAIT_INTERVAL: Duration = Duration::from_millis(20);
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixedCommandError {
    FailedBeforeSpawn,
    OutcomeUnknown,
}

pub(crate) struct FixedCommandOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: String,
    #[allow(
        dead_code,
        reason = "nft classifies a missing table from bounded stderr on Linux"
    )]
    pub(crate) stderr: String,
}

pub(crate) fn run(
    candidates: &[&str],
    arguments: &[&str],
    stdin: Option<&[u8]>,
    max_input_bytes: usize,
) -> Result<FixedCommandOutput, FixedCommandError> {
    run_with_timeout(
        candidates,
        arguments,
        stdin,
        max_input_bytes,
        COMMAND_TIMEOUT,
    )
}

pub(crate) fn run_with_timeout(
    candidates: &[&str],
    arguments: &[&str],
    stdin: Option<&[u8]>,
    max_input_bytes: usize,
    timeout: Duration,
) -> Result<FixedCommandOutput, FixedCommandError> {
    if timeout.is_zero() || timeout > COMMAND_TIMEOUT {
        return Err(FixedCommandError::FailedBeforeSpawn);
    }
    if stdin.is_some_and(|body| body.len() > max_input_bytes) {
        return Err(FixedCommandError::FailedBeforeSpawn);
    }
    let binary = verified_fixed_binary(candidates)?;
    run_bounded(&binary, arguments, stdin, timeout)
}

fn verified_fixed_binary(candidates: &[&str]) -> Result<PathBuf, FixedCommandError> {
    candidates
        .iter()
        .map(Path::new)
        .find_map(|candidate| {
            let metadata = std::fs::symlink_metadata(candidate).ok()?;
            if !metadata.is_file()
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
        .ok_or(FixedCommandError::FailedBeforeSpawn)
}

fn root_owned_nonwritable_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_dir()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o022 == 0
    })
}

fn run_bounded(
    binary: &Path,
    arguments: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<FixedCommandOutput, FixedCommandError> {
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
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| FixedCommandError::FailedBeforeSpawn)?;
    thread::scope(|scope| {
        let input_writer = child.stdin.take().map(|mut pipe| {
            scope.spawn(move || stdin.is_none_or(|body| pipe.write_all(body).is_ok()))
        });
        let stdout_reader = child
            .stdout
            .take()
            .map(|pipe| scope.spawn(move || read_bounded(pipe)));
        let stderr_reader = child
            .stderr
            .take()
            .map(|pipe| scope.spawn(move || read_bounded(pipe)));
        let deadline = Instant::now() + timeout;
        let mut wait_interval = INITIAL_WAIT_INTERVAL;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(wait_interval);
                    wait_interval = (wait_interval * 2).min(MAX_WAIT_INTERVAL);
                }
                Ok(None) | Err(_) => {
                    terminate_process_group(&mut child);
                    join_discard(input_writer, stdout_reader, stderr_reader);
                    return Err(FixedCommandError::OutcomeUnknown);
                }
            }
        };
        let input_ok = input_writer.is_none_or(|writer| writer.join().ok() == Some(true));
        let stdout = join_output(stdout_reader);
        let stderr = join_output(stderr_reader);
        if !input_ok {
            return Err(FixedCommandError::OutcomeUnknown);
        }
        Ok(FixedCommandOutput {
            status,
            stdout: stdout?,
            stderr: stderr?,
        })
    })
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
            "privileged command output exceeded limit",
        ));
    }
    Ok(bytes)
}

fn join_output(
    reader: Option<thread::ScopedJoinHandle<'_, std::io::Result<Vec<u8>>>>,
) -> Result<String, FixedCommandError> {
    let bytes = reader
        .ok_or(FixedCommandError::OutcomeUnknown)?
        .join()
        .map_err(|_| FixedCommandError::OutcomeUnknown)?
        .map_err(|_| FixedCommandError::OutcomeUnknown)?;
    String::from_utf8(bytes).map_err(|_| FixedCommandError::OutcomeUnknown)
}

fn join_discard<'scope>(
    input: Option<thread::ScopedJoinHandle<'scope, bool>>,
    stdout: Option<thread::ScopedJoinHandle<'scope, std::io::Result<Vec<u8>>>>,
    stderr: Option<thread::ScopedJoinHandle<'scope, std::io::Result<Vec<u8>>>>,
) {
    let _ = input.map(thread::ScopedJoinHandle::join);
    let _ = stdout.map(thread::ScopedJoinHandle::join);
    let _ = stderr.map(thread::ScopedJoinHandle::join);
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
    use std::io::Cursor;

    use super::*;

    #[test]
    fn bounded_reader_rejects_oversized_output() {
        let bytes = vec![b'x'; usize::try_from(MAX_OUTPUT_BYTES).unwrap() + 1];
        assert_eq!(
            read_bounded(Cursor::new(bytes)).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn caller_timeout_must_stay_within_the_fixed_command_ceiling() {
        for timeout in [Duration::ZERO, COMMAND_TIMEOUT + Duration::from_millis(1)] {
            assert!(matches!(
                run_with_timeout(&[], &[], None, 0, timeout),
                Err(FixedCommandError::FailedBeforeSpawn)
            ));
        }
    }
}
