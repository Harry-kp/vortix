use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead as _, Write as _};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde::Serialize;
use vortix::vortix_core::ports::process::{
    CommandSpec, ManagedProcessId, ProcessError, ProcessLifecycle, ProcessOwnership,
};
use vortix::vortix_core::profile::ProfileId;
use vortix::vortix_process::{CustodianError, StandardCustodian};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Spawn,
    Probe,
    Graceful,
    Wait,
    Force,
    Reap,
}

#[derive(Default)]
struct FakeProcess {
    alive: BTreeMap<ManagedProcessId, bool>,
    waits: VecDeque<bool>,
    fail_start_probe: bool,
    calls: Vec<Call>,
}

impl ProcessLifecycle for FakeProcess {
    fn spawn_foreground(
        &mut self,
        identity: ManagedProcessId,
        _spec: CommandSpec,
    ) -> Result<ProcessOwnership, ProcessError> {
        self.calls.push(Call::Spawn);
        self.alive.insert(identity.clone(), true);
        Ok(ProcessOwnership {
            identity,
            pid: 4242,
        })
    }

    fn is_alive(&mut self, identity: &ManagedProcessId) -> Result<bool, ProcessError> {
        self.calls.push(Call::Probe);
        if self.fail_start_probe {
            self.fail_start_probe = false;
            return Ok(false);
        }
        Ok(self.alive.get(identity).copied().unwrap_or(false))
    }

    fn graceful_stop(&mut self, _identity: &ManagedProcessId) -> Result<(), ProcessError> {
        self.calls.push(Call::Graceful);
        Ok(())
    }

    fn wait_for_exit(
        &mut self,
        identity: &ManagedProcessId,
        _timeout: Duration,
    ) -> Result<bool, ProcessError> {
        self.calls.push(Call::Wait);
        let exited = self.waits.pop_front().unwrap_or(true);
        if exited {
            self.alive.insert(identity.clone(), false);
        }
        Ok(exited)
    }

    fn force_kill(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError> {
        self.calls.push(Call::Force);
        self.alive.insert(identity.clone(), false);
        Ok(())
    }

    fn reap(&mut self, identity: &ManagedProcessId) -> Result<(), ProcessError> {
        self.calls.push(Call::Reap);
        self.alive.remove(identity);
        Ok(())
    }
}

fn identity(generation: u64) -> ManagedProcessId {
    ManagedProcessId {
        profile_id: ProfileId::new("stable-profile-id"),
        generation,
        ownership_token: format!("{generation:064x}"),
    }
}

#[test]
fn foreground_child_handshake_then_graceful_stop_and_reap() {
    let fake = FakeProcess::default();
    let mut custodian = StandardCustodian::new(fake, Duration::from_millis(10));
    let id = identity(7);
    let handshake = custodian
        .start(id.clone(), CommandSpec::oneshot("fake-openvpn", Vec::new()))
        .unwrap();
    assert_eq!(handshake.identity, id);
    assert_eq!(handshake.pid, 4242);
    assert!(custodian.owns(&id));
    custodian.stop(&id).unwrap();
    assert!(!custodian.owns(&id));
}

#[test]
fn deadline_escalates_to_process_group_kill_then_reaps() {
    let fake = FakeProcess {
        waits: VecDeque::from([false, true]),
        ..FakeProcess::default()
    };
    let mut custodian = StandardCustodian::new(fake, Duration::from_millis(10));
    let id = identity(8);
    custodian
        .start(id.clone(), CommandSpec::oneshot("fake-openvpn", Vec::new()))
        .unwrap();
    custodian.stop(&id).unwrap();
    assert!(!custodian.owns(&id));
}

#[test]
fn failed_startup_is_force_killed_reaped_and_never_owned() {
    let fake = FakeProcess {
        fail_start_probe: true,
        ..FakeProcess::default()
    };
    let mut custodian = StandardCustodian::new(fake, Duration::from_millis(10));
    let id = identity(9);
    assert!(matches!(
        custodian.start(id.clone(), CommandSpec::oneshot("fake-openvpn", Vec::new())),
        Err(CustodianError::StartupFailed)
    ));
    assert!(!custodian.owns(&id));
}

#[test]
fn crash_containment_cleans_every_child_without_control_authority() {
    let fake = FakeProcess::default();
    let mut custodian = StandardCustodian::new(fake, Duration::from_millis(10));
    let first = identity(10);
    let mut second = identity(11);
    second.profile_id = ProfileId::new("other-stable-profile");
    custodian
        .start(
            first.clone(),
            CommandSpec::oneshot("fake-openvpn", Vec::new()),
        )
        .unwrap();
    custodian
        .start(
            second.clone(),
            CommandSpec::oneshot("fake-openvpn", Vec::new()),
        )
        .unwrap();
    assert!(custodian.contain_all().is_empty());
    assert!(!custodian.owns(&first));
    assert!(!custodian.owns(&second));
}

#[derive(Serialize)]
struct TestLaunchRequest {
    identity: ManagedProcessId,
    spec: CommandSpec,
    cleanup_paths: Vec<std::path::PathBuf>,
    graceful_timeout_ms: u64,
}

fn spawn_hidden_until_ready(
    request: &TestLaunchRequest,
) -> (
    std::process::Child,
    std::process::ChildStdin,
    std::io::BufReader<std::process::ChildStdout>,
    u32,
) {
    let mut hidden = Command::new(env!("CARGO_BIN_EXE_vortix"))
        .arg("__vortix-tunnel-custodian")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = hidden.stdin.take().unwrap();
    serde_json::to_writer(&mut input, request).unwrap();
    input.write_all(b"\n").unwrap();
    input.flush().unwrap();
    let mut output = std::io::BufReader::new(hidden.stdout.take().unwrap());
    let mut ready = String::new();
    output.read_line(&mut ready).unwrap();
    let frame: serde_json::Value = serde_json::from_str(&ready).unwrap();
    assert_eq!(frame["type"], "ready");
    let group_pid = u32::try_from(frame["handshake"]["pid"].as_u64().unwrap()).unwrap();
    (hidden, input, output, group_pid)
}

fn wait_for_group_absence(pid: u32) {
    for _ in 0..200 {
        if !group_exists(pid) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!group_exists(pid), "process group {pid} remained alive");
}

struct EnvGuard;

impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("VORTIX_CUSTODIAN_EXE");
        std::env::remove_var("VORTIX_CUSTODIAN_RUNTIME_DIR");
    }
}

fn real_identity(profile_byte: char) -> ManagedProcessId {
    ManagedProcessId::generate(ProfileId::new(profile_byte.to_string().repeat(64))).unwrap()
}

fn group_exists(pid: u32) -> bool {
    let pid = i32::try_from(pid).unwrap();
    // SAFETY: signal zero is an existence probe for the process group.
    #[allow(unsafe_code)]
    let result = unsafe { libc::kill(-pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[test]
#[allow(clippy::too_many_lines)] // one serial real-process scenario owns the shared test env
fn real_tunnel_scoped_custodians_handoff_authenticate_and_contain_groups() {
    if std::env::var_os("CODEX_SANDBOX").is_some() {
        eprintln!("skipping real process-group test inside the Codex seatbelt sandbox");
        return;
    }
    // Unix-domain socket path limits are small on macOS; production uses the
    // similarly short `/tmp/vortix-custodian-<uid>` root.
    let temp = tempfile::Builder::new()
        .prefix("vortix-custodian-test-")
        .tempdir_in("/tmp")
        .unwrap();
    let runtime = temp.path().to_path_buf();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::env::set_var("VORTIX_CUSTODIAN_EXE", env!("CARGO_BIN_EXE_vortix"));
    std::env::set_var("VORTIX_CUSTODIAN_RUNTIME_DIR", &runtime);
    let _env = EnvGuard;

    let first = real_identity('a');
    let handshake = vortix::vortix_process::start_managed_foreground(
        first.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
        Vec::new(),
    )
    .unwrap();
    assert!(vortix::vortix_process::status_managed_foreground(&first).unwrap());
    assert_eq!(
        vortix::vortix_process::managed_identity_for_profile(&first.profile_id)
            .unwrap()
            .as_ref(),
        Some(&first)
    );

    let mut wrong = first.clone();
    let replacement = if wrong.ownership_token.ends_with('0') {
        "1"
    } else {
        "0"
    };
    wrong.ownership_token.replace_range(63..64, replacement);
    assert!(vortix::vortix_process::status_managed_foreground(&wrong).is_err());
    assert!(group_exists(handshake.pid));
    vortix::vortix_process::stop_managed_foreground(&first).unwrap();
    assert!(!group_exists(handshake.pid));
    assert!(vortix::vortix_process::status_managed_foreground(&first).is_err());

    // A stale capability cannot stop a newer attempt for the same profile.
    let newer = ManagedProcessId::generate(first.profile_id.clone()).unwrap();
    vortix::vortix_process::start_managed_foreground(
        newer.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
        Vec::new(),
    )
    .unwrap();
    assert!(vortix::vortix_process::stop_managed_foreground(&first).is_err());
    assert!(vortix::vortix_process::status_managed_foreground(&newer).unwrap());
    vortix::vortix_process::stop_managed_foreground(&newer).unwrap();

    // Per-profile actors stop concurrently rather than waiting behind a
    // process-global mutex.
    let second = real_identity('b');
    let third = real_identity('c');
    for identity in [&second, &third] {
        vortix::vortix_process::start_managed_foreground(
            identity.clone(),
            CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
            Vec::new(),
        )
        .unwrap();
    }
    let second_stop =
        thread::spawn(move || vortix::vortix_process::stop_managed_foreground(&second));
    let third_stop = thread::spawn(move || vortix::vortix_process::stop_managed_foreground(&third));
    second_stop.join().unwrap().unwrap();
    third_stop.join().unwrap().unwrap();

    // TERM-resistant leader and descendant require group SIGKILL, and the
    // group must be absent before stop is acknowledged.
    let stubborn = real_identity('d');
    let stubborn_handshake = vortix::vortix_process::start_managed_foreground(
        stubborn.clone(),
        CommandSpec::oneshot(
            "/bin/sh",
            vec![
                "-c".into(),
                "trap '' TERM; (trap '' TERM; exec sleep 30) & wait".into(),
            ],
        ),
        Vec::new(),
    )
    .unwrap();
    thread::sleep(Duration::from_millis(50));
    vortix::vortix_process::stop_managed_foreground(&stubborn).unwrap();
    assert!(!group_exists(stubborn_handshake.pid));

    // Natural exit releases the exact receipt and permits reconnect.
    let natural = real_identity('e');
    vortix::vortix_process::start_managed_foreground(
        natural.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["1".into()]),
        Vec::new(),
    )
    .unwrap();
    for _ in 0..100 {
        if vortix::vortix_process::managed_identity_for_profile(&natural.profile_id)
            .unwrap()
            .is_none()
        {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        vortix::vortix_process::managed_identity_for_profile(&natural.profile_id)
            .unwrap()
            .is_none()
    );

    // Spawn failure is fully cleaned and does not poison a later attempt.
    let failed = real_identity('f');
    assert!(vortix::vortix_process::start_managed_foreground(
        failed.clone(),
        CommandSpec::oneshot("/definitely/not/a/program", Vec::new()),
        Vec::new(),
    )
    .is_err());
    vortix::vortix_process::start_managed_foreground(
        failed.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
        Vec::new(),
    )
    .unwrap();
    vortix::vortix_process::stop_managed_foreground(&failed).unwrap();

    // Simulate a one-shot parent dying before COMMIT: EOF on the handoff pipe
    // makes the hidden custodian contain and reap its already-spawned child.
    let pre_handoff = real_identity('1');
    let child_pid_path = temp.path().join("pre-handoff-child.pid");
    let script = format!("echo $$ > '{}'; exec sleep 30", child_pid_path.display());
    let request = TestLaunchRequest {
        identity: pre_handoff,
        spec: CommandSpec::oneshot("/bin/sh", vec!["-c".into(), script]),
        cleanup_paths: Vec::new(),
        graceful_timeout_ms: 100,
    };
    let (mut hidden, hidden_stdin, _output, group_pid) = spawn_hidden_until_ready(&request);
    for _ in 0..40 {
        if child_pid_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    let child_pid = std::fs::read_to_string(&child_pid_path)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    drop(hidden_stdin);
    assert!(!hidden.wait().unwrap().success());
    wait_for_group_absence(group_pid);
    assert!(!group_exists(child_pid));

    // Signals are installed before spawn and the READY/COMMIT wait polls the
    // termination flag. Keep stdin open to prove SIGTERM, rather than EOF,
    // drives containment in this window.
    let signal_identity = real_identity('2');
    let request = TestLaunchRequest {
        identity: signal_identity,
        spec: CommandSpec::oneshot(
            "/bin/sh",
            vec![
                "-c".into(),
                "trap '' TERM; (trap '' TERM; exec sleep 30) & wait".into(),
            ],
        ),
        cleanup_paths: Vec::new(),
        graceful_timeout_ms: 100,
    };
    let (mut hidden, _input, _output, group_pid) = spawn_hidden_until_ready(&request);
    let hidden_pid = i32::try_from(hidden.id()).unwrap();
    // SAFETY: this targets the exact child process started immediately above.
    #[allow(unsafe_code)]
    let signal_result = unsafe { libc::kill(hidden_pid, libc::SIGTERM) };
    assert_eq!(signal_result, 0);
    assert!(!hidden.wait().unwrap().success());
    wait_for_group_absence(group_pid);

    // Abrupt custodian death closes the inherited guardian lifeline. The
    // guardian is group leader and kills the complete stubborn group on both
    // Linux and macOS. This intentionally does not claim power-loss recovery.
    let death_identity = real_identity('3');
    let request = TestLaunchRequest {
        identity: death_identity,
        spec: CommandSpec::oneshot(
            "/bin/sh",
            vec![
                "-c".into(),
                "trap '' TERM; (trap '' TERM; exec sleep 30) & wait".into(),
            ],
        ),
        cleanup_paths: Vec::new(),
        graceful_timeout_ms: 100,
    };
    let (mut hidden, mut input, mut output, group_pid) = spawn_hidden_until_ready(&request);
    input.write_all(b"{\"type\":\"commit\"}\n").unwrap();
    input.flush().unwrap();
    let mut committed = String::new();
    output.read_line(&mut committed).unwrap();
    assert!(committed.contains("\"type\":\"committed\""));
    assert!(group_exists(group_pid));
    hidden.kill().unwrap();
    let _ = hidden.wait();
    wait_for_group_absence(group_pid);

    // A status client may disappear before reading its response. Framing and
    // EPIPE are connection-local and must not stop a healthy owned tunnel.
    let dropped = real_identity('4');
    vortix::vortix_process::start_managed_foreground(
        dropped.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
        Vec::new(),
    )
    .unwrap();
    let socket_suffix = format!(
        "-{:016x}-{}.sock",
        dropped.generation,
        &dropped.ownership_token[..16]
    );
    let socket = std::fs::read_dir(&runtime)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.to_string_lossy().ends_with(&socket_suffix))
        .unwrap();
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    serde_json::to_writer(
        &mut stream,
        &serde_json::json!({"command": "status", "identity": dropped.clone()}),
    )
    .unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
    drop(stream);
    thread::sleep(Duration::from_millis(100));
    assert!(vortix::vortix_process::status_managed_foreground(&dropped).unwrap());
    vortix::vortix_process::stop_managed_foreground(&dropped).unwrap();
}
