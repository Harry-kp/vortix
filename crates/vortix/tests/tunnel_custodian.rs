use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead as _, Write as _};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde::Serialize;
use vortix::process::{
    CommandSpec, ManagedProcessId, ProcessError, ProcessLifecycle, ProcessOwnership,
};
use vortix::process::{CustodianError, StandardCustodian};
use vortix::profile::ProfileId;

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
        if !group_has_live_members(pid) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !group_has_live_members(pid),
        "process group {pid} retained a live member"
    );
}

fn wait_for_pid_file(path: &std::path::Path) -> u32 {
    for _ in 0..40 {
        if let Ok(pid) = std::fs::read_to_string(path)
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .parse::<u32>()
        {
            return pid;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("child pid file was not populated: {}", path.display());
}

fn pid_recording_sleep(path: &std::path::Path) -> CommandSpec {
    CommandSpec::oneshot(
        "/bin/sh",
        vec![
            "-c".into(),
            "echo $$ > \"$1\"; exec sleep 30".into(),
            "vortix-test-child".into(),
            path.to_string_lossy().into_owned(),
        ],
    )
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

fn group_has_live_members(pid: u32) -> bool {
    // `kill(-pgid, 0)` reports zombie-only groups as present. That is useful
    // for raw existence checks but wrong for leak detection after abrupt
    // custodian death, where the orphaned guardian is already dead and only
    // awaiting OS reaping. Prefer a process-state snapshot and fall back to
    // the signal probe when `ps` is unavailable.
    if let Ok(output) = Command::new("ps").args(["-axo", "pgid=,stat="]).output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            return text.lines().any(|line| {
                let mut fields = line.split_whitespace();
                let member_group = fields.next().and_then(|value| value.parse::<u32>().ok());
                let state = fields.next();
                member_group == Some(pid) && state.is_some_and(|value| !value.starts_with('Z'))
            });
        }
    }

    let pid = i32::try_from(pid).unwrap();
    // SAFETY: signal zero is an existence probe for the process group.
    #[allow(unsafe_code)]
    let result = unsafe { libc::kill(-pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[test]
fn zombie_only_process_group_is_not_a_live_leak() {
    use std::os::unix::process::CommandExt as _;

    if std::env::var_os("CODEX_SANDBOX").is_some() {
        eprintln!("skipping process-state test inside the Codex seatbelt sandbox");
        return;
    }
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut state = String::new();
    for _ in 0..200 {
        let status = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        state = String::from_utf8(status.stdout).unwrap();
        if state.trim_start().starts_with('Z') {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(state.trim_start().starts_with('Z'), "state was {state:?}");
    let reported_alive = group_has_live_members(pid);
    child.wait().unwrap();

    assert!(!reported_alive, "a zombie-only group is not a live leak");
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
    let handshake = vortix::process::custodian::spawn_custodian(
        first.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
        Vec::new(),
        None,
    )
    .unwrap();
    assert!(vortix::process::custodian::remote_status(&first).unwrap());
    assert_eq!(
        vortix::process::custodian::load_identity(&first.profile_id)
            .unwrap()
            .as_ref(),
        Some(&first)
    );

    // A later one-shot Standard-mode authority reconstructs the exact
    // OpenVPN handle from the authenticated custodian receipt and can stop it
    // without an in-memory executor ledger.
    let recovered_identity = real_identity('0');
    let operation: vortix::tunnel::OperationId =
        serde_json::from_str("\"op-0000000000000001-0000000000000001\"").unwrap();
    let recovered_child_pid_path = temp.path().join("recovered-openvpn-child.pid");
    let recovered_handshake = vortix::process::custodian::spawn_custodian(
        recovered_identity.clone(),
        pid_recording_sleep(&recovered_child_pid_path),
        Vec::new(),
        Some(operation.clone()),
    )
    .unwrap();
    wait_for_pid_file(&recovered_child_pid_path);
    assert_eq!(
        vortix::process::custodian::load_handshake(&recovered_identity.profile_id)
            .unwrap()
            .and_then(|handshake| handshake.operation_id),
        Some(operation.clone()),
        "authenticated receipt must retain the connect operation independently of history",
    );
    vortix::process::custodian::remote_stop(&recovered_identity).unwrap();
    assert!(!group_has_live_members(recovered_handshake.pid));

    let mut wrong = first.clone();
    let replacement = if wrong.ownership_token.ends_with('0') {
        "1"
    } else {
        "0"
    };
    wrong.ownership_token.replace_range(63..64, replacement);
    assert!(vortix::process::custodian::remote_status(&wrong).is_err());
    assert!(group_has_live_members(handshake.pid));
    vortix::process::custodian::remote_stop(&first).unwrap();
    assert!(!group_has_live_members(handshake.pid));
    assert!(vortix::process::custodian::remote_status(&first).is_err());

    // A stale capability cannot stop a newer attempt for the same profile.
    let newer = ManagedProcessId::generate(first.profile_id.clone()).unwrap();
    vortix::process::custodian::spawn_custodian(
        newer.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
        Vec::new(),
        None,
    )
    .unwrap();
    assert!(vortix::process::custodian::remote_stop(&first).is_err());
    assert!(vortix::process::custodian::remote_status(&newer).unwrap());
    vortix::process::custodian::remote_stop(&newer).unwrap();

    // Per-profile actors stop concurrently rather than waiting behind a
    // process-global mutex.
    let second = real_identity('b');
    let third = real_identity('c');
    for identity in [&second, &third] {
        vortix::process::custodian::spawn_custodian(
            identity.clone(),
            CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
            Vec::new(),
            None,
        )
        .unwrap();
    }
    let second_stop = thread::spawn(move || vortix::process::custodian::remote_stop(&second));
    let third_stop = thread::spawn(move || vortix::process::custodian::remote_stop(&third));
    second_stop.join().unwrap().unwrap();
    third_stop.join().unwrap().unwrap();

    // Natural exit releases the exact receipt and permits reconnect.
    let natural = real_identity('e');
    let natural_handshake = vortix::process::custodian::spawn_custodian(
        natural.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["1".into()]),
        Vec::new(),
        None,
    )
    .unwrap();
    for _ in 0..100 {
        if vortix::process::custodian::load_identity(&natural.profile_id)
            .unwrap()
            .is_none()
        {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        vortix::process::custodian::load_identity(&natural.profile_id)
            .unwrap()
            .is_none()
    );
    vortix::process::custodian::remote_stop_after_startup(&natural_handshake)
        .expect("the startup owner can prove an already-clean natural exit");

    // Spawn failure is fully cleaned and does not poison a later attempt.
    let failed = real_identity('f');
    assert!(vortix::process::custodian::spawn_custodian(
        failed.clone(),
        CommandSpec::oneshot("/definitely/not/a/program", Vec::new()),
        Vec::new(),
        None,
    )
    .is_err());
    vortix::process::custodian::spawn_custodian(
        failed.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
        Vec::new(),
        None,
    )
    .unwrap();
    vortix::process::custodian::remote_stop(&failed).unwrap();

    // Simulate a one-shot parent dying before COMMIT: EOF on the handoff pipe
    // makes the hidden custodian contain and reap its already-spawned child.
    let pre_handoff = real_identity('1');
    let child_pid_path = temp.path().join("pre-handoff-child.pid");
    let request = TestLaunchRequest {
        identity: pre_handoff,
        spec: pid_recording_sleep(&child_pid_path),
        cleanup_paths: Vec::new(),
        graceful_timeout_ms: 100,
    };
    let (mut hidden, hidden_stdin, _output, group_pid) = spawn_hidden_until_ready(&request);
    let child_pid = wait_for_pid_file(&child_pid_path);
    drop(hidden_stdin);
    assert!(!hidden.wait().unwrap().success());
    wait_for_group_absence(group_pid);
    assert!(!group_has_live_members(child_pid));

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
    assert!(group_has_live_members(group_pid));
    hidden.kill().unwrap();
    let _ = hidden.wait();
    wait_for_group_absence(group_pid);

    // A status client may disappear before reading its response. Framing and
    // EPIPE are connection-local and must not stop a healthy owned tunnel.
    let dropped = real_identity('4');
    vortix::process::custodian::spawn_custodian(
        dropped.clone(),
        CommandSpec::oneshot("/bin/sleep", vec!["30".into()]),
        Vec::new(),
        None,
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
    assert!(vortix::process::custodian::remote_status(&dropped).unwrap());
    vortix::process::custodian::remote_stop(&dropped).unwrap();
}
