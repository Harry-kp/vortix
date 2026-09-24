//! The OS adapters for this build, and small per-OS helpers.

#[cfg(target_os = "linux")]
pub use crate::linux::{
    IptablesFirewall as Firewall, LinuxDns as Dns, LinuxInterface as Interface,
    LinuxNetworkStats as NetworkStats, LinuxRouteTable as Routes, ProcSocketAudit as SocketAudit,
};
#[cfg(target_os = "macos")]
pub use crate::macos::{
    LsofSocketAudit as SocketAudit, MacDns as Dns, MacInterface as Interface,
    MacNetworkStats as NetworkStats, MacRouteTable as Routes, PfFirewall as Firewall,
};

/// Live network-interface names; empty when enumeration fails, which
/// callers must read as "unknown", not "none present".
#[must_use]
pub fn available_network_interfaces() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        crate::linux::interface_list::available_network_interfaces()
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos::interface_list::available_network_interfaces()
    }
}

#[cfg(target_os = "macos")]
// xtask:allow-platform-cfg: the only remaining caller is the macOS DNS adapter
pub(crate) mod fixed_root_command {
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
        #[allow(
            dead_code,
            reason = "drained to avoid pipe deadlock; only status is inspected today"
        )]
        pub(crate) stdout: String,
        #[allow(
            dead_code,
            reason = "drained to avoid pipe deadlock; only status is inspected today"
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
}
pub(crate) mod route_probe {
    //! Shared failure backoff for platform route-table probes.

    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use crate::process::CommandSpec;

    pub(crate) enum ProbeOutcome {
        BackedOff,
        Success(String),
        Failed {
            consecutive_failures: u32,
            cooldown: Duration,
        },
    }

    struct ProbeBackoff {
        consecutive_failures: u32,
        next_allowed: Instant,
    }

    /// Process-wide state for one platform route probe.
    pub(crate) struct RouteProbe {
        state: OnceLock<Mutex<ProbeBackoff>>,
    }

    impl RouteProbe {
        pub(crate) const fn new() -> Self {
            Self {
                state: OnceLock::new(),
            }
        }

        pub(crate) fn run(&self, spec: CommandSpec) -> ProbeOutcome {
            let state = self.state.get_or_init(|| {
                Mutex::new(ProbeBackoff {
                    consecutive_failures: 0,
                    next_allowed: Instant::now(),
                })
            });

            {
                let state = state.lock().expect("backoff state mutex poisoned");
                if Instant::now() < state.next_allowed {
                    return ProbeOutcome::BackedOff;
                }
            }

            let result = crate::process::run_to_output(spec);
            let mut state = state.lock().expect("backoff state mutex poisoned");
            if let Ok(output) = result {
                state.consecutive_failures = 0;
                state.next_allowed = Instant::now();
                return ProbeOutcome::Success(String::from_utf8_lossy(&output.stdout).into_owned());
            }

            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            let cooldown = cooldown_for_failures(state.consecutive_failures);
            state.next_allowed = Instant::now() + cooldown;
            ProbeOutcome::Failed {
                consecutive_failures: state.consecutive_failures,
                cooldown,
            }
        }
    }

    fn cooldown_for_failures(failures: u32) -> Duration {
        Duration::from_secs(match failures {
            0..=2 => 0,
            3..=5 => 5,
            6..=10 => 15,
            _ => 60,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cooldown_ladder_escalates_then_caps() {
            assert_eq!(cooldown_for_failures(0), Duration::ZERO);
            assert_eq!(cooldown_for_failures(2), Duration::ZERO);
            assert_eq!(cooldown_for_failures(3), Duration::from_secs(5));
            assert_eq!(cooldown_for_failures(5), Duration::from_secs(5));
            assert_eq!(cooldown_for_failures(6), Duration::from_secs(15));
            assert_eq!(cooldown_for_failures(10), Duration::from_secs(15));
            assert_eq!(cooldown_for_failures(11), Duration::from_secs(60));
            assert_eq!(cooldown_for_failures(1_000_000), Duration::from_secs(60));
        }
    }
}

/// Directory a confined `wg-quick` is permitted to read configs from, when
/// the platform confines it at all.
///
/// Debian and Ubuntu ship an `AppArmor` profile for wg-quick granting no read
/// access outside `/etc/wireguard`, so a lifecycle copy staged anywhere else
/// is refused by the kernel before wg-quick even runs. The profile's rule is
/// `file rw @{etc_rw}/wireguard/{,**}` — the `{,**}` covers the tree
/// recursively, so Vortix takes its own subdirectory rather than writing
/// beside configs the user manages. Nothing there is ever theirs, so there is
/// no file to avoid clobbering and none of its contents outlive a teardown.
///
/// `None` means the platform does not confine wg-quick and the caller may
/// stage wherever it likes.
pub(crate) fn wireguard_staging_dir() -> Option<&'static std::path::Path> {
    #[cfg(target_os = "linux")] // xtask:allow-platform-cfg: AppArmor confines wg-quick on Linux only
    const STAGING_DIR: Option<&str> = Some("/etc/wireguard/vortix");
    #[cfg(not(target_os = "linux"))] // xtask:allow-platform-cfg: see above
    const STAGING_DIR: Option<&str> = None;

    STAGING_DIR.map(std::path::Path::new)
}

#[cfg(target_os = "linux")]
pub(crate) fn process_group_has_live_members(group_id: u32) -> std::io::Result<Option<bool>> {
    crate::linux::process_identity::process_group_has_live_members(group_id)
}

#[cfg(target_os = "macos")]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the Linux platform probe so the process layer stays OS-agnostic"
)]
pub(crate) fn process_group_has_live_members(_group_id: u32) -> std::io::Result<Option<bool>> {
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("Vortix currently only supports macOS and Linux");

// Re-export platform constants from the centralized constants module for convenience.
pub use crate::constants::KILLSWITCH_EMERGENCY_MSG;

fn syscall_result(result: libc::c_int) -> std::io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Replace the current process's supplementary groups on macOS.
///
/// This is called from a `pre_exec` closure, so it performs only bounded
/// scalar conversion and the async-signal-safe `setgroups` syscall.
#[cfg(target_os = "macos")]
pub(crate) fn set_process_supplementary_groups(groups: &[u32]) -> std::io::Result<()> {
    let count =
        i32::try_from(groups.len()).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `groups` remains valid for the duration of the syscall.
    #[allow(unsafe_code)]
    let result = unsafe { libc::setgroups(count, groups.as_ptr()) };
    syscall_result(result)
}

/// Linux variant of [`set_process_supplementary_groups`].
#[cfg(target_os = "linux")]
pub(crate) fn set_process_supplementary_groups(groups: &[u32]) -> std::io::Result<()> {
    // SAFETY: `groups` remains valid for the duration of the syscall.
    #[allow(unsafe_code)]
    let result = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    syscall_result(result)
}

/// Resolve a user's complete OS group list without invoking an external
/// command. The libc signature differs between macOS and Linux, so the
/// normalization belongs at this platform boundary.
#[cfg(target_os = "macos")]
pub(crate) fn supplementary_groups_for_user(
    user: &std::ffi::CStr,
    gid: u32,
    max_groups: usize,
) -> Option<Vec<u32>> {
    let base_group = i32::try_from(gid).ok()?;
    let mut group_count = i32::try_from(max_groups).ok()?;
    let mut groups = vec![0_i32; max_groups];
    // SAFETY: the call uses the stable C string and a buffer whose length is
    // supplied through `group_count`.
    #[allow(unsafe_code)]
    unsafe {
        if libc::getgrouplist(
            user.as_ptr(),
            base_group,
            groups.as_mut_ptr(),
            &raw mut group_count,
        ) < 0
        {
            return None;
        }
        groups.truncate(usize::try_from(group_count).ok()?);
        if groups.is_empty() {
            return None;
        }
        groups
            .into_iter()
            .map(|group| u32::try_from(group).ok())
            .collect()
    }
}

/// Linux variant of [`supplementary_groups_for_user`].
#[cfg(target_os = "linux")]
pub(crate) fn supplementary_groups_for_user(
    user: &std::ffi::CStr,
    gid: u32,
    max_groups: usize,
) -> Option<Vec<u32>> {
    let mut group_count = i32::try_from(max_groups).ok()?;
    let mut groups = vec![0_u32; max_groups];
    // SAFETY: the call uses the stable C string and a buffer whose length is
    // supplied through `group_count`.
    #[allow(unsafe_code)]
    unsafe {
        if libc::getgrouplist(
            user.as_ptr(),
            gid,
            groups.as_mut_ptr(),
            &raw mut group_count,
        ) < 0
        {
            return None;
        }
        groups.truncate(usize::try_from(group_count).ok()?);
        if groups.is_empty() {
            return None;
        }
        Some(groups)
    }
}

/// The command that shows this platform's Vortix-owned firewall rules, so a
/// reader who is told Vortix cannot confirm them can look for themselves.
#[cfg(target_os = "macos")]
#[must_use]
pub fn firewall_inspect_hint() -> &'static str {
    "sudo pfctl -a com.apple/vortix.killswitch -sr"
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn firewall_inspect_hint() -> &'static str {
    "sudo nft list table inet vortix_killswitch"
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[must_use]
pub fn firewall_inspect_hint() -> &'static str {
    "(no firewall inspection command on this platform)"
}

/// Platform-appropriate install hint for a package.
#[cfg(target_os = "macos")]
#[must_use]
pub fn install_hint(pkg: &str) -> String {
    format!("brew install {pkg}")
}

/// The install command for this machine's package manager.
///
/// Read from `/etc/os-release`: `ID` first, then `ID_LIKE`, so derivatives
/// resolve to the family they are built on -- `CachyOS` and `EndeavourOS` report
/// `ID_LIKE=arch`, Nobara reports `fedora`, Mint reports `debian`. A distro
/// that matches nothing falls back to listing every family, which is what
/// this function used to print unconditionally.
#[cfg(target_os = "linux")]
fn install_command(pkg: &str) -> Option<String> {
    let release = std::fs::read_to_string("/etc/os-release").ok()?;
    let field = |key: &str| -> Option<String> {
        release.lines().find_map(|line| {
            let value = line.strip_prefix(key)?.strip_prefix('=')?;
            Some(value.trim_matches('"').to_lowercase())
        })
    };
    let ids = [field("ID"), field("ID_LIKE")];
    let families = ids.iter().flatten().flat_map(|v| {
        v.split_whitespace()
            .map(std::borrow::ToOwned::to_owned)
            .collect::<Vec<_>>()
    });
    for family in families {
        match family.as_str() {
            "debian" | "ubuntu" => return Some(format!("sudo apt install {pkg}")),
            "arch" | "archlinux" | "cachyos" | "manjaro" => {
                return Some(format!("sudo pacman -S {pkg}"))
            }
            "fedora" | "rhel" | "centos" => return Some(format!("sudo dnf install {pkg}")),
            _ => {}
        }
    }
    None
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn install_hint(pkg: &str) -> String {
    // A package whose name differs per family, or which is not a package at
    // all, keeps its hand-written block below.
    let uniform = matches!(pkg, "wg" | "wg-quick" | "wireguard-tools" | "openvpn");
    if uniform {
        let package = if pkg == "openvpn" {
            "openvpn"
        } else {
            "wireguard-tools"
        };
        if let Some(command) = install_command(package) {
            return command;
        }
    }
    match pkg {
        // systemd-resolved is managing DNS — need the systemd-provided shim.
        // `openresolv` will NOT work here (causes "signature mismatch").
        "resolvconf (systemd)" => "\
sudo apt install systemd-resolved  # Debian/Ubuntu (provides resolvconf shim)\n\
sudo pacman -S systemd-resolvconf  # Arch\n\
sudo dnf install systemd-resolved  # Fedora"
            .to_string(),
        // Non-systemd system — standalone openresolv works fine.
        "resolvconf" => "\
sudo apt install openresolv  # Debian/Ubuntu\n\
sudo pacman -S openresolv    # Arch\n\
sudo dnf install openresolv  # Fedora"
            .to_string(),
        // Not a package (#242) — the fix is a sysctl, boot-param, or profile edit.
        "host IPv6 (kernel disabled)" => "\
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0\n\
# if that reports 'unknown oid': remove ipv6.disable=1 from the kernel cmdline\n\
# or: remove the IPv6 entry from the profile's Address line"
            .to_string(),
        // WireGuard binaries (wg, wg-quick) and the package itself all
        // share the same install hint — both binaries ship in the
        // wireguard-tools package on every supported distro.
        "wg" | "wg-quick" | "wireguard-tools" => "\
sudo apt install wireguard-tools  # Debian/Ubuntu\n\
sudo pacman -S wireguard-tools    # Arch\n\
sudo dnf install wireguard-tools  # Fedora"
            .to_string(),
        // OpenVPN ships under its eponymous package everywhere.
        "openvpn" => "\
sudo apt install openvpn  # Debian/Ubuntu\n\
sudo pacman -S openvpn    # Arch\n\
sudo dnf install openvpn  # Fedora"
            .to_string(),
        // Unknown package: best-effort generic hint (the calling code
        // should add a specific case above before relying on this).
        _ => format!(
            "\
sudo apt install {pkg}  # Debian/Ubuntu\n\
sudo pacman -S {pkg}    # Arch\n\
sudo dnf install {pkg}  # Fedora"
        ),
    }
}

#[cfg(test)]
mod external_interface_tests {}
