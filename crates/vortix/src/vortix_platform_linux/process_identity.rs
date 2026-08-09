//! Linux process identity from `/proc/<pid>/stat` without subprocesses.

use std::io;

use crate::vortix_core::ports::process::KernelProcessIdentity;

pub fn observe(pid: u32) -> io::Result<Option<KernelProcessIdentity>> {
    if pid == 0 {
        return Ok(None);
    }
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let stat = parse_proc_stat(pid, &stat)?;
    if is_dead_state(stat.state) {
        return Ok(None);
    }
    Ok(KernelProcessIdentity::new(
        stat.start_token,
        stat.process_group == pid,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcStat {
    state: char,
    process_group: u32,
    start_token: u64,
}

fn parse_proc_stat(pid: u32, stat: &str) -> io::Result<ProcStat> {
    let open = stat.find('(').ok_or_else(invalid_stat)?;
    let close = stat.rfind(')').ok_or_else(invalid_stat)?;
    if close <= open
        || stat[..open].trim().parse::<u32>().ok() != Some(pid)
        || !stat[close + 1..].starts_with(' ')
    {
        return Err(invalid_stat());
    }
    let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    if fields.len() < 20 {
        return Err(invalid_stat());
    }
    let state = fields[0].chars().next().ok_or_else(invalid_stat)?;
    let process_group = fields[2].parse::<u32>().map_err(|_| invalid_stat())?;
    let start_token = fields[19].parse::<u64>().map_err(|_| invalid_stat())?;
    Ok(ProcStat {
        state,
        process_group,
        start_token,
    })
}

pub(crate) fn process_group_has_live_members(group_id: u32) -> io::Result<Option<bool>> {
    let mut complete_snapshot = true;
    for entry in std::fs::read_dir("/proc")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                complete_snapshot = false;
                continue;
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                complete_snapshot = false;
                continue;
            }
        };
        let stat = match parse_proc_stat(pid, &stat) {
            Ok(stat) => stat,
            Err(_) => {
                complete_snapshot = false;
                continue;
            }
        };
        if stat.process_group == group_id && !is_dead_state(stat.state) {
            return Ok(Some(true));
        }
    }
    Ok(complete_snapshot.then_some(false))
}

const fn is_dead_state(state: char) -> bool {
    matches!(state, 'Z' | 'X' | 'x')
}

fn invalid_stat() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid proc process identity")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fork_process_group(exit_immediately: bool) -> u32 {
        // SAFETY: the child performs only async-signal-safe libc calls before
        // exiting or pausing, so it does not touch inherited Rust runtime state.
        #[allow(unsafe_code)]
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: both calls operate only on the forked child process.
            #[allow(unsafe_code)]
            unsafe {
                if libc::setpgid(0, 0) != 0 {
                    libc::_exit(125);
                }
                if exit_immediately {
                    libc::_exit(0);
                }
                loop {
                    libc::pause();
                }
            }
        }

        let group_id = u32::try_from(pid).unwrap();
        for _ in 0..200 {
            // SAFETY: signal zero is a read-only existence probe for the child group.
            #[allow(unsafe_code)]
            if unsafe { libc::kill(-pid, 0) } == 0 {
                return group_id;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("forked process group {group_id} did not become observable");
    }

    fn reap(pid: u32) {
        let mut status = 0;
        // SAFETY: `pid` came from `fork_process_group` and `status` is writable.
        #[allow(unsafe_code)]
        let waited = unsafe { libc::waitpid(i32::try_from(pid).unwrap(), &raw mut status, 0) };
        assert_eq!(waited, i32::try_from(pid).unwrap());
    }

    fn stat(pid: u32, state: &str, process_group: u32, start_token: u64) -> String {
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = state.to_owned();
        fields[2] = process_group.to_string();
        fields[19] = start_token.to_string();
        format!("{pid} (openvpn worker) {}", fields.join(" "))
    }

    #[test]
    fn proc_stat_binds_start_token_and_private_group() {
        let parsed = parse_proc_stat(42, &stat(42, "S", 42, 9001)).unwrap();
        assert_eq!(parsed.start_token, 9001);
        assert_eq!(parsed.process_group, 42);

        let member = parse_proc_stat(42, &stat(42, "S", 7, 9001)).unwrap();
        assert_eq!(member.process_group, 7);
    }

    #[test]
    fn proc_stat_rejects_pid_relabel_malformed_and_zombie_records() {
        assert!(parse_proc_stat(42, &stat(41, "S", 41, 9)).is_err());
        assert!(parse_proc_stat(42, "42 malformed").is_err());
        assert_eq!(
            parse_proc_stat(42, &stat(42, "Z", 42, 9)).unwrap().state,
            'Z'
        );
    }

    #[test]
    fn live_process_group_has_live_members() {
        let pid = fork_process_group(false);
        assert_eq!(process_group_has_live_members(pid).unwrap(), Some(true));
        // SAFETY: the forked child is the leader of this private test group.
        #[allow(unsafe_code)]
        unsafe {
            libc::kill(-i32::try_from(pid).unwrap(), libc::SIGKILL);
        }
        reap(pid);
    }

    #[test]
    fn zombie_only_process_group_has_no_live_members() {
        let pid = fork_process_group(true);
        let mut state = None;
        for _ in 0..200 {
            state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| parse_proc_stat(pid, &stat).ok().map(|stat| stat.state));
            if state == Some('Z') {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(state, Some('Z'));
        assert_eq!(process_group_has_live_members(pid).unwrap(), Some(false));
        reap(pid);
    }
}
