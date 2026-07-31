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
    parse_proc_stat(pid, &stat)
}

fn parse_proc_stat(pid: u32, stat: &str) -> io::Result<Option<KernelProcessIdentity>> {
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
    if fields[0] == "Z" {
        return Ok(None);
    }
    let process_group = fields[2].parse::<u32>().map_err(|_| invalid_stat())?;
    let start_token = fields[19].parse::<u64>().map_err(|_| invalid_stat())?;
    Ok(KernelProcessIdentity::new(
        start_token,
        process_group == pid,
    ))
}

fn invalid_stat() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid proc process identity")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(pid: u32, state: &str, process_group: u32, start_token: u64) -> String {
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = state.to_owned();
        fields[2] = process_group.to_string();
        fields[19] = start_token.to_string();
        format!("{pid} (openvpn worker) {}", fields.join(" "))
    }

    #[test]
    fn proc_stat_binds_start_token_and_private_group() {
        let identity = parse_proc_stat(42, &stat(42, "S", 42, 9001))
            .unwrap()
            .unwrap();
        assert_eq!(identity.start_token(), 9001);
        assert!(identity.is_process_group_leader());

        let member = parse_proc_stat(42, &stat(42, "S", 7, 9001))
            .unwrap()
            .unwrap();
        assert!(!member.is_process_group_leader());
    }

    #[test]
    fn proc_stat_rejects_pid_relabel_malformed_and_zombie_records() {
        assert!(parse_proc_stat(42, &stat(41, "S", 41, 9)).is_err());
        assert!(parse_proc_stat(42, "42 malformed").is_err());
        assert_eq!(parse_proc_stat(42, &stat(42, "Z", 42, 9)).unwrap(), None);
    }
}
