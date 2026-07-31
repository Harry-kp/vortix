//! macOS process identity from `proc_pidinfo(PROC_PIDTBSDINFO)`.

use std::io;
use std::mem::{self, MaybeUninit};

use crate::vortix_core::ports::process::KernelProcessIdentity;

const PROC_PIDTBSDINFO: libc::c_int = 3;
const ZOMBIE_STATUS: u32 = 5;

pub fn observe(pid: u32) -> io::Result<Option<KernelProcessIdentity>> {
    let pid = libc::pid_t::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process id"))?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = libc::c_int::try_from(mem::size_of::<libc::proc_bsdinfo>())
        .map_err(|_| io::Error::other("process identity structure is too large"))?;
    // SAFETY: `info` is a correctly sized writable proc_bsdinfo buffer.
    #[allow(unsafe_code)]
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    if written != size {
        // SAFETY: signal zero only probes existence and touches no Rust memory.
        #[allow(unsafe_code)]
        let exists = unsafe { libc::kill(pid, 0) } == 0;
        return if exists {
            Err(io::Error::last_os_error())
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            Ok(None)
        } else {
            Err(io::Error::last_os_error())
        };
    }
    // SAFETY: proc_pidinfo returned the exact requested structure size.
    #[allow(unsafe_code)]
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != u32::try_from(pid).unwrap_or_default() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned a mismatched process identity",
        ));
    }
    if info.pbi_status == ZOMBIE_STATUS {
        return Ok(None);
    }
    let start_token = info
        .pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process start time overflow"))?;
    Ok(KernelProcessIdentity::new(
        start_token,
        info.pbi_pgid == u32::try_from(pid).unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_has_a_nonzero_kernel_start_token() {
        let identity = observe(std::process::id()).unwrap().unwrap();
        assert_ne!(identity.start_token(), 0);
    }
}
