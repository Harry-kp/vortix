//! Hand-rolled libproc FFI for macOS — replaces the `lsof` shell-outs.
//!
//! Plan 002 U7 (lsof bundle): mirrors the relevant structs from
//! `<sys/proc_info.h>` (Apple SDK `MacOSX.sdk/usr/include/sys/proc_info.h`)
//! so we can call `proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, …)`
//! directly. `socket_audit::LsofSocketAudit` walks every PID's socket FDs
//! to produce the snapshot the prior `lsof -i -P -n` parser yielded;
//! `interface::Interface::get_wireguard_pid` walks them to find the
//! process holding `/var/run/wireguard/<iface>.sock` (the prior
//! `lsof -t <sock>` use).
//!
//! The struct layouts are verified at compile time via `size_of`
//! assertions against the byte counts Apple's header documents — any
//! future SDK drift fails the build instead of silently returning
//! garbage.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_ptr_alignment)]
// Struct field prefixes (`fi_`, `vst_`, `sbi_`, `unsi_`, `soi_`, `insi_`,
// `tcpsi_`) mirror Apple's <sys/proc_info.h> header verbatim — clippy's
// `struct_field_names` lint reads them as redundant but renaming would
// break the layout-by-eyeball property we rely on.
#![allow(clippy::struct_field_names)]

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Constants from <sys/proc_info.h>
// ---------------------------------------------------------------------------

/// `proc_listpids` flavor: enumerate every live PID.
const PROC_ALL_PIDS: u32 = 1;
/// `proc_pidinfo` flavor: enumerate a PID's file descriptors.
const PROC_PIDLISTFDS: libc::c_int = 1;
/// `proc_pidfdinfo` flavor: read socket info for an FD.
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
/// `proc_fdinfo.proc_fdtype` value for socket FDs.
const PROX_FDTYPE_SOCKET: u32 = 2;

const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const SOCKINFO_UN: i32 = 3;

const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;

const SOCK_MAXADDRLEN: usize = 255;

// ---------------------------------------------------------------------------
// Struct layouts mirroring <sys/proc_info.h>
//
// Field-by-field with explicit padding where C's natural alignment
// inserts gaps. Final sizes are asserted at compile time below.
// ---------------------------------------------------------------------------

#[repr(C)]
struct proc_fileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
struct vinfo_stat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
struct sockbuf_info {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

/// `union { struct in4in6_addr ina_46; struct in6_addr ina_6; }` — both
/// variants are 16 bytes. IPv4 lives in the last 4 bytes (`i46a_addr4`
/// after three `u32` of pad); IPv6 lives across all 16. `insi_vflag`
/// (`INI_IPV4` vs `INI_IPV6`) picks which.
#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct in4in6_addr_union {
    bytes: [u8; 16],
}

/// `in_sockinfo` for IPv4/IPv6 datagram + raw sockets and embedded inside
/// `tcp_sockinfo`. Layout includes explicit pad for natural alignment of
/// `rfu_1` after `insi_ip_ttl`.
#[repr(C)]
struct in_sockinfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    _pad_after_ttl: [u8; 2],
    rfu_1: u32,
    insi_faddr: in4in6_addr_union,
    insi_laddr: in4in6_addr_union,
    /// Anonymous struct `insi_v4 { u_char in4_tos; }` (1 byte +
    /// 3 bytes pad to align next int).
    insi_v4_tos: u8,
    _pad_after_v4: [u8; 3],
    /// Anonymous struct `insi_v6 { uint8_t in6_hlim; int in6_cksum;
    /// u_short in6_ifindex; short in6_hops; }`. 12 bytes total.
    insi_v6_hlim: u8,
    _pad_after_hlim: [u8; 3],
    insi_v6_cksum: i32,
    insi_v6_ifindex: u16,
    insi_v6_hops: i16,
}

#[repr(C)]
struct tcp_sockinfo {
    tcpsi_ini: in_sockinfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

/// `un_sockinfo`'s two address unions: `union { struct sockaddr_un ua_sun;
/// char ua_dummy[SOCK_MAXADDRLEN]; }`. `sockaddr_un` is
/// `(u8 sun_len, u8 sun_family, char sun_path[104])` = 106 bytes;
/// `ua_dummy` is 255 bytes. The union takes the max = 255, align-1.
#[repr(C)]
#[derive(Clone, Copy)]
struct un_addr_union {
    bytes: [u8; SOCK_MAXADDRLEN],
}

#[repr(C)]
struct un_sockinfo {
    unsi_conn_so: u64,
    unsi_conn_pcb: u64,
    unsi_addr: un_addr_union,
    unsi_caddr: un_addr_union,
}

/// `union soi_proto`: max-variant size is `un_sockinfo` at 526 bytes
/// (8 + 8 + 255 + 255), padded to its 8-byte alignment = 528.
const SOI_PROTO_UNION_SIZE: usize = mem::size_of::<un_sockinfo>();

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct soi_proto_union {
    bytes: [u8; SOI_PROTO_UNION_SIZE],
}

#[repr(C)]
struct socket_info {
    soi_stat: vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: sockbuf_info,
    soi_snd: sockbuf_info,
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: soi_proto_union,
}

#[repr(C)]
struct socket_fdinfo {
    pfi: proc_fileinfo,
    psi: socket_info,
}

// Compile-time size checks against Apple's documented layout. If these
// fail, the SDK has drifted and the field-by-field definitions above
// need updating.
const _: () = {
    assert!(mem::size_of::<proc_fileinfo>() == 24);
    assert!(mem::size_of::<vinfo_stat>() == 136);
    assert!(mem::size_of::<sockbuf_info>() == 24);
    assert!(mem::size_of::<in_sockinfo>() == 80);
    assert!(mem::size_of::<tcp_sockinfo>() == 120);
    assert!(mem::size_of::<un_sockinfo>() == 528);
    assert!(mem::size_of::<socket_info>() == 768);
    assert!(mem::size_of::<socket_fdinfo>() == 792);
};

// ---------------------------------------------------------------------------
// libc FFI declarations (not in libc 0.2 today)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn proc_pidfdinfo(
        pid: libc::c_int,
        fd: libc::c_int,
        flavor: libc::c_int,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

// ---------------------------------------------------------------------------
// Public, safe API
// ---------------------------------------------------------------------------

/// Decoded view of a socket FD owned by some process.
#[derive(Debug, Clone)]
pub(super) enum SocketView {
    /// IPv4/IPv6 TCP or UDP socket.
    Inet {
        kind: InetKind,
        local: SocketAddr,
        remote: Option<SocketAddr>,
    },
    /// Unix domain socket. `path` is the bound or peer path; empty when
    /// the kernel reports an anonymous socket.
    Unix { path: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InetKind {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

/// Enumerate every live PID via `proc_listpids(PROC_ALL_PIDS)`.
pub(super) fn list_all_pids() -> Vec<libc::pid_t> {
    unsafe {
        let needed = libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
        let Some(needed_usize) = usize::try_from(needed).ok().filter(|&n| n > 0) else {
            return Vec::new();
        };
        let count_hint = needed_usize / mem::size_of::<libc::pid_t>();
        let mut pids: Vec<libc::pid_t> = vec![0; count_hint + 16];
        let buf_bytes = pids.len() * mem::size_of::<libc::pid_t>();
        let Ok(buf_bytes_i32) = libc::c_int::try_from(buf_bytes) else {
            return Vec::new();
        };
        let written = libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast::<libc::c_void>(),
            buf_bytes_i32,
        );
        let Some(written_usize) = usize::try_from(written).ok().filter(|&n| n > 0) else {
            return Vec::new();
        };
        let actual = written_usize / mem::size_of::<libc::pid_t>();
        pids.truncate(actual);
        pids
    }
}

/// Read a PID's binary path via `proc_pidpath`.
pub(super) fn pid_path(pid: libc::pid_t) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    unsafe {
        let buf_size = u32::try_from(buf.len()).ok()?;
        let len = libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<libc::c_void>(), buf_size);
        let len_usize = usize::try_from(len).ok().filter(|&n| n > 0)?;
        buf.truncate(len_usize);
    }
    String::from_utf8(buf).ok()
}

/// List a PID's socket-typed FDs.
pub(super) fn list_socket_fds(pid: libc::pid_t) -> Vec<libc::c_int> {
    if pid <= 0 {
        return Vec::new();
    }
    unsafe {
        // Sizing call.
        let needed = libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
        let Some(needed_usize) = usize::try_from(needed).ok().filter(|&n| n > 0) else {
            return Vec::new();
        };
        let count_hint = needed_usize / mem::size_of::<libc::proc_fdinfo>();
        let mut fds: Vec<libc::proc_fdinfo> = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            count_hint + 16
        ];
        let buf_bytes = fds.len() * mem::size_of::<libc::proc_fdinfo>();
        let Ok(buf_bytes_i32) = libc::c_int::try_from(buf_bytes) else {
            return Vec::new();
        };
        let written = libc::proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast::<libc::c_void>(),
            buf_bytes_i32,
        );
        let Some(written_usize) = usize::try_from(written).ok().filter(|&n| n > 0) else {
            return Vec::new();
        };
        let actual = written_usize / mem::size_of::<libc::proc_fdinfo>();
        fds.truncate(actual);
        fds.into_iter()
            .filter(|fdinfo| fdinfo.proc_fdtype == PROX_FDTYPE_SOCKET)
            .map(|fdinfo| fdinfo.proc_fd)
            .collect()
    }
}

/// Read the `socket_fdinfo` for `(pid, fd)` and decode it into a
/// `SocketView`. Returns `None` for unsupported socket kinds
/// (generic, `NDRV`, `kern_event`, `kern_ctl`, `vsock`).
pub(super) fn socket_view(pid: libc::pid_t, fd: libc::c_int) -> Option<SocketView> {
    let mut info = mem::MaybeUninit::<socket_fdinfo>::zeroed();
    let written = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            info.as_mut_ptr().cast::<libc::c_void>(),
            mem::size_of::<socket_fdinfo>() as libc::c_int,
        )
    };
    if usize::try_from(written).ok()? != mem::size_of::<socket_fdinfo>() {
        return None;
    }
    // SAFETY: proc_pidfdinfo wrote exactly `size_of::<socket_fdinfo>()`
    // bytes when the return value matched. The zeroed init ensures any
    // un-touched bytes (none, per the kernel contract) read as 0.
    let info = unsafe { info.assume_init() };
    decode(&info.psi)
}

fn decode(psi: &socket_info) -> Option<SocketView> {
    match psi.soi_kind {
        SOCKINFO_TCP => {
            let tcp = unsafe { &*std::ptr::addr_of!(psi.soi_proto).cast::<tcp_sockinfo>() };
            decode_inet(&tcp.tcpsi_ini, /* is_tcp */ true)
        }
        SOCKINFO_IN => {
            let inet = unsafe { &*std::ptr::addr_of!(psi.soi_proto).cast::<in_sockinfo>() };
            decode_inet(inet, /* is_tcp */ false)
        }
        SOCKINFO_UN => {
            let un = unsafe { &*std::ptr::addr_of!(psi.soi_proto).cast::<un_sockinfo>() };
            Some(SocketView::Unix {
                path: decode_un_path(&un.unsi_addr).or_else(|| decode_un_path(&un.unsi_caddr))?,
            })
        }
        _ => None,
    }
}

fn decode_inet(ini: &in_sockinfo, is_tcp: bool) -> Option<SocketView> {
    // `insi_fport` / `insi_lport` are stored in network byte order;
    // convert to host order so `SocketAddr` formats correctly.
    let lport = u16::from_be(ini.insi_lport as u16);
    let fport = u16::from_be(ini.insi_fport as u16);

    let is_v6 = ini.insi_vflag & INI_IPV6 != 0;
    let is_v4 = ini.insi_vflag & INI_IPV4 != 0;

    let kind = match (is_tcp, is_v6) {
        (true, false) if is_v4 => InetKind::Tcp4,
        (true, true) => InetKind::Tcp6,
        (false, false) if is_v4 => InetKind::Udp4,
        (false, true) => InetKind::Udp6,
        _ => return None,
    };

    let local = build_sockaddr(&ini.insi_laddr, lport, is_v6);
    let remote_addr = build_sockaddr(&ini.insi_faddr, fport, is_v6);
    // Foreign port == 0 with foreign addr unspecified means "not
    // connected" (listening or bound-only socket).
    let remote = if fport == 0 && is_addr_unspecified(&remote_addr) {
        None
    } else {
        Some(remote_addr)
    };

    Some(SocketView::Inet {
        kind,
        local,
        remote,
    })
}

fn build_sockaddr(addr: &in4in6_addr_union, port: u16, is_v6: bool) -> SocketAddr {
    if is_v6 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&addr.bytes);
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
    } else {
        // IPv4-in-IPv6 layout: the v4 address lives in the LAST 4 bytes
        // (offsets 12..16) per `struct in4in6_addr { u_int32_t
        // i46a_pad32[3]; struct in_addr i46a_addr4; }`.
        let v4: [u8; 4] = [
            addr.bytes[12],
            addr.bytes[13],
            addr.bytes[14],
            addr.bytes[15],
        ];
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4)), port)
    }
}

fn is_addr_unspecified(sa: &SocketAddr) -> bool {
    match sa.ip() {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

fn decode_un_path(addr: &un_addr_union) -> Option<PathBuf> {
    // The union holds either `sockaddr_un { u8 sun_len; u8 sun_family;
    // char sun_path[104]; }` or `char ua_dummy[255]`. The kernel
    // populates the sockaddr_un view when the socket is bound; sun_path
    // begins at byte offset 2 and is a NUL-terminated C string.
    const SUN_PATH_OFFSET: usize = 2;
    if addr.bytes.len() <= SUN_PATH_OFFSET {
        return None;
    }
    let tail = &addr.bytes[SUN_PATH_OFFSET..];
    let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    if nul == 0 {
        return None;
    }
    let bytes = &tail[..nul];
    let s = std::str::from_utf8(bytes).ok()?;
    Some(PathBuf::from(s))
}

/// Convenience: walk every (pid, socket-fd) pair the kernel will report.
/// Each yielded item is `(pid, fd, SocketView)`. Skips FDs that decode
/// to unsupported kinds.
pub(super) fn iter_all_sockets() -> Vec<(libc::pid_t, libc::c_int, SocketView)> {
    let mut out = Vec::new();
    for pid in list_all_pids() {
        for fd in list_socket_fds(pid) {
            if let Some(view) = socket_view(pid, fd) {
                out.push((pid, fd, view));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstr_in_un_path() {
        let mut bytes = [0u8; SOCK_MAXADDRLEN];
        bytes[0] = 16; // sun_len
        bytes[1] = libc::AF_UNIX as u8;
        let path = b"/var/run/wireguard/wg0.sock";
        bytes[2..2 + path.len()].copy_from_slice(path);
        let addr = un_addr_union { bytes };
        let decoded = decode_un_path(&addr).expect("should decode");
        assert_eq!(decoded, PathBuf::from("/var/run/wireguard/wg0.sock"));
    }

    #[test]
    fn empty_un_path_is_none() {
        let addr = un_addr_union {
            bytes: [0u8; SOCK_MAXADDRLEN],
        };
        assert!(decode_un_path(&addr).is_none());
    }

    #[test]
    fn lists_self_pid_among_all_pids() {
        let pids = list_all_pids();
        let mine = std::process::id() as libc::pid_t;
        assert!(pids.contains(&mine), "expected own pid {mine} in {pids:?}");
    }

    #[test]
    fn snapshot_returns_at_least_one_socket() {
        // Every macOS test runner has at least the launchd-managed
        // sockets plus the cargo test runner's own listeners. An empty
        // snapshot would indicate a broken FFI path.
        let snaps = iter_all_sockets();
        assert!(!snaps.is_empty(), "expected at least one socket FD");
    }
}
