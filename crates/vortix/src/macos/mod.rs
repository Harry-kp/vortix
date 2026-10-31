//! macOS adapters:
//! - firewall via pf (`pfctl`).
//! - DNS via `SCDynamicStore`.
//! - interfaces via `libc::getifaddrs` + libproc FFI.
//! - byte counters via `libc::getifaddrs` + BSD `if_data`.
//! - routes via `route get default`.
//! - socket audit via hand-rolled libproc FFI.

#![allow(clippy::missing_errors_doc)]

pub mod autoconnect;
pub mod dns;
pub mod firewall;
pub mod interface;
mod libproc;
pub mod route_table;

pub use dns::MacDns;
pub use firewall::PfFirewall;
pub use interface::MacInterface;
pub use interface::MacNetworkStats;
pub use libproc::LsofSocketAudit;
pub use route_table::MacRouteTable;

/// Report line for this OS, e.g. `macOS 14.5 (Darwin 23.5.0)`.
#[must_use]
pub fn os_description() -> String {
    let version = macos_product_version().unwrap_or_default();
    let kernel = crate::platform::uname_release().unwrap_or_default();
    if version.is_empty() {
        format!("macOS (Darwin {kernel})")
    } else {
        format!("macOS {version} (Darwin {kernel})")
    }
}

/// A setting the organization's device management pins for an app; keys
/// match in any case, as the apps read them.
#[must_use]
pub fn managed_setting(domain: &str, key: &str) -> Option<String> {
    let file = format!("/Library/Managed Preferences/{domain}.plist");
    let outcome = crate::process::simple_output("plutil", &["-convert", "json", "-o", "-", &file])?;
    let settings: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&outcome.stdout_lossy()).ok()?;
    settings
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .and_then(|(_, value)| value.as_str())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The kill-switch firewall tool and its version flag (none for `pfctl`).
pub const FIREWALL_TOOL: (&str, &[&str]) = ("pfctl", &[]);

/// Clipboard writers to try, in order.
#[must_use]
pub fn clipboard_commands() -> Vec<&'static str> {
    vec!["pbcopy"]
}

/// Read `kern.osproductversion` via `sysctlbyname` — equivalent to
/// `sw_vers -productVersion` on macOS (returns e.g. "14.5", "13.7.1").
///
fn macos_product_version() -> Option<String> {
    use std::ffi::CString;
    let key = CString::new("kern.osproductversion").ok()?;
    // Preallocate enough buffer for any plausible version string.
    // macOS product versions are at most "X.Y.Z" with single-digit
    // components today; 64 bytes is comfortable headroom.
    let mut buf = vec![0u8; 64];
    let mut len = buf.len();

    // SAFETY: `sysctlbyname(name, oldp, oldlenp, newp, newlen)`. We
    // pass: name = CString-owned C-string; oldp = buf.as_mut_ptr() cast
    // to *mut c_void; oldlenp = &mut len; newp = null (not setting);
    // newlen = 0. The kernel writes at most `len` bytes into buf and
    // updates len with the actual byte count written.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    // `len` now holds the number of bytes written (including the
    // trailing NUL). Trim to len-1 to drop the NUL before UTF-8 decode.
    let written = len.saturating_sub(1);
    buf.truncate(written);
    String::from_utf8(buf).ok()
}
