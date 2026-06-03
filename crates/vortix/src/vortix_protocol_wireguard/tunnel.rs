//! `WgTunnel` — `WireGuard` impl of the `Tunnel` port.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, ProtocolStatus, Tunnel, TunnelCapabilities, TunnelError,
    TunnelHandle, TunnelKindTag, TunnelStatus,
};
use crate::vortix_core::profile::Profile;
use crate::vortix_process::{CommandSpec, PrivilegeReq};
use tracing::info;
// `warn!` is only used by the macOS-only diagnostic at line ~227.
// Gate the import so Linux clippy doesn't flag it as unused.
#[cfg(target_os = "macos")] // xtask:allow-platform-cfg: import for macOS-only warn! call
use tracing::warn;

use crate::vortix_protocol_wireguard::parser::parse_wg_conf;

/// `wg-quick`-based `WireGuard` tunnel.
///
/// Plan #004 v1 supports kernel `WireGuard` only — `wireguard-go`/`boringtun`
/// user-space backends land with idea 5's daemon work.
///
/// `is_secondary` (default `false`) routes connect-time through the DNS-
/// scoping path (plan #009 U13): the user's `.conf` is rewritten with
/// `DNS = …` lines stripped, written under
/// `${config_dir}/tmp/${session_id}/${basename}` at mode `0o600`, and
/// `wg-quick up` is invoked against the rewritten copy. Primaries keep the
/// existing fast path (no copy, original config used directly).
///
/// The `TunnelRegistry` (plan #009 U5) flips `is_secondary` via
/// [`WgTunnel::with_secondary`] before calling `up()` once multi-connection
/// wiring lands; until then no production callsite sets it and behaviour is
/// identical to v0.3.x.
#[derive(Debug, Default, Clone)]
pub struct WgTunnel {
    /// True when this tunnel is a secondary in a multi-tunnel session. When
    /// set, `up()` strips `DNS =` lines from the user's profile before
    /// invoking `wg-quick up` — only the primary may own system DNS.
    pub is_secondary: bool,
    /// Path to the temp config written at `up()` time when `is_secondary` is
    /// true. Stored so `down()` can unlink it and (if empty) its parent
    /// session subdir. `None` for primaries and before `up()` succeeds.
    temp_config_path: Option<PathBuf>,
}

impl WgTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: mark this tunnel as a secondary in a multi-tunnel session
    /// (plan #009 U13). When `true`, `up()` reads the user's `.conf`, strips
    /// any `DNS = …` directive, and writes the result to a per-session temp
    /// path at mode `0o600`; `wg-quick up` runs against that temp path. The
    /// temp file's basename matches the original so wg-quick's
    /// interface-from-basename derivation — and any `%i` substitution in
    /// `PostUp`/`PreDown` hooks — stays equivalent to the user's original
    /// profile.
    ///
    /// Defaults to `false`. No production callsite flips this until the
    /// registry's primary-aware connect path lands.
    #[must_use]
    pub fn with_secondary(mut self, is_secondary: bool) -> Self {
        self.is_secondary = is_secondary;
        self
    }

    #[must_use]
    pub fn is_secondary(&self) -> bool {
        self.is_secondary
    }
}

/// Strip `DNS = …` lines from a `WireGuard` `.conf` body.
///
/// Wrapper around [`strip_and_capture_dns_directive`] kept for the
/// equivalence-test surface — production callers go through the capture-
/// aware function directly so they can pass the IP list to resolvectl
/// (see `WgTunnel::up`).
#[cfg(test)]
#[must_use]
pub(crate) fn strip_dns_directive(text: &str) -> String {
    strip_and_capture_dns_directive(text).0
}

/// Strip `DNS = …` lines AND return the captured DNS server IPs.
///
/// Same stripping behaviour as [`strip_dns_directive`]: case-insensitive
/// directive match, non-directive lines preserved verbatim. The captured
/// list contains valid IP addresses (IPv4 + IPv6) in source order across
/// every `DNS =` line. Non-IP entries on the RHS (wg-quick treats those as
/// DNS search domains) are skipped — the caller is interested in resolver
/// targets, not search suffixes. Trailing `#` and `;` comments on the
/// directive line are stripped before parsing.
#[must_use]
pub(crate) fn strip_and_capture_dns_directive(text: &str) -> (String, Vec<String>) {
    use std::net::IpAddr;
    use std::str::FromStr;

    let mut out = String::with_capacity(text.len());
    let mut ips: Vec<String> = Vec::new();
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        // Match "DNS" (case-insensitive) followed (after optional
        // whitespace) by '='. Anything else starting with "dns" (e.g. a
        // comment that mentions DNS, or a `dns_search = …` directive) is
        // kept verbatim.
        let after_dns = trimmed
            .strip_prefix(|c: char| c == 'D' || c == 'd')
            .and_then(|r| r.strip_prefix(|c: char| c == 'N' || c == 'n'))
            .and_then(|r| r.strip_prefix(|c: char| c == 'S' || c == 's'));
        let value_after_eq = after_dns.and_then(|r| {
            let r = r.trim_start();
            r.strip_prefix('=')
        });

        match value_after_eq {
            Some(rhs) => {
                // RHS may carry a trailing comment; strip everything from
                // the first `#` or `;` onwards before splitting on commas.
                let rhs_no_comment = rhs.split(['#', ';']).next().unwrap_or("");
                for entry in rhs_no_comment.split(',') {
                    let token = entry.trim();
                    if token.is_empty() {
                        continue;
                    }
                    if IpAddr::from_str(token).is_ok() {
                        ips.push(token.to_string());
                    }
                    // Non-IP tokens are wg-quick DNS search domains; skip.
                }
                // Directive line itself is dropped from `out`.
            }
            None => {
                out.push_str(line);
            }
        }
    }
    (out, ips)
}

/// Resolve the current `session_id` from the global journal, or fall back to
/// a pid-derived stable value when the journal is disabled (tests, or
/// `[journal] disk = false`). The fallback is deterministic within a process
/// so repeated calls within one run yield the same subdir.
fn resolve_session_id() -> String {
    crate::vortix_core::journal::global_journal()
        .and_then(crate::vortix_core::journal::Journal::session_id)
        .unwrap_or_else(|| format!("nojournal-{}", std::process::id()))
}

/// Inner helper: write the sanitized body to `${session_dir}/${basename}` at
/// mode `0o600`. The basename is preserved verbatim so wg-quick's
/// `interface = basename(filename)` derivation produces the same interface
/// name as the user's original profile (relevant for `%i` substitution in
/// `PostUp`/`PreDown` hooks).
///
/// If a stale leaf with the same basename exists in the session subdir (very
/// fast disconnect-reconnect within one session), it is unlinked first —
/// `write_secret_file` refuses to overwrite.
///
/// Separated from [`write_secondary_temp_config`] so tests can exercise the
/// file-writing logic against a per-test tempdir without depending on the
/// process-global `config_dir` set by `set_config_dir` (a `OnceLock` shared
/// across the test binary).
fn write_secondary_temp_config_at(
    session_dir: &Path,
    user_conf_path: &Path,
    stripped_body: &[u8],
) -> Result<PathBuf, TunnelError> {
    use crate::vortix_core::secret_file::{write_secret_file, SecretFileError};

    let basename = user_conf_path
        .file_name()
        .ok_or_else(|| TunnelError::Subprocess("WG config has no basename".into()))?;

    let temp_path = session_dir.join(basename);

    // Best-effort unlink of any stale leaf from a same-session reconnect.
    // Ignore all errors — NotFound is the happy path and any other error is
    // surfaced by the subsequent write_secret_file attempt.
    let _ = std::fs::remove_file(&temp_path);

    write_secret_file(&temp_path, stripped_body).map_err(|e| match e {
        SecretFileError::Io(io) => {
            TunnelError::Subprocess(format!("write secondary WG temp config: {io}"))
        }
        other => TunnelError::Subprocess(format!("write secondary WG temp config: {other}")),
    })?;

    Ok(temp_path)
}

/// Public wrapper used by `up()`: resolves the per-session tmp dir from the
/// global journal `session_id`, then delegates to
/// [`write_secondary_temp_config_at`].
fn write_secondary_temp_config(
    user_conf_path: &Path,
    stripped_body: &[u8],
) -> Result<PathBuf, TunnelError> {
    let session_id = resolve_session_id();
    let session_dir = crate::utils::get_tmp_config_dir(&session_id).map_err(|e| {
        TunnelError::Subprocess(format!("failed to create per-session tmp dir: {e}"))
    })?;
    write_secondary_temp_config_at(&session_dir, user_conf_path, stripped_body)
}

/// Remove the per-session temp file written by [`write_secondary_temp_config`]
/// and, if the per-session subdir is now empty, remove that too. Errors are
/// swallowed: at disconnect time the tunnel is already down, so a residual
/// temp file is harmless and the startup sweep will collect it on the next
/// run.
fn cleanup_secondary_temp_config(temp_path: &Path) {
    let _ = std::fs::remove_file(temp_path);
    if let Some(parent) = temp_path.parent() {
        // `remove_dir` only succeeds when the dir is empty — exactly the
        // condition we want. Other secondaries in the same session keep
        // their own leaf and the dir survives.
        let _ = std::fs::remove_dir(parent);
    }
}

/// Minimal `WireGuard` status — extended once the binary-side scanner moves
/// into this crate (deferred to plan #005).
#[derive(Debug, Default)]
pub struct WgStatus {
    pub interface_name: String,
}

impl ProtocolStatus for WgStatus {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Decide the kernel-visible interface name for a `WireGuard` tunnel
/// based on the config basename and the platform port's
/// `resolve_wireguard_interface` result.
///
/// Platform behaviour:
/// - **Linux / BSD**: `wg-quick` names the kernel interface after the
///   config basename (the file passed to `wg-quick up`). The platform
///   port's `resolve_wireguard_interface` returns `None`, and the
///   basename is the correct value to store.
/// - **macOS**: `wg-quick` creates a `utunN` kernel device via
///   wireguard-go and writes the config-basename → `utunN` mapping to
///   `/var/run/wireguard/<basename>.name`. The platform port returns
///   `Some("utun7")` (or similar). The registry needs `utun7` stored
///   to match `route -n get`'s output.
///
/// Falling back to the basename when the port returns `None` is the
/// correct behaviour on Linux. On macOS, reaching the fallback path
/// post-`wg-quick up` indicates the `.name` file is missing — an
/// anomalous wg-quick install / permission state worth logging.
///
/// `profile_id` is plumbed through purely so the macOS-side warning
/// can attribute the anomaly to a profile.
fn resolve_kernel_iface(
    basename: &str,
    port_result: Option<String>,
    profile_id: &crate::vortix_core::profile::ProfileId,
) -> String {
    if let Some(iface) = port_result {
        return iface;
    }
    #[cfg(target_os = "macos")] // xtask:allow-platform-cfg: warn-only diagnostic for an anomalous wg-quick state on macOS
    warn!(
        target: "vortix::tunnel::wireguard",
        profile = %profile_id,
        basename = %basename,
        "wg.up: resolve_wireguard_interface returned None on macOS; falling back to basename. \
         Expected /var/run/wireguard/<basename>.name to exist post-`wg-quick up` — check wg-quick install / permissions."
    );
    let _ = profile_id;
    basename.to_string()
}

fn interface_from_path(path: &std::path::Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wg0")
        .to_string()
}

/// Decide whether `WgTunnel::up()` should strip the `DNS = …` line before
/// invoking `wg-quick up`.
///
/// Two reasons to strip:
/// 1. Secondary tunnels (multi-tunnel guarantee: only the primary owns
///    system DNS — wg-quick is not given DNS for secondaries).
/// 2. Linux hosts on the resolvectl path: vortix takes over per-link DNS
///    via `resolvectl` itself, so wg-quick must not attempt to call its
///    own `resolvconf` shim.
#[must_use]
pub(crate) fn should_strip_dns(is_secondary: bool) -> bool {
    if is_secondary {
        return true;
    }
    #[cfg(target_os = "linux")]
    // xtask:allow-platform-cfg: resolvectl-path strip predicate is Linux-only
    {
        crate::utils::use_resolvectl_path()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

impl Tunnel for WgTunnel {
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        // Strip the user's `DNS = …` line and run wg-quick against a
        // sanitized copy when:
        //   - this tunnel is a secondary in a multi-tunnel session, OR
        //   - we're on Linux + systemd-resolved + resolvectl works (the
        //     resolvectl path takes ownership of per-link DNS after up).
        //
        // The temp file's basename is preserved so wg-quick's interface
        // name derivation — and any `%i` substitution in PostUp/PreDown
        // hooks — stays equivalent to the user's original profile.
        let strip_dns = should_strip_dns(self.is_secondary);
        let (effective_path, temp_path, captured_dns_ips): (PathBuf, Option<PathBuf>, Vec<String>) =
            if strip_dns {
                let user_body = std::fs::read_to_string(&profile.config_path).map_err(|e| {
                    TunnelError::Subprocess(format!(
                        "read WG config {}: {e}",
                        profile.config_path.display()
                    ))
                })?;
                let (stripped, ips) = strip_and_capture_dns_directive(&user_body);
                let temp = write_secondary_temp_config(&profile.config_path, stripped.as_bytes())?;
                (temp.clone(), Some(temp), ips)
            } else {
                (profile.config_path.clone(), None, Vec::new())
            };

        let path_str = effective_path.to_string_lossy().into_owned();
        info!(
            target: "vortix::tunnel::wireguard",
            profile = %profile.id,
            config = %path_str,
            secondary = self.is_secondary,
            "wg.up"
        );

        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot("wg-quick", vec!["up".into(), path_str.clone()])
                .privilege(PrivilegeReq::Root),
        )
        .map_err(|e| {
            // Subprocess invocation itself failed (not just non-zero exit).
            // Clean up the temp file we wrote — the tunnel never came up so
            // nobody else holds a reference to it.
            if let Some(p) = &temp_path {
                cleanup_secondary_temp_config(p);
            }
            TunnelError::Subprocess(format!("wg-quick up: {e}"))
        })?;

        if !output.status.success() {
            if let Some(p) = &temp_path {
                cleanup_secondary_temp_config(p);
            }
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(TunnelError::HandshakeFailed(format!("WireGuard: {stderr}")));
        }

        // Stash the temp path on `self` so `down()` can unlink it. The
        // interface name is still derived from the basename, which equals
        // the temp file's basename (preserved by design).
        self.temp_config_path = temp_path;

        let basename = interface_from_path(&effective_path);
        let interface_name = resolve_kernel_iface(
            &basename,
            crate::platform::current_platform()
                .interface
                .resolve_wireguard_interface(&basename),
            &profile.id,
        );

        // On the resolvectl path with captured DNS servers, register
        // per-link DNS via systemd-resolved now that wg-quick has brought
        // the kernel interface up. Fail-open: on error the tunnel still
        // works (packets flow, routes are installed) and the user's host
        // resolver answers queries — log the failure and proceed.
        #[cfg(target_os = "linux")]
        // xtask:allow-platform-cfg: resolvectl set_link_dns is Linux-only
        if !captured_dns_ips.is_empty() && crate::utils::use_resolvectl_path() {
            let authoritative = !self.is_secondary;
            if let Err(e) = crate::vortix_platform_linux::dns::set_link_dns(
                &interface_name,
                &captured_dns_ips,
                authoritative,
            ) {
                tracing::warn!(
                    target: "vortix::tunnel::wireguard",
                    profile = %profile.id,
                    interface = %interface_name,
                    err = %e,
                    "resolvectl set_link_dns failed; tunnel is up but DNS not registered via resolved"
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = captured_dns_ips;

        Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            interface_name,
            pid: None,
            started_at: SystemTime::now(),
            kind: TunnelKindTag::WireGuard,
        })
    }

    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        info!(
            target: "vortix::tunnel::wireguard",
            profile = %handle.profile_id,
            interface = %handle.interface_name,
            secondary = self.is_secondary,
            "wg.down"
        );

        // Pass the interface name; `wg-quick down <iface>` looks up the
        // config in the standard locations. (The engine's previous code
        // passed the full path here too — both forms work; the iface name
        // is shorter and matches the handle.)
        let output = crate::vortix_process::run_to_output(
            CommandSpec::oneshot(
                "wg-quick",
                vec!["down".into(), handle.interface_name.clone()],
            )
            .privilege(PrivilegeReq::Root),
        );

        // Always attempt to unlink the temp file, even when `wg-quick down`
        // errors — leaving it behind would still be collected by the next
        // startup sweep, but eager cleanup keeps the dir tidy. `take()`
        // ensures we don't double-unlink across a retry.
        let temp_to_remove = self.temp_config_path.take();

        let output = output.map_err(|e| TunnelError::Subprocess(format!("wg-quick down: {e}")))?;

        if !output.status.success() {
            if let Some(p) = &temp_to_remove {
                cleanup_secondary_temp_config(p);
            }
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(TunnelError::Subprocess(format!("WireGuard down: {stderr}")));
        }

        if let Some(p) = &temp_to_remove {
            cleanup_secondary_temp_config(p);
        }

        Ok(())
    }

    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        // Minimal status today — the engine still uses the binary-side
        // scanner for richer wg-show parsing until plan #005 relocates it.
        Ok(TunnelStatus {
            handle: handle.clone(),
            bytes_rx: 0,
            bytes_tx: 0,
            last_handshake: None,
            observed_at: SystemTime::now(),
            detail: Box::new(WgStatus {
                interface_name: handle.interface_name.clone(),
            }),
        })
    }

    fn parse_profile(&self, raw: &[u8]) -> Result<Box<dyn ParsedProfile>, ParseError> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| ParseError::Encoding(format!("WireGuard .conf must be UTF-8: {e}")))?;
        let parsed = parse_wg_conf(text)?;
        Ok(Box::new(parsed))
    }

    fn capabilities(&self) -> TunnelCapabilities {
        TunnelCapabilities {
            supports_split_tunnel: false,
            supports_ipv6: true,
            mtu_configurable: true,
            supports_reconnect_without_disconnect: true,
            requires_root: true,
            userspace: false,
        }
    }

    fn kind_tag(&self) -> TunnelKindTag {
        TunnelKindTag::WireGuard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_match_kernel_wireguard() {
        let caps = WgTunnel::new().capabilities();
        assert!(caps.requires_root);
        assert!(caps.supports_ipv6);
        assert!(!caps.userspace);
    }

    #[test]
    fn interface_from_path_uses_stem() {
        let p = std::path::PathBuf::from("/etc/wireguard/corp.conf");
        assert_eq!(interface_from_path(&p), "corp");
    }

    // --- U2: resolve_kernel_iface contract ---

    #[test]
    fn resolve_kernel_iface_uses_port_result_when_present() {
        // macOS-shape: platform port returns the underlying utun device.
        // This is the value the registry must store to match `route get`'s
        // output byte-for-byte.
        let profile_id = crate::vortix_core::profile::ProfileId::new("corp");
        let resolved = resolve_kernel_iface("corp", Some("utun7".to_string()), &profile_id);
        assert_eq!(resolved, "utun7");
    }

    #[test]
    fn resolve_kernel_iface_falls_back_to_basename_when_port_returns_none() {
        // Linux-shape: platform port returns None because the kernel
        // device name IS the config basename. The fallback is the
        // correct value to store.
        let profile_id = crate::vortix_core::profile::ProfileId::new("corp");
        let resolved = resolve_kernel_iface("corp", None, &profile_id);
        assert_eq!(resolved, "corp");
    }

    #[test]
    fn resolve_kernel_iface_preserves_port_result_even_when_equal_to_basename() {
        // Edge: Mock variant returns `Some(name)` for `wg_present=true`
        // (the legacy default before U2 added the override). This MUST
        // be preserved verbatim — the helper has no business stripping
        // the port's answer just because it happens to equal the
        // basename.
        let profile_id = crate::vortix_core::profile::ProfileId::new("corp");
        let resolved = resolve_kernel_iface("corp", Some("corp".to_string()), &profile_id);
        assert_eq!(resolved, "corp");
    }

    // --- U13: DNS scoping for secondaries ---

    #[test]
    fn default_is_not_secondary() {
        let t = WgTunnel::new();
        assert!(!t.is_secondary());
        assert!(t.temp_config_path.is_none());
    }

    #[test]
    fn with_secondary_builder_flips_flag() {
        let t = WgTunnel::new().with_secondary(true);
        assert!(t.is_secondary());
    }

    #[test]
    fn strip_dns_removes_directive_with_equals() {
        let body = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = xyz\n";
        let out = strip_dns_directive(body);
        assert!(!out.contains("DNS"));
        assert!(out.contains("PrivateKey = abc"));
        assert!(out.contains("MTU = 1420"));
        assert!(out.contains("[Peer]"));
    }

    #[test]
    fn strip_dns_is_case_insensitive() {
        let body =
            "[Interface]\nPrivateKey = abc\ndns = 8.8.8.8\nDns=4.4.4.4\nAddress = 10.0.0.2/24\n";
        let out = strip_dns_directive(body);
        assert!(!out.to_lowercase().contains("dns ="));
        assert!(!out.to_lowercase().contains("dns="));
        assert!(out.contains("Address = 10.0.0.2/24"));
    }

    #[test]
    fn strip_dns_tolerates_leading_whitespace() {
        let body = "[Interface]\n  DNS  =  1.1.1.1, 8.8.8.8\nAddress = 10.0.0.2/24\n";
        let out = strip_dns_directive(body);
        assert!(!out.contains("1.1.1.1"));
        assert!(out.contains("Address = 10.0.0.2/24"));
    }

    #[test]
    fn strip_dns_preserves_non_directive_lines_starting_with_dns() {
        // A comment that *mentions* DNS but doesn't have "DNS = ..." must
        // survive — wg-quick only treats "DNS =" as the directive.
        let body = "[Interface]\n# Custom DNS overrides below\nPrivateKey = abc\n";
        let out = strip_dns_directive(body);
        assert!(out.contains("# Custom DNS overrides below"));
        assert!(out.contains("PrivateKey = abc"));
    }

    #[test]
    fn strip_dns_no_op_when_directive_absent() {
        let body =
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n\n[Peer]\nPublicKey = xyz\n";
        assert_eq!(strip_dns_directive(body), body);
    }

    // ── strip_and_capture_dns_directive ──────────────────────────────────

    #[test]
    fn capture_dns_empty_input() {
        let (out, ips) = strip_and_capture_dns_directive("");
        assert_eq!(out, "");
        assert!(ips.is_empty());
    }

    #[test]
    fn capture_dns_no_directive_returns_input_verbatim() {
        let body = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n";
        let (out, ips) = strip_and_capture_dns_directive(body);
        assert_eq!(out, body);
        assert!(ips.is_empty());
    }

    #[test]
    fn capture_dns_single_ip() {
        let body = "[Interface]\nPrivateKey = abc\nDNS = 1.1.1.1\n";
        let (out, ips) = strip_and_capture_dns_directive(body);
        assert!(!out.contains("DNS"));
        assert_eq!(ips, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn capture_dns_comma_separated() {
        let body = "[Interface]\nDNS = 1.1.1.1, 8.8.8.8\nAddress = 10.0.0.2/24\n";
        let (_out, ips) = strip_and_capture_dns_directive(body);
        assert_eq!(ips, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn capture_dns_multiple_directive_lines_preserve_order() {
        // A .conf may legally split DNS across multiple lines; capture
        // every IP in source order.
        let body = "[Interface]\nDNS = 1.1.1.1\nAddress = 10.0.0.2/24\nDNS = 8.8.8.8\n";
        let (out, ips) = strip_and_capture_dns_directive(body);
        assert!(!out.contains("DNS"));
        assert_eq!(ips, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn capture_dns_case_insensitive() {
        // The directive name is case-insensitive (wg-quick keys are).
        // Each capital/lowercase variant captures identically.
        for variant in ["DNS = 1.1.1.1", "dns = 1.1.1.1", "Dns = 1.1.1.1"] {
            let body = format!("[Interface]\n{variant}\nAddress = 10.0.0.2/24\n");
            let (_out, ips) = strip_and_capture_dns_directive(&body);
            assert_eq!(
                ips,
                vec!["1.1.1.1".to_string()],
                "variant `{variant}` did not capture"
            );
        }
    }

    #[test]
    fn capture_dns_whitespace_variation_around_equals() {
        // wg-quick accepts the directive with arbitrary whitespace around
        // `=`; the capture path must mirror that tolerance.
        for variant in ["DNS=1.1.1.1", "DNS =1.1.1.1", "DNS  =  1.1.1.1"] {
            let body = format!("[Interface]\n{variant}\nAddress = 10.0.0.2/24\n");
            let (_out, ips) = strip_and_capture_dns_directive(&body);
            assert_eq!(
                ips,
                vec!["1.1.1.1".to_string()],
                "variant `{variant}` did not capture"
            );
        }
    }

    #[test]
    fn capture_dns_ipv6() {
        let body = "[Interface]\nDNS = 2001:db8::1\n";
        let (_out, ips) = strip_and_capture_dns_directive(body);
        assert_eq!(ips, vec!["2001:db8::1".to_string()]);
    }

    #[test]
    fn capture_dns_mixed_ipv4_ipv6() {
        let body = "[Interface]\nDNS = 1.1.1.1, 2001:db8::1\n";
        let (_out, ips) = strip_and_capture_dns_directive(body);
        assert_eq!(ips, vec!["1.1.1.1".to_string(), "2001:db8::1".to_string()]);
    }

    #[test]
    fn capture_dns_strips_trailing_hash_comment() {
        let body = "[Interface]\nDNS = 1.1.1.1  # corp resolver\n";
        let (_out, ips) = strip_and_capture_dns_directive(body);
        assert_eq!(ips, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn capture_dns_strips_trailing_semicolon_comment() {
        let body = "[Interface]\nDNS = 1.1.1.1 ; corp resolver\n";
        let (_out, ips) = strip_and_capture_dns_directive(body);
        assert_eq!(ips, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn capture_dns_search_domains_dropped() {
        // wg-quick treats non-IP tokens on the RHS as DNS search suffixes.
        // resolvectl wants IPs, not suffixes, so non-IP tokens are dropped
        // from the captured list while the directive line is still stripped.
        let body = "[Interface]\nDNS = 1.1.1.1, corp.example.com\n";
        let (out, ips) = strip_and_capture_dns_directive(body);
        assert!(!out.contains("DNS"));
        assert_eq!(ips, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn capture_dns_search_directive_is_not_dns() {
        // `dns_search = …` looks DNS-ish but is not the wg-quick `DNS`
        // directive; both the line and any IPs on it must be left alone.
        let body = "[Interface]\ndns_search = corp.example.com\nPrivateKey = abc\n";
        let (out, ips) = strip_and_capture_dns_directive(body);
        assert!(out.contains("dns_search = corp.example.com"));
        assert!(ips.is_empty());
    }

    #[test]
    fn capture_dns_leading_whitespace_on_directive() {
        let body = "[Interface]\n  DNS = 1.1.1.1\n";
        let (out, ips) = strip_and_capture_dns_directive(body);
        assert!(!out.contains("DNS"));
        assert_eq!(ips, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn capture_dns_strip_path_is_byte_identical_to_legacy_helper() {
        // Equivalence guard: anything the wrapper `strip_dns_directive`
        // returned for a given input, the capture-aware function must
        // return identically in its first tuple element. Prevents
        // accidental drift between the two paths.
        let bodies = [
            "",
            "[Interface]\nPrivateKey = abc\n",
            "[Interface]\nDNS = 1.1.1.1\nAddress = 10.0.0.2/24\n",
            "[Interface]\n  DNS  =  1.1.1.1, 8.8.8.8  # corp\n",
            "[Interface]\ndns = 8.8.8.8\nDns=4.4.4.4\n",
            "[Interface]\n# Custom DNS overrides below\nPrivateKey = abc\n",
        ];
        for body in bodies {
            let legacy = strip_dns_directive(body);
            let (capture, _ips) = strip_and_capture_dns_directive(body);
            assert_eq!(legacy, capture, "drift for input `{body}`");
        }
    }

    /// Per-test isolation: build a fresh session-style subdir at mode `0o700`
    /// under a tempdir. Avoids touching the process-global `config_dir`
    /// (`OnceLock` → first-write-wins → races across tests when set in each).
    #[cfg(unix)]
    fn fresh_session_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::DirBuilderExt;

        let root = tempfile::Builder::new()
            .prefix("vortix_wg_tunnel_test_")
            .tempdir()
            .unwrap();
        let session = root.path().join("tmp").join("sid-test");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&session)
            .unwrap();
        (root, session)
    }

    #[cfg(not(unix))]
    fn fresh_session_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::Builder::new()
            .prefix("vortix_wg_tunnel_test_")
            .tempdir()
            .unwrap();
        let session = root.path().join("tmp").join("sid-test");
        std::fs::create_dir_all(&session).unwrap();
        (root, session)
    }

    #[cfg(unix)]
    #[test]
    fn fresh_session_dir_is_0700() {
        // Sanity-check the test fixture mirrors the production permission
        // contract (so the "verify 0o700" property below isn't tautological
        // against a 0o755 default umask).
        use std::os::unix::fs::PermissionsExt;
        let (_root, session) = fresh_session_dir();
        let perms = std::fs::metadata(&session).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);
    }

    #[test]
    fn write_secondary_temp_config_strips_dns_and_preserves_basename() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("corp.conf");
        std::fs::write(
            &user_conf,
            "[Interface]\nPrivateKey = SECRET\nAddress = 10.0.0.2/24\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = PUBKEY\n",
        )
        .unwrap();
        let body = std::fs::read_to_string(&user_conf).unwrap();
        let stripped = strip_dns_directive(&body);

        let temp =
            write_secondary_temp_config_at(&session, &user_conf, stripped.as_bytes()).unwrap();
        // Basename matches the original — wg-quick will derive interface
        // "corp" from this path, identical to the user's original.
        assert_eq!(temp.file_name().unwrap(), "corp.conf");

        let written = std::fs::read_to_string(&temp).unwrap();
        assert!(!written.contains("DNS"));
        assert!(written.contains("PrivateKey = SECRET"));
        assert!(written.contains("[Peer]"));
    }

    #[cfg(unix)]
    #[test]
    fn secondary_temp_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("wg0.conf");
        std::fs::write(
            &user_conf,
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n",
        )
        .unwrap();

        let temp = write_secondary_temp_config_at(
            &session,
            &user_conf,
            b"[Interface]\nPrivateKey = abc\n",
        )
        .unwrap();
        let perms = std::fs::metadata(&temp).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn write_secondary_overwrites_stale_same_session_leaf() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("vpn.conf");
        std::fs::write(&user_conf, "[Interface]\nPrivateKey = a\n").unwrap();

        // First write — leaf does not exist yet.
        let t1 = write_secondary_temp_config_at(&session, &user_conf, b"first").unwrap();
        // Second write within same session — stale leaf is unlinked first
        // (write_secret_file would otherwise refuse with FileExists).
        let t2 = write_secondary_temp_config_at(&session, &user_conf, b"second").unwrap();
        assert_eq!(t1, t2);
        assert_eq!(std::fs::read_to_string(&t2).unwrap(), "second");
    }

    #[test]
    fn cleanup_removes_leaf_and_empty_session_dir() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("only.conf");
        std::fs::write(&user_conf, "[Interface]\nPrivateKey = a\n").unwrap();

        let temp = write_secondary_temp_config_at(&session, &user_conf, b"body").unwrap();
        assert!(temp.exists());
        assert!(session.exists());

        cleanup_secondary_temp_config(&temp);
        assert!(!temp.exists());
        assert!(!session.exists(), "empty session dir should be removed");
    }

    #[test]
    fn cleanup_keeps_session_dir_when_other_leaves_remain() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let conf_a = scratch.path().join("a.conf");
        let conf_b = scratch.path().join("b.conf");
        std::fs::write(&conf_a, "x").unwrap();
        std::fs::write(&conf_b, "y").unwrap();

        let temp_a = write_secondary_temp_config_at(&session, &conf_a, b"a-body").unwrap();
        let temp_b = write_secondary_temp_config_at(&session, &conf_b, b"b-body").unwrap();
        assert_eq!(session, temp_a.parent().unwrap());
        assert_eq!(session, temp_b.parent().unwrap());

        cleanup_secondary_temp_config(&temp_a);
        assert!(!temp_a.exists());
        assert!(temp_b.exists(), "sibling secondary's leaf must survive");
        assert!(session.exists(), "session dir must survive while non-empty");

        cleanup_secondary_temp_config(&temp_b);
        assert!(!session.exists());
    }

    /// Mirror of the production helper at
    /// `crates/vortix/src/main.rs::sweep_orphan_temp_configs` so we can
    /// exercise it without invoking `main()`.
    fn sweep_orphan_temp_configs(config_dir: &std::path::Path, current_session_id: &str) {
        let tmp_dir = config_dir.join(crate::constants::TMP_CONFIG_DIR);
        if !tmp_dir.exists() {
            return;
        }
        let Ok(entries) = std::fs::read_dir(&tmp_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name == current_session_id {
                continue;
            }
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }

    #[test]
    fn sweep_removes_prior_session_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path();
        let prior = config_dir.join("tmp").join("2025-01-01T000000Z-9999");
        let current = config_dir.join("tmp").join("2026-05-28T120000Z-1234");
        std::fs::create_dir_all(&prior).unwrap();
        std::fs::create_dir_all(&current).unwrap();
        std::fs::write(prior.join("corp.conf"), "stale").unwrap();
        std::fs::write(current.join("vpn.conf"), "live").unwrap();

        sweep_orphan_temp_configs(config_dir, "2026-05-28T120000Z-1234");

        assert!(!prior.exists(), "orphan session subdir must be removed");
        assert!(current.exists(), "current session subdir must survive");
        assert!(current.join("vpn.conf").exists());
    }

    #[test]
    fn sweep_is_noop_when_tmp_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        // No tmp/ created. Sweep must not panic and must not create anything.
        sweep_orphan_temp_configs(tmp.path(), "sid");
        assert!(!tmp.path().join("tmp").exists());
    }

    #[test]
    fn primary_skips_dns_stripping_at_struct_level() {
        // We can't safely call `up()` here without owning the process-global
        // runner, but the structural invariant is observable directly: a
        // primary's `is_secondary` is false and its `temp_config_path`
        // starts unset. The `up()` body's strip predicate is the single
        // source of truth for the temp-file path; see `should_strip_dns`
        // tests below for the resolved-host coverage.
        let t = WgTunnel::new();
        assert!(!t.is_secondary());
        assert!(t.temp_config_path.is_none());
    }

    // ── should_strip_dns ─────────────────────────────────────────────────

    #[test]
    fn should_strip_dns_secondary_always_true() {
        // Independent of platform / resolvectl detection — secondaries
        // always strip so the multi-tunnel "primary owns system DNS"
        // contract holds regardless of which Linux DNS path is active.
        assert!(should_strip_dns(true));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn should_strip_dns_primary_on_non_linux_is_false() {
        // macOS / Windows: no resolvectl path; primary never strips
        // (matches the legacy behaviour on those platforms).
        assert!(!should_strip_dns(false));
    }

    // Linux primary behaviour depends on `use_resolvectl_path()` which
    // probes systemd-resolved + resolvectl at runtime. That probe is
    // host-state-dependent and not unit-testable from inside the crate
    // (the global runner is mock-default-success, but `is_systemd_resolved`
    // reads /etc/resolv.conf directly). Linux CI lanes + the manual-
    // testing rows in `docs/manual-testing/backlog.md` cover the
    // resolved-host integration matrix.
}
