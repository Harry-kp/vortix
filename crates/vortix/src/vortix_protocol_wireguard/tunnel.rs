//! `WgTunnel` — `WireGuard` impl of the `Tunnel` port.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, ProtocolStatus, Tunnel, TunnelCapabilities, TunnelError,
    TunnelHandle, TunnelKindTag, TunnelStatus, TunnelTeardownConfig,
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
/// DNS directives are always removed from the `wg-quick` input. The parsed
/// request is returned on [`TunnelHandle`] for the protocol-neutral policy
/// coordinator; `wg-quick` never mutates resolver state itself.
#[derive(Debug, Default, Clone)]
pub struct WgTunnel;

impl WgTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Parse requested DNS without applying platform state.
    pub fn requested_dns(
        &self,
        profile: &Profile,
    ) -> Result<crate::vortix_core::ports::dns::DnsRequest, TunnelError> {
        let body = std::fs::read_to_string(&profile.config_path).map_err(|error| {
            TunnelError::Subprocess(format!(
                "read WG config {}: {error}",
                profile.config_path.display()
            ))
        })?;
        parse_wg_conf(&body)
            .map(|parsed| parsed.dns_request())
            .map_err(|error| {
                TunnelError::Subprocess(format!("parse WireGuard DNS intent: {error}"))
            })
    }
}

/// Strip `DNS = …` lines from a `WireGuard` `.conf` body.
///
/// Protocol parsing captures the request separately; this helper only keeps
/// `wg-quick` from mutating resolver state.
#[must_use]
pub(crate) fn strip_dns_directive(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
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
        let is_dns = after_dns.is_some_and(|rest| rest.trim_start().starts_with('='));
        if !is_dns {
            out.push_str(line);
        }
    }
    out
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
/// Separated from [`write_managed_temp_config`] so tests can exercise the
/// file-writing logic against a per-test tempdir without depending on the
/// process-global `config_dir` set by `set_config_dir` (a `OnceLock` shared
/// across the test binary).
fn write_managed_temp_config_at(
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
            TunnelError::Subprocess(format!("write managed WG temp config: {io}"))
        }
        other => TunnelError::Subprocess(format!("write managed WG temp config: {other}")),
    })?;

    Ok(temp_path)
}

/// Public wrapper used by `up()`: resolves the per-session tmp dir from the
/// global journal `session_id`, then delegates to
/// [`write_managed_temp_config_at`].
fn write_managed_temp_config(
    user_conf_path: &Path,
    stripped_body: &[u8],
) -> Result<PathBuf, TunnelError> {
    let session_id = resolve_session_id();
    let session_root = crate::utils::get_tmp_config_dir(&session_id).map_err(|e| {
        TunnelError::Subprocess(format!("failed to create per-session tmp dir: {e}"))
    })?;
    let lifecycle_dir = create_lifecycle_dir(&session_root)?;
    match write_managed_temp_config_at(&lifecycle_dir, user_conf_path, stripped_body) {
        Ok(path) => Ok(path),
        Err(error) => {
            let _ = std::fs::remove_dir(&lifecycle_dir);
            Err(error)
        }
    }
}

fn create_lifecycle_dir(session_root: &Path) -> Result<PathBuf, TunnelError> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_LIFECYCLE: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let sequence = NEXT_LIFECYCLE.fetch_add(1, Ordering::Relaxed);
        let path = session_root.join(format!("wg-{}-{sequence}", std::process::id()));
        #[cfg(unix)]
        let result = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(&path)
        };
        #[cfg(not(unix))]
        let result = std::fs::create_dir(&path);

        match result {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(TunnelError::Subprocess(format!(
                    "create managed WG lifecycle dir: {error}"
                )));
            }
        }
    }
    Err(TunnelError::Subprocess(
        "could not allocate a unique managed WG lifecycle dir".into(),
    ))
}

/// Remove the per-session temp file written by [`write_managed_temp_config`]
/// and, if the per-session subdir is now empty, remove that too. Errors are
/// swallowed: at disconnect time the tunnel is already down, so a residual
/// temp file is harmless and the startup sweep will collect it on the next
/// run.
fn cleanup_managed_temp_config(temp_path: &Path) {
    let _ = std::fs::remove_file(temp_path);
    if let Some(parent) = temp_path.parent() {
        // `remove_dir` only succeeds when the dir is empty — exactly the
        // condition we want. Other secondaries in the same session keep
        // their own leaf and the dir survives.
        let removed_lifecycle = std::fs::remove_dir(parent).is_ok()
            && parent
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.starts_with("wg-"));
        if removed_lifecycle {
            if let Some(session_root) = parent.parent() {
                let _ = std::fs::remove_dir(session_root);
            }
        }
    }
}

/// Minimal `WireGuard` status — extended once the binary-side scanner moves
/// into this crate (deferred).
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

struct PreparedDownTarget {
    target: String,
    cleanup_after_attempt: Option<PathBuf>,
    cleanup_after_success: Option<PathBuf>,
}

fn looks_like_config_path(value: &str) -> bool {
    Path::new(value)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("conf"))
        || Path::new(value).components().count() > 1
}

/// Resolve a teardown-safe `wg-quick down` target.
///
/// Managed configs were sanitized during `up` and must stay alive until the
/// matching `down`. Source configs are sanitized into a fresh managed copy
/// here when needed, covering synthetic handles built after a restart or a
/// scanner adoption. Interface-only handles never involve a config file.
fn prepare_down_target_with(
    handle: &TunnelHandle,
    write_managed: impl FnOnce(&Path, &[u8]) -> Result<PathBuf, TunnelError>,
) -> Result<PreparedDownTarget, TunnelError> {
    let config = handle.teardown_config.clone().or_else(|| {
        looks_like_config_path(&handle.interface_name).then(|| TunnelTeardownConfig {
            path: PathBuf::from(&handle.interface_name),
            managed: false,
        })
    });

    let Some(config) = config else {
        return Ok(PreparedDownTarget {
            target: handle.interface_name.clone(),
            cleanup_after_attempt: None,
            cleanup_after_success: None,
        });
    };

    if config.managed {
        return Ok(PreparedDownTarget {
            target: config.path.to_string_lossy().into_owned(),
            cleanup_after_attempt: None,
            cleanup_after_success: Some(config.path),
        });
    }

    let body = std::fs::read_to_string(&config.path).map_err(|error| {
        TunnelError::Subprocess(format!(
            "read WG teardown config {}: {error}",
            config.path.display()
        ))
    })?;
    let stripped = strip_dns_directive(&body);
    if stripped == body {
        return Ok(PreparedDownTarget {
            target: config.path.to_string_lossy().into_owned(),
            cleanup_after_attempt: None,
            cleanup_after_success: None,
        });
    }

    let temp_path = write_managed(&config.path, stripped.as_bytes())?;
    Ok(PreparedDownTarget {
        target: temp_path.to_string_lossy().into_owned(),
        cleanup_after_attempt: Some(temp_path),
        cleanup_after_success: None,
    })
}

fn prepare_down_target(handle: &TunnelHandle) -> Result<PreparedDownTarget, TunnelError> {
    prepare_down_target_with(handle, write_managed_temp_config)
}

fn wg_quick_down_spec(target: String) -> CommandSpec {
    CommandSpec::oneshot("wg-quick", vec!["down".into(), target]).privilege(PrivilegeReq::Root)
}

impl Tunnel for WgTunnel {
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        let user_body = std::fs::read_to_string(&profile.config_path).map_err(|e| {
            TunnelError::Subprocess(format!(
                "read WG config {}: {e}",
                profile.config_path.display()
            ))
        })?;
        let dns_request = parse_wg_conf(&user_body)
            .map(|parsed| parsed.dns_request())
            .map_err(|error| {
                TunnelError::Subprocess(format!("parse WireGuard DNS intent: {error}"))
            })?;
        let stripped = strip_dns_directive(&user_body);
        // Keep one private lifecycle copy even when the source has no DNS.
        // `wg-quick down` needs the same routes/hooks as `up`, and arbitrary
        // imported profiles are not discoverable through `/etc/wireguard` by
        // interface name alone.
        let temp_path = write_managed_temp_config(&profile.config_path, stripped.as_bytes())?;
        let effective_path = temp_path.clone();

        let path_str = effective_path.to_string_lossy().into_owned();
        info!(
            target: "vortix::tunnel::wireguard",
            profile = %profile.id,
            config = %path_str,
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
            cleanup_managed_temp_config(&temp_path);
            TunnelError::Subprocess(format!("wg-quick up: {e}"))
        })?;

        if !output.status.success() {
            cleanup_managed_temp_config(&temp_path);
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(TunnelError::HandshakeFailed(format!("WireGuard: {stderr}")));
        }

        let basename = interface_from_path(&effective_path);
        let interface_name = resolve_kernel_iface(
            &basename,
            crate::platform::current_platform()
                .interface
                .resolve_wireguard_interface(&basename),
            &profile.id,
        );

        Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            interface_name,
            pid: None,
            started_at: SystemTime::now(),
            kind: TunnelKindTag::WireGuard,
            teardown_config: Some(TunnelTeardownConfig {
                path: temp_path,
                managed: true,
            }),
            dns_request,
        })
    }

    fn down(&mut self, handle: TunnelHandle) -> Result<(), TunnelError> {
        info!(
            target: "vortix::tunnel::wireguard",
            profile = %handle.profile_id,
            interface = %handle.interface_name,
            "wg.down"
        );

        let prepared = prepare_down_target(&handle)?;
        let output = crate::vortix_process::run_to_output(wg_quick_down_spec(prepared.target));

        if let Some(path) = &prepared.cleanup_after_attempt {
            cleanup_managed_temp_config(path);
        }

        let output = output.map_err(|e| TunnelError::Subprocess(format!("wg-quick down: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(TunnelError::Subprocess(format!("WireGuard down: {stderr}")));
        }

        if let Some(path) = &prepared.cleanup_after_success {
            cleanup_managed_temp_config(path);
        }

        Ok(())
    }

    fn status(&self, handle: &TunnelHandle) -> Result<TunnelStatus, TunnelError> {
        // Minimal status today — the engine still uses the binary-side
        // scanner for richer wg-show parsing until a later migration relocates it.
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

    // --- resolve_kernel_iface contract ---

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
        // (the legacy default before the override existed). This MUST
        // be preserved verbatim — the helper has no business stripping
        // the port's answer just because it happens to equal the
        // basename.
        let profile_id = crate::vortix_core::profile::ProfileId::new("corp");
        let resolved = resolve_kernel_iface("corp", Some("corp".to_string()), &profile_id);
        assert_eq!(resolved, "corp");
    }

    // --- DNS extraction and protocol-side suppression ---

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

    fn wg_handle(
        interface_name: &str,
        teardown_config: Option<TunnelTeardownConfig>,
    ) -> TunnelHandle {
        TunnelHandle {
            profile_id: crate::vortix_core::profile::ProfileId::new("corp"),
            interface_name: interface_name.to_string(),
            pid: None,
            started_at: SystemTime::now(),
            kind: TunnelKindTag::WireGuard,
            teardown_config,
            dns_request: crate::vortix_core::ports::dns::DnsRequest::default(),
        }
    }

    #[test]
    fn synthetic_down_command_uses_dns_free_managed_copy() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let source = scratch.path().join("corp.conf");
        std::fs::write(
            &source,
            "[Interface]\nPrivateKey = SECRET\nDNS = 1.1.1.1\nAddress = 10.0.0.2/24\n",
        )
        .unwrap();
        let handle = wg_handle(
            "corp",
            Some(TunnelTeardownConfig {
                path: source.clone(),
                managed: false,
            }),
        );

        let prepared = prepare_down_target_with(&handle, |path, body| {
            write_managed_temp_config_at(&session, path, body)
        })
        .unwrap();
        let spec = wg_quick_down_spec(prepared.target.clone());

        assert_eq!(spec.program, "wg-quick");
        assert_eq!(spec.args, vec!["down", prepared.target.as_str()]);
        assert_ne!(prepared.target, source.to_string_lossy());
        let command_body = std::fs::read_to_string(&prepared.target).unwrap();
        assert!(!command_body.contains("DNS ="));
        assert!(command_body.contains("PrivateKey = SECRET"));
    }

    #[test]
    fn real_handle_down_command_keeps_managed_config_until_success() {
        let scratch = tempfile::tempdir().unwrap();
        let managed = scratch.path().join("corp.conf");
        std::fs::write(&managed, "[Interface]\nPrivateKey = SECRET\n").unwrap();
        let handle = wg_handle(
            "wg0",
            Some(TunnelTeardownConfig {
                path: managed.clone(),
                managed: true,
            }),
        );

        let prepared = prepare_down_target_with(&handle, |_path, _body| {
            panic!("managed config must not be rewritten")
        })
        .unwrap();
        let spec = wg_quick_down_spec(prepared.target);

        assert_eq!(spec.args, vec!["down", managed.to_string_lossy().as_ref()]);
        assert!(prepared.cleanup_after_attempt.is_none());
        assert_eq!(
            prepared.cleanup_after_success.as_deref(),
            Some(managed.as_path())
        );
        assert!(
            managed.exists(),
            "managed config must survive until down succeeds"
        );
    }

    #[test]
    fn adopted_interface_down_command_never_uses_a_profile_path() {
        let handle = wg_handle("utun7", None);
        let prepared = prepare_down_target_with(&handle, |_path, _body| {
            panic!("interface-only teardown must not create a config")
        })
        .unwrap();
        let spec = wg_quick_down_spec(prepared.target);

        assert_eq!(spec.args, vec!["down", "utun7"]);
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
    fn managed_temp_config_strips_dns_and_preserves_basename() {
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

        let temp = write_managed_temp_config_at(&session, &user_conf, stripped.as_bytes()).unwrap();
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
    fn managed_temp_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("wg0.conf");
        std::fs::write(
            &user_conf,
            "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/24\n",
        )
        .unwrap();

        let temp =
            write_managed_temp_config_at(&session, &user_conf, b"[Interface]\nPrivateKey = abc\n")
                .unwrap();
        let perms = std::fs::metadata(&temp).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn write_managed_overwrites_stale_same_session_leaf() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("vpn.conf");
        std::fs::write(&user_conf, "[Interface]\nPrivateKey = a\n").unwrap();

        // First write — leaf does not exist yet.
        let t1 = write_managed_temp_config_at(&session, &user_conf, b"first").unwrap();
        // Second write within same session — stale leaf is unlinked first
        // (write_secret_file would otherwise refuse with FileExists).
        let t2 = write_managed_temp_config_at(&session, &user_conf, b"second").unwrap();
        assert_eq!(t1, t2);
        assert_eq!(std::fs::read_to_string(&t2).unwrap(), "second");
    }

    #[test]
    fn lifecycle_directories_do_not_overwrite_an_active_teardown_config() {
        let (_root, session) = fresh_session_dir();
        let first_dir = create_lifecycle_dir(&session).unwrap();
        let second_dir = create_lifecycle_dir(&session).unwrap();
        let source = session.join("corp.conf");

        let first = write_managed_temp_config_at(&first_dir, &source, b"first").unwrap();
        let second = write_managed_temp_config_at(&second_dir, &source, b"second").unwrap();

        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(first).unwrap(), "first");
        assert_eq!(std::fs::read_to_string(second).unwrap(), "second");
    }

    #[test]
    fn cleanup_removes_leaf_and_empty_session_dir() {
        let (_root, session) = fresh_session_dir();
        let scratch = tempfile::tempdir().unwrap();
        let user_conf = scratch.path().join("only.conf");
        std::fs::write(&user_conf, "[Interface]\nPrivateKey = a\n").unwrap();

        let temp = write_managed_temp_config_at(&session, &user_conf, b"body").unwrap();
        assert!(temp.exists());
        assert!(session.exists());

        cleanup_managed_temp_config(&temp);
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

        let temp_a = write_managed_temp_config_at(&session, &conf_a, b"a-body").unwrap();
        let temp_b = write_managed_temp_config_at(&session, &conf_b, b"b-body").unwrap();
        assert_eq!(session, temp_a.parent().unwrap());
        assert_eq!(session, temp_b.parent().unwrap());

        cleanup_managed_temp_config(&temp_a);
        assert!(!temp_a.exists());
        assert!(temp_b.exists(), "sibling managed leaf must survive");
        assert!(session.exists(), "session dir must survive while non-empty");

        cleanup_managed_temp_config(&temp_b);
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
}
