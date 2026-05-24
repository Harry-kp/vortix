//! `WgTunnel` — `WireGuard` impl of the `Tunnel` port.

use std::time::SystemTime;

use tracing::info;
use vortix_core::ports::tunnel::{
    ParseError, ParsedProfile, ProtocolStatus, Tunnel, TunnelCapabilities, TunnelError,
    TunnelHandle, TunnelKindTag, TunnelStatus,
};
use vortix_core::profile::Profile;
use vortix_process::{CommandSpec, PrivilegeReq};

use crate::parser::parse_wg_conf;

/// `wg-quick`-based `WireGuard` tunnel.
///
/// Plan #004 v1 supports kernel `WireGuard` only — `wireguard-go`/`boringtun`
/// user-space backends land with idea 5's daemon work.
#[derive(Debug, Default, Clone)]
pub struct WgTunnel;

impl WgTunnel {
    #[must_use]
    pub fn new() -> Self {
        Self
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

fn interface_from_path(path: &std::path::Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wg0")
        .to_string()
}

impl Tunnel for WgTunnel {
    fn up(&mut self, profile: &Profile) -> Result<TunnelHandle, TunnelError> {
        let path = profile.config_path.to_string_lossy().into_owned();
        info!(
            target: "vortix::tunnel::wireguard",
            profile = %profile.id,
            config = %path,
            "wg.up"
        );

        let output = vortix_process::run_to_output(
            CommandSpec::oneshot("wg-quick", vec!["up".into(), path.clone()])
                .privilege(PrivilegeReq::Root),
        )
        .map_err(|e| TunnelError::Subprocess(format!("wg-quick up: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(TunnelError::HandshakeFailed(format!("WireGuard: {stderr}")));
        }

        Ok(TunnelHandle {
            profile_id: profile.id.clone(),
            interface_name: interface_from_path(&profile.config_path),
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
            "wg.down"
        );

        // Pass the interface name; `wg-quick down <iface>` looks up the
        // config in the standard locations. (The engine's previous code
        // passed the full path here too — both forms work; the iface name
        // is shorter and matches the handle.)
        let output = vortix_process::run_to_output(
            CommandSpec::oneshot(
                "wg-quick",
                vec!["down".into(), handle.interface_name.clone()],
            )
            .privilege(PrivilegeReq::Root),
        )
        .map_err(|e| TunnelError::Subprocess(format!("wg-quick down: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(TunnelError::Subprocess(format!("WireGuard down: {stderr}")));
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
}
