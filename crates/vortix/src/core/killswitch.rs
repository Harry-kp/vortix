//! Kill switch firewall control — relocated trait now lives in `vortix-core`
//! (plan 003 U1). This module keeps the binary-crate-side state persistence
//! and the platform dispatch shim until plan 003 U7 swaps callers over to
//! the `Platform` aggregate.

use crate::constants;
use crate::logger::{self, LogLevel};
use crate::state::{KillSwitchMode, KillSwitchState};
use crate::utils;
use std::fs;
use std::io;
use std::path::PathBuf;

// Re-export the canonical types so existing `crate::core::killswitch::*`
// imports keep resolving.
pub use crate::vortix_core::ports::killswitch::{ActiveTunnelInfo, KillswitchError, Result};

// Backwards-compat alias — the old name is `KillSwitchError`.
pub type KillSwitchError = KillswitchError;

/// Enable kill switch with a per-tunnel ruleset.
///
/// Routes through the process-global `Platform` aggregate. The per-OS
/// impl lives in `vortix_platform_{macos,linux,windows}` and synthesises
/// allow rules for every entry in `active` plus an RFC1918 base with
/// secondary-declared CIDRs subtracted.
///
/// Multi-connection plan U8 replaces the legacy single-tunnel
/// `enable_blocking(interface, server_ip)` form with this slice-based
/// API. Callers building from a single connection should construct a
/// one-element slice; see [`ActiveTunnelInfo`].
///
/// # Errors
///
/// Returns error if not running as root or firewall commands fail.
pub fn enable_blocking_multi(active: &[ActiveTunnelInfo]) -> Result<()> {
    crate::platform::current_platform()
        .killswitch
        .enable_blocking_multi(active)
}

/// Disable kill switch by flushing firewall rules.
///
/// # Errors
///
/// Returns error if not running as root or firewall commands fail.
pub fn disable_blocking() -> Result<()> {
    crate::platform::current_platform()
        .killswitch
        .disable_blocking()
}

/// Get the state file path.
fn get_state_path() -> Option<PathBuf> {
    utils::get_app_config_dir()
        .ok()
        .map(|dir| dir.join(constants::KILLSWITCH_STATE_FILE))
}

/// Current `PersistedState` on-disk schema version. V1 (pre-multi-connection)
/// carried only `vpn_interface`/`vpn_server_ip`; V2 (plan multi-connection
/// U11) adds `active_tunnels` for the multi-tunnel killswitch.
pub const PERSISTED_STATE_SCHEMA_V2: u8 = 2;

fn default_schema_version() -> u8 {
    // V1 files on disk omit `schema_version` entirely — defaulting to 1
    // is what triggers the V1→V2 migration path in `load_state`.
    1
}

/// Per-tunnel persisted form of `ActiveTunnelInfo`.
///
/// IPs and CIDRs are stored as strings for JSON portability and forward
/// compatibility — the in-memory `ActiveTunnelInfo` uses typed `IpAddr`
/// and `Cidr`, but persisted state must tolerate any value that round-
/// trips through `Display`/`FromStr`, including future address families.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedTunnelInfo {
    /// Tunnel interface name, e.g. `utun3` or `wg0`.
    pub interface: String,
    /// VPN server IPs, stringified (IPv4 dotted-quad or IPv6 textual).
    #[serde(default)]
    pub server_ips: Vec<String>,
    /// CIDR ranges this tunnel declares as its routed scope (e.g.
    /// `"10.0.0.0/8"`). Used by secondaries to subtract from the
    /// RFC1918 base in the killswitch synthesizer.
    #[serde(default)]
    pub declared_cidrs: Vec<String>,
    /// `true` when this tunnel claims the default route.
    #[serde(default)]
    pub is_primary: bool,
}

/// Persistent state for kill-switch recovery across process restarts.
///
/// **Schema versioning (plan multi-connection U11):** This struct
/// transparently absorbs both V1 (single-tunnel — `vpn_interface` +
/// `vpn_server_ip`) and V2 (multi-tunnel — `active_tunnels`) on-disk
/// forms via `#[serde(default)]`. On load, V1 files are coerced into V2
/// shape; the next save writes V2 explicitly.
///
/// The V1 legacy fields remain on the struct for two reasons:
/// 1. Direct deserialization of V1 files without a separate type.
/// 2. Forward compatibility — V2 writes currently leave them as `None`,
///    but if a future schema needs them again the field is still there.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedState {
    /// On-disk schema version. Missing or `1` means V1; `2` means V2.
    /// Unknown future values are treated as V1 fallback with a warning.
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
    pub mode: KillSwitchMode,
    pub state: KillSwitchState,
    /// V1 legacy — single-tunnel interface name. `None` on fresh V2
    /// writes.
    #[serde(default)]
    pub vpn_interface: Option<String>,
    /// V1 legacy — single-tunnel server IP. `None` on fresh V2 writes.
    #[serde(default)]
    pub vpn_server_ip: Option<String>,
    /// V2 — per-tunnel state for the multi-connection killswitch.
    /// Empty for V1 files until coerced by `load_state`.
    #[serde(default)]
    pub active_tunnels: Vec<PersistedTunnelInfo>,
}

/// Coerce a V1 (or unknown-version-fallback) `PersistedState` into V2
/// in place. Single-tunnel `vpn_interface`/`vpn_server_ip` fields fold
/// into a one-element `active_tunnels` vec.
fn coerce_v1_to_v2(state: &mut PersistedState) {
    if state.active_tunnels.is_empty() {
        if let Some(iface) = state.vpn_interface.clone() {
            state.active_tunnels.push(PersistedTunnelInfo {
                interface: iface,
                server_ips: state.vpn_server_ip.clone().into_iter().collect(),
                declared_cidrs: Vec::new(),
                is_primary: true,
            });
        }
    }
    state.schema_version = PERSISTED_STATE_SCHEMA_V2;
}

/// Drop entries from `active_tunnels` whose interface no longer exists
/// in `live`. If `live` is empty the filter is a no-op — empty means
/// "unknown" (platform enumeration failed or is unimplemented), not
/// "no interfaces present".
fn filter_phantom_tunnels(state: &mut PersistedState, live: &[String]) {
    if live.is_empty() {
        return;
    }
    let mut dropped: Vec<String> = Vec::new();
    state.active_tunnels.retain(|t| {
        if live.iter().any(|name| name == &t.interface) {
            true
        } else {
            dropped.push(t.interface.clone());
            false
        }
    });
    if !dropped.is_empty() {
        tracing::warn!(
            target: "FIREWALL",
            dropped = ?dropped,
            "Dropped persisted tunnel entries whose interface no longer exists in the kernel"
        );
    }
}

/// Load kill switch state from persistence file.
///
/// Absorbs both V1 and V2 on-disk shapes. V1 files are migrated in
/// memory to V2 (the next `save_state` call rewrites them on disk).
/// Phantom interfaces — entries naming a kernel interface that no
/// longer exists — are dropped with a warning.
#[must_use]
pub fn load_state() -> Option<PersistedState> {
    let path = get_state_path()?;
    let content = fs::read_to_string(&path).ok()?;
    let mut persisted: PersistedState = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            logger::log(
                LogLevel::Warning,
                "FIREWALL",
                format!("Failed to parse persisted state: {e}"),
            );
            return None;
        }
    };

    logger::log(
        LogLevel::Debug,
        "FIREWALL",
        format!(
            "Loaded persisted state from {} (schema v{})",
            path.display(),
            persisted.schema_version
        ),
    );

    match persisted.schema_version {
        0 | 1 => {
            if !persisted.active_tunnels.is_empty()
                || persisted.vpn_interface.is_some()
                || persisted.vpn_server_ip.is_some()
            {
                logger::log(
                    LogLevel::Info,
                    "FIREWALL",
                    "Migrating persisted killswitch state V1 → V2".to_string(),
                );
            }
            coerce_v1_to_v2(&mut persisted);
        }
        PERSISTED_STATE_SCHEMA_V2 => {}
        other => {
            tracing::warn!(
                target: "FIREWALL",
                schema = other,
                "Unknown PersistedState schema version; falling back to V1 coercion"
            );
            coerce_v1_to_v2(&mut persisted);
        }
    }

    let live = crate::platform::current_platform().available_network_interfaces();
    filter_phantom_tunnels(&mut persisted, &live);

    Some(persisted)
}

/// Save kill switch state to persistence file.
///
/// Writes the V2 schema using an atomic write: serialize to a sibling
/// `.tmp` file, fsync, then `rename` over the target. A crash mid-write
/// leaves the prior valid file intact.
///
/// # Errors
///
/// Returns [`KillswitchError::Io`] when the file cannot be written.
pub fn save_state(
    mode: KillSwitchMode,
    state: KillSwitchState,
    active_tunnels: Vec<PersistedTunnelInfo>,
) -> Result<()> {
    let Some(path) = get_state_path() else {
        return Ok(()); // Silently skip if no home dir
    };

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let persisted = PersistedState {
        schema_version: PERSISTED_STATE_SCHEMA_V2,
        mode,
        state,
        // V1 legacy fields — left empty on fresh V2 writes. V1 readers
        // that lack `#[serde(default)]` tolerance need D5 (see plan).
        vpn_interface: None,
        vpn_server_ip: None,
        active_tunnels,
    };

    let content = serde_json::to_string_pretty(&persisted).map_err(io::Error::other)?;

    atomic_write(&path, content.as_bytes())?;
    Ok(())
}

/// Convenience helper: build a `PersistedTunnelInfo` slice from
/// `ActiveTunnelInfo` and persist. Callers holding the live registry
/// can stringify in one place.
#[must_use]
pub fn persisted_from_active(active: &[ActiveTunnelInfo]) -> Vec<PersistedTunnelInfo> {
    active
        .iter()
        .map(|a| PersistedTunnelInfo {
            interface: a.interface.clone(),
            server_ips: a.server_ips.iter().map(ToString::to_string).collect(),
            declared_cidrs: a
                .declared_cidrs
                .iter()
                .map(|c| format!("{}/{}", c.addr, c.prefix_len))
                .collect(),
            is_primary: a.is_primary,
        })
        .collect()
}

/// Atomic write: temp file → fsync → rename.
///
/// `fs::write` truncates in place: a crash between the truncate and
/// the final write leaves an empty or partial file that `load_state`
/// silently rejects. The temp+rename pattern preserves the prior valid
/// file across any failure point.
fn atomic_write(path: &std::path::Path, contents: &[u8]) -> io::Result<()> {
    let tmp_path = path.with_extension("json.tmp");
    crate::utils::write_user_file(&tmp_path, contents)?;
    // fsync the temp file so its data hits disk before we rename. On
    // platforms where `sync_all` is unsupported (rare), the write is
    // still atomic at the rename step — sync_all just narrows the
    // window during which a post-rename crash could lose data.
    {
        let file = std::fs::OpenOptions::new().read(true).open(&tmp_path)?;
        let _ = file.sync_all();
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Clear the persisted state file.
pub fn clear_state() {
    if let Some(path) = get_state_path() {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_persisted_state_round_trips() {
        let state = PersistedState {
            schema_version: PERSISTED_STATE_SCHEMA_V2,
            mode: KillSwitchMode::Auto,
            state: KillSwitchState::Armed,
            vpn_interface: None,
            vpn_server_ip: None,
            active_tunnels: vec![PersistedTunnelInfo {
                interface: "utun3".to_string(),
                server_ips: vec!["1.2.3.4".to_string()],
                declared_cidrs: vec!["10.0.0.0/8".to_string()],
                is_primary: true,
            }],
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let deserialized: PersistedState = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.schema_version, PERSISTED_STATE_SCHEMA_V2);
        assert_eq!(deserialized.mode, KillSwitchMode::Auto);
        assert_eq!(deserialized.state, KillSwitchState::Armed);
        assert_eq!(deserialized.active_tunnels.len(), 1);
        assert_eq!(deserialized.active_tunnels[0].interface, "utun3");
        assert!(deserialized.active_tunnels[0].is_primary);
    }

    #[test]
    fn v1_file_deserializes_with_serde_defaults() {
        // V1 on-disk shape: no schema_version, no active_tunnels.
        let json =
            r#"{"mode":"Auto","state":"Armed","vpn_interface":"utun3","vpn_server_ip":"1.2.3.4"}"#;
        let mut state: PersistedState = serde_json::from_str(json).unwrap();
        assert_eq!(
            state.schema_version, 1,
            "missing schema_version defaults to 1"
        );
        assert_eq!(state.vpn_interface.as_deref(), Some("utun3"));
        assert!(state.active_tunnels.is_empty());

        coerce_v1_to_v2(&mut state);
        assert_eq!(state.schema_version, PERSISTED_STATE_SCHEMA_V2);
        assert_eq!(state.active_tunnels.len(), 1);
        assert_eq!(state.active_tunnels[0].interface, "utun3");
        assert_eq!(
            state.active_tunnels[0].server_ips,
            vec!["1.2.3.4".to_string()]
        );
        assert!(state.active_tunnels[0].is_primary);
    }

    #[test]
    fn v1_with_no_interface_coerces_to_empty_active_tunnels() {
        let json = r#"{"mode":"Off","state":"Disabled","vpn_interface":null,"vpn_server_ip":null}"#;
        let mut state: PersistedState = serde_json::from_str(json).unwrap();
        coerce_v1_to_v2(&mut state);
        assert_eq!(state.schema_version, PERSISTED_STATE_SCHEMA_V2);
        assert!(state.active_tunnels.is_empty());
    }

    #[test]
    fn v2_file_with_schema_version_field_deserializes() {
        let json = r#"{
            "schema_version": 2,
            "mode": "Auto",
            "state": "Armed",
            "vpn_interface": null,
            "vpn_server_ip": null,
            "active_tunnels": [
                {"interface":"wg0","server_ips":["1.2.3.4"],"declared_cidrs":[],"is_primary":true},
                {"interface":"utun5","server_ips":["5.6.7.8"],"declared_cidrs":["10.0.0.0/8"],"is_primary":false}
            ]
        }"#;
        let state: PersistedState = serde_json::from_str(json).unwrap();
        assert_eq!(state.schema_version, PERSISTED_STATE_SCHEMA_V2);
        assert_eq!(state.active_tunnels.len(), 2);
        assert!(state.active_tunnels[0].is_primary);
        assert!(!state.active_tunnels[1].is_primary);
        assert_eq!(
            state.active_tunnels[1].declared_cidrs,
            vec!["10.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn persisted_state_corrupted_mode_fails() {
        let json = r#"{"mode":"InvalidValue","state":"Disabled"}"#;
        let result: std::result::Result<PersistedState, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn persisted_state_empty_json_fails() {
        // `mode` and `state` are required (no default) — empty {} must fail.
        let result: std::result::Result<PersistedState, _> = serde_json::from_str("{}");
        assert!(result.is_err());
    }

    #[test]
    fn filter_phantom_tunnels_drops_unknown_interfaces() {
        let mut state = PersistedState {
            schema_version: PERSISTED_STATE_SCHEMA_V2,
            mode: KillSwitchMode::Auto,
            state: KillSwitchState::Armed,
            vpn_interface: None,
            vpn_server_ip: None,
            active_tunnels: vec![
                PersistedTunnelInfo {
                    interface: "eth0".to_string(),
                    server_ips: Vec::new(),
                    declared_cidrs: Vec::new(),
                    is_primary: true,
                },
                PersistedTunnelInfo {
                    interface: "utun99".to_string(),
                    server_ips: Vec::new(),
                    declared_cidrs: Vec::new(),
                    is_primary: false,
                },
            ],
        };
        let live = vec!["lo".to_string(), "eth0".to_string()];
        filter_phantom_tunnels(&mut state, &live);
        assert_eq!(state.active_tunnels.len(), 1);
        assert_eq!(state.active_tunnels[0].interface, "eth0");
    }

    #[test]
    fn filter_phantom_tunnels_noop_on_empty_live_list() {
        // Empty `live` means "unknown" — preserve persisted state.
        let mut state = PersistedState {
            schema_version: PERSISTED_STATE_SCHEMA_V2,
            mode: KillSwitchMode::Auto,
            state: KillSwitchState::Armed,
            vpn_interface: None,
            vpn_server_ip: None,
            active_tunnels: vec![PersistedTunnelInfo {
                interface: "utun99".to_string(),
                server_ips: Vec::new(),
                declared_cidrs: Vec::new(),
                is_primary: true,
            }],
        };
        filter_phantom_tunnels(&mut state, &[]);
        assert_eq!(state.active_tunnels.len(), 1);
    }

    #[test]
    fn unknown_future_schema_falls_back_to_v1_coercion() {
        // schema_version=99 should be tolerated: coerce_v1_to_v2 runs.
        // In this case active_tunnels is already populated, so nothing
        // changes — but schema_version flips to V2.
        let json = r#"{
            "schema_version": 99,
            "mode": "Auto",
            "state": "Armed",
            "vpn_interface": null,
            "vpn_server_ip": null,
            "active_tunnels": [
                {"interface":"wg0","server_ips":[],"declared_cidrs":[],"is_primary":true}
            ]
        }"#;
        let mut state: PersistedState = serde_json::from_str(json).unwrap();
        assert_eq!(state.schema_version, 99);
        coerce_v1_to_v2(&mut state);
        assert_eq!(state.schema_version, PERSISTED_STATE_SCHEMA_V2);
        assert_eq!(state.active_tunnels.len(), 1);
    }

    #[test]
    fn atomic_write_creates_target_and_no_tmp_left_behind() {
        let tmp_dir = std::env::temp_dir();
        let path = tmp_dir.join(format!(
            "vortix-killswitch-atomic-write-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let tmp = path.with_extension("json.tmp");
        let _ = fs::remove_file(&tmp);

        atomic_write(&path, b"hello").unwrap();

        assert!(path.exists(), "target file must exist after atomic_write");
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        assert!(!tmp.exists(), "temp file must be renamed away");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persisted_from_active_stringifies_addresses_and_cidrs() {
        use crate::vortix_core::cidr::Cidr;
        use std::net::IpAddr;
        let active = vec![ActiveTunnelInfo {
            interface: "utun3".to_string(),
            server_ips: vec!["1.2.3.4".parse::<IpAddr>().unwrap()],
            declared_cidrs: vec!["10.0.0.0/8".parse::<Cidr>().unwrap()],
            is_primary: true,
        }];
        let persisted = persisted_from_active(&active);
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].interface, "utun3");
        assert_eq!(persisted[0].server_ips, vec!["1.2.3.4".to_string()]);
        assert_eq!(persisted[0].declared_cidrs, vec!["10.0.0.0/8".to_string()]);
        assert!(persisted[0].is_primary);
    }

    /// Forward-compat integration check (plan U11): a v0.3.x reader of
    /// the V1 `PersistedState` (with `#[serde(deny_unknown_fields)]`
    /// **not** set, which is the default for serde) must successfully
    /// deserialize a V2 file. We simulate the v0.3.x V1 type locally.
    #[test]
    fn v0_3_x_v1_reader_tolerates_v2_file() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct V1PersistedState {
            mode: KillSwitchMode,
            state: KillSwitchState,
            vpn_interface: Option<String>,
            vpn_server_ip: Option<String>,
        }

        let v2_json = r#"{
            "schema_version": 2,
            "mode": "Auto",
            "state": "Armed",
            "vpn_interface": null,
            "vpn_server_ip": null,
            "active_tunnels": [
                {"interface":"wg0","server_ips":["1.2.3.4"],"declared_cidrs":[],"is_primary":true}
            ]
        }"#;
        // serde_json ignores unknown fields by default, so this must succeed.
        let parsed: V1PersistedState = serde_json::from_str(v2_json).unwrap();
        assert_eq!(parsed.mode, KillSwitchMode::Auto);
        assert_eq!(parsed.state, KillSwitchState::Armed);
        assert!(parsed.vpn_interface.is_none());
    }
}
