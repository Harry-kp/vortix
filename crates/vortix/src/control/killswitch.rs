//! Kill switch: the mode/state vocabulary, its persisted record, and the
//! calls into this OS's firewall.

pub use mode::{KillSwitchMode, KillSwitchState};

mod mode {
    //! Kill switch state types.
    //!
    //! The kill switch prevents traffic leakage when the VPN connection
    //! drops unexpectedly (`block-on-drop`) or keeps the firewall
    //! engaged at all times (`vpn-only`).
    //!
    //! # One vocabulary, used everywhere
    //!
    //! Every surface — TUI panels, header bar, `vortix status` /
    //! `vortix report` / `vortix killswitch` output, the JSON envelope,
    //! and the CLI input verb — uses the same three slugs. Rust enum
    //! variants (`Off` / `Auto` / `AlwaysOn`) stay idiomatic for the
    //! language; every display path routes through
    //! [`KillSwitchMode::display_name`] / [`KillSwitchMode::cli_verb`] /
    //! [`KillSwitchState::display_status`] so the enum names never leak
    //! into output.
    //!
    //! | Rust enum    | Slug              | What it does                                        |
    //! |--------------|-------------------|-----------------------------------------------------|
    //! | `Off`        | `off`             | No firewall rules. Real IP exposed if VPN drops.    |
    //! | `Auto`       | `block-on-drop`   | Block traffic only if the VPN drops unexpectedly.   |
    //! | `AlwaysOn`   | `vpn-only`        | Only VPN traffic permitted. No internet without VPN.|
    //!
    //! [`KillSwitchMode::display_name`] returns the title-cased prose form
    //! of the same slug (`Off` / `Block on drop` / `VPN-only`) for
    //! long-form rendering. No old verbs (`auto`, `always`,
    //! `always-on`) are accepted — the CLI parser returns an explicit
    //! "Use: off, block-on-drop, vpn-only" error.

    use serde::{Deserialize, Serialize};

    /// Kill switch operating mode.
    ///
    /// Determines when the kill switch should activate. See the module
    /// docs for the variant ↔ UI label mapping.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    pub enum KillSwitchMode {
        /// No traffic blocking. Slug: `off`.
        #[default]
        Off,
        /// Blocks only on unexpected VPN drops, releases on manual
        /// disconnect. Slug: `block-on-drop`.
        Auto,
        /// Keeps the firewall engaged whether VPN is up or down
        /// (default-DROP egress + per-tunnel ACCEPT rules). Slug:
        /// `vpn-only`.
        AlwaysOn,
    }

    impl KillSwitchMode {
        /// The label users read for this mode — same string in TUI,
        /// `vortix status`, `vortix killswitch`, and the JSON envelope.
        /// See the module docs for the full mapping. Every display path
        /// must route through this helper (don't hardcode strings).
        #[must_use]
        pub const fn display_name(self) -> &'static str {
            match self {
                Self::Off => "Off",
                Self::Auto => "Block on drop",
                Self::AlwaysOn => "VPN-only",
            }
        }

        /// CLI input verb — the kebab-case slug accepted by
        /// `vortix killswitch <verb>` and shown in `--help`. Same
        /// vocabulary as `display_name`, just typing-friendly.
        #[must_use]
        pub const fn cli_verb(self) -> &'static str {
            match self {
                Self::Off => "off",
                Self::Auto => "block-on-drop",
                Self::AlwaysOn => "vpn-only",
            }
        }

        /// Parse a user-typed CLI verb back into [`KillSwitchMode`].
        /// Case-insensitive over the slugs returned by [`Self::cli_verb`].
        /// Returns `None` for any other string — callers should surface a
        /// "Use: off, block-on-drop, vpn-only" hint.
        #[must_use]
        pub fn from_cli_verb(verb: &str) -> Option<Self> {
            match verb.to_ascii_lowercase().as_str() {
                "off" => Some(Self::Off),
                "block-on-drop" => Some(Self::Auto),
                "vpn-only" => Some(Self::AlwaysOn),
                _ => None,
            }
        }

        /// One-sentence behaviour summary for hover-style help / toasts.
        #[must_use]
        pub const fn one_liner(self) -> &'static str {
            match self {
                Self::Off => "All traffic flows. If the VPN drops, your real IP is exposed.",
                Self::Auto => {
                    "If the VPN drops unexpectedly, block all traffic until you reconnect."
                }
                Self::AlwaysOn => {
                    "Only traffic through active VPN tunnels. No internet without a VPN."
                }
            }
        }

        /// The desired `KillSwitchState` for this mode given the current
        /// connection status and the previous state. The canonical control
        /// service combines this policy decision with authenticated platform
        /// read-back before publishing effective protection truth.
        ///
        /// | Mode       | `is_connected` | `old_state`   | result     |
        /// |------------|----------------|---------------|------------|
        /// | `Off`      | (any)          | (any)         | `Disabled` |
        /// | `Auto`     | true           | (any)         | `Armed`    |
        /// | `Auto`     | false          | Blocking/Degraded | `Blocking` |
        /// | `Auto`     | false          | Disabled/Armed | `Armed`    |
        /// | `AlwaysOn` | (any)          | (any)         | `Blocking` |
        ///
        /// `AlwaysOn` always resolves to `Blocking` — the firewall stays
        /// engaged whether the VPN is up or down. That's the canonical
        /// Linux killswitch shape; tested by
        /// `tests/integration/killswitch.sh`.
        ///
        /// # What the canonical control service delivers
        ///
        /// This is the policy the deprecated direct shim applies. The canonical
        /// control service publishes effective state from firewall read-back
        /// instead, so it delivers every row above *except* `Auto` + not
        /// connected ⇒ `Blocking`: the pre-tunnel barrier does engage the
        /// firewall on an unexpected drop, but it installs it without a gate
        /// read-back, so no evidence reaches the snapshot to report it with.
        /// See P0-22 in `docs/manual-testing/P0.md`.
        #[must_use]
        pub const fn desired_state(
            self,
            old_state: KillSwitchState,
            is_connected: bool,
        ) -> KillSwitchState {
            match self {
                Self::Off => KillSwitchState::Disabled,
                Self::Auto => {
                    if is_connected {
                        KillSwitchState::Armed
                    } else if matches!(
                        old_state,
                        KillSwitchState::Blocking | KillSwitchState::Degraded
                    ) {
                        KillSwitchState::Blocking
                    } else {
                        KillSwitchState::Armed
                    }
                }
                Self::AlwaysOn => KillSwitchState::Blocking,
            }
        }

        /// Two-line "what happens when …" explainer, suitable for the
        /// Security Guard panel.
        ///
        /// Returns `(vpn_up_line, vpn_down_line)`.
        #[must_use]
        pub const fn behavior_lines(self) -> (&'static str, &'static str) {
            match self {
                Self::Off => (
                    "VPN up: all traffic flows freely.",
                    "VPN down: real IPv4 (and IPv6, if present) exposed.",
                ),
                Self::Auto => (
                    "VPN up: browse normally.",
                    "VPN down: traffic blocks until reconnect or `release-killswitch`.",
                ),
                Self::AlwaysOn => (
                    "VPN up: only tunnel traffic permitted.",
                    "VPN down: no internet at all (canonical kill-switch shape).",
                ),
            }
        }
    }

    impl KillSwitchMode {
        /// Cycle to next mode: Off → Auto → `AlwaysOn` → Off
        #[must_use]
        pub fn next(self) -> Self {
            match self {
                Self::Off => Self::Auto,
                Self::Auto => Self::AlwaysOn,
                Self::AlwaysOn => Self::Off,
            }
        }
    }

    /// Current kill switch operational state. `Degraded` is the explicit
    /// no-claim state when policy application or read-back cannot be proven.
    ///
    /// Like [`KillSwitchMode`], renders through helper methods rather
    /// than the variant name. [`Self::display_status`] is the prose form
    /// shown to humans; [`Self::cli_verb`] is the slug used in the JSON
    /// envelope and log lines.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    pub enum KillSwitchState {
        /// Kill switch is disabled (mode = Off). Slug: `inactive`.
        #[default]
        Disabled,
        /// Armed and ready to block, but the firewall is not yet engaged.
        /// Reached when mode = Auto and a VPN is up — we're watching for
        /// a drop. Slug: `watching`.
        Armed,
        /// Firewall is actively engaged. Reached either by `AlwaysOn` mode
        /// (steady state) or by `Auto` mode after detecting a VPN drop.
        /// Slug: `blocking`.
        Blocking,
        /// A firewall mutation or ownership read-back failed, or previously
        /// verified evidence became stale. No protection claim is valid until a
        /// fresh synchronization succeeds. Slug: `degraded`.
        Degraded,
    }

    impl KillSwitchState {
        /// Check if currently blocking traffic
        #[must_use]
        pub const fn is_blocking(self) -> bool {
            matches!(self, Self::Blocking)
        }

        /// Prose form shown to humans (`Inactive` / `Watching` / `Blocking` /
        /// `Degraded`). One vocabulary across TUI, CLI, and JSON — same
        /// letters as [`Self::cli_verb`], just capitalised.
        #[must_use]
        pub const fn display_status(self) -> &'static str {
            match self {
                Self::Disabled => "Inactive",
                Self::Armed => "Watching",
                Self::Blocking => "Blocking",
                Self::Degraded => "Degraded",
            }
        }

        /// Slug used in the JSON envelope and log lines. Lower-cased
        /// form of [`Self::display_status`].
        #[must_use]
        pub const fn cli_verb(self) -> &'static str {
            match self {
                Self::Disabled => "inactive",
                Self::Armed => "watching",
                Self::Blocking => "blocking",
                Self::Degraded => "degraded",
            }
        }

        /// Optional detail paired with [`Self::display_status`] on compact human
        /// surfaces. Keeping this copy here prevents TUI/CLI wording drift.
        #[must_use]
        pub const fn status_detail(self) -> Option<&'static str> {
            match self {
                Self::Degraded => Some("firewall policy unverified"),
                Self::Disabled | Self::Armed | Self::Blocking => None,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_mode_cycle() {
            assert_eq!(KillSwitchMode::Off.next(), KillSwitchMode::Auto);
            assert_eq!(KillSwitchMode::Auto.next(), KillSwitchMode::AlwaysOn);
            assert_eq!(KillSwitchMode::AlwaysOn.next(), KillSwitchMode::Off);
        }

        #[test]
        fn test_state_is_blocking() {
            assert!(!KillSwitchState::Disabled.is_blocking());
            assert!(!KillSwitchState::Armed.is_blocking());
            assert!(KillSwitchState::Blocking.is_blocking());
            assert!(!KillSwitchState::Degraded.is_blocking());
            assert_eq!(
                KillSwitchState::Degraded.status_detail(),
                Some("firewall policy unverified")
            );
        }

        #[test]
        fn off_mode_always_disabled() {
            for old in [
                KillSwitchState::Disabled,
                KillSwitchState::Armed,
                KillSwitchState::Blocking,
                KillSwitchState::Degraded,
            ] {
                for is_connected in [false, true] {
                    assert_eq!(
                    KillSwitchMode::Off.desired_state(old, is_connected),
                    KillSwitchState::Disabled,
                    "Off should always resolve to Disabled (old={old:?}, is_connected={is_connected})"
                );
                }
            }
        }

        #[test]
        fn auto_mode_is_armed_when_connected_blocking_when_dropped() {
            // Connected → Armed (watching).
            assert_eq!(
                KillSwitchMode::Auto.desired_state(KillSwitchState::Armed, true),
                KillSwitchState::Armed
            );
            // Not connected from a fresh state → Armed.
            assert_eq!(
                KillSwitchMode::Auto.desired_state(KillSwitchState::Disabled, false),
                KillSwitchState::Armed
            );
            assert_eq!(
                KillSwitchMode::Auto.desired_state(KillSwitchState::Armed, false),
                KillSwitchState::Armed
            );
            // Not connected from a Blocking state → stays Blocking (preserves
            // the post-drop block until user reconnects or releases).
            assert_eq!(
                KillSwitchMode::Auto.desired_state(KillSwitchState::Blocking, false),
                KillSwitchState::Blocking
            );
            assert_eq!(
                KillSwitchMode::Auto.desired_state(KillSwitchState::Degraded, false),
                KillSwitchState::Blocking,
                "degraded prior blocking intent must retry verification"
            );
        }

        /// Regression for the `AlwaysOn` killswitch semantic fix (commit
        /// `34f07e3`). Pre-fix, `AlwaysOn + is_connected → Armed` left the
        /// firewall NOT engaged — the gap between a drop and reconnect
        /// could leak. The integration test `tests/integration/killswitch.sh`
        /// catches the kernel-level miss; this test catches the policy
        /// decision at the pure-function level so a regression fires
        /// here first.
        #[test]
        fn always_on_resolves_to_blocking_regardless_of_connection_or_history() {
            for old in [
                KillSwitchState::Disabled,
                KillSwitchState::Armed,
                KillSwitchState::Blocking,
                KillSwitchState::Degraded,
            ] {
                for is_connected in [false, true] {
                    assert_eq!(
                        KillSwitchMode::AlwaysOn.desired_state(old, is_connected),
                        KillSwitchState::Blocking,
                        "AlwaysOn must always resolve to Blocking — that's the \
                     whole point of the mode. old={old:?}, \
                     is_connected={is_connected}"
                    );
                }
            }
        }

        /// `cli_verb` ↔ `from_cli_verb` round-trip on every variant. Pins
        /// the canonical CLI vocabulary so a future rename can't silently
        /// drift the user-typed grammar away from what the help text and
        /// docs advertise.
        #[test]
        fn cli_verb_roundtrips_for_every_variant() {
            for mode in [
                KillSwitchMode::Off,
                KillSwitchMode::Auto,
                KillSwitchMode::AlwaysOn,
            ] {
                assert_eq!(
                    KillSwitchMode::from_cli_verb(mode.cli_verb()),
                    Some(mode),
                    "cli_verb / from_cli_verb must round-trip for {mode:?}"
                );
            }
            // The three canonical slugs are exactly what the help text
            // promises. If you change one of these, change the help text,
            // the README mapping table, and CLAUDE.md in the same commit.
            assert_eq!(KillSwitchMode::Off.cli_verb(), "off");
            assert_eq!(KillSwitchMode::Auto.cli_verb(), "block-on-drop");
            assert_eq!(KillSwitchMode::AlwaysOn.cli_verb(), "vpn-only");
        }

        /// Case-insensitive on the canonical slugs; everything else is
        /// rejected with `None`. In particular, the legacy verbs
        /// (`auto`, `always`, `always-on`) and the title-cased UI prose
        /// (`VPN-only`) are NOT accepted — the parser only takes the
        /// kebab-case slugs.
        #[test]
        fn from_cli_verb_rejects_legacy_and_prose_forms() {
            assert_eq!(
                KillSwitchMode::from_cli_verb("VPN-ONLY"),
                Some(KillSwitchMode::AlwaysOn),
                "slugs must be case-insensitive"
            );
            assert_eq!(
                KillSwitchMode::from_cli_verb("Block-On-Drop"),
                Some(KillSwitchMode::Auto)
            );
            for rejected in [
                "auto",
                "always",
                "always-on",
                "alwayson",
                "VPN only", // space, not dash
                "blockondrop",
                "",
                "vpn-only-extra",
            ] {
                assert!(
                    KillSwitchMode::from_cli_verb(rejected).is_none(),
                    "must reject '{rejected}' — only the canonical slugs are valid"
                );
            }
        }
    }
}

use crate::constants;
use crate::logger::{self, LogLevel};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

/// Stable digest of the complete requested firewall policy.
///
/// The digest is independent of caller iteration order: tunnels, endpoints,
/// and declared CIDRs are sorted before hashing. Platform adapters stamp a
/// platform-safe encoding of this digest identity into their owned rules and
/// require the same value during read-back, so a successful command alone can
/// never promote protection truth.
#[must_use]
pub fn policy_digest(active: &[ActiveTunnelInfo]) -> String {
    crate::profile::hex(&policy_digest_bytes(active))
}

/// Raw policy digest for platform formats with constrained encodings.
pub(crate) fn policy_digest_bytes(active: &[ActiveTunnelInfo]) -> [u8; 32] {
    let mut tunnels: Vec<String> = active
        .iter()
        .map(|tunnel| {
            let mut endpoints: Vec<String> =
                tunnel.server_ips.iter().map(ToString::to_string).collect();
            endpoints.sort_unstable();
            let mut cidrs: Vec<String> = tunnel
                .declared_cidrs
                .iter()
                .map(ToString::to_string)
                .collect();
            cidrs.sort_unstable();
            format!(
                "{}|{}|{}|{}",
                tunnel.interface,
                tunnel.is_primary,
                endpoints.join(","),
                cidrs.join(",")
            )
        })
        .collect();
    tunnels.sort_unstable();

    Sha256::digest(tunnels.join("\n").as_bytes()).into()
}

/// Validate values that platform adapters interpolate into firewall syntax.
/// Typed addresses/CIDRs are already syntax-safe; interface names are the
/// remaining text boundary and must fit the common Unix IFNAMSIZ contract.
///
/// # Errors
///
/// Returns [`KillswitchError::InvalidPolicy`] for empty, overlong, or
/// non-portable interface names.
pub fn validate_policy(active: &[ActiveTunnelInfo]) -> Result<()> {
    for tunnel in active {
        let endpoint_allowlist = tunnel.is_endpoint_allowlist()
            && !tunnel.server_ips.is_empty()
            && tunnel.declared_cidrs.is_empty()
            && !tunnel.is_primary;
        if !endpoint_allowlist && !crate::profile::is_safe_interface_name(&tunnel.interface) {
            return Err(KillswitchError::InvalidPolicy(format!(
                "unsafe interface name {:?}",
                tunnel.interface
            )));
        }
        if tunnel.is_endpoint_allowlist() && !endpoint_allowlist {
            return Err(KillswitchError::InvalidPolicy(
                "endpoint-only policy entries require at least one server IP and no route role"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Enable kill switch with a per-tunnel ruleset.
///
/// The per-OS impl in `macos`/`linux` synthesises
/// allow rules for every entry in `active` plus an RFC1918 base with
/// secondary-declared CIDRs subtracted.
///
/// replaces the legacy single-tunnel
/// `enable_blocking(interface, server_ip)` form with this slice-based
/// API. Callers building from a single connection should construct a
/// one-element slice; see [`ActiveTunnelInfo`].
///
/// # Errors
///
/// Returns error if not running as root or firewall commands fail.
pub fn enable_blocking_multi(active: &[ActiveTunnelInfo]) -> Result<()> {
    crate::platform::Firewall::enable_blocking_multi(active)
}

/// Disable kill switch by flushing firewall rules.
///
/// # Errors
///
/// Returns error if not running as root or firewall commands fail.
pub fn disable_blocking() -> Result<()> {
    crate::platform::Firewall::disable_blocking()
}

/// Prove that no Vortix-owned firewall policy remains without mutating it.
pub fn verify_disabled() -> Result<()> {
    crate::platform::Firewall::verify_disabled()
}

/// Get the state file path.
fn get_state_path() -> Option<PathBuf> {
    crate::config::get_config_dir()
        .ok()
        .map(|dir| dir.join(constants::KILLSWITCH_STATE_FILE))
}

/// Current `PersistedState` on-disk schema version. V1 (pre-multi-connection)
/// carried only `vpn_interface`/`vpn_server_ip`; V2 adds `active_tunnels` for the multi-tunnel killswitch.
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
/// **Schema versioning:** This struct
/// transparently absorbs both V1 (single-tunnel — `vpn_interface` +
/// `vpn_server_ip`) and V2 (multi-tunnel — `active_tunnels`) on-disk
/// forms via `#[serde(default)]`. On load, V1 files are coerced into V2
/// shape; the next save writes V2 explicitly.
///
/// The V1 legacy fields remain on the struct for two reasons:
/// 1. Direct deserialization of V1 files without a separate type.
/// 2. Downgrade compatibility — V2 writes currently leave them as `None`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedState {
    /// On-disk schema version. Missing or `1` means V1; `2` means V2.
    /// Unknown future values are rejected rather than destructively
    /// reinterpreted as an older shape.
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
    pub mode: KillSwitchMode,
    pub state: KillSwitchState,
    /// Expanded effective truth for new readers. The legacy `state` field is
    /// kept downgrade-readable (`Degraded` is encoded there as `Armed`).
    #[serde(default)]
    pub effective_state: Option<KillSwitchState>,
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
    /// Durable fence written by `release-killswitch`. Canonical startup must
    /// honor this even when the control journal was temporarily unreadable
    /// during the emergency release.
    #[serde(default)]
    pub emergency_release_fence: bool,
}

impl PersistedState {
    /// The state a reader may present for a record loaded from disk. A
    /// `Blocking` record is a request, not proof: it stands only while a live
    /// read-back finds that exact policy in the firewall, and reads as
    /// `Degraded` otherwise. Every reader routes through here.
    #[must_use]
    pub fn live_state(&self) -> KillSwitchState {
        let state = self.effective_state.unwrap_or(self.state);
        if state != KillSwitchState::Blocking {
            return state;
        }
        let verified = active_from_persisted(&self.active_tunnels)
            .is_some_and(|active| crate::platform::Firewall::verify_blocking(&active).is_ok());
        if verified {
            KillSwitchState::Blocking
        } else {
            KillSwitchState::Degraded
        }
    }
}

/// Why persisted kill-switch truth could not be loaded safely.
#[derive(Debug)]
pub enum PersistedStateLoadError {
    ConfigDirectory(io::Error),
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    UnsupportedSchema(u8),
}

impl fmt::Display for PersistedStateLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDirectory(error) => {
                write!(
                    formatter,
                    "cannot resolve the kill-switch state directory: {error}"
                )
            }
            Self::Read { path, source } => {
                write!(formatter, "cannot read {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(formatter, "cannot parse {}: {source}", path.display())
            }
            Self::UnsupportedSchema(schema) => write!(
                formatter,
                "kill-switch state uses unsupported schema version {schema}"
            ),
        }
    }
}

impl std::error::Error for PersistedStateLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfigDirectory(error) => Some(error),
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::UnsupportedSchema(_) => None,
        }
    }
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

fn migrate_supported_schema(state: &mut PersistedState) -> std::result::Result<(), u8> {
    match state.schema_version {
        0 | 1 => {
            coerce_v1_to_v2(state);
            Ok(())
        }
        PERSISTED_STATE_SCHEMA_V2 => Ok(()),
        unsupported => Err(unsupported),
    }
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
        // Empty-interface entries are endpoint-only vpn-only reconnect
        // allowances, not phantom kernel tunnels.
        if t.interface.is_empty() || live.iter().any(|name| name == &t.interface) {
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
///
/// # Errors
///
/// Returns an error when the state path cannot be resolved/read, the JSON is
/// invalid, or a newer schema cannot be interpreted safely.
pub fn load_state_checked() -> std::result::Result<Option<PersistedState>, PersistedStateLoadError>
{
    let path = crate::config::get_config_dir()
        .map_err(PersistedStateLoadError::ConfigDirectory)?
        .join(constants::KILLSWITCH_STATE_FILE);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(PersistedStateLoadError::Read { path, source }),
    };
    let mut persisted = decode_persisted_state(&content, &path)?;
    let live = crate::platform::available_network_interfaces();
    filter_phantom_tunnels(&mut persisted, &live);

    Ok(Some(persisted))
}

fn decode_persisted_state(
    content: &str,
    path: &std::path::Path,
) -> std::result::Result<PersistedState, PersistedStateLoadError> {
    let mut persisted: PersistedState =
        serde_json::from_str(content).map_err(|source| PersistedStateLoadError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    if let Some(effective) = persisted.effective_state {
        persisted.state = effective;
    }

    logger::log(
        LogLevel::Debug,
        "FIREWALL",
        format!(
            "Loaded persisted state from {} (schema v{})",
            path.display(),
            persisted.schema_version
        ),
    );

    let legacy_schema = matches!(persisted.schema_version, 0 | 1);
    if legacy_schema
        && (!persisted.active_tunnels.is_empty()
            || persisted.vpn_interface.is_some()
            || persisted.vpn_server_ip.is_some())
    {
        logger::log(
            LogLevel::Info,
            "FIREWALL",
            "Migrating persisted killswitch state V1 → V2".to_string(),
        );
    }
    if let Err(other) = migrate_supported_schema(&mut persisted) {
        tracing::warn!(
            target: "FIREWALL",
            schema = other,
            "Unknown PersistedState schema version; refusing to reinterpret future state"
        );
        return Err(PersistedStateLoadError::UnsupportedSchema(other));
    }

    Ok(persisted)
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
    save_state_at(&path, mode, state, active_tunnels, false)
}

/// Persist an emergency `off` intent that fences any temporarily unreadable
/// control journal from re-engaging an older blocking mode later.
///
/// # Errors
///
/// Returns [`KillswitchError::Io`] when the state cannot be durably replaced.
pub(crate) fn save_emergency_release_state(config_dir: &std::path::Path) -> Result<()> {
    save_state_at(
        &config_dir.join(constants::KILLSWITCH_STATE_FILE),
        KillSwitchMode::Off,
        KillSwitchState::Disabled,
        Vec::new(),
        true,
    )
}

fn save_state_at(
    path: &std::path::Path,
    mode: KillSwitchMode,
    state: KillSwitchState,
    active_tunnels: Vec<PersistedTunnelInfo>,
    emergency_release_fence: bool,
) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let legacy_state = if state == KillSwitchState::Degraded {
        KillSwitchState::Armed
    } else {
        state
    };
    let persisted = PersistedState {
        schema_version: PERSISTED_STATE_SCHEMA_V2,
        mode,
        state: legacy_state,
        effective_state: Some(state),
        // V1 fields, left empty on V2 writes so older readers still parse.
        vpn_interface: None,
        vpn_server_ip: None,
        active_tunnels,
        emergency_release_fence,
    };

    let content = serde_json::to_string_pretty(&persisted).map_err(io::Error::other)?;

    atomic_write(path, content.as_bytes())?;
    Ok(())
}

fn active_from_persisted(active: &[PersistedTunnelInfo]) -> Option<Vec<ActiveTunnelInfo>> {
    active
        .iter()
        .map(|tunnel| {
            Some(ActiveTunnelInfo {
                interface: tunnel.interface.clone(),
                server_ips: tunnel
                    .server_ips
                    .iter()
                    .map(|ip| ip.parse().ok())
                    .collect::<Option<Vec<_>>>()?,
                declared_cidrs: tunnel
                    .declared_cidrs
                    .iter()
                    .map(|cidr| cidr.parse().ok())
                    .collect::<Option<Vec<_>>>()?,
                is_primary: tunnel.is_primary,
            })
        })
        .collect()
}

/// Convenience helper: build a `PersistedTunnelInfo` slice from
/// `ActiveTunnelInfo` and persist. Callers holding the live engine snapshot
/// can stringify in one place.
#[must_use]
pub fn persisted_from_active(active: &[ActiveTunnelInfo]) -> Vec<PersistedTunnelInfo> {
    active
        .iter()
        .map(|a| PersistedTunnelInfo {
            interface: a.interface.clone(),
            server_ips: a.server_ips.iter().map(ToString::to_string).collect(),
            declared_cidrs: a.declared_cidrs.iter().map(ToString::to_string).collect(),
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
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "kill-switch state has no parent",
        )
    })?;
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "kill-switch state name is not valid UTF-8",
            )
        })?;
    let (uid, gid) = crate::config::config_owner(parent).map_err(io::Error::other)?;
    let directory = crate::config::owned_file::open_owned_directory(parent, false, uid, gid)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config directory is missing"))?;
    crate::config::owned_file::write_owned_atomic(&directory, name, contents, uid, gid)
        .map_err(io::Error::other)
}

/// The kill-switch mode and state recorded on disk; `Degraded` when the
/// record exists but cannot be verified.
#[must_use]
pub fn persisted() -> (KillSwitchMode, KillSwitchState) {
    match load_state_checked() {
        Ok(Some(persisted)) => (persisted.mode, persisted.live_state()),
        Ok(None) => (KillSwitchMode::default(), KillSwitchState::default()),
        Err(error) => {
            tracing::warn!(%error, "kill-switch state could not be verified");
            (KillSwitchMode::default(), KillSwitchState::Degraded)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_digest_covers_full_policy_but_not_iteration_order() {
        use crate::cidr::Cidr;
        use std::net::IpAddr;

        let first = ActiveTunnelInfo {
            interface: "wg0".to_string(),
            server_ips: vec!["1.2.3.4".parse::<IpAddr>().unwrap()],
            declared_cidrs: vec!["0.0.0.0/0".parse::<Cidr>().unwrap()],
            is_primary: true,
        };
        let second = ActiveTunnelInfo {
            interface: "wg1".to_string(),
            server_ips: vec!["2001:db8::1".parse::<IpAddr>().unwrap()],
            declared_cidrs: vec!["10.0.0.0/8".parse::<Cidr>().unwrap()],
            is_primary: false,
        };

        assert_eq!(
            policy_digest(&[first.clone(), second.clone()]),
            policy_digest(&[second.clone(), first.clone()])
        );

        let mut changed = second;
        changed.interface = "wg2".to_string();
        assert_ne!(
            policy_digest(&[first.clone(), changed]),
            policy_digest(&[first])
        );
    }

    #[test]
    fn policy_validation_rejects_firewall_script_injection() {
        let malicious = ActiveTunnelInfo {
            interface: "wg0\nblock all".to_string(),
            server_ips: Vec::new(),
            declared_cidrs: Vec::new(),
            is_primary: true,
        };
        assert!(matches!(
            validate_policy(&[malicious]),
            Err(KillswitchError::InvalidPolicy(_))
        ));
        let safe = ActiveTunnelInfo {
            interface: "wg-corp.1".to_string(),
            server_ips: Vec::new(),
            declared_cidrs: Vec::new(),
            is_primary: true,
        };
        assert!(validate_policy(&[safe]).is_ok());
    }

    #[test]
    fn endpoint_allowlist_is_valid_only_with_resolved_servers() {
        let valid = ActiveTunnelInfo::endpoint_allowlist(vec!["1.2.3.4".parse().unwrap()]);
        assert!(validate_policy(&[valid]).is_ok());
        let empty = ActiveTunnelInfo::endpoint_allowlist(Vec::new());
        assert!(matches!(
            validate_policy(&[empty]),
            Err(KillswitchError::InvalidPolicy(_))
        ));
    }

    /// Non-blocking states are already claims about absence, which the modes
    /// themselves assert; they pass through untouched.
    #[test]
    fn persisted_non_blocking_states_pass_through() {
        for state in [
            KillSwitchState::Disabled,
            KillSwitchState::Armed,
            KillSwitchState::Degraded,
        ] {
            let record = PersistedState {
                schema_version: PERSISTED_STATE_SCHEMA_V2,
                mode: KillSwitchMode::Auto,
                state: KillSwitchState::Armed,
                effective_state: Some(state),
                vpn_interface: None,
                vpn_server_ip: None,
                active_tunnels: Vec::new(),
                emergency_release_fence: false,
            };
            assert_eq!(record.live_state(), state);
        }
    }

    #[test]
    fn v2_persisted_state_round_trips() {
        let state = PersistedState {
            schema_version: PERSISTED_STATE_SCHEMA_V2,
            mode: KillSwitchMode::Auto,
            state: KillSwitchState::Armed,
            effective_state: None,
            vpn_interface: None,
            vpn_server_ip: None,
            active_tunnels: vec![PersistedTunnelInfo {
                interface: "utun3".to_string(),
                server_ips: vec!["1.2.3.4".to_string()],
                declared_cidrs: vec!["10.0.0.0/8".to_string()],
                is_primary: true,
            }],
            emergency_release_fence: false,
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
            effective_state: None,
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
                PersistedTunnelInfo {
                    interface: String::new(),
                    server_ips: vec!["203.0.113.19".into()],
                    declared_cidrs: Vec::new(),
                    is_primary: false,
                },
            ],
            emergency_release_fence: false,
        };
        let live = vec!["lo".to_string(), "eth0".to_string()];
        filter_phantom_tunnels(&mut state, &live);
        assert_eq!(state.active_tunnels.len(), 2);
        assert_eq!(state.active_tunnels[0].interface, "eth0");
        assert!(state.active_tunnels[1].interface.is_empty());
    }

    #[test]
    fn filter_phantom_tunnels_noop_on_empty_live_list() {
        // Empty `live` means "unknown" — preserve persisted state.
        let mut state = PersistedState {
            schema_version: PERSISTED_STATE_SCHEMA_V2,
            mode: KillSwitchMode::Auto,
            state: KillSwitchState::Armed,
            effective_state: None,
            vpn_interface: None,
            vpn_server_ip: None,
            active_tunnels: vec![PersistedTunnelInfo {
                interface: "utun99".to_string(),
                server_ips: Vec::new(),
                declared_cidrs: Vec::new(),
                is_primary: true,
            }],
            emergency_release_fence: false,
        };
        filter_phantom_tunnels(&mut state, &[]);
        assert_eq!(state.active_tunnels.len(), 1);
    }

    #[test]
    fn unknown_future_schema_is_rejected_without_rewriting_it() {
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
        assert_eq!(migrate_supported_schema(&mut state), Err(99));
        assert_eq!(state.schema_version, 99);
        assert_eq!(state.active_tunnels.len(), 1);
        assert!(matches!(
            decode_persisted_state(json, std::path::Path::new("killswitch.state")),
            Err(PersistedStateLoadError::UnsupportedSchema(99))
        ));
    }

    #[test]
    fn atomic_write_does_not_follow_the_legacy_predictable_temp_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(constants::KILLSWITCH_STATE_FILE);
        let victim = directory.path().join("victim");
        fs::write(&victim, b"must survive").unwrap();
        let legacy_temp = path.with_extension("json.tmp");
        symlink(&victim, &legacy_temp).unwrap();

        atomic_write(&path, b"hello").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"hello");
        assert_eq!(fs::read(&victim).unwrap(), b"must survive");
        assert!(legacy_temp.is_symlink());
    }

    #[test]
    fn persisted_from_active_stringifies_addresses_and_cidrs() {
        use crate::cidr::Cidr;
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

    /// Forward-compat integration check: a v0.3.x reader of
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

    #[test]
    fn degraded_write_remains_readable_as_armed_to_v0_3() {
        #[derive(Debug, serde::Deserialize)]
        struct V1PersistedState {
            state: KillSwitchState,
        }

        let state = PersistedState {
            schema_version: PERSISTED_STATE_SCHEMA_V2,
            mode: KillSwitchMode::AlwaysOn,
            state: KillSwitchState::Armed,
            effective_state: Some(KillSwitchState::Degraded),
            vpn_interface: None,
            vpn_server_ip: None,
            active_tunnels: Vec::new(),
            emergency_release_fence: false,
        };
        let json = serde_json::to_string(&state).unwrap();
        let old: V1PersistedState = serde_json::from_str(&json).unwrap();
        assert_eq!(old.state, KillSwitchState::Armed);

        let mut current: PersistedState = serde_json::from_str(&json).unwrap();
        current.state = current.effective_state.unwrap_or(current.state);
        assert_eq!(current.state, KillSwitchState::Degraded);
    }
}

use std::net::IpAddr;

use thiserror::Error;

use crate::cidr::Cidr;

/// Result alias for kill-switch operations.
pub type Result<T> = std::result::Result<T, KillswitchError>;

/// Errors that can occur during kill-switch operations.
#[derive(Debug, Error)]
pub enum KillswitchError {
    /// The normalized policy contains an unsafe or unsupported value.
    #[error("invalid kill-switch policy: {0}")]
    InvalidPolicy(String),
    /// A firewall subprocess returned a non-zero exit or otherwise failed.
    #[error("firewall command failed: {0}")]
    CommandFailed(String),
    /// I/O error (reading/writing pf config, opening sockets, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The caller is not running as root and the operation requires root.
    #[error("kill switch requires root privileges")]
    NotRoot,
    /// No safe firewall backend is available on this host (Linux requires
    /// `nft`; split-family iptables replacement cannot be atomic).
    #[error("no firewall backend available on this host")]
    NoBackendAvailable,
}

/// Per-tunnel state needed to synthesise multi-interface killswitch
/// rules. The platform impl uses the interface name for interface-allow
/// rules, the server IPs for reconnect-allow rules, and the declared
/// CIDRs to subtract from the RFC1918 base when this tunnel is a
/// secondary.
///
/// Primary tunnels (claiming the default route, `is_primary == true`)
/// do **not** contribute to RFC1918 subtraction — their interface allow
/// rule covers all egress, and subtracting `0.0.0.0/0` would strip
/// loopback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveTunnelInfo {
    /// VPN tunnel interface name, e.g. `"utun3"` (macOS) or `"wg0"` (Linux).
    pub interface: String,
    /// Server IPs to allow for reconnection. May be empty if the tunnel
    /// has no externally observable server endpoint (mock / dev).
    pub server_ips: Vec<IpAddr>,
    /// CIDRs this tunnel declares as its routed scope. Used only for
    /// secondaries: subtracted from the RFC1918 base so traffic to those
    /// nets cannot escape onto the underlay.
    pub declared_cidrs: Vec<Cidr>,
    /// `true` when this tunnel claims the default route (primary).
    /// Primaries are excluded from RFC1918 subtraction.
    pub is_primary: bool,
}

pub(crate) const FIREWALL_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const FIREWALL_OUTPUT_LIMIT: usize = 1024 * 1024;

/// The LAN egress both firewalls allow: RFC1918 minus every secondary's
/// declared CIDRs, so traffic to those nets cannot escape onto the underlay.
pub(crate) fn lan_allowance(active: &[ActiveTunnelInfo]) -> Vec<Cidr> {
    let secondary_cidrs: Vec<Cidr> = active
        .iter()
        .filter(|tunnel| !tunnel.is_primary)
        .flat_map(|tunnel| tunnel.declared_cidrs.iter().copied())
        .collect();
    crate::cidr::cidr_subtract(&crate::cidr::rfc1918_ranges(), &secondary_cidrs)
}

#[cfg(test)]
pub(crate) fn test_tunnel(
    interface: &str,
    server_ips: &[&str],
    declared: &[&str],
    is_primary: bool,
) -> ActiveTunnelInfo {
    ActiveTunnelInfo {
        interface: interface.to_string(),
        server_ips: server_ips.iter().map(|s| s.parse().unwrap()).collect(),
        declared_cidrs: declared.iter().map(|s| s.parse().unwrap()).collect(),
        is_primary,
    }
}

impl ActiveTunnelInfo {
    /// Policy-only endpoint allowance used while a tunnel interface does not
    /// exist yet. Platform adapters emit only the destination exceptions and
    /// never an interface allow rule for this value.
    #[must_use]
    pub fn endpoint_allowlist(server_ips: Vec<IpAddr>) -> Self {
        Self {
            interface: String::new(),
            server_ips,
            declared_cidrs: Vec::new(),
            is_primary: false,
        }
    }

    #[must_use]
    pub fn is_endpoint_allowlist(&self) -> bool {
        self.interface.is_empty()
    }
}
