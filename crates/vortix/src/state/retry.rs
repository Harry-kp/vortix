//! Per-profile retry / auto-reconnect state.
//!
//! Replaces the single-slot `retry_count` + `retry_profile_idx` +
//! `auto_reconnect_profile` triple on `VpnRuntime` with a
//! `HashMap<ProfileId, RetryState>` (`VpnRuntime::retry_state`) so each
//! tunnel's retry is independent — a connect-failure on profile A no
//! longer overwrites or blocks an auto-reconnect on profile B.
//!
//! Plan per-profile retry. See

/// Per-profile retry attempt bookkeeping.
///
/// The `HashMap` key and this value both retain the stable profile identity.
/// Carrying identity through the delayed message prevents a sort, import, or
/// rename from redirecting a retry to whichever profile later occupies an
/// old list index. The struct also records whether the retry was triggered
/// by an unexpected drop (auto-reconnect) vs a user-initiated connect
/// that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryState {
    /// Stable identity for this retry sequence.
    pub profile_id: crate::vortix_core::profile::ProfileId,
    /// 1-based attempt counter for the current retry sequence.
    /// Matches the `attempt` field on `Message::RetryConnect`. Incremented
    /// on every connect-failure that still has retry budget remaining.
    pub attempt: u32,
    /// `true` when this retry was triggered by an unexpected drop
    /// (scanner saw the kernel interface disappear) rather than a
    /// user-initiated connect that failed. Used to differentiate
    /// "VPN dropped — reconnecting" toasts from "Retry 2/3" toasts and
    /// to drive the network-changed re-trigger path.
    pub auto_reconnect: bool,
}
