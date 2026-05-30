//! Per-profile retry / auto-reconnect state.
//!
//! Replaces the single-slot `retry_count` + `retry_profile_idx` +
//! `auto_reconnect_profile` triple on `VpnRuntime` with a
//! `HashMap<ProfileId, RetryState>` (`VpnRuntime::retry_state`) so each
//! tunnel's retry is independent — a connect-failure on profile A no
//! longer overwrites or blocks an auto-reconnect on profile B.
//!
//! Plan P5b U-P5b-1: per-profile retry. See
//! `docs/plans/2026-05-30-002-refactor-retire-legacy-connectionstate-plan.md`.

/// Per-profile retry attempt bookkeeping.
///
/// The `HashMap` key (a `ProfileId`) identifies the profile; this struct
/// carries the attempt number, the original profile index (preserved so
/// the legacy `Message::RetryConnect { idx, .. }` can still locate the
/// profile after a sort reorder), and whether the retry was triggered
/// by an unexpected drop (auto-reconnect) vs a user-initiated connect
/// that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryState {
    /// 1-based attempt counter for the current retry sequence.
    /// Matches the `attempt` field on `Message::RetryConnect`. Incremented
    /// on every connect-failure that still has retry budget remaining.
    pub attempt: u32,
    /// Profile index at the time the retry was scheduled. Used as a
    /// stale-check value: if the user reorders profiles or imports new
    /// ones, the saved index may no longer point to the same profile,
    /// in which case the retry is treated as stale and dropped.
    pub profile_idx: usize,
    /// `true` when this retry was triggered by an unexpected drop
    /// (scanner saw the kernel interface disappear) rather than a
    /// user-initiated connect that failed. Used to differentiate
    /// "VPN dropped — reconnecting" toasts from "Retry 2/3" toasts and
    /// to drive the network-changed re-trigger path.
    pub auto_reconnect: bool,
}
