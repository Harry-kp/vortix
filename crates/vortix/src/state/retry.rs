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

/// Exponential backoff delay (seconds) for a given 1-based `attempt`.
///
/// `base * 2^(attempt-1)`, saturating, capped at `max_delay`. The shift
/// is clamped to 63 to avoid UB on the left-shift for pathological
/// attempt counts. Pure policy shared by the TUI retry ladder and the
/// daemon supervisor so both compute identical
/// delays.
#[must_use]
pub fn backoff_delay_secs(base: u64, max_delay: u64, attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(63);
    base.saturating_mul(1u64 << shift).min(max_delay)
}

/// Whether a profile at `current_attempt` still has retry budget.
///
/// `max_retries == 0` disables retry entirely. Pure policy shared by
/// the TUI and daemon supervisor so the attempt cap is enforced
/// identically on both surfaces.
#[must_use]
pub fn has_retry_budget(max_retries: u32, current_attempt: u32) -> bool {
    max_retries > 0 && current_attempt < max_retries
}

/// Delay (seconds) before the `attempt`-th reconnect after an unexpected
/// drop. The first attempt waits the fixed `auto_reconnect_delay` (the
/// TUI's drop→reconnect grace window); subsequent attempts use
/// exponential [`backoff_delay_secs`]. Re-homing the reconnect driver
/// into the daemon supervisor must compute the
/// same sequence the TUI does, so this pins it.
#[must_use]
pub fn reconnect_delay_for_attempt(
    attempt: u32,
    auto_reconnect_delay: u64,
    base: u64,
    max_delay: u64,
) -> u64 {
    if attempt <= 1 {
        auto_reconnect_delay
    } else {
        backoff_delay_secs(base, max_delay, attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Characterization: pins today's TUI ladder behavior with the
    // shipped defaults (base=2, max=300, max_retries=3) so the daemon
    // supervisor re-homing cannot silently change the numbers.

    #[test]
    fn backoff_matches_default_ladder_2_4_8() {
        assert_eq!(backoff_delay_secs(2, 300, 1), 2);
        assert_eq!(backoff_delay_secs(2, 300, 2), 4);
        assert_eq!(backoff_delay_secs(2, 300, 3), 8);
    }

    #[test]
    fn backoff_caps_at_max_delay() {
        // attempt 9 would be 2*256=512 uncapped; cap holds at 300.
        assert_eq!(backoff_delay_secs(2, 300, 9), 300);
    }

    #[test]
    fn backoff_shift_clamp_does_not_overflow() {
        // Pathological attempt count must not UB on the shift.
        assert_eq!(backoff_delay_secs(2, 300, u32::MAX), 300);
    }

    #[test]
    fn budget_exhausts_at_max_retries() {
        assert!(has_retry_budget(3, 0));
        assert!(has_retry_budget(3, 2));
        assert!(!has_retry_budget(3, 3));
    }

    #[test]
    fn zero_max_retries_disables_retry() {
        assert!(!has_retry_budget(0, 0));
    }

    #[test]
    fn reconnect_first_attempt_uses_fixed_grace_then_backoff() {
        // Drop grace (auto_reconnect_delay) = 5s; backoff base=2, cap=300.
        assert_eq!(reconnect_delay_for_attempt(1, 5, 2, 300), 5);
        assert_eq!(reconnect_delay_for_attempt(2, 5, 2, 300), 4);
        assert_eq!(reconnect_delay_for_attempt(3, 5, 2, 300), 8);
        assert_eq!(reconnect_delay_for_attempt(4, 5, 2, 300), 16);
    }

    #[test]
    fn reconnect_attempt_zero_treated_as_first() {
        assert_eq!(reconnect_delay_for_attempt(0, 5, 2, 300), 5);
    }
}
