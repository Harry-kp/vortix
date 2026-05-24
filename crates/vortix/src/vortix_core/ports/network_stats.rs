//! `NetworkStats` port — per-host byte counters.

/// Read aggregate interface byte counters.
///
/// Implementations read whichever per-interface byte counter source is
/// available on the host (`netstat -ib` on macOS, `/proc/net/dev` on Linux)
/// and return the running totals across all non-loopback interfaces.
pub trait NetworkStats {
    /// Total bytes received and transmitted across all non-loopback interfaces.
    fn get_total_bytes() -> (u64, u64);
}
