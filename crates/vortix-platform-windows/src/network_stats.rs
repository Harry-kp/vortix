//! Windows network stats stub (plan 008 U4).
//!
//! Real impl would query `Get-NetAdapterStatistics` / IP Helper. Today
//! it reports zero bytes in both directions; telemetry consumers
//! render this as "no throughput yet."

use vortix_core::ports::network_stats::NetworkStats;

#[derive(Debug, Clone, Default)]
pub struct WindowsNetworkStats;

impl NetworkStats for WindowsNetworkStats {
    fn get_total_bytes() -> (u64, u64) {
        (0, 0)
    }
}
