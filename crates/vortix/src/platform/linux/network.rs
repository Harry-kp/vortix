//! Linux network statistics via `/proc/net/dev`.

use crate::constants;
use crate::core::telemetry::parse_proc_net_dev;
use crate::platform::NetworkStatsProvider;

/// Linux network stats from /proc/net/dev.
pub struct LinuxNetworkStats;

impl NetworkStatsProvider for LinuxNetworkStats {
    fn get_total_bytes() -> (u64, u64) {
        match std::fs::read_to_string(constants::PROC_NET_DEV_PATH) {
            Ok(content) => parse_proc_net_dev(&content),
            Err(_) => (0, 0),
        }
    }
}
