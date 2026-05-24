//! Linux network statistics via `/proc/net/dev`.

use vortix_core::ports::network_stats::NetworkStats;

const PROC_NET_DEV_PATH: &str = "/proc/net/dev";

/// Linux network stats from `/proc/net/dev`.
pub struct LinuxNetworkStats;

impl NetworkStats for LinuxNetworkStats {
    fn get_total_bytes() -> (u64, u64) {
        match std::fs::read_to_string(PROC_NET_DEV_PATH) {
            Ok(content) => parse_proc_net_dev(&content),
            Err(_) => (0, 0),
        }
    }
}

/// Parse `/proc/net/dev` content into `(total_rx_bytes, total_tx_bytes)`,
/// excluding loopback.
///
/// Format: `iface: rx_bytes rx_packets rx_errs ... tx_bytes tx_packets tx_errs ...`
pub(crate) fn parse_proc_net_dev(content: &str) -> (u64, u64) {
    let mut total_in: u64 = 0;
    let mut total_out: u64 = 0;

    for line in content.lines().skip(2) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let iface = parts[0].trim();
        if iface == "lo" {
            continue;
        }

        let stats: Vec<&str> = parts[1].split_whitespace().collect();
        // rx_bytes is index 0, tx_bytes is index 8
        if stats.len() >= 10 {
            if let Ok(rx) = stats[0].parse::<u64>() {
                total_in += rx;
            }
            if let Ok(tx) = stats[8].parse::<u64>() {
                total_out += tx;
            }
        }
    }

    (total_in, total_out)
}

#[cfg(test)]
mod tests {
    use super::parse_proc_net_dev;

    #[test]
    fn test_parse_proc_net_dev() {
        let content = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    8910    0    0    0     0          0         0  1234567    8910    0    0    0     0       0          0
  eth0: 5000000   12345    0    0    0     0          0         0  3000000   12000    0    0    0     0       0          0
   wg0: 2000000    5000    0    0    0     0          0         0  1500000    4000    0    0    0     0       0          0
";
        let (bytes_in, bytes_out) = parse_proc_net_dev(content);
        // Should sum eth0 + wg0, excluding lo
        assert_eq!(bytes_in, 5_000_000 + 2_000_000);
        assert_eq!(bytes_out, 3_000_000 + 1_500_000);
    }

    #[test]
    fn test_parse_proc_net_dev_only_loopback() {
        let content = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567    8910    0    0    0     0          0         0  1234567    8910    0    0    0     0       0          0
";
        let (bytes_in, bytes_out) = parse_proc_net_dev(content);
        assert_eq!(bytes_in, 0);
        assert_eq!(bytes_out, 0);
    }

    #[test]
    fn test_parse_proc_net_dev_empty() {
        let (bytes_in, bytes_out) = parse_proc_net_dev("");
        assert_eq!(bytes_in, 0);
        assert_eq!(bytes_out, 0);
    }
}
