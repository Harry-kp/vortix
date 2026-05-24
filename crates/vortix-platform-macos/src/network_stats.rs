//! macOS network statistics via `netstat -ib`.

use std::time::Duration;

use vortix_core::ports::network_stats::NetworkStats;
use vortix_process::CommandSpec;

/// Timeout for the `netstat -ib` invocation — same as the binary-side default.
const NETSTAT_TIMEOUT: Duration = Duration::from_secs(5);

/// macOS network stats using `netstat -ib`.
pub struct MacNetworkStats;

impl NetworkStats for MacNetworkStats {
    fn get_total_bytes() -> (u64, u64) {
        let mut total_in: u64 = 0;
        let mut total_out: u64 = 0;

        let Ok(output) = vortix_process::run_to_output(
            CommandSpec::oneshot("netstat", vec!["-ib".into()]).timeout(NETSTAT_TIMEOUT),
        ) else {
            return (total_in, total_out);
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut lines = stdout.lines();

        let (ibytes_idx, obytes_idx) = if let Some(header) = lines.next() {
            let headers: Vec<&str> = header.split_whitespace().collect();
            let ibytes_pos = headers
                .iter()
                .position(|&h| h.eq_ignore_ascii_case("ibytes"));
            let obytes_pos = headers
                .iter()
                .position(|&h| h.eq_ignore_ascii_case("obytes"));

            match (ibytes_pos, obytes_pos) {
                (Some(i), Some(o)) => (i, o),
                _ => (6, 9),
            }
        } else {
            return (total_in, total_out);
        };

        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > ibytes_idx.max(obytes_idx) {
                let iface = parts[0];
                if iface.starts_with("lo") {
                    continue;
                }

                if let (Some(ibytes_str), Some(obytes_str)) =
                    (parts.get(ibytes_idx), parts.get(obytes_idx))
                {
                    if ibytes_str.chars().all(|c| c.is_ascii_digit())
                        && obytes_str.chars().all(|c| c.is_ascii_digit())
                    {
                        if let (Ok(ibytes), Ok(obytes)) =
                            (ibytes_str.parse::<u64>(), obytes_str.parse::<u64>())
                        {
                            total_in += ibytes;
                            total_out += obytes;
                        }
                    }
                }
            }
        }

        (total_in, total_out)
    }
}
