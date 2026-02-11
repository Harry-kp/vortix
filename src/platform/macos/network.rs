//! macOS network statistics via `netstat -ib`.

use crate::platform::NetworkStatsProvider;

/// macOS network stats using `netstat -ib`.
pub struct MacNetworkStats;

impl NetworkStatsProvider for MacNetworkStats {
    fn get_total_bytes() -> (u64, u64) {
        let mut total_in: u64 = 0;
        let mut total_out: u64 = 0;

        let timeout = std::time::Duration::from_secs(crate::constants::CMD_TIMEOUT_SECS);
        if let Some(output) = crate::utils::run_with_timeout(
            std::process::Command::new("netstat").args(["-ib"]),
            timeout,
        ) {
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
        }

        (total_in, total_out)
    }
}
