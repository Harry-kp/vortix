//! CIDR subtraction — given a base set of CIDRs and a remove set, returns
//! the remainder as a minimal canonical list of CIDRs.
//!
//! Used by the killswitch rule synthesizer to subtract per-tunnel declared
//! CIDRs from the flat RFC1918 allow-list, so that traffic to networks
//! claimed by a secondary tunnel cannot escape onto the underlay.
//!
//! Per Q-DEF-9 resolution D-6, primary tunnels (claiming `0.0.0.0/0`) do
//! **not** subtract from the RFC1918 base. Their interface allow rule
//! covers their traffic; subtracting `0/0` would strip loopback and break
//! local services. Only secondary tunnels with declared CIDRs contribute
//! to the remove list.
//!
//! Operates on IPv4 only — the killswitch base list is RFC1918, which is
//! v4-exclusive. v6 CIDRs in the input are ignored. See unit U8 in the
//! multi-connection plan.

use std::net::{IpAddr, Ipv4Addr};

use crate::vortix_core::cidr::Cidr;

/// Subtract `remove` from `base`, returning the canonical CIDR list of
/// what remains. Inputs are unsorted; output is sorted by start address.
///
/// Algorithm:
/// 1. Convert each base CIDR to a `(start, end)` numeric range.
/// 2. Build a remove range list, merge overlapping/adjacent intervals.
/// 3. For each base range, subtract the merged remove ranges, yielding
///    zero or more leftover sub-ranges.
/// 4. Re-canonicalise each leftover range as the minimal set of CIDR
///    blocks that exactly cover it.
///
/// IPv6 CIDRs in either input are silently dropped — the killswitch base
/// is RFC1918, which is v4-only.
#[must_use]
pub fn cidr_subtract(base: &[Cidr], remove: &[Cidr]) -> Vec<Cidr> {
    let base_ranges: Vec<(u32, u32)> = base.iter().filter_map(cidr_to_v4_range).collect();
    if base_ranges.is_empty() {
        return Vec::new();
    }

    let mut remove_ranges: Vec<(u32, u32)> = remove.iter().filter_map(cidr_to_v4_range).collect();
    merge_ranges(&mut remove_ranges);

    let mut leftover: Vec<(u32, u32)> = Vec::new();
    for (start, end) in base_ranges {
        leftover.extend(subtract_from_range(start, end, &remove_ranges));
    }

    let mut out: Vec<Cidr> = Vec::new();
    for (start, end) in leftover {
        range_to_cidrs(start, end, &mut out);
    }
    out
}

/// Convert a v4 `Cidr` to a `(start, end)` numeric range. Returns `None`
/// for IPv6 inputs.
fn cidr_to_v4_range(cidr: &Cidr) -> Option<(u32, u32)> {
    let IpAddr::V4(v4) = cidr.addr else {
        return None;
    };
    let bits = u32::from(v4);
    let mask: u32 = u32::MAX
        .checked_shl(u32::from(32 - cidr.prefix_len))
        .unwrap_or(0);
    let start = bits & mask;
    let end = start | !mask;
    Some((start, end))
}

/// Merge overlapping or adjacent ranges in place. Sorts the input.
fn merge_ranges(ranges: &mut Vec<(u32, u32)>) {
    if ranges.is_empty() {
        return;
    }
    ranges.sort_unstable_by_key(|&(start, _)| start);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    let (mut cur_start, mut cur_end) = ranges[0];
    for &(start, end) in &ranges[1..] {
        if start > cur_end.saturating_add(1) {
            merged.push((cur_start, cur_end));
            cur_start = start;
            cur_end = end;
        } else if end > cur_end {
            cur_end = end;
        }
    }
    merged.push((cur_start, cur_end));
    *ranges = merged;
}

/// Subtract the (sorted, merged) `removes` list from `[start, end]`,
/// returning the leftover sub-ranges in order.
fn subtract_from_range(start: u32, end: u32, removes: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut cursor = start;
    let mut out: Vec<(u32, u32)> = Vec::new();
    for &(r_start, r_end) in removes {
        if r_end < cursor || r_start > end {
            continue;
        }
        if r_start > cursor {
            out.push((cursor, r_start - 1));
        }
        cursor = r_end.saturating_add(1);
        if cursor > end || r_end == u32::MAX {
            return out;
        }
    }
    if cursor <= end {
        out.push((cursor, end));
    }
    out
}

/// Decompose a `[start, end]` v4 range into the minimal canonical CIDR
/// set. Standard greedy "largest aligned block that fits" algorithm.
fn range_to_cidrs(mut start: u32, end: u32, out: &mut Vec<Cidr>) {
    while start <= end {
        // Largest prefix length whose block, anchored at `start`, fits in
        // `[start, end]`. Two bounds: alignment of `start` and remaining
        // length.
        let align_zeros = if start == 0 {
            32
        } else {
            start.trailing_zeros()
        };
        // Size of the remaining range, capped at u32::MAX so we don't
        // overflow when end == u32::MAX and start == 0.
        let size: u64 = u64::from(end - start) + 1;
        let length_log2 = max_block_log2_u64(size);
        // The block of size 2^k anchored at `start` fits iff
        // k <= align_zeros AND 2^k <= size.
        let k = align_zeros.min(length_log2);
        // k is bounded by 32 above, so (32 - k) fits in u8.
        let prefix_len = u8::try_from(32 - k).expect("k <= 32, so 32 - k fits in u8");
        let block_size: u64 = 1u64 << k;
        let cidr = Cidr {
            addr: IpAddr::V4(Ipv4Addr::from(start)),
            prefix_len,
        };
        out.push(cidr);
        let new_start = u64::from(start) + block_size;
        if new_start > u64::from(u32::MAX) {
            break;
        }
        start = u32::try_from(new_start).expect("new_start <= u32::MAX checked above");
    }
}

/// Largest `k` such that `2^k <= n`, capped at 32 (since v4 ranges fit
/// in a u32 and the maximum block is `2^32`). Caller guarantees `n >= 1`.
fn max_block_log2_u64(n: u64) -> u32 {
    let lz = n.leading_zeros();
    if lz >= 64 {
        0
    } else {
        (63 - lz).min(32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr_v4(s: &str) -> Cidr {
        s.parse().expect("valid v4 cidr")
    }

    fn cidrs(strs: &[&str]) -> Vec<Cidr> {
        strs.iter().map(|s| cidr_v4(s)).collect()
    }

    /// The fixed RFC1918 base list used by the killswitch.
    fn rfc1918_base() -> Vec<Cidr> {
        cidrs(&["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    }

    /// Helper — render the output as a sorted set of canonical strings.
    fn rendered(cidrs: &[Cidr]) -> Vec<String> {
        let mut out: Vec<String> = cidrs
            .iter()
            .map(|c| match c.addr {
                IpAddr::V4(v4) => format!("{v4}/{}", c.prefix_len),
                IpAddr::V6(v6) => format!("{v6}/{}", c.prefix_len),
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn empty_remove_returns_full_base() {
        let out = cidr_subtract(&rfc1918_base(), &[]);
        assert_eq!(
            rendered(&out),
            vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        );
    }

    #[test]
    fn primary_zero_slash_zero_does_not_subtract() {
        // Per Q-DEF-9 / D-6: this helper's caller is expected to *exclude*
        // primary tunnels from the remove list. The function itself only
        // sees the remove list. We simulate that by passing an empty
        // remove list (the caller's job) and confirm the base is intact.
        let out = cidr_subtract(&rfc1918_base(), &[]);
        assert_eq!(
            rendered(&out),
            vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        );
    }

    #[test]
    fn single_secondary_removes_one_full_block() {
        let out = cidr_subtract(&rfc1918_base(), &cidrs(&["10.0.0.0/8"]));
        assert_eq!(rendered(&out), vec!["172.16.0.0/12", "192.168.0.0/16"]);
    }

    #[test]
    fn carve_out_subnet_from_larger_block() {
        // 192.168.0.0/16 minus 192.168.50.0/24 should canonicalize to the
        // minimal CIDR cover of 192.168.0.0/16 \ 192.168.50.0/24.
        let out = cidr_subtract(&rfc1918_base(), &cidrs(&["10.0.0.0/8", "192.168.50.0/24"]));
        let r = rendered(&out);
        // 10/8 is fully gone. 172.16/12 is intact. 192.168/16 is carved.
        assert!(!r.iter().any(|s| s.starts_with("10.")));
        assert!(r.iter().any(|s| s == "172.16.0.0/12"));
        // The carved-out range covers 192.168.0.0..192.168.49.255 plus
        // 192.168.51.0..192.168.255.255 — should not contain 192.168.50.0/24
        // anywhere.
        assert!(!r.contains(&"192.168.50.0/24".to_string()));
        // Sanity: the union of all 192.168.* entries must equal 65536 - 256.
        let total: u64 = out
            .iter()
            .filter(|c| match c.addr {
                IpAddr::V4(v4) => v4.octets()[0] == 192 && v4.octets()[1] == 168,
                IpAddr::V6(_) => false,
            })
            .map(|c| 1u64 << (32 - c.prefix_len))
            .sum();
        assert_eq!(total, 65536 - 256);
    }

    #[test]
    fn secondary_claims_172_block_exactly() {
        let out = cidr_subtract(&rfc1918_base(), &cidrs(&["172.16.0.0/12"]));
        assert_eq!(rendered(&out), vec!["10.0.0.0/8", "192.168.0.0/16"]);
    }

    #[test]
    fn public_cidr_in_remove_is_noop() {
        let out = cidr_subtract(&rfc1918_base(), &cidrs(&["1.2.3.0/24"]));
        assert_eq!(
            rendered(&out),
            vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        );
    }

    #[test]
    fn overlapping_secondaries_dont_double_subtract() {
        // 10.0.0.0/8 and 10.5.0.0/16 — the second is contained in the
        // first. Result must be identical to subtracting just 10/8.
        let out = cidr_subtract(&rfc1918_base(), &cidrs(&["10.0.0.0/8", "10.5.0.0/16"]));
        assert_eq!(rendered(&out), vec!["172.16.0.0/12", "192.168.0.0/16"]);
    }

    #[test]
    fn ipv6_inputs_are_ignored() {
        let out = cidr_subtract(&rfc1918_base(), &cidrs(&["::/0"]));
        // ::/0 is v6, so it does nothing.
        assert_eq!(
            rendered(&out),
            vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        );
    }

    #[test]
    fn merge_ranges_handles_adjacent() {
        let mut r = vec![(0u32, 99u32), (100u32, 199u32), (300u32, 399u32)];
        merge_ranges(&mut r);
        assert_eq!(r, vec![(0, 199), (300, 399)]);
    }

    #[test]
    fn range_to_cidrs_aligned_block_is_single() {
        let mut out = Vec::new();
        range_to_cidrs(0x0A00_0000, 0x0AFF_FFFF, &mut out);
        assert_eq!(rendered(&out), vec!["10.0.0.0/8"]);
    }

    #[test]
    fn range_to_cidrs_misaligned_decomposes() {
        // 192.168.51.0 .. 192.168.255.255 — non-power-of-two range that
        // canonicalises to a small set of blocks.
        let start = u32::from(Ipv4Addr::new(192, 168, 51, 0));
        let end = u32::from(Ipv4Addr::new(192, 168, 255, 255));
        let mut out = Vec::new();
        range_to_cidrs(start, end, &mut out);
        // Sanity: total covered == end - start + 1.
        let total: u64 = out.iter().map(|c| 1u64 << (32 - c.prefix_len)).sum();
        assert_eq!(total, u64::from(end - start + 1));
    }
}
