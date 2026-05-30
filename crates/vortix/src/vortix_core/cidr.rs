//! CIDR aggregation helper for detecting whether a set of allowed CIDRs
//! claims the full IPv4 or IPv6 default route.
//!
//! Used by the engine to recognise split-tunnel vs full-tunnel profile
//! shapes regardless of how the user expressed the routes. We accept the
//! canonical `0.0.0.0/0`, the classic `0.0.0.0/1` + `128.0.0.0/1` pair, and
//! any deeper fragmentation (`/2` quartet, `/3` octet, mixed prefixes) as
//! long as the union of ranges covers the entire address space.
//!
//! Implemented directly — no external CIDR crate — so the dependency
//! surface stays small. See the multi-connection plan, unit U3.

use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A parsed CIDR block: an IP address paired with a prefix length.
///
/// The address is stored verbatim — callers may pass non-canonical inputs
/// such as `10.0.0.5/8`; aggregation masks the host bits away before
/// computing the numeric range, so the result is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl Cidr {
    /// Construct a new `Cidr`. Returns `None` if `prefix_len` exceeds the
    /// address-family width (32 for v4, 128 for v6).
    #[must_use]
    pub fn new(addr: IpAddr, prefix_len: u8) -> Option<Self> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return None;
        }
        Some(Self { addr, prefix_len })
    }

    #[must_use]
    pub fn is_v4(&self) -> bool {
        matches!(self.addr, IpAddr::V4(_))
    }

    #[must_use]
    pub fn is_v6(&self) -> bool {
        matches!(self.addr, IpAddr::V6(_))
    }

    /// Whether this CIDR block intersects (shares any addresses with)
    /// `other`. Two blocks intersect when their common-prefix bits
    /// match — every address in the smaller block is contained in the
    /// larger, or they alias exactly. Cross-family blocks (v4 ↔ v6)
    /// never intersect.
    ///
    /// Used by the CLI's `up` conflict gate to detect non-default
    /// route overlap; available to the registry when R10 v2 grows
    /// route-overlap detection.
    #[must_use]
    pub fn intersects(&self, other: &Cidr) -> bool {
        match (self.addr, other.addr) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let abits = u32::from(a);
                let bbits = u32::from(b);
                let amask = u32::MAX
                    .checked_shl(u32::from(32 - self.prefix_len))
                    .unwrap_or(0);
                let bmask = u32::MAX
                    .checked_shl(u32::from(32 - other.prefix_len))
                    .unwrap_or(0);
                let common = amask & bmask;
                (abits & common) == (bbits & common)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let abits = u128::from(a);
                let bbits = u128::from(b);
                let amask = u128::MAX
                    .checked_shl(u32::from(128 - self.prefix_len))
                    .unwrap_or(0);
                let bmask = u128::MAX
                    .checked_shl(u32::from(128 - other.prefix_len))
                    .unwrap_or(0);
                let common = amask & bmask;
                (abits & common) == (bbits & common)
            }
            _ => false,
        }
    }
}

/// Return the CIDRs from `a` that intersect any CIDR in `b`. O(|a|·|b|);
/// `AllowedIPs` sets are typically tiny so the quadratic shape is fine.
#[must_use]
pub fn overlapping_cidrs(a: &[Cidr], b: &[Cidr]) -> Vec<Cidr> {
    let mut out = Vec::new();
    for x in a {
        if b.iter().any(|y| x.intersects(y)) {
            out.push(*x);
        }
    }
    out
}

/// Parses CIDR strings like `"10.0.0.0/8"` or `"::/0"`. Missing prefix is
/// rejected — callers should be explicit.
impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_part, prefix_part) = s.split_once('/').ok_or(CidrParseError::MissingPrefix)?;
        let addr: IpAddr = addr_part.parse().map_err(|_| CidrParseError::InvalidAddr)?;
        let prefix_len: u8 = prefix_part
            .parse()
            .map_err(|_| CidrParseError::InvalidPrefix)?;
        Self::new(addr, prefix_len).ok_or(CidrParseError::PrefixOutOfRange)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrParseError {
    MissingPrefix,
    InvalidAddr,
    InvalidPrefix,
    PrefixOutOfRange,
}

impl std::fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPrefix => f.write_str("missing '/<prefix>' in CIDR"),
            Self::InvalidAddr => f.write_str("invalid IP address in CIDR"),
            Self::InvalidPrefix => f.write_str("invalid prefix length"),
            Self::PrefixOutOfRange => f.write_str("prefix length exceeds address-family width"),
        }
    }
}

impl std::error::Error for CidrParseError {}

/// Returns `true` iff the union of all IPv4 CIDRs in `allowed_ips` covers
/// `0.0.0.0/0`. IPv6 entries are ignored.
#[must_use]
pub fn claims_default_route_v4(allowed_ips: &[Cidr]) -> bool {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for cidr in allowed_ips {
        let IpAddr::V4(v4) = cidr.addr else { continue };
        if cidr.prefix_len == 0 {
            return true;
        }
        let bits = u32::from(v4);
        let mask: u32 = u32::MAX
            .checked_shl(u32::from(32 - cidr.prefix_len))
            .unwrap_or(0);
        let start = bits & mask;
        let end = start | !mask;
        ranges.push((start, end));
    }
    covers_full_u32(&mut ranges)
}

/// Returns `true` iff the union of all IPv6 CIDRs in `allowed_ips` covers
/// `::/0`. IPv4 entries are ignored.
#[must_use]
pub fn claims_default_route_v6(allowed_ips: &[Cidr]) -> bool {
    let mut ranges: Vec<(u128, u128)> = Vec::new();
    for cidr in allowed_ips {
        let IpAddr::V6(v6) = cidr.addr else { continue };
        if cidr.prefix_len == 0 {
            return true;
        }
        let bits = u128::from(v6);
        let mask: u128 = u128::MAX
            .checked_shl(u32::from(128 - cidr.prefix_len))
            .unwrap_or(0);
        let start = bits & mask;
        let end = start | !mask;
        ranges.push((start, end));
    }
    covers_full_u128(&mut ranges)
}

fn covers_full_u32(ranges: &mut [(u32, u32)]) -> bool {
    if ranges.is_empty() {
        return false;
    }
    ranges.sort_unstable_by_key(|&(start, _)| start);
    // The merged set must start at 0, be contiguous (no gaps), and end at u32::MAX.
    let (first_start, mut cur_end) = ranges[0];
    if first_start != 0 {
        return false;
    }
    for &(start, end) in &ranges[1..] {
        // Adjacent or overlapping: extend. Gap: fail.
        // Use saturating_add to handle cur_end == u32::MAX safely.
        if start > cur_end.saturating_add(1) {
            return false;
        }
        if end > cur_end {
            cur_end = end;
        }
    }
    cur_end == u32::MAX
}

fn covers_full_u128(ranges: &mut [(u128, u128)]) -> bool {
    if ranges.is_empty() {
        return false;
    }
    ranges.sort_unstable_by_key(|&(start, _)| start);
    let (first_start, mut cur_end) = ranges[0];
    if first_start != 0 {
        return false;
    }
    for &(start, end) in &ranges[1..] {
        if start > cur_end.saturating_add(1) {
            return false;
        }
        if end > cur_end {
            cur_end = end;
        }
    }
    cur_end == u128::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Cidr {
        s.parse().expect("valid v4 cidr")
    }

    fn v6(s: &str) -> Cidr {
        s.parse().expect("valid v6 cidr")
    }

    #[test]
    fn default_route_zero_prefix() {
        assert!(claims_default_route_v4(&[v4("0.0.0.0/0")]));
    }

    #[test]
    fn canonical_slash_one_pair() {
        // SC10: classic WireGuard split into two /1 halves.
        assert!(claims_default_route_v4(&[
            v4("0.0.0.0/1"),
            v4("128.0.0.0/1"),
        ]));
    }

    #[test]
    fn slash_two_quartet() {
        // SC11: full coverage via four /2 blocks.
        assert!(claims_default_route_v4(&[
            v4("0.0.0.0/2"),
            v4("64.0.0.0/2"),
            v4("128.0.0.0/2"),
            v4("192.0.0.0/2"),
        ]));
    }

    #[test]
    fn slash_three_octet() {
        assert!(claims_default_route_v4(&[
            v4("0.0.0.0/3"),
            v4("32.0.0.0/3"),
            v4("64.0.0.0/3"),
            v4("96.0.0.0/3"),
            v4("128.0.0.0/3"),
            v4("160.0.0.0/3"),
            v4("192.0.0.0/3"),
            v4("224.0.0.0/3"),
        ]));
    }

    #[test]
    fn single_private_cidr_is_not_default() {
        assert!(!claims_default_route_v4(&[v4("10.0.0.0/8")]));
    }

    #[test]
    fn two_disjoint_private_cidrs() {
        assert!(!claims_default_route_v4(&[
            v4("10.0.0.0/8"),
            v4("192.168.0.0/16"),
        ]));
    }

    #[test]
    fn mixed_prefix_lengths_aggregate_to_full() {
        // 0.0.0.0/1 covers 0..=2^31-1, 64.0.0.0/2 is contained in it (redundant),
        // 128.0.0.0/1 covers the upper half. Union == /0.
        assert!(claims_default_route_v4(&[
            v4("0.0.0.0/1"),
            v4("64.0.0.0/2"),
            v4("128.0.0.0/1"),
        ]));
    }

    #[test]
    fn partial_upper_half_leaves_gap() {
        // 128.0.0.0/2 covers only 128..=191; 192.0.0.0/2 is missing.
        assert!(!claims_default_route_v4(&[
            v4("0.0.0.0/1"),
            v4("128.0.0.0/2"),
        ]));
    }

    #[test]
    fn overlap_does_not_help_cover_full() {
        assert!(!claims_default_route_v4(&[
            v4("10.0.0.0/8"),
            v4("10.0.0.0/16"),
        ]));
    }

    #[test]
    fn empty_input_is_not_default() {
        assert!(!claims_default_route_v4(&[]));
        assert!(!claims_default_route_v6(&[]));
    }

    #[test]
    fn slash_four_fragmentation_aggregates() {
        // Sixteen /4s tile the entire IPv4 space — sanity-checks that the
        // algorithm is a real union-aggregator, not a pattern-match.
        let blocks: Vec<Cidr> = (0u32..16)
            .map(|i| {
                let octet = u8::try_from(i * 16).expect("i ∈ 0..16 so i*16 ∈ 0..240");
                format!("{octet}.0.0.0/4").parse().expect("valid")
            })
            .collect();
        assert!(claims_default_route_v4(&blocks));
    }

    #[test]
    fn ipv6_default_route_zero_prefix() {
        assert!(claims_default_route_v6(&[v6("::/0")]));
    }

    #[test]
    fn ipv6_canonical_slash_one_pair() {
        assert!(claims_default_route_v6(&[v6("::/1"), v6("8000::/1")]));
    }

    #[test]
    fn ipv6_single_block_is_not_default() {
        assert!(!claims_default_route_v6(&[v6("fd00::/8")]));
    }

    #[test]
    fn v4_helper_ignores_v6_entries() {
        // Without the /1 pair the v4 union has a giant hole, so even a
        // matching IPv6 default route must not bleed into the v4 result.
        assert!(!claims_default_route_v4(&[v4("0.0.0.0/1"), v6("::/0"),]));
        // And vice-versa: v6 helper ignores v4 entries.
        assert!(!claims_default_route_v6(&[v4("0.0.0.0/0")]));
    }

    #[test]
    fn mixed_input_each_family_evaluated_independently() {
        let mixed = [
            v4("0.0.0.0/1"),
            v4("128.0.0.0/1"),
            v6("::/1"),
            v6("8000::/1"),
        ];
        assert!(claims_default_route_v4(&mixed));
        assert!(claims_default_route_v6(&mixed));
    }

    #[test]
    fn from_str_parses_v4() {
        let cidr: Cidr = "10.0.0.0/8".parse().expect("parses");
        assert_eq!(cidr.prefix_len, 8);
        assert!(cidr.is_v4());
    }

    #[test]
    fn from_str_rejects_out_of_range_prefix() {
        assert_eq!(
            "10.0.0.0/33".parse::<Cidr>().unwrap_err(),
            CidrParseError::PrefixOutOfRange
        );
        assert_eq!(
            "::/129".parse::<Cidr>().unwrap_err(),
            CidrParseError::PrefixOutOfRange
        );
    }

    #[test]
    fn from_str_rejects_missing_prefix() {
        assert_eq!(
            "10.0.0.0".parse::<Cidr>().unwrap_err(),
            CidrParseError::MissingPrefix
        );
    }

    #[test]
    fn non_canonical_host_bits_are_masked() {
        // 10.0.0.5/8 should be treated identically to 10.0.0.0/8 — the host
        // bits don't affect aggregation.
        assert!(!claims_default_route_v4(&[v4("10.0.0.5/8")]));
    }

    #[test]
    fn cidr_new_rejects_out_of_range() {
        let v4_addr: IpAddr = "10.0.0.0".parse().unwrap();
        assert!(Cidr::new(v4_addr, 33).is_none());
        let v6_addr: IpAddr = "::".parse().unwrap();
        assert!(Cidr::new(v6_addr, 129).is_none());
    }
}
