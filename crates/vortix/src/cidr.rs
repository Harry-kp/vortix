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
//! surface stays small.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A parsed CIDR block: an IP address paired with a prefix length.
///
/// The address is stored verbatim — callers may pass non-canonical inputs
/// such as `10.0.0.5/8`; aggregation masks the host bits away before
/// computing the numeric range, so the result is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CidrWire {
    addr: IpAddr,
    prefix_len: u8,
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CidrWire::deserialize(deserializer)?;
        Self::new(wire.addr, wire.prefix_len)
            .ok_or_else(|| serde::de::Error::custom(CidrParseError::PrefixOutOfRange))
    }
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

    /// Revalidate a literal `Cidr`. Public fields remain available for
    /// backwards compatibility, so security boundaries must call this before
    /// accepting caller-constructed values.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        match self.addr {
            IpAddr::V4(_) => self.prefix_len <= 32,
            IpAddr::V6(_) => self.prefix_len <= 128,
        }
    }

    /// Build from an IPv4 `<addr> <netmask>` pair, as `OpenVPN` writes routes.
    /// `None` unless both are IPv4 and the mask is a contiguous prefix.
    #[must_use]
    pub fn parse_netmask_v4(addr: &str, mask: &str) -> Option<Self> {
        let addr: IpAddr = addr.trim().parse().ok()?;
        let mask: IpAddr = mask.trim().parse().ok()?;
        let (IpAddr::V4(_), IpAddr::V4(mask)) = (addr, mask) else {
            return None;
        };
        let bits = u32::from(mask);
        let prefix_len: u8 = bits.leading_ones().try_into().ok()?;
        if u32::from(prefix_len) + bits.trailing_zeros() != 32 {
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

    /// Return this CIDR with every host bit cleared.
    ///
    /// Security boundaries use this to reject aliases such as
    /// `10.1.2.3/8` when an exact kernel-network identity is required.
    #[must_use]
    pub fn canonical_network(self) -> Self {
        let addr = match self.addr {
            IpAddr::V4(address) => {
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - self.prefix_len))
                    .unwrap_or(0);
                IpAddr::V4((u32::from(address) & mask).into())
            }
            IpAddr::V6(address) => {
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - self.prefix_len))
                    .unwrap_or(0);
                IpAddr::V6((u128::from(address) & mask).into())
            }
        };
        Self {
            addr,
            prefix_len: self.prefix_len,
        }
    }

    /// Whether this CIDR block intersects (shares any addresses with)
    /// `other`. Two blocks intersect when their common-prefix bits
    /// match — every address in the smaller block is contained in the
    /// larger, or they alias exactly. Cross-family blocks (v4 ↔ v6)
    /// never intersect.
    ///
    /// Used by the CLI's `up` conflict gate to detect non-default
    /// route overlap; available to the engine when conflict detection grows
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

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// The ordered RFC 1918 private IPv4 ranges used by platform firewalls.
#[must_use]
pub const fn rfc1918_ranges() -> [Cidr; 3] {
    [
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 8,
        },
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
            prefix_len: 12,
        },
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix_len: 16,
        },
    ]
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
        let addr: IpAddr = addr_part
            .trim()
            .parse()
            .map_err(|_| CidrParseError::InvalidAddr)?;
        let prefix_len: u8 = prefix_part
            .trim()
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

/// A full tunnel: it routes a `/0`, so it competes for the default route.
#[must_use]
pub fn is_full<'a>(routes: impl IntoIterator<Item = &'a Cidr>) -> bool {
    routes.into_iter().any(|route| route.prefix_len == 0)
}

/// Returns `true` iff the union of all IPv6 CIDRs in `allowed_ips` covers
/// `::/0`, so split halves such as `::/1` + `8000::/1` count. IPv4 entries
/// are ignored.
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

    #[test]
    fn parses_trimmed_slash_and_openvpn_netmask_forms() {
        assert_eq!(
            " 10.0.0.0 / 8 ".parse::<Cidr>().unwrap(),
            "10.0.0.0/8".parse::<Cidr>().unwrap()
        );
        assert_eq!(
            Cidr::parse_netmask_v4("10.8.0.0", "255.255.0.0"),
            Some("10.8.0.0/16".parse().unwrap())
        );
        assert_eq!(Cidr::parse_netmask_v4("10.8.0.0", "255.0.255.0"), None);
        assert_eq!(Cidr::parse_netmask_v4("::1", "255.255.0.0"), None);
    }

    fn v6(s: &str) -> Cidr {
        s.parse().expect("valid v6 cidr")
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
    fn deserialize_rejects_out_of_range_prefix_and_unknown_fields() {
        for malformed in [
            serde_json::json!({"addr": "10.0.0.0", "prefix_len": 33}),
            serde_json::json!({"addr": "::", "prefix_len": 129}),
            serde_json::json!({
                "addr": "10.0.0.0",
                "prefix_len": 8,
                "injected": true
            }),
        ] {
            assert!(serde_json::from_value::<Cidr>(malformed).is_err());
        }
    }

    #[test]
    fn from_str_rejects_missing_prefix() {
        assert_eq!(
            "10.0.0.0".parse::<Cidr>().unwrap_err(),
            CidrParseError::MissingPrefix
        );
    }

    #[test]
    fn cidr_new_rejects_out_of_range() {
        let v4_addr: IpAddr = "10.0.0.0".parse().unwrap();
        assert!(Cidr::new(v4_addr, 33).is_none());
        let v6_addr: IpAddr = "::".parse().unwrap();
        assert!(Cidr::new(v6_addr, 129).is_none());
    }
}

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
mod more_tests {
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
