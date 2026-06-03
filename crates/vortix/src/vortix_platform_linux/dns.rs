//! Linux DNS resolver using resolvectl, nmcli, and /etc/resolv.conf.
//!
//! Read-only inspection lives behind the [`LinuxDns`] / [`DnsResolver`]
//! port. Mutating per-link DNS via systemd-resolved (`resolvectl dns`,
//! `resolvectl domain`) is exposed as a free function ([`set_link_dns`])
//! since vortix only needs the mutating path on Linux today; lift to a
//! port when macOS or Windows ever needs a peer feature.

use crate::vortix_core::ports::dns::DnsResolver;
use crate::vortix_process::CommandSpec;
use std::time::Duration;

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Timeout for each `resolvectl` invocation in [`set_link_dns`].
///
/// 5s is generous for a healthy resolved (typical roundtrip is ~10ms over
/// the local `DBus` / `Varlink` socket). Caps the failure window when
/// resolved is wedged or `DBus` is stuck — the caller's fail-open posture
/// surfaces the timeout as a `tracing::warn!` rather than blocking the
/// connect.
const RESOLVECTL_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Linux DNS resolution with fallback chain:
/// 1. `resolvectl` (systemd-resolved)
/// 2. `nmcli` (`NetworkManager`)
/// 3. `/etc/resolv.conf` (universal fallback)
pub struct LinuxDns;

impl DnsResolver for LinuxDns {
    fn get_dns_server() -> Option<String> {
        try_get_dns_resolvectl()
            .or_else(try_get_dns_nmcli)
            .or_else(try_get_dns_resolv_conf)
    }
}

/// Error from [`set_link_dns`].
#[derive(Debug)]
pub enum DnsManagerError {
    /// `resolvectl dns <iface> <ips>` failed (subprocess error or non-zero exit).
    ResolvectlDnsFailed(String),
    /// `resolvectl domain <iface> ~.` failed.
    ResolvectlDomainFailed(String),
}

impl std::fmt::Display for DnsManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResolvectlDnsFailed(s) => write!(f, "resolvectl dns: {s}"),
            Self::ResolvectlDomainFailed(s) => write!(f, "resolvectl domain: {s}"),
        }
    }
}

impl std::error::Error for DnsManagerError {}

/// Build the resolvectl `CommandSpec`s [`set_link_dns`] would issue.
///
/// Pure function — no I/O. Splits spec construction from execution so the
/// invocation shape (program, args, timeout) can be unit-tested without
/// fighting the process-wide runner `OnceLock`. The first spec is always
/// the `resolvectl dns <iface> <ips...>` call; the second (present only
/// when `authoritative` is `true`) is the `resolvectl domain <iface> ~.`
/// call that marks the link as the catchall resolver.
#[must_use]
pub(crate) fn build_set_link_dns_specs(
    iface: &str,
    ips: &[String],
    authoritative: bool,
) -> Vec<CommandSpec> {
    let mut dns_args: Vec<String> = Vec::with_capacity(2 + ips.len());
    dns_args.push("dns".into());
    dns_args.push(iface.to_string());
    for ip in ips {
        dns_args.push(ip.clone());
    }
    let mut specs =
        vec![CommandSpec::oneshot("resolvectl", dns_args).timeout(RESOLVECTL_CALL_TIMEOUT)];
    if authoritative {
        specs.push(
            CommandSpec::oneshot(
                "resolvectl",
                vec!["domain".into(), iface.to_string(), "~.".into()],
            )
            .timeout(RESOLVECTL_CALL_TIMEOUT),
        );
    }
    specs
}

/// Register per-link DNS on a kernel interface via systemd-resolved.
///
/// Issues `resolvectl dns <iface> <ip1> <ip2> ...` and, when
/// `authoritative` is `true`, also `resolvectl domain <iface> ~.` so the
/// link becomes the default catchall resolver. The non-authoritative form
/// (used for secondary tunnels) makes the link's DNS reachable for
/// direct/reverse queries against that link without competing with the
/// primary's catchall resolver for general hostname resolution.
///
/// Returns immediately if `ips` is empty — no point invoking resolvectl
/// with no servers. Callers should gate on the captured IP list anyway.
///
/// On error the partial state (`dns` succeeded but `domain` failed) is
/// acceptable — resolvectl is idempotent and `wg-quick down` will clear
/// the link's resolved state on disconnect via `ip link delete`. The
/// caller's `tracing::warn!` surface is sufficient.
pub fn set_link_dns(
    iface: &str,
    ips: &[String],
    authoritative: bool,
) -> Result<(), DnsManagerError> {
    if ips.is_empty() {
        return Ok(());
    }
    let specs = build_set_link_dns_specs(iface, ips, authoritative);
    for (idx, spec) in specs.into_iter().enumerate() {
        let output = crate::vortix_process::run_to_output(spec).map_err(|e| {
            if idx == 0 {
                DnsManagerError::ResolvectlDnsFailed(e.to_string())
            } else {
                DnsManagerError::ResolvectlDomainFailed(e.to_string())
            }
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(if idx == 0 {
                DnsManagerError::ResolvectlDnsFailed(stderr)
            } else {
                DnsManagerError::ResolvectlDomainFailed(stderr)
            });
        }
    }
    Ok(())
}

/// Try to get DNS from resolvectl (systemd-resolved, most modern distros).
fn try_get_dns_resolvectl() -> Option<String> {
    let output = crate::vortix_process::run_to_output(CommandSpec::oneshot(
        "resolvectl",
        vec!["status".into()],
    ))
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Look for "DNS Servers:" or "Current DNS Server:" line
        if trimmed.starts_with("DNS Servers:") || trimmed.starts_with("Current DNS Server:") {
            if let Some(dns) = trimmed.split(':').nth(1) {
                let dns = dns.trim().to_string();
                // May have multiple servers, take the first one
                let first = dns.split_whitespace().next().unwrap_or("").to_string();
                if !first.is_empty() {
                    return Some(first);
                }
            }
        }
    }
    None
}

/// Try to get DNS from `nmcli` (`NetworkManager` distros).
fn try_get_dns_nmcli() -> Option<String> {
    let output = crate::vortix_process::run_to_output(CommandSpec::oneshot(
        "nmcli",
        vec!["dev".into(), "show".into()],
    ))
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("IP4.DNS") {
            // Format: "IP4.DNS[1]:                             1.1.1.1"
            if let Some(dns) = trimmed.split(':').nth(1) {
                let dns = dns.trim().to_string();
                if !dns.is_empty() {
                    return Some(dns);
                }
            }
        }
    }
    None
}

/// Try to get DNS from /etc/resolv.conf (universal fallback).
fn try_get_dns_resolv_conf() -> Option<String> {
    let content = std::fs::read_to_string(RESOLV_CONF_PATH).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver") {
            let dns = trimmed.trim_start_matches("nameserver").trim().to_string();
            if !dns.is_empty() {
                return Some(dns);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_of(spec: &CommandSpec) -> Vec<String> {
        spec.args.clone()
    }

    // ── build_set_link_dns_specs (pure spec construction) ────────────────

    #[test]
    fn build_specs_authoritative_emits_dns_then_domain() {
        let specs = build_set_link_dns_specs("wg0", &["1.1.1.1".to_string()], true);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].program, "resolvectl");
        assert_eq!(args_of(&specs[0]), vec!["dns", "wg0", "1.1.1.1"]);
        assert_eq!(specs[1].program, "resolvectl");
        assert_eq!(args_of(&specs[1]), vec!["domain", "wg0", "~."]);
    }

    #[test]
    fn build_specs_non_authoritative_emits_only_dns() {
        let specs = build_set_link_dns_specs("wg1", &["1.1.1.1".to_string()], false);
        assert_eq!(specs.len(), 1);
        assert_eq!(args_of(&specs[0]), vec!["dns", "wg1", "1.1.1.1"]);
    }

    #[test]
    fn build_specs_passes_multiple_ips_as_separate_args() {
        let ips = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let specs = build_set_link_dns_specs("wg0", &ips, false);
        assert_eq!(specs.len(), 1);
        assert_eq!(args_of(&specs[0]), vec!["dns", "wg0", "1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn build_specs_passes_ipv6_through_verbatim() {
        let ips = vec!["2001:db8::1".to_string()];
        let specs = build_set_link_dns_specs("wg0", &ips, true);
        assert_eq!(args_of(&specs[0]), vec!["dns", "wg0", "2001:db8::1"]);
        assert_eq!(args_of(&specs[1]), vec!["domain", "wg0", "~."]);
    }

    #[test]
    fn build_specs_preserves_ip_order() {
        let ips = vec![
            "1.1.1.1".to_string(),
            "2001:db8::1".to_string(),
            "8.8.8.8".to_string(),
        ];
        let specs = build_set_link_dns_specs("wg0", &ips, false);
        assert_eq!(
            args_of(&specs[0]),
            vec!["dns", "wg0", "1.1.1.1", "2001:db8::1", "8.8.8.8"]
        );
    }

    #[test]
    fn build_specs_carries_timeout_on_every_spec() {
        let specs = build_set_link_dns_specs("wg0", &["1.1.1.1".to_string()], true);
        for spec in &specs {
            assert_eq!(spec.timeout, Some(RESOLVECTL_CALL_TIMEOUT));
        }
    }

    // ── set_link_dns (driver behaviour) ──────────────────────────────────

    #[test]
    fn set_link_dns_empty_ips_is_noop_ok() {
        // No IPs → return Ok without issuing any subprocess. Mirrors the
        // caller's "captured_ips.is_empty()" gate at the WgTunnel layer
        // but provides an inner safety net.
        let result = set_link_dns("wg0", &[], true);
        assert!(result.is_ok());
    }

    #[test]
    fn set_link_dns_with_default_mock_runner_returns_ok() {
        // The test binary's default global runner is mock-default-success,
        // so the driver completes both calls and returns Ok. Verifies the
        // spec sequencing wiring without exercising the failure branches
        // (which are covered by manual-testing rows per the plan).
        let result = set_link_dns("wg0", &["1.1.1.1".to_string()], true);
        assert!(
            result.is_ok(),
            "expected Ok under default-success mock, got {result:?}"
        );
    }

    #[test]
    fn dns_manager_error_display_includes_phase() {
        // Failure-path messages must name which resolvectl call failed so
        // the fail-open tracing::warn surfaces actionable context.
        let dns_err = DnsManagerError::ResolvectlDnsFailed("boom".into());
        let domain_err = DnsManagerError::ResolvectlDomainFailed("boom".into());
        assert!(format!("{dns_err}").contains("dns"));
        assert!(format!("{domain_err}").contains("domain"));
    }

    // ── existing read-only resolver tests ────────────────────────────────

    #[test]
    fn test_parse_resolv_conf() {
        // Simulate the parsing logic
        let content = "# Generated by NetworkManager\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        let mut result = None;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                let dns = trimmed.trim_start_matches("nameserver").trim().to_string();
                if !dns.is_empty() {
                    result = Some(dns);
                    break;
                }
            }
        }
        assert_eq!(result, Some("1.1.1.1".to_string()));
    }
}
