//! HTTP helper for the telemetry workers (plan 002 U9, revised).
//!
//! Wraps a single process-wide `ureq::Agent` (lazy-init via `OnceLock`)
//! configured to match curl's no-flag default behavior:
//!
//! - `max_redirects(0)` — curl invoked without `-L` does NOT follow
//!   redirects. ureq's default `max_redirects_will_error = true` then
//!   surfaces a 3xx as an error, which we map to `None`. The prior
//!   shell-out's `output.status.success()` check treated a 3xx
//!   response as a non-success; both paths produce identical observable
//!   behavior for the calling contract.
//! - rustls TLS — verification on, no OpenSSL. Trust anchors come from
//!   `webpki-roots` (Mozilla CA bundle).
//! - Default agent is used for IPv4-or-IPv6 calls; a separate
//!   `IpFamily::Ipv6Only` agent serves the IPv6-leak probe.
//!
//! Timeout is per-call (mirrors `curl --max-time N`) via
//! `RequestBuilder::config_mut().timeout_global(...)`.

use std::sync::OnceLock;
use std::time::Duration;

use serde::de::DeserializeOwned;
use ureq::config::{Config, IpFamily};
use ureq::Agent;

/// Lazy-init process-wide agent. Re-uses TCP connections + TLS
/// sessions across telemetry calls. Configured with redirects
/// disabled to match curl-without-`-L`.
fn agent() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| build_agent(IpFamily::Any))
}

/// IPv6-only agent for the leak probe.
fn ipv6_agent() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| build_agent(IpFamily::Ipv6Only))
}

fn build_agent(family: IpFamily) -> Agent {
    Config::builder()
        .max_redirects(0)
        .ip_family(family)
        .build()
        .new_agent()
}

/// GET `url` with the given per-call timeout. Returns the response
/// body as `String` on 2xx, `None` for any error: timeout, DNS
/// failure, connection refused, TLS failure, non-2xx status,
/// redirect (per the no-follow contract).
///
/// Matches the prior `curl -s --max-time N <url>` shell-out's
/// `output.status.success()` + `stdout` semantics.
#[must_use]
pub fn get_text(url: &str, timeout: Duration) -> Option<String> {
    let mut response = agent()
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.body_mut().read_to_string().ok()
}

/// GET `url` with the given per-call timeout and deserialize the
/// 2xx JSON body into `T`. Returns `None` for any error: timeout,
/// DNS, connection, TLS, non-2xx, redirect, deserialization.
///
/// Matches the prior shell-out flow that piped curl stdout into
/// `serde_json::from_str`, just without the intermediate
/// `Vec<u8>` → `String` step.
#[must_use]
pub fn get_json<T: DeserializeOwned>(url: &str, timeout: Duration) -> Option<T> {
    let mut response = agent()
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.body_mut().read_json::<T>().ok()
}

/// IPv6-only GET — used by the IPv6-leak probe in
/// `fetch_security_info`. Returns `true` if the request reached a
/// 2xx response over IPv6; `false` for any failure (no IPv6 route,
/// timeout, non-2xx).
///
/// Curl achieves IPv6-only with `-6`; ureq exposes the same via
/// `Config::ip_family(IpFamily::Ipv6Only)`.
#[must_use]
pub fn probe_ipv6(url: &str, timeout: Duration) -> bool {
    let Ok(response) = ipv6_agent()
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
    else {
        return false;
    };
    response.status().is_success()
}
