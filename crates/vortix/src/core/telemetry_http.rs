//! HTTP helper for the telemetry workers.
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
    get_text_result(url, timeout).ok()
}

/// Failure returned by [`get_text_result`]. HTTP status is retained so a
/// caller can distinguish a provider quota from a transient transport error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetTextError {
    /// The server returned a non-success HTTP status.
    HttpStatus(u16),
    /// DNS, TLS, timeout, redirect, or response-body failure.
    Transport,
}

/// GET `url` while preserving a non-success HTTP status for provider policy.
pub fn get_text_result(url: &str, timeout: Duration) -> Result<String, GetTextError> {
    let response = agent()
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call();
    let mut response = match response {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(status)) => return Err(GetTextError::HttpStatus(status)),
        Err(_) => return Err(GetTextError::Transport),
    };
    if !response.status().is_success() {
        return Err(GetTextError::HttpStatus(response.status().as_u16()));
    }
    response
        .body_mut()
        .read_to_string()
        .map_err(|_| GetTextError::Transport)
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

/// IPv6-only GET. Returns the trimmed response body (the host's public
/// IPv6 when the endpoint echoes it) or `None` on any failure.
#[must_use]
pub fn probe_ipv6(url: &str, timeout: Duration) -> Option<String> {
    let mut response = ipv6_agent()
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = response.body_mut().read_to_string().ok()?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    fn text_request_preserves_rate_limit_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });

        let result = get_text_result(&format!("http://{address}/limited"), Duration::from_secs(1));
        server.join().unwrap();

        assert_eq!(result, Err(GetTextError::HttpStatus(429)));
    }
}
