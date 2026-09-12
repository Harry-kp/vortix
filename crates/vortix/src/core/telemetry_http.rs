//! HTTP helper for the telemetry workers.
//!
//! Wraps one process-wide `ureq::Agent` per address family (lazy-init via
//! `OnceLock`) configured to match curl's no-flag default behavior:
//!
//! - `max_redirects(0)` — curl invoked without `-L` does NOT follow
//!   redirects. ureq's default `max_redirects_will_error = true` then
//!   surfaces a 3xx as an error, which we map to `None`. The prior
//!   shell-out's `output.status.success()` check treated a 3xx
//!   response as a non-success; both paths produce identical observable
//!   behavior for the calling contract.
//! - rustls TLS — verification on, no OpenSSL. Trust anchors come from
//!   `webpki-roots` (Mozilla CA bundle).
//! - One agent per address family. Every probe states the family it is
//!   asking about: [`get_text_v4`] / [`get_text_v4_result`] for the IPv4
//!   identity, [`probe_ipv6`] for the IPv6 one. There is no family-agnostic
//!   request helper, because an IP-echo endpoint answers with whichever
//!   family the request left on — a family-agnostic probe cannot tell you
//!   which field its answer belongs in.
//!
//! Timeout is per-call (mirrors `curl --max-time N`) via
//! `RequestBuilder::config_mut().timeout_global(...)`.

use std::sync::OnceLock;
use std::time::Duration;

use serde::de::DeserializeOwned;
use ureq::config::{Config, IpFamily};
use ureq::Agent;

/// Lazy-init process-wide IPv4-only agent. Re-uses TCP connections + TLS
/// sessions across telemetry calls. Configured with redirects disabled to
/// match curl-without-`-L`.
///
/// Pinned to IPv4 for two reasons that both showed up in the field:
///
/// 1. An IP-echo endpoint reports the address the request arrived from. On a
///    dual-stack host the resolver hands back AAAA first for several of the
///    configured providers, so a family-agnostic GET answers with the host's
///    IPv6 — which then landed in the "Public IPv4" slot.
/// 2. A full-tunnel profile that routes only `0.0.0.0/0` leaves the kill
///    switch correctly dropping all IPv6 egress. A family-agnostic probe
///    then aims at the one family the active policy forbids and burns the
///    whole per-call timeout, every poll, so the field never refreshes.
///    Asking over IPv4 is not a relaxation of the policy — it is asking over
///    the family the policy actually carries.
fn ipv4_agent() -> &'static Agent {
    static AGENT: OnceLock<Agent> = OnceLock::new();
    AGENT.get_or_init(|| build_agent(IpFamily::Ipv4Only))
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

/// GET `url` over IPv4 with the given per-call timeout. Returns the
/// response body as `String` on 2xx, `None` for any error: timeout, DNS
/// failure, connection refused, TLS failure, non-2xx status, redirect
/// (per the no-follow contract).
///
/// Matches the prior `curl -s -4 --max-time N <url>` semantics.
#[must_use]
pub fn get_text_v4(url: &str, timeout: Duration) -> Option<String> {
    get_text_v4_result(url, timeout).ok()
}

/// Failure returned by [`get_text_v4_result`]. HTTP status is retained so a
/// caller can distinguish a provider quota from a transient transport error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetTextError {
    /// The server returned a non-success HTTP status.
    HttpStatus(u16),
    /// DNS, TLS, timeout, redirect, or response-body failure.
    Transport,
}

/// GET `url` over IPv4 while preserving a non-success HTTP status for
/// provider policy.
pub fn get_text_v4_result(url: &str, timeout: Duration) -> Result<String, GetTextError> {
    let response = ipv4_agent()
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

/// GET `url` over IPv4 with the given per-call timeout and deserialize the
/// 2xx JSON body into `T`. Returns `None` for any error: timeout, DNS,
/// connection, TLS, non-2xx, redirect, deserialization.
#[must_use]
pub fn get_json_v4<T: DeserializeOwned>(url: &str, timeout: Duration) -> Option<T> {
    let mut response = ipv4_agent()
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

        let result =
            get_text_v4_result(&format!("http://{address}/limited"), Duration::from_secs(1));
        server.join().unwrap();

        assert_eq!(result, Err(GetTextError::HttpStatus(429)));
    }

    /// The IPv4 probe must not reach a v6-only destination. This is the
    /// structural half of the "no IPv6 value in an IPv4 field" guarantee:
    /// the request cannot leave over IPv6, so the echo it reads back cannot
    /// be an IPv6 address, whatever the endpoint's DNS advertises.
    ///
    /// The mock serves real 200s and reports whether anything connected, so
    /// the assertion is that the probe never reached it — not merely that
    /// the call returned an error.
    #[test]
    fn ipv4_probe_cannot_reach_an_ipv6_only_destination() {
        use std::io::ErrorKind;
        use std::time::Instant;

        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            // No IPv6 loopback on this host — nothing to assert against.
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            listener.set_nonblocking(true).expect("non-blocking accept");
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking stream");
                        let mut request = [0_u8; 1024];
                        let _ = stream.read(&mut request);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n::1",
                        );
                        return true;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return false,
                }
            }
            false
        });

        let result =
            get_text_v4_result(&format!("http://[::1]:{port}/echo"), Duration::from_secs(1));
        let connected = server.join().expect("mock server thread");

        assert!(
            !connected,
            "the IPv4 probe reached a v6-only endpoint; its answer could be an IPv6 address"
        );
        assert_eq!(result, Err(GetTextError::Transport));
    }
}
