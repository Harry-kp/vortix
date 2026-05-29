//! HTTP helper for the telemetry workers (plan 002 U9).
//!
//! Wraps a single process-wide `reqwest::blocking::Client` (lazy-init via
//! `OnceLock`) configured to match curl's no-flag default behavior:
//!
//! - `Policy::none()` — curl invoked without `-L` does NOT follow
//!   redirects. The prior shell-out's `output.status.success()` check
//!   treated a redirect response as success-with-redirect-body; we
//!   instead map any non-2xx (including 3xx) to `None`. Callers parsed
//!   stdout as IP text; an IP buried in a redirect body was never a
//!   valid signal, so this is behavior-preserving for the calling
//!   contract.
//! - rustls-tls — TLS verification on, no OpenSSL.
//! - `connection_verbose(false)` and default redirect-followed = none.
//!
//! Timeout is per-request (mirrors `curl --max-time N` semantics), set
//! via `.timeout(Duration)` on the request builder rather than the
//! client builder.

use std::sync::OnceLock;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::de::DeserializeOwned;

/// Lazy-init process-wide client. Re-uses TCP connections + TLS
/// sessions across telemetry calls. Returns `None` if the client could
/// not be constructed (extremely rare — rustls init failure).
fn client() -> Option<&'static Client> {
    static CLIENT: OnceLock<Option<Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            Client::builder()
                .redirect(Policy::none())
                // No `.timeout(...)` here — per-request timeouts are
                // applied by the caller via `RequestBuilder::timeout`.
                .build()
                .ok()
        })
        .as_ref()
}

/// GET `url` with the given timeout. Returns the response body as
/// `String` on 2xx, `None` for any error: timeout, DNS failure,
/// connection refused, TLS failure, non-2xx status.
///
/// Matches the prior `curl -s --max-time N <url>` shell-out's
/// `output.status.success()` + `stdout` semantics.
#[must_use]
pub fn get_text(url: &str, timeout: Duration) -> Option<String> {
    let client = client()?;
    let response = client.get(url).timeout(timeout).send().ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.text().ok()
}

/// GET `url` with the given timeout and deserialize the 2xx JSON body
/// into `T`. Returns `None` for any error: timeout, DNS, connection,
/// TLS, non-2xx, or deserialization failure.
///
/// Matches the prior shell-out flow that piped curl stdout into
/// `serde_json::from_str`, just without the intermediate `Vec<u8>` →
/// `String` step.
#[must_use]
pub fn get_json<T: DeserializeOwned>(url: &str, timeout: Duration) -> Option<T> {
    let client = client()?;
    let response = client.get(url).timeout(timeout).send().ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<T>().ok()
}

/// IPv6-only GET — used by the IPv6-leak probe in `fetch_security_info`.
/// Returns `true` if the request reached a 2xx response over IPv6;
/// `false` for any failure (no IPv6 route, timeout, non-2xx).
///
/// Curl achieves IPv6-only with `-6`; reqwest exposes this via
/// `local_address` set to `::` (any IPv6). Binding the local address
/// to `std::net::Ipv6Addr::UNSPECIFIED` forces the connection to be
/// made over IPv6.
#[must_use]
pub fn probe_ipv6(url: &str, timeout: Duration) -> bool {
    let Ok(client) = Client::builder()
        .redirect(Policy::none())
        .local_address(Some(std::net::Ipv6Addr::UNSPECIFIED.into()))
        .build()
    else {
        return false;
    };
    client
        .get(url)
        .timeout(timeout)
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}
