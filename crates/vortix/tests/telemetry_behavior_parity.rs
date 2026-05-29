//! Plan 002 U9 — behavior-parity tests for the `reqwest`-based telemetry
//! HTTP helper. Locks in the contract before the curl swap: timeouts,
//! redirect policy, non-2xx mapping, and JSON deserialization all match
//! what the prior `curl -s --max-time N <url>` invocation produced.
//!
//! The mock server is a hand-rolled `std::net::TcpListener` that reads
//! the request line and writes a crafted HTTP/1.1 response per path —
//! no external mock framework dep.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use vortix::core::telemetry_http;

/// Bind ephemeral port + spawn a thread that handles connections until
/// `shutdown` flips. Returns the bound port + a `Drop` guard that flips
/// the shutdown flag (so each test releases its server).
fn spawn_mock_server() -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    listener
        .set_nonblocking(true)
        .expect("set listener non-blocking");
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let handle = thread::spawn(move || {
        while !shutdown_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    thread::spawn(move || handle_connection(stream));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    MockServer {
        port,
        shutdown,
        join: Some(handle),
    }
}

struct MockServer {
    port: u16,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Read the request line ("GET /path HTTP/1.1"), drain remaining
/// headers, then write a response per `path`.
fn handle_connection(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("dup stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut path = String::new();
    if let Some(p) = request_line.split_whitespace().nth(1) {
        path.push_str(p);
    }
    // Drain header lines until empty line.
    let mut header = String::new();
    loop {
        header.clear();
        if reader.read_line(&mut header).is_err() || header == "\r\n" || header.is_empty() {
            break;
        }
    }
    write_response(&mut stream, &path);
}

fn write_response(stream: &mut TcpStream, path: &str) {
    match path {
        "/ok" => {
            let body = "203.0.113.5\n";
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            );
        }
        "/json" => {
            let body =
                r#"{"ip":"198.51.100.42","isp":"Acme ISP","city":"Townsville","country":"NA"}"#;
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            );
        }
        "/500" => {
            let _ =
                stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
        }
        "/redirect" => {
            let _ = stream.write_all(
                b"HTTP/1.1 301 Moved Permanently\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\n\r\n",
            );
        }
        "/slow" => {
            // Read response slowly enough to trip the client timeout.
            thread::sleep(Duration::from_secs(3));
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        }
        _ => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        }
    }
    let _ = stream.flush();
    // Read-then-discard whatever the client sends to clean shutdown.
    let mut sink = [0u8; 64];
    let _ = stream.read(&mut sink);
}

#[derive(Debug, serde::Deserialize)]
struct MockJsonBody {
    ip: String,
    isp: String,
    city: String,
}

#[test]
fn get_text_returns_body_on_200() {
    let server = spawn_mock_server();
    let body = telemetry_http::get_text(&server.url("/ok"), Duration::from_secs(2))
        .expect("expected 200 + body");
    assert_eq!(body.trim(), "203.0.113.5");
}

#[test]
fn get_text_returns_none_on_5xx() {
    // Curl-without-`-L` exits non-zero on 5xx because it uses HTTP/1.1
    // and doesn't follow; our helper maps non-success → None to match
    // the prior caller's `output.status.success()` check.
    let server = spawn_mock_server();
    let result = telemetry_http::get_text(&server.url("/500"), Duration::from_secs(2));
    assert!(result.is_none(), "expected None on 5xx, got {result:?}");
}

#[test]
fn get_text_does_not_follow_redirects() {
    // Curl without `-L` does NOT follow 3xx — it surfaces the redirect
    // response itself. Our helper is configured with `Policy::none()`
    // so reqwest behaves the same way: redirect → None (not-2xx).
    let server = spawn_mock_server();
    let result = telemetry_http::get_text(&server.url("/redirect"), Duration::from_secs(2));
    assert!(
        result.is_none(),
        "expected None on un-followed redirect, got {result:?}"
    );
}

#[test]
fn get_text_times_out_within_budget() {
    // Curl's `--max-time 1` translates to reqwest's `.timeout(1s)`. A
    // server that takes 3s to respond must trip the timeout in ~1s.
    let server = spawn_mock_server();
    let start = std::time::Instant::now();
    let result = telemetry_http::get_text(&server.url("/slow"), Duration::from_secs(1));
    let elapsed = start.elapsed();
    assert!(result.is_none(), "expected timeout None, got {result:?}");
    assert!(
        elapsed < Duration::from_millis(2500),
        "timeout should fire within ~1s budget, elapsed: {elapsed:?}"
    );
}

#[test]
fn get_json_deserializes_typed_response() {
    let server = spawn_mock_server();
    let parsed: MockJsonBody =
        telemetry_http::get_json(&server.url("/json"), Duration::from_secs(2))
            .expect("expected JSON deserialization");
    assert_eq!(parsed.ip, "198.51.100.42");
    assert_eq!(parsed.isp, "Acme ISP");
    assert_eq!(parsed.city, "Townsville");
}

#[test]
fn unreachable_endpoint_returns_none() {
    // Curl returns exit-7 on connection refused; we map to None.
    // Use a localhost port we just bound + immediately dropped to make
    // ECONNREFUSED reliable.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    drop(listener); // free the port so subsequent connects refuse
    let url = format!("http://127.0.0.1:{port}/whatever");
    let result = telemetry_http::get_text(&url, Duration::from_secs(2));
    assert!(
        result.is_none(),
        "expected None for connection-refused, got {result:?}"
    );
}
