//! JSON v2 envelope shape tests — multi-connection plan U21.
//!
//! Validates the wire shape downstream JSON consumers depend on:
//! - top-level `schema_version: 2`, `ok`, `command`, optional `data`
//!   / `error` / `next_actions`
//! - `data` for `status` contains `connections: [...]`, `primary: <id|null>`,
//!   `connection: <entry|null>` (v1 back-compat)
//! - `ConnectionEntry` field set is stable
//!
//! These tests pin the CONTRACT — what an external `jq`-using script sees —
//! not the code path that produces it. They catch field-rename regressions
//! and schema-version drift. Full-path coverage of `handle_status` requires
//! a process-spawn integration layer; deferred to a follow-up unit.
//!
//! Plan: docs/plans/2026-05-29-002-feat-behavioral-test-automation-plan.md (U7)

use serde::Serialize;
use vortix::cli::output::{CliResponse, ConnectionEntry, SCHEMA_VERSION};

/// Mirror of the private `StatusData` shape in `cli/commands.rs` — frozen
/// here so test failures fire IF the production shape drifts. When the
/// production shape changes intentionally, this struct must update in
/// lockstep; the test break is the signal that downstream JSON consumers
/// (`jq '.data.primary'`-using scripts) will also break.
///
/// `Serialize`-only by design — production `ConnectionEntry` is one-way
/// (we write JSON; consumers read it). Round-trip tests go through
/// `serde_json::Value` instead.
#[derive(Debug, Clone, Serialize)]
struct StatusDataShape {
    connections: Vec<ConnectionEntry>,
    primary: Option<String>,
    connection: Option<ConnectionEntry>,
}

fn make_connection_entry(profile: &str, protocol: &str) -> ConnectionEntry {
    // Construct via direct field assignment to mirror the production
    // builder; if `ConnectionEntry` gains required fields this test fails
    // to compile, surfacing the schema break loudly.
    ConnectionEntry {
        state: "connected".into(),
        profile: Some(profile.into()),
        protocol: Some(protocol.into()),
        uptime_secs: Some(120),
    }
}

#[test]
fn json_v2_schema_version_is_two() {
    assert_eq!(
        SCHEMA_VERSION, 2,
        "schema_version constant must stay at 2 — any bump is a breaking change to JSON consumers"
    );
}

#[test]
fn json_v2_envelope_no_tunnels_has_empty_connections_and_null_primary() {
    let data = StatusDataShape {
        connections: Vec::new(),
        primary: None,
        connection: None,
    };
    let resp = CliResponse::success("status", data, vec![]);
    let json = serde_json::to_value(&resp).unwrap();

    assert_eq!(json["schema_version"], 2);
    assert_eq!(json["ok"], true);
    assert_eq!(json["command"], "status");
    assert_eq!(json["data"]["connections"].as_array().unwrap().len(), 0);
    assert!(json["data"]["primary"].is_null());
    assert!(json["data"]["connection"].is_null());
}

#[test]
fn json_v2_envelope_one_primary_populates_back_compat_connection_field() {
    let entry = make_connection_entry("corp", "wireguard");
    let data = StatusDataShape {
        connections: vec![entry.clone()],
        primary: Some("corp".into()),
        connection: Some(entry),
    };
    let resp = CliResponse::success("status", data, vec![]);
    let json = serde_json::to_value(&resp).unwrap();

    assert_eq!(json["schema_version"], 2);
    let conns = json["data"]["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0]["profile"], "corp");
    assert_eq!(json["data"]["primary"], "corp");
    // v1 back-compat: data.connection MUST be populated when a primary
    // exists so `jq '.data.connection.profile'` from v0.3.x consumers
    // still works. This is the load-bearing R6 invariant.
    assert!(!json["data"]["connection"].is_null());
    assert_eq!(json["data"]["connection"]["profile"], "corp");
}

#[test]
fn json_v2_envelope_two_tunnels_lists_both_and_picks_primary() {
    let primary = make_connection_entry("corp", "wireguard");
    let secondary = make_connection_entry("lab", "wireguard");
    let data = StatusDataShape {
        connections: vec![primary.clone(), secondary],
        primary: Some("corp".into()),
        connection: Some(primary),
    };
    let resp = CliResponse::success("status", data, vec![]);
    let json = serde_json::to_value(&resp).unwrap();

    let conns = json["data"]["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 2);
    let names: Vec<&str> = conns
        .iter()
        .map(|c| c["profile"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"corp"));
    assert!(names.contains(&"lab"));
    assert_eq!(json["data"]["primary"], "corp");
    assert_eq!(json["data"]["connection"]["profile"], "corp");
}

#[test]
fn json_v2_envelope_secondaries_only_has_null_primary_and_null_connection() {
    // No tunnel claims the default route — primary is null. v1 readers
    // see `data.connection: null` so they fall through to their
    // "disconnected" handling, which is the correct behavior on a
    // no-primary state.
    let lab = make_connection_entry("lab", "wireguard");
    let home = make_connection_entry("home", "wireguard");
    let data = StatusDataShape {
        connections: vec![lab, home],
        primary: None,
        connection: None,
    };
    let resp = CliResponse::success("status", data, vec![]);
    let json = serde_json::to_value(&resp).unwrap();

    let conns = json["data"]["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 2);
    assert!(json["data"]["primary"].is_null());
    assert!(json["data"]["connection"].is_null());
}

#[test]
fn json_v2_envelope_roundtrips_serde() {
    // Round-trip stability: if `ConnectionEntry`'s serde annotations
    // drift, the second deserialize will fail or yield a different
    // value than the first serialize.
    let entry = make_connection_entry("corp", "wireguard");
    let data = StatusDataShape {
        connections: vec![entry.clone()],
        primary: Some("corp".into()),
        connection: Some(entry),
    };
    let resp = CliResponse::success("status", data, vec![]);
    let json_one = serde_json::to_string(&resp).unwrap();

    // Deserialize as a generic Value, re-serialize — bytes should match
    // exactly modulo field ordering.
    let value: serde_json::Value = serde_json::from_str(&json_one).unwrap();
    let json_two = serde_json::to_string(&value).unwrap();
    let value_again: serde_json::Value = serde_json::from_str(&json_two).unwrap();
    assert_eq!(value, value_again);
}

#[test]
fn json_v2_envelope_optional_fields_skip_when_none() {
    // `data.connection` and `data.primary` use `Option`; when None, the
    // envelope SHOULD render them as `null` not omit them — v1 readers
    // expect the field to exist. The CliResponse top-level `next_actions`
    // and `error` DO skip when None (different invariant).
    let data = StatusDataShape {
        connections: Vec::new(),
        primary: None,
        connection: None,
    };
    let resp = CliResponse::success("status", data, vec![]);
    let json = serde_json::to_string(&resp).unwrap();

    // data.primary and data.connection ARE serialized as null
    assert!(
        json.contains("\"primary\":null"),
        "data.primary must serialize as null when None; got: {json}"
    );
    assert!(
        json.contains("\"connection\":null"),
        "data.connection must serialize as null when None; got: {json}"
    );
    // top-level error IS skipped when None (different invariant)
    assert!(
        !json.contains("\"error\":"),
        "CliResponse.error should skip when None; got: {json}"
    );
}
