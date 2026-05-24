//! Integration tests for `hooks_writer` (plan 017 U2).
//!
//! Snapshot tests covering the comment-preservation invariant
//! (R2/R11/SC2): every byte outside the `[[hooks]]` array must survive
//! a TUI write byte-for-byte.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use vortix_config::{write_hooks, write_hooks_with_mtime_check, HookConfig, HooksWriteError};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn copy_fixture(name: &str, dir: &tempfile::TempDir) -> PathBuf {
    let dest = dir.path().join("settings.toml");
    fs::copy(fixture(name), &dest).expect("fixture copy");
    dest
}

fn hook(event: &str, args: &[&str]) -> HookConfig {
    HookConfig {
        event: event.into(),
        command: args.iter().map(|s| (*s).to_string()).collect(),
        timeout_secs: 5,
        env: HashMap::new(),
        enabled: None,
    }
}

fn hook_full(
    event: &str,
    args: &[&str],
    timeout_secs: u64,
    env: &[(&str, &str)],
    enabled: Option<bool>,
) -> HookConfig {
    HookConfig {
        event: event.into(),
        command: args.iter().map(|s| (*s).to_string()).collect(),
        timeout_secs,
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        enabled,
    }
}

/// Extract every byte of the file that's outside the `hooks` array.
/// The invariant the writer guarantees: this slice is identical
/// before and after a hooks-only write. We approximate "the hooks
/// region" as "lines that mention hooks or sit inside a `[[hooks]]`
/// table" — close enough for the smoke contract; the byte-identity
/// of comments outside that region is what matters.
fn non_hook_lines(content: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_hook = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("[[hooks]]") {
            in_hook = true;
            continue;
        }
        // Any new top-level table header ends the hook region.
        if in_hook && trimmed.starts_with('[') && !trimmed.starts_with("[hooks.") {
            in_hook = false;
        }
        if !in_hook {
            out.push(line);
        }
    }
    out
}

#[test]
fn writing_hooks_preserves_header_and_inline_comments() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture("settings_with_comments.toml", &dir);
    let before = fs::read_to_string(&path).unwrap();

    // Add a third hook — the existing two must round-trip exactly.
    let hooks = vec![
        hook("post_connect", &["echo", "hello"]),
        hook_full("post_disconnect", &["echo", "bye"], 10, &[], None),
        hook("connect_failed", &["echo", "oops"]),
    ];
    write_hooks(&path, &hooks).unwrap();

    let after = fs::read_to_string(&path).unwrap();
    let before_non_hook: Vec<&str> = non_hook_lines(&before);
    let after_non_hook: Vec<&str> = non_hook_lines(&after);
    assert_eq!(
        before_non_hook, after_non_hook,
        "non-hook lines must survive byte-for-byte"
    );
    // The new hook is present.
    assert!(
        after.contains("connect_failed"),
        "new hook should appear in output:\n{after}"
    );
}

#[test]
fn writing_into_file_with_no_hooks_section_appends_array() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture("settings_no_hooks.toml", &dir);
    let before = fs::read_to_string(&path).unwrap();

    write_hooks(&path, &[hook("post_connect", &["echo", "hi"])]).unwrap();
    let after = fs::read_to_string(&path).unwrap();

    // Pre-existing lines all survive.
    for line in before.lines() {
        assert!(
            after.contains(line),
            "line '{line}' missing from output"
        );
    }
    assert!(after.contains("[[hooks]]"));
    assert!(after.contains("post_connect"));
}

#[test]
fn writing_zero_hooks_removes_all_hook_blocks_keeping_other_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture("settings_with_comments.toml", &dir);

    write_hooks(&path, &[]).unwrap();
    let after = fs::read_to_string(&path).unwrap();

    // The literal `[[hooks]]` may appear in surviving comment text;
    // the contract is that no `[[hooks]]` *section header* remains.
    let has_section_header = after
        .lines()
        .any(|l| l.trim_start().starts_with("[[hooks]]"));
    assert!(
        !has_section_header,
        "no hooks section should remain, got:\n{after}"
    );
    // Top-of-file comment survives.
    assert!(after.contains("# vortix settings — hand-curated by the maintainer."));
    // Non-hook key survives.
    assert!(after.contains("log_level = \"info\""));
}

#[test]
fn other_sections_preserved_byte_for_byte_around_hooks_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture("settings_multi_sections.toml", &dir);
    let before = fs::read_to_string(&path).unwrap();

    let hooks = vec![hook("post_connect", &["notify-send", "VPN up"])];
    write_hooks(&path, &hooks).unwrap();
    let after = fs::read_to_string(&path).unwrap();

    // [journal] and [engine] sections preserved as a unit.
    let before_non_hook: Vec<&str> = non_hook_lines(&before);
    let after_non_hook: Vec<&str> = non_hook_lines(&after);
    assert_eq!(before_non_hook, after_non_hook);
}

#[test]
fn timeout_secs_default_value_is_omitted_from_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    write_hooks(&path, &[hook("post_connect", &["echo", "hi"])]).unwrap();
    let out = fs::read_to_string(&path).unwrap();
    assert!(!out.contains("timeout_secs"), "5s default should be omitted:\n{out}");
}

#[test]
fn timeout_secs_non_default_is_emitted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    write_hooks(
        &path,
        &[hook_full("post_connect", &["echo"], 30, &[], None)],
    )
    .unwrap();
    let out = fs::read_to_string(&path).unwrap();
    assert!(out.contains("timeout_secs = 30"), "output:\n{out}");
}

#[test]
fn enabled_none_omits_line_some_false_emits_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    write_hooks(
        &path,
        &[
            hook("post_connect", &["echo", "a"]),                              // None → no line
            hook_full("post_disconnect", &["echo", "b"], 5, &[], Some(false)), // → enabled = false
        ],
    )
    .unwrap();
    let out = fs::read_to_string(&path).unwrap();
    // First entry has no enabled line.
    let first_chunk = out
        .split("[[hooks]]")
        .nth(1)
        .expect("expected first hook chunk");
    assert!(!first_chunk.contains("enabled"), "first hook chunk:\n{first_chunk}");
    // Second entry has explicit `enabled = false`.
    assert!(out.contains("enabled = false"), "full output:\n{out}");
}

#[test]
fn env_with_two_keys_uses_inline_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    write_hooks(
        &path,
        &[hook_full(
            "post_connect",
            &["echo"],
            5,
            &[("A", "1"), ("B", "2")],
            None,
        )],
    )
    .unwrap();
    let out = fs::read_to_string(&path).unwrap();
    // Inline table form has `env = { ... }` on one line.
    assert!(
        out.lines().any(|l| l.contains("env = {") && l.contains('}')),
        "expected inline-table env, got:\n{out}"
    );
}

#[test]
fn env_with_three_keys_uses_sub_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    write_hooks(
        &path,
        &[hook_full(
            "post_connect",
            &["echo"],
            5,
            &[("A", "1"), ("B", "2"), ("C", "3")],
            None,
        )],
    )
    .unwrap();
    let out = fs::read_to_string(&path).unwrap();
    // Sub-table form has a `[hooks.env]` header line.
    assert!(
        out.contains("[hooks.env]") || out.contains("[[hooks.env]]"),
        "expected sub-table env header, got:\n{out}"
    );
}

#[test]
fn atomic_write_leaves_no_tmp_file_on_success() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    write_hooks(&path, &[hook("post_connect", &["echo"])]).unwrap();
    let tmp = dir.path().join("settings.toml.tmp");
    assert!(!tmp.exists(), "tmp file should be renamed away");
}

#[test]
fn mtime_check_passes_when_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture("settings_no_hooks.toml", &dir);
    let original_mtime = fs::metadata(&path).unwrap().modified().unwrap();
    write_hooks_with_mtime_check(
        &path,
        original_mtime,
        &[hook("post_connect", &["echo"])],
    )
    .expect("matching mtime should write cleanly");
}

#[test]
fn mtime_check_fails_when_file_changed_externally() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture("settings_no_hooks.toml", &dir);
    // Capture a fake "old" mtime older than the actual file.
    let stale_mtime = SystemTime::UNIX_EPOCH;

    let err = write_hooks_with_mtime_check(
        &path,
        stale_mtime,
        &[hook("post_connect", &["echo"])],
    )
    .expect_err("stale mtime should refuse to overwrite");
    assert!(matches!(err, HooksWriteError::MtimeChanged { .. }));

    // File untouched.
    let after = fs::read_to_string(&path).unwrap();
    assert!(!after.contains("[[hooks]]"));
}

#[test]
fn mtime_check_writes_when_target_does_not_exist_yet() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    // No file yet — mtime check has nothing to compare against; we
    // proceed.
    write_hooks_with_mtime_check(
        &path,
        SystemTime::UNIX_EPOCH,
        &[hook("post_connect", &["echo"])],
    )
    .expect("nonexistent target should not block first write");
    assert!(path.exists());
}

#[test]
fn malformed_existing_settings_is_reported_not_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    fs::write(&path, "this is not = valid = toml = at = all\n").unwrap();
    let before = fs::read_to_string(&path).unwrap();

    let err = write_hooks(&path, &[hook("post_connect", &["echo"])])
        .expect_err("malformed input should error");
    assert!(matches!(err, HooksWriteError::Parse(_)));

    // Original content untouched.
    let after = fs::read_to_string(&path).unwrap();
    assert_eq!(before, after, "malformed file must not be overwritten");
}
