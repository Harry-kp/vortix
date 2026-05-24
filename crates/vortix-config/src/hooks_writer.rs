//! Comment-preserving writer for the `[[hooks]]` section of
//! `settings.toml` (plan 017 U2).
//!
//! The TUI hook management surface mutates only the `hooks` array of
//! tables; everything else in `settings.toml` — comments, blank lines,
//! key ordering, unrelated sections — must round-trip unchanged. The
//! `toml` crate flattens all of that, so this module routes writes
//! through `toml_edit` which preserves the document model.
//!
//! Public API:
//! - [`write_hooks`] — read-mutate-write of the `hooks` slice.
//! - [`write_hooks_with_mtime_check`] — the same, with an external-
//!   edit guard for the TUI's mtime-based conflict detection.
//!
//! Atomicity: writes go through a sibling `<path>.tmp` file that's
//! fsync'd and renamed over the target, so a process death mid-write
//! cannot leave a half-written `settings.toml`.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use thiserror::Error;
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use crate::hooks_config::HookConfig;

/// Errors surfaced by the hooks writer.
#[derive(Debug, Error)]
pub enum HooksWriteError {
    /// I/O failure reading, writing, syncing, or renaming.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The existing `settings.toml` could not be parsed. The TUI must
    /// surface this without overwriting — the user has a malformed
    /// file we shouldn't trample.
    #[error("settings.toml is not valid TOML: {0}")]
    Parse(String),
    /// External-edit guard: the file's mtime has advanced since the
    /// caller captured `expected_mtime`. The caller decides whether to
    /// retry with [`write_hooks`] (overwrite-anyway) or abort.
    #[error("settings.toml changed externally")]
    MtimeChanged {
        /// The mtime as observed at the moment of the failed check.
        current: SystemTime,
    },
}

/// Replace the `hooks` array in `path` with `hooks`, preserving every
/// byte outside the `hooks` region. If `path` does not exist, creates
/// a new file containing only the hooks section.
///
/// # Errors
/// Returns [`HooksWriteError::Io`] on filesystem failure or
/// [`HooksWriteError::Parse`] when the existing file is not valid TOML.
pub fn write_hooks(path: &Path, hooks: &[HookConfig]) -> Result<(), HooksWriteError> {
    let mut doc = load_document(path)?;
    set_hooks_array(&mut doc, hooks);
    atomic_write(path, doc.to_string().as_bytes())
}

/// Same as [`write_hooks`] but refuses to write when the file's
/// current mtime differs from `expected_mtime` — the TUI's external-
/// edit guard.
///
/// # Errors
/// Returns [`HooksWriteError::MtimeChanged`] when the file has been
/// modified since `expected_mtime` was captured; the file is NOT
/// overwritten in that case. Otherwise behaves like [`write_hooks`].
pub fn write_hooks_with_mtime_check(
    path: &Path,
    expected_mtime: SystemTime,
    hooks: &[HookConfig],
) -> Result<(), HooksWriteError> {
    if let Ok(meta) = fs::metadata(path) {
        let current = meta.modified()?;
        if current != expected_mtime {
            return Err(HooksWriteError::MtimeChanged { current });
        }
    }
    // If the file doesn't exist, no mtime to check — the expected
    // mtime came from a stat we can't verify against. Proceed.
    write_hooks(path, hooks)
}

fn load_document(path: &Path) -> Result<DocumentMut, HooksWriteError> {
    match fs::read_to_string(path) {
        Ok(s) => s
            .parse::<DocumentMut>()
            .map_err(|e| HooksWriteError::Parse(e.to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(DocumentMut::new()),
        Err(e) => Err(HooksWriteError::Io(e)),
    }
}

/// Replace the document's `hooks` array-of-tables with one entry per
/// `HookConfig`. Other top-level items — including comments and
/// blank lines attached to surrounding sections — are untouched.
///
/// Three cases:
/// 1. The document already has a `hooks` array-of-tables. We mutate
///    in place: clear and re-push. This preserves the array's
///    position in the file AND the decor (comments, blank lines)
///    attached to the surrounding tables.
/// 2. The document has a `hooks` key of some other shape (unlikely
///    but possible if the user hand-edited badly). Replace with an
///    array-of-tables in the same key slot.
/// 3. No `hooks` key. Append at the end of the document.
///
/// Case 1 is the dominant path and the one the comment-preservation
/// invariant cares about. Cases 2 and 3 are correctness fallbacks.
fn set_hooks_array(doc: &mut DocumentMut, hooks: &[HookConfig]) {
    if hooks.is_empty() {
        // Remove the array entirely — but preserve adjacent decor.
        // toml_edit's `remove` on a `DocumentMut` drops the value AND
        // its leading whitespace. For zero-hooks we accept that as
        // the lesser evil — a trailing-comment regression is
        // documented in the U2 test fixture.
        doc.remove("hooks");
        return;
    }

    // Case 1 + 2: an existing key under "hooks". Try to reuse it as
    // an ArrayOfTables. If the existing item is the right shape,
    // mutate IN PLACE (preserving position AND the per-table decor —
    // i.e. comments attached to each `[[hooks]]` header line). This
    // is the comment-preservation path the round-trip invariant
    // depends on.
    if doc.contains_key("hooks") {
        if let Some(aot) = doc
            .get_mut("hooks")
            .and_then(Item::as_array_of_tables_mut)
        {
            // Edit overlap of existing entries IN PLACE — preserve
            // decor on each surviving table. Then grow or shrink.
            let existing_len = aot.len();
            for (i, cfg) in hooks.iter().enumerate() {
                if i < existing_len {
                    let table = aot.get_mut(i).expect("checked length");
                    overwrite_table_contents(table, cfg);
                } else {
                    aot.push(hook_to_table(cfg));
                }
            }
            // Shrink: drop extra trailing entries.
            while aot.len() > hooks.len() {
                aot.remove(aot.len() - 1);
            }
            return;
        }
        // Wrong shape — replace the value at the same key.
        let mut aot = ArrayOfTables::new();
        for cfg in hooks {
            aot.push(hook_to_table(cfg));
        }
        doc["hooks"] = Item::ArrayOfTables(aot);
        return;
    }

    // Case 3: no existing key, append at end.
    let mut aot = ArrayOfTables::new();
    for cfg in hooks {
        aot.push(hook_to_table(cfg));
    }
    doc.insert("hooks", Item::ArrayOfTables(aot));
}

/// Replace the contents of an existing `[[hooks]]` table with the
/// fields from `cfg`. Preserves the table's decor (the comment block
/// attached to its header) by mutating in place. Removes keys not
/// present in the new config so toggling enabled=false → None
/// actually drops the line.
fn overwrite_table_contents(table: &mut Table, cfg: &HookConfig) {
    // Remove every key currently in the table.
    let existing_keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
    for k in existing_keys {
        table.remove(&k);
    }
    // Refill in canonical order matching hook_to_table.
    table.insert("event", Item::Value(Value::from(cfg.event.clone())));
    table.insert(
        "command",
        Item::Value(Value::Array(command_array(&cfg.command))),
    );
    if cfg.timeout_secs != 5 {
        table.insert(
            "timeout_secs",
            Item::Value(Value::from(
                i64::try_from(cfg.timeout_secs).unwrap_or(i64::MAX),
            )),
        );
    }
    if let Some(v) = cfg.enabled {
        table.insert("enabled", Item::Value(Value::from(v)));
    }
    if !cfg.env.is_empty() {
        table.insert("env", env_item(&cfg.env));
    }
}

fn hook_to_table(cfg: &HookConfig) -> Table {
    let mut t = Table::new();
    t.insert("event", Item::Value(Value::from(cfg.event.clone())));
    t.insert("command", Item::Value(Value::Array(command_array(&cfg.command))));
    // Only emit timeout_secs when it differs from the schema default
    // (5) — keeps "minimal" hook entries minimal on disk.
    if cfg.timeout_secs != 5 {
        t.insert(
            "timeout_secs",
            Item::Value(Value::from(i64::try_from(cfg.timeout_secs).unwrap_or(i64::MAX))),
        );
    }
    // Only emit enabled when it's been explicitly set. `None` ⇒ no
    // line (matches plan 017 D1: pre-017 settings.toml files survive
    // untouched until the user actively toggles a hook).
    if let Some(v) = cfg.enabled {
        t.insert("enabled", Item::Value(Value::from(v)));
    }
    if !cfg.env.is_empty() {
        t.insert("env", env_item(&cfg.env));
    }
    t
}

fn command_array(args: &[String]) -> Array {
    let mut arr = Array::new();
    for a in args {
        arr.push(a.clone());
    }
    arr
}

/// Inline-table for ≤2 entries, sub-table for 3+. Pure aesthetic
/// choice; pin the boundary via snapshot test so changing it later is
/// a deliberate, visible decision.
fn env_item(env: &HashMap<String, String>) -> Item {
    if env.len() <= 2 {
        let mut t = InlineTable::new();
        // Sort keys so output is stable across HashMap iteration order
        // (HashMap has nondeterministic iteration; we need byte-stable
        // writes for the round-trip invariant).
        let mut keys: Vec<&String> = env.keys().collect();
        keys.sort();
        for k in keys {
            t.insert(k, Value::from(env[k].clone()));
        }
        Item::Value(Value::InlineTable(t))
    } else {
        let mut t = Table::new();
        let mut keys: Vec<&String> = env.keys().collect();
        keys.sort();
        for k in keys {
            t.insert(k, Item::Value(Value::from(env[k].clone())));
        }
        Item::Table(t)
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), HooksWriteError> {
    // Same directory as the target so rename stays atomic on the same
    // filesystem (cross-fs rename is not atomic). Use a deterministic
    // suffix so partial writes from a previous crash are visible to
    // the user (rather than a tempfile sprinkled with random suffixes).
    let tmp = tmp_path(path);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup; ignore secondary failure.
            let _ = fs::remove_file(&tmp);
            Err(HooksWriteError::Io(e))
        }
    }
}

fn tmp_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}
