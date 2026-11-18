//! Opt-in behavioural trace for diagnosing a live session.
//!
//! Off unless `VORTIX_TRACE_LOG` names a file, so nothing is written on a
//! user's machine unless they are helping debug something. When it is on,
//! every key, every message, every command and every control-state transition
//! lands in one file in the order it happened — enough to reconstruct what the
//! session did without asking the person in front of it to remember.
//!
//! Deliberately not `tracing`: this is a flight recorder for one session, read
//! by a human afterwards, and it must not depend on a subscriber being
//! installed or compete with the event log the user actually sees.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static SINK: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();

fn sink() -> Option<&'static Mutex<std::fs::File>> {
    SINK.get_or_init(|| {
        let path = std::env::var_os("VORTIX_TRACE_LOG")?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        Some(Mutex::new(file))
    })
    .as_ref()
}

/// Whether tracing is on. Callers with expensive detail should check first.
#[must_use]
pub fn enabled() -> bool {
    sink().is_some()
}

/// Record one event under a category, e.g. `key`, `msg`, `cmd`, `ctl`.
pub fn record(category: &str, detail: &str) {
    let Some(sink) = sink() else {
        return;
    };
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis());
    let Ok(mut file) = sink.lock() else {
        return;
    };
    let _ = writeln!(file, "{stamp} {category:<4} {detail}");
    let _ = file.flush();
}

/// Record only when tracing is on, without building the string otherwise.
#[macro_export]
macro_rules! trace_event {
    ($category:expr, $($arg:tt)*) => {
        if $crate::trace::enabled() {
            $crate::trace::record($category, &format!($($arg)*));
        }
    };
}

/// Record a dispatched message.
///
/// Ticks are dropped and long payloads are clipped: a snapshot rendered in
/// full is thousands of characters and buries the keys and commands around
/// it, which are the reason to read this file at all. The control-state
/// transitions worth having are recorded separately under `ctl`.
pub fn message(msg: &crate::message::Message) {
    const LIMIT: usize = 160;

    if !enabled() || matches!(msg, crate::message::Message::Tick) {
        return;
    }
    let rendered = format!("{msg:?}");
    let clipped = rendered
        .char_indices()
        .nth(LIMIT)
        .map_or(rendered.clone(), |(index, _)| {
            format!("{}…", &rendered[..index])
        });
    record("msg", &clipped);
}
