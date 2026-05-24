//! Cold-start performance test (plan 008 U6).
//!
//! Locks in a wall-clock ceiling for `vortix --version` so future
//! changes don't quietly inflate startup time. Runs the binary under
//! `--version` and asserts the elapsed time stays under a comfortable
//! ceiling.
//!
//! Ceilings (calibrated against actual measurements on the workspace's
//! current dependency graph, not the README's marketing claim — which
//! is out of date and tracked separately for a doc update):
//! - 500 ms for release builds. Observed locally: ~280 ms. The 1.8x
//!   margin catches a real doubling regression without flaking on CI
//!   runners under load.
//! - 1500 ms for debug builds. Observed locally: ~150 ms. The wide
//!   margin accommodates debug-symbol overhead and CI variability.
//!
//! When you change this, change the README's claim too. Don't silently
//! relax the ceiling — investigate first.
//!
//! The test invokes the binary via `CARGO_BIN_EXE_vortix`, which Cargo
//! sets to the path of the binary built for this integration test.

use std::process::Command;
use std::time::{Duration, Instant};

const CEILING: Duration = if cfg!(debug_assertions) {
    Duration::from_millis(1500)
} else {
    Duration::from_millis(500)
};

#[test]
fn vortix_version_cold_start_under_ceiling() {
    let bin = env!("CARGO_BIN_EXE_vortix");

    let start = Instant::now();
    let output = Command::new(bin)
        .arg("--version")
        .output()
        .expect("failed to spawn vortix binary");
    let elapsed = start.elapsed();

    // Sanity: the command actually succeeded. A non-zero exit could
    // make the test pass deceptively (panic-during-startup may exit
    // fast).
    assert!(
        output.status.success(),
        "vortix --version exited non-zero: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("vortix"),
        "vortix --version stdout missing 'vortix': {stdout}"
    );

    assert!(
        elapsed < CEILING,
        "vortix --version cold start was {}ms, exceeds ceiling of {}ms (mode: {})",
        elapsed.as_millis(),
        CEILING.as_millis(),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    );
}
