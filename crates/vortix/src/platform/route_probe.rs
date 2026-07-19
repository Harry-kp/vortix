//! Shared failure backoff for platform route-table probes.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::vortix_process::CommandSpec;

pub(crate) enum ProbeOutcome {
    BackedOff,
    Success(String),
    Failed {
        consecutive_failures: u32,
        cooldown: Duration,
    },
}

struct ProbeBackoff {
    consecutive_failures: u32,
    next_allowed: Instant,
}

/// Process-wide state for one platform route probe.
pub(crate) struct RouteProbe {
    state: OnceLock<Mutex<ProbeBackoff>>,
}

impl RouteProbe {
    pub(crate) const fn new() -> Self {
        Self {
            state: OnceLock::new(),
        }
    }

    pub(crate) fn run(&self, spec: CommandSpec) -> ProbeOutcome {
        let state = self.state.get_or_init(|| {
            Mutex::new(ProbeBackoff {
                consecutive_failures: 0,
                next_allowed: Instant::now(),
            })
        });

        {
            let state = state.lock().expect("backoff state mutex poisoned");
            if Instant::now() < state.next_allowed {
                return ProbeOutcome::BackedOff;
            }
        }

        let result = crate::vortix_process::run_to_output(spec);
        let mut state = state.lock().expect("backoff state mutex poisoned");
        if let Ok(output) = result {
            state.consecutive_failures = 0;
            state.next_allowed = Instant::now();
            return ProbeOutcome::Success(String::from_utf8_lossy(&output.stdout).into_owned());
        }

        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let cooldown = cooldown_for_failures(state.consecutive_failures);
        state.next_allowed = Instant::now() + cooldown;
        ProbeOutcome::Failed {
            consecutive_failures: state.consecutive_failures,
            cooldown,
        }
    }
}

fn cooldown_for_failures(failures: u32) -> Duration {
    Duration::from_secs(match failures {
        0..=2 => 0,
        3..=5 => 5,
        6..=10 => 15,
        _ => 60,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_ladder_escalates_then_caps() {
        assert_eq!(cooldown_for_failures(0), Duration::ZERO);
        assert_eq!(cooldown_for_failures(2), Duration::ZERO);
        assert_eq!(cooldown_for_failures(3), Duration::from_secs(5));
        assert_eq!(cooldown_for_failures(5), Duration::from_secs(5));
        assert_eq!(cooldown_for_failures(6), Duration::from_secs(15));
        assert_eq!(cooldown_for_failures(10), Duration::from_secs(15));
        assert_eq!(cooldown_for_failures(11), Duration::from_secs(60));
        assert_eq!(cooldown_for_failures(1_000_000), Duration::from_secs(60));
    }
}
