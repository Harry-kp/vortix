//! Lifecycle hooks (plan 015 phase A / plan 009).
//!
//! Defines the seam that lets users run scripts at FSM transitions
//! (pre-/post-connect, pre-/post-disconnect, connect-failed, reconnecting).
//! The trait is async; concrete impls live in the binary crate (`ShellHook`
//! in `crates/vortix/src/hooks/`) because they need subprocess access via
//! the `CommandRunner` port.
//!
//! Wiring: at startup the binary subscribes to the `Journal` broadcast,
//! maps `EngineEvent` → `LifecycleEvent`, and dispatches via
//! [`HookRegistry::dispatch`]. Dispatch never blocks the FSM; each hook
//! runs under its own configured timeout and failures are journal-logged.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::profile::{ProfileId, ProtocolKind};

/// The lifecycle event a hook is invoked with.
///
/// `#[non_exhaustive]` so future variants (mid-flow auth challenge, IP
/// changed, etc.) don't break consumers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LifecycleEvent {
    /// About to start a connect attempt.
    PreConnect {
        profile_id: ProfileId,
        protocol: ProtocolKind,
    },
    /// `TunnelUp` was just observed.
    PostConnect {
        profile_id: ProfileId,
        protocol: ProtocolKind,
        interface_name: String,
    },
    /// User asked to disconnect; FSM is moving into `Disconnecting`.
    PreDisconnect { profile_id: ProfileId },
    /// `TunnelDown` was just observed.
    PostDisconnect { profile_id: ProfileId },
    /// A connect attempt failed and is not being retried automatically.
    ConnectFailed {
        profile_id: ProfileId,
        reason: String,
    },
    /// FSM transitioned into `Reconnecting`.
    Reconnecting { profile_id: ProfileId, attempt: u32 },
}

impl LifecycleEvent {
    /// The kebab-cased name of this event, used to match against
    /// configured hook entries (e.g. `event = "post_connect"`).
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::PreConnect { .. } => "pre_connect",
            Self::PostConnect { .. } => "post_connect",
            Self::PreDisconnect { .. } => "pre_disconnect",
            Self::PostDisconnect { .. } => "post_disconnect",
            Self::ConnectFailed { .. } => "connect_failed",
            Self::Reconnecting { .. } => "reconnecting",
        }
    }

    /// The `ProfileId` associated with this event.
    #[must_use]
    pub fn profile_id(&self) -> &ProfileId {
        match self {
            Self::PreConnect { profile_id, .. }
            | Self::PostConnect { profile_id, .. }
            | Self::PreDisconnect { profile_id }
            | Self::PostDisconnect { profile_id }
            | Self::ConnectFailed { profile_id, .. }
            | Self::Reconnecting { profile_id, .. } => profile_id,
        }
    }
}

/// Outcome of a single hook firing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome {
    /// Hook ran to completion (exit code 0 for `ShellHook`).
    Success,
    /// Hook exited non-zero. Body carries the error description for
    /// logging.
    Failed(String),
    /// Hook exceeded its configured timeout and was cancelled.
    TimedOut,
    /// Hook panicked or was otherwise aborted internally.
    Aborted(String),
}

/// A registered hook. Implementations live in the binary crate.
///
/// Returning `()` (not `Result`) is deliberate — hooks are fire-and-
/// forget observers. Failures surface via [`HookOutcome`] returned to
/// the registry, not via the trait method's signature.
pub trait Hook: Send + Sync {
    /// Fire this hook for the given event. Must respect the supplied
    /// timeout (cancel any in-flight work when exceeded).
    fn fire<'a>(
        &'a self,
        event: &'a LifecycleEvent,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = HookOutcome> + Send + 'a>>;

    /// Which `LifecycleEvent::kind_str()` values this hook subscribes
    /// to. Empty means "all events."
    fn subscribed_kinds(&self) -> &[&'static str];

    /// Configured per-hook timeout. The registry passes this to
    /// [`Self::fire`].
    fn timeout(&self) -> Duration;

    /// Human-readable name for logging. Defaults to the trait
    /// implementer's type name.
    fn name(&self) -> &'static str {
        "hook"
    }
}

/// In-process registry of hooks. Held by the binary; the
/// journal-subscriber task calls [`Self::dispatch`] for each
/// `LifecycleEvent` it derives from the `EngineEvent` stream.
#[derive(Default)]
pub struct HookRegistry {
    hooks: Vec<Box<dyn Hook>>,
}

impl HookRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hook. Order matters for log readability but not for
    /// correctness — hooks are independent.
    pub fn register(&mut self, hook: Box<dyn Hook>) {
        self.hooks.push(hook);
    }

    /// Number of registered hooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// Whether any hooks are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Fire every subscribed hook for `event`. Failures don't propagate;
    /// outcomes are returned for the caller to log/journal as they see
    /// fit. Hooks run sequentially (small N expected; parallel adds
    /// complexity for no observable win in the v0.3.0 surface).
    pub async fn dispatch(&self, event: &LifecycleEvent) -> Vec<(String, HookOutcome)> {
        let mut out = Vec::new();
        for hook in &self.hooks {
            let kinds = hook.subscribed_kinds();
            if !kinds.is_empty() && !kinds.contains(&event.kind_str()) {
                continue;
            }
            let outcome = hook.fire(event, hook.timeout()).await;
            out.push((hook.name().to_string(), outcome));
        }
        out
    }
}

impl std::fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRegistry")
            .field("hooks", &format!("[{}]", self.hooks.len()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingHook {
        count: Arc<AtomicUsize>,
        outcome: HookOutcome,
        kinds: &'static [&'static str],
    }

    impl Hook for CountingHook {
        fn fire<'a>(
            &'a self,
            _event: &'a LifecycleEvent,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = HookOutcome> + Send + 'a>> {
            let outcome = self.outcome.clone();
            let count = self.count.clone();
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                outcome
            })
        }
        fn subscribed_kinds(&self) -> &[&'static str] {
            self.kinds
        }
        fn timeout(&self) -> Duration {
            Duration::from_secs(5)
        }
        fn name(&self) -> &'static str {
            "counting"
        }
    }

    fn pre_connect_event() -> LifecycleEvent {
        LifecycleEvent::PreConnect {
            profile_id: ProfileId::new("corp"),
            protocol: ProtocolKind::WireGuard,
        }
    }

    #[tokio::test]
    async fn registry_dispatch_with_zero_hooks_returns_empty() {
        let reg = HookRegistry::new();
        let outcomes = reg.dispatch(&pre_connect_event()).await;
        assert!(outcomes.is_empty());
    }

    #[tokio::test]
    async fn all_hooks_fire_when_subscribed_to_all_events() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut reg = HookRegistry::new();
        for _ in 0..3 {
            reg.register(Box::new(CountingHook {
                count: count.clone(),
                outcome: HookOutcome::Success,
                kinds: &[],
            }));
        }
        let outcomes = reg.dispatch(&pre_connect_event()).await;
        assert_eq!(outcomes.len(), 3);
        assert_eq!(count.load(Ordering::SeqCst), 3);
        assert!(outcomes.iter().all(|(_, o)| *o == HookOutcome::Success));
    }

    #[tokio::test]
    async fn hook_skipped_when_not_subscribed_to_event_kind() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut reg = HookRegistry::new();
        reg.register(Box::new(CountingHook {
            count: count.clone(),
            outcome: HookOutcome::Success,
            kinds: &["post_disconnect"],
        }));
        let outcomes = reg.dispatch(&pre_connect_event()).await;
        assert!(outcomes.is_empty());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failing_hook_outcome_is_captured_without_aborting_others() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut reg = HookRegistry::new();
        reg.register(Box::new(CountingHook {
            count: count.clone(),
            outcome: HookOutcome::Failed("simulated".into()),
            kinds: &[],
        }));
        reg.register(Box::new(CountingHook {
            count: count.clone(),
            outcome: HookOutcome::Success,
            kinds: &[],
        }));
        let outcomes = reg.dispatch(&pre_connect_event()).await;
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(outcomes[0].1, HookOutcome::Failed(_)));
        assert_eq!(outcomes[1].1, HookOutcome::Success);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn lifecycle_event_kind_str_round_trip() {
        let events = vec![
            ("pre_connect", pre_connect_event()),
            (
                "post_connect",
                LifecycleEvent::PostConnect {
                    profile_id: ProfileId::new("c"),
                    protocol: ProtocolKind::OpenVpn,
                    interface_name: "tun0".into(),
                },
            ),
            (
                "post_disconnect",
                LifecycleEvent::PostDisconnect {
                    profile_id: ProfileId::new("c"),
                },
            ),
        ];
        for (kind, ev) in events {
            assert_eq!(ev.kind_str(), kind);
            let json = serde_json::to_string(&ev).unwrap();
            let back: LifecycleEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(back.kind_str(), kind);
        }
    }
}
