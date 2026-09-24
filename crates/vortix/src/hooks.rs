//! Owner-run observational hooks fired on tunnel lifecycle events.

mod event {
    //! Typed lifecycle facts consumed by unprivileged observational hooks.
    //!
    //! This module deliberately contains no subprocess vocabulary.  The control
    //! owner publishes committed facts; an outer adapter may attempt bounded
    //! delivery without gaining any lifecycle veto or privileged capability.

    use serde::{Deserialize, Serialize};

    use crate::profile::{ProfileId, ProtocolKind};

    /// Lifecycle transitions available to global hook specifications.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum HookEvent {
        ConnectStarted,
        Connected,
        DisconnectStarted,
        Disconnected,
        ConnectFailed,
        Reconnecting,
    }

    impl HookEvent {
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::ConnectStarted => "connect_started",
                Self::Connected => "connected",
                Self::DisconnectStarted => "disconnect_started",
                Self::Disconnected => "disconnected",
                Self::ConnectFailed => "connect_failed",
                Self::Reconnecting => "reconnecting",
            }
        }
    }

    /// Stable identity for one committed lifecycle fact.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct HookEventId(String);

    impl HookEventId {
        pub(crate) fn from_parts(authority_epoch: u64, sequence: u64) -> Self {
            Self(format!("hook-{authority_epoch:016x}-{sequence:016x}"))
        }

        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl std::fmt::Display for HookEventId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    /// A committed lifecycle transition safe to expose to an owner-run hook.
    ///
    /// Endpoint, address, DNS, credential, and profile-body data are
    /// intentionally absent.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LifecycleFact {
        pub event_id: HookEventId,
        pub event: HookEvent,
        pub profile_id: ProfileId,
        pub display_name: String,
        pub protocol: ProtocolKind,
        pub occurred_at_millis: u64,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn lifecycle_fact_schema_excludes_network_and_secret_material() {
            let fact = LifecycleFact {
                event_id: HookEventId::from_parts(4, 9),
                event: HookEvent::Connected,
                profile_id: ProfileId::new("corp"),
                display_name: "Corporate".into(),
                protocol: ProtocolKind::WireGuard,
                occurred_at_millis: 42,
            };
            let json = serde_json::to_value(fact).unwrap();
            let object = json.as_object().unwrap();
            assert_eq!(object.len(), 6);
            for forbidden in [
                "endpoint",
                "address",
                "dns",
                "credential",
                "secret",
                "profile_body",
            ] {
                assert!(!object.contains_key(forbidden));
            }
        }
    }
}
mod runner {
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::future::Future;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use thiserror::Error;
    use tokio::sync::{broadcast, mpsc};
    use tokio::task::{JoinHandle, JoinSet};

    use crate::config::hooks_config::{validate_hooks, HookConfigError, HookSpec};
    use crate::hooks::{HookEvent, HookEventId, LifecycleFact};
    use crate::process::{CommandRunner, CommandSpec};
    use crate::process::{ProcessCredentials, ProcessError};

    const HOOK_QUEUE_CAPACITY: usize = 64;
    const HOOK_DIAGNOSTIC_CAPACITY: usize = 128;
    const HOOK_MAX_CONCURRENCY: usize = 4;
    const HOOK_STREAM_LIMIT_BYTES: usize = 16 * 1024;
    const HOOK_RECENT_ATTEMPTS: usize = 64;
    const HOOK_MAX_SUPPLEMENTARY_GROUPS: usize = 1_024;

    /// OS-checked identity used for every hook spawn.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VerifiedHookOwner {
        credentials: ProcessCredentials,
    }

    impl VerifiedHookOwner {
        /// Prove the owner.
        ///
        /// A direct non-root invocation must own the selected configuration path.
        /// A root invocation additionally needs coherent sudo uid/gid/user facts;
        /// direct or root-targeting sudo execution is refused.
        pub fn for_standard_mode(config_path: &Path) -> Result<Self, HookOwnerError> {
            let metadata = std::fs::symlink_metadata(config_path)
                .map_err(|source| HookOwnerError::ConfigMetadata { source })?;
            if metadata.file_type().is_symlink() {
                return Err(HookOwnerError::SymlinkConfig);
            }
            let (process_user, process_group) = crate::platform::effective_user_group_ids();
            if process_user != 0 {
                if process_group == 0 {
                    return Err(HookOwnerError::RootOwner);
                }
                if metadata.uid() != process_user {
                    return Err(HookOwnerError::ConfigOwnerMismatch {
                        expected: process_user,
                        actual: metadata.uid(),
                    });
                }
                let supplementary_groups = current_groups()?;
                if supplementary_groups.contains(&0) {
                    return Err(HookOwnerError::RootOwner);
                }
                return Ok(Self {
                    credentials: ProcessCredentials {
                        uid: process_user,
                        gid: process_group,
                        supplementary_groups,
                    },
                });
            }

            let (uid, gid) = crate::config::sudo_ids()
                .ok()
                .flatten()
                .ok_or(HookOwnerError::AmbiguousRoot)?;
            if uid == 0 || gid == 0 {
                return Err(HookOwnerError::RootOwner);
            }
            let sudo_user =
                std::env::var("SUDO_USER").map_err(|_| HookOwnerError::AmbiguousRoot)?;
            let (recorded_user, recorded_group, supplementary_groups) = lookup_user(&sudo_user)?;
            if recorded_user != uid || recorded_group != gid {
                return Err(HookOwnerError::SudoIdentityMismatch);
            }
            if supplementary_groups.contains(&0) {
                return Err(HookOwnerError::RootOwner);
            }
            if metadata.uid() != uid {
                return Err(HookOwnerError::ConfigOwnerMismatch {
                    expected: uid,
                    actual: metadata.uid(),
                });
            }
            Ok(Self {
                credentials: ProcessCredentials {
                    uid,
                    gid,
                    supplementary_groups,
                },
            })
        }

        #[cfg(test)]
        fn from_ids(uid: u32, gid: u32) -> Self {
            Self {
                credentials: ProcessCredentials {
                    uid,
                    gid,
                    supplementary_groups: Vec::new(),
                },
            }
        }
    }

    #[derive(Debug, Error)]
    #[non_exhaustive]
    pub enum HookOwnerError {
        #[error("cannot verify hook owner: configuration metadata failed: {source}")]
        ConfigMetadata { source: std::io::Error },
        #[error("cannot verify hook owner through a symlinked configuration path")]
        SymlinkConfig,
        #[error("configuration owner is uid {actual}, expected invoking uid {expected}")]
        ConfigOwnerMismatch { expected: u32, actual: u32 },
        #[error("direct or ambiguous root invocation cannot execute lifecycle hooks")]
        AmbiguousRoot,
        #[error("lifecycle hooks are never executed as root")]
        RootOwner,
        #[error("sudo uid/gid do not match the operating-system user record")]
        SudoIdentityMismatch,
        #[error("cannot resolve invoking user from the operating system")]
        UnknownUser,
        #[error("cannot read process groups: {source}")]
        Groups { source: std::io::Error },
    }

    fn current_groups() -> Result<Vec<u32>, HookOwnerError> {
        crate::platform::current_groups().map_err(|source| HookOwnerError::Groups { source })
    }

    fn lookup_user(user: &str) -> Result<(u32, u32, Vec<u32>), HookOwnerError> {
        let user = std::ffi::CString::new(user).map_err(|_| HookOwnerError::UnknownUser)?;
        let (uid, gid, _) =
            crate::platform::lookup_user(&user).ok_or(HookOwnerError::UnknownUser)?;
        let mut groups = crate::platform::supplementary_groups_for_user(
            &user,
            gid,
            HOOK_MAX_SUPPLEMENTARY_GROUPS,
        )
        .ok_or(HookOwnerError::UnknownUser)?;
        groups.sort_unstable();
        groups.dedup();
        Ok((uid, gid, groups))
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct HookAttemptId {
        pub event_id: HookEventId,
        pub hook_index: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HookDiagnostic {
        pub attempt_id: HookAttemptId,
        pub kind: HookDiagnosticKind,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum HookDiagnosticKind {
        Queued,
        Started,
        Completed { exit_code: Option<i32> },
        Failed(HookFailure),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HookFailure {
        QueueSaturated,
        Timeout,
        NonZeroExit,
        OutputLimitExceeded,
        RunnerFailure,
        RunnerStopped,
    }

    pub struct HookDiagnostics {
        receiver: broadcast::Receiver<HookDiagnostic>,
    }

    impl HookDiagnostics {
        pub async fn recv(&mut self) -> Result<HookDiagnostic, broadcast::error::RecvError> {
            self.receiver.recv().await
        }

        pub fn try_recv(&mut self) -> Result<HookDiagnostic, broadcast::error::TryRecvError> {
            self.receiver.try_recv()
        }
    }

    #[derive(Clone)]
    pub struct HookDispatcher {
        specs: Arc<BTreeMap<HookEvent, Vec<(usize, HookSpec)>>>,
        jobs: mpsc::Sender<HookJob>,
        diagnostics: broadcast::Sender<HookDiagnostic>,
        recent_attempts: Arc<Mutex<VecDeque<HookAttemptId>>>,
    }

    impl HookDispatcher {
        /// Attempt each matching specification once without waiting for execution.
        pub fn dispatch(&self, fact: &LifecycleFact) {
            let Some(specs) = self.specs.get(&fact.event) else {
                return;
            };
            for (hook_index, spec) in specs {
                let attempt_id = HookAttemptId {
                    event_id: fact.event_id.clone(),
                    hook_index: *hook_index,
                };
                {
                    let mut recent = self
                        .recent_attempts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if recent.contains(&attempt_id) {
                        continue;
                    }
                    if recent.len() == HOOK_RECENT_ATTEMPTS {
                        recent.pop_front();
                    }
                    recent.push_back(attempt_id.clone());
                }
                let queued = HookDiagnostic {
                    attempt_id: attempt_id.clone(),
                    kind: HookDiagnosticKind::Queued,
                };
                let _ = self.diagnostics.send(queued);
                let job = HookJob {
                    attempt_id: attempt_id.clone(),
                    fact: fact.clone(),
                    spec: spec.clone(),
                };
                if self.jobs.try_send(job).is_err() {
                    let _ = self.diagnostics.send(HookDiagnostic {
                        attempt_id,
                        kind: HookDiagnosticKind::Failed(HookFailure::QueueSaturated),
                    });
                }
            }
        }
    }

    struct HookJob {
        attempt_id: HookAttemptId,
        fact: LifecycleFact,
        spec: HookSpec,
    }

    /// Owns the bounded in-memory queue and its non-replaying workers.
    pub struct HookRunner {
        dispatcher: Option<HookDispatcher>,
        task: Option<JoinHandle<()>>,
    }

    impl HookRunner {
        /// Validate and start only when at least one hook exists.
        pub fn start(
            specs: Vec<HookSpec>,
            owner: VerifiedHookOwner,
            runner: CommandRunner,
        ) -> Result<Option<(Self, HookDiagnostics)>, HookConfigError> {
            validate_hooks(&specs)?;
            if specs.is_empty() {
                return Ok(None);
            }
            let mut by_event = BTreeMap::<HookEvent, Vec<(usize, HookSpec)>>::new();
            for (index, spec) in specs.into_iter().enumerate() {
                by_event.entry(spec.event).or_default().push((index, spec));
            }
            let (jobs, receiver) = mpsc::channel(HOOK_QUEUE_CAPACITY);
            let (diagnostics, diagnostic_receiver) = broadcast::channel(HOOK_DIAGNOSTIC_CAPACITY);
            let dispatcher = HookDispatcher {
                specs: Arc::new(by_event),
                jobs,
                diagnostics: diagnostics.clone(),
                recent_attempts: Arc::new(Mutex::new(VecDeque::with_capacity(
                    HOOK_RECENT_ATTEMPTS,
                ))),
            };
            let task = tokio::spawn(run_jobs(receiver, diagnostics, owner, runner));
            Ok(Some((
                Self {
                    dispatcher: Some(dispatcher),
                    task: Some(task),
                },
                HookDiagnostics {
                    receiver: diagnostic_receiver,
                },
            )))
        }

        #[must_use]
        /// Clone the non-blocking hook dispatcher.
        ///
        /// # Panics
        ///
        /// Panics only if called while the runner is being consumed by shutdown;
        /// safe Rust ownership prevents that state from being observed by callers.
        pub fn dispatcher(&self) -> HookDispatcher {
            self.dispatcher
                .as_ref()
                .expect("hook runner has not shut down")
                .clone()
        }

        /// Stop accepting control events and give already-queued observers a
        /// bounded opportunity to finish. Lifecycle never waits for hook success;
        /// this is only the process-exit drain.
        pub async fn shutdown_bounded(mut self, timeout: std::time::Duration) {
            drop(self.dispatcher.take());
            let Some(task) = self.task.take() else {
                return;
            };
            let abort = task.abort_handle();
            if tokio::time::timeout(timeout, task).await.is_err() {
                abort.abort();
            }
        }
    }

    impl Drop for HookRunner {
        fn drop(&mut self) {
            if let Some(task) = &self.task {
                task.abort();
            }
        }
    }

    async fn run_jobs(
        mut receiver: mpsc::Receiver<HookJob>,
        diagnostics: broadcast::Sender<HookDiagnostic>,
        owner: VerifiedHookOwner,
        runner: CommandRunner,
    ) {
        let mut active = JoinSet::new();
        loop {
            if active.len() >= HOOK_MAX_CONCURRENCY {
                let _ = active.join_next().await;
                continue;
            }
            tokio::select! {
                job = receiver.recv() => {
                    let Some(job) = job else { break };
                    let diagnostics = diagnostics.clone();
                    let owner = owner.clone();
                    let runner = runner.clone();
                    active.spawn(async move {
                        let attempt_id = job.attempt_id.clone();
                        if CatchPanic::new(run_one(job, diagnostics.clone(), owner, runner))
                            .await
                            .is_err()
                        {
                            let _ = diagnostics.send(HookDiagnostic {
                                attempt_id,
                                kind: HookDiagnosticKind::Failed(HookFailure::RunnerFailure),
                            });
                        }
                    });
                }
                result = active.join_next(), if !active.is_empty() => {
                    let _ = result;
                }
            }
        }
        while active.join_next().await.is_some() {}
    }

    struct CatchPanic<F> {
        future: Pin<Box<F>>,
    }

    impl<F> CatchPanic<F> {
        fn new(future: F) -> Self {
            Self {
                future: Box::pin(future),
            }
        }
    }

    impl<F: Future> Future for CatchPanic<F> {
        type Output = Result<F::Output, Box<dyn std::any::Any + Send>>;

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.future.as_mut().poll(context)
            })) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
                Err(panic) => Poll::Ready(Err(panic)),
            }
        }
    }

    async fn run_one(
        job: HookJob,
        diagnostics: broadcast::Sender<HookDiagnostic>,
        owner: VerifiedHookOwner,
        runner: CommandRunner,
    ) {
        let _ = diagnostics.send(HookDiagnostic {
            attempt_id: job.attempt_id.clone(),
            kind: HookDiagnosticKind::Started,
        });
        let mut env = HashMap::with_capacity(5);
        env.insert("VORTIX_EVENT_ID".into(), job.fact.event_id.to_string());
        env.insert("VORTIX_EVENT".into(), job.fact.event.as_str().into());
        env.insert("VORTIX_PROFILE_ID".into(), job.fact.profile_id.to_string());
        env.insert("VORTIX_PROFILE_NAME".into(), job.fact.display_name);
        env.insert(
            "VORTIX_PROTOCOL".into(),
            match job.fact.protocol {
                crate::profile::ProtocolKind::WireGuard => "wireguard",
                crate::profile::ProtocolKind::OpenVpn => "openvpn",
            }
            .into(),
        );
        let timeout = job.spec.timeout();
        let argument_count = job.spec.args.len();
        let mut command = CommandSpec::oneshot(
            job.spec
                .executable
                .to_str()
                .expect("validated hook executable")
                .to_owned(),
            job.spec.args,
        )
        .timeout(timeout)
        .output_limit(HOOK_STREAM_LIMIT_BYTES)
        .redact_args(0..argument_count)
        .run_as(owner.credentials)
        .contain_process_group();
        command.env_clear = true;
        command.env = env;

        let kind = match runner.run(command).await {
            Ok(outcome) if outcome.success() => HookDiagnosticKind::Completed {
                exit_code: outcome.exit_status.code,
            },
            Ok(_) => HookDiagnosticKind::Failed(HookFailure::NonZeroExit),
            Err(error) => HookDiagnosticKind::Failed(map_failure(&error)),
        };
        let _ = diagnostics.send(HookDiagnostic {
            attempt_id: job.attempt_id,
            kind,
        });
    }

    fn map_failure(error: &ProcessError) -> HookFailure {
        match error {
            ProcessError::Timeout { .. } => HookFailure::Timeout,
            ProcessError::Killed { .. } => HookFailure::NonZeroExit,
            ProcessError::OutputLimitExceeded { .. } => HookFailure::OutputLimitExceeded,
            ProcessError::ProgramNotFound { .. } | ProcessError::IoError { .. } => {
                HookFailure::RunnerFailure
            }
            ProcessError::PrivilegeDenied { .. } | ProcessError::InvalidCredentials { .. } => {
                HookFailure::RunnerStopped
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::path::PathBuf;
        use std::time::Duration;

        use super::*;
        use crate::profile::{ProfileId, ProtocolKind};

        #[test]
        fn empty_configuration_starts_no_runner() {
            assert!(HookRunner::start(
                Vec::new(),
                VerifiedHookOwner::from_ids(501, 20),
                CommandRunner::mock_default_success(),
            )
            .unwrap()
            .is_none());
        }

        #[test]
        fn standard_owner_requires_non_root_or_sudo_provenance() {
            let temp = tempfile::tempdir().unwrap();
            let result = VerifiedHookOwner::for_standard_mode(temp.path());
            if crate::platform::is_root() {
                assert!(result.is_err());
            } else {
                let owner = result.unwrap();
                assert_eq!(
                    owner.credentials.uid,
                    crate::platform::effective_user_group_ids().0
                );
            }
        }

        #[test]
        fn standard_owner_rejects_symlinked_configuration() {
            use std::os::unix::fs::symlink;

            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("settings.toml");
            let link = temp.path().join("settings-link.toml");
            std::fs::write(&target, "").unwrap();
            symlink(&target, &link).unwrap();
            assert!(matches!(
                VerifiedHookOwner::for_standard_mode(&link),
                Err(HookOwnerError::SymlinkConfig)
            ));
        }

        #[test]
        fn operating_system_user_lookup_returns_bounded_groups() {
            let (uid, gid, groups) = lookup_user("root").unwrap();
            assert_eq!(uid, 0);
            assert_eq!(gid, 0);
            assert!(groups.contains(&0));
            assert!(groups.len() <= HOOK_MAX_SUPPLEMENTARY_GROUPS);
        }

        #[tokio::test]
        async fn hook_uses_only_allowlisted_environment_and_owner_credentials() {
            let mock = crate::process::MockRunner::with_default_success();
            let (runner, mut diagnostics) = HookRunner::start(
                vec![HookSpec {
                    event: HookEvent::Connected,
                    executable: PathBuf::from("/usr/bin/true"),
                    args: vec!["safe".into()],
                    timeout_secs: 5,
                }],
                VerifiedHookOwner::from_ids(501, 20),
                CommandRunner::Mock(mock.clone()),
            )
            .unwrap()
            .unwrap();
            runner.dispatcher().dispatch(&LifecycleFact {
                event_id: HookEventId::from_parts(1, 2),
                event: HookEvent::Connected,
                profile_id: ProfileId::new("corp"),
                display_name: "Corporate".into(),
                protocol: ProtocolKind::WireGuard,
                occurred_at_millis: 9,
            });
            let mut terminal = None;
            for _ in 0..3 {
                let diagnostic = diagnostics.recv().await.unwrap();
                if matches!(diagnostic.kind, HookDiagnosticKind::Completed { .. }) {
                    terminal = Some(diagnostic);
                }
            }
            assert!(terminal.is_some());
            let invocation = mock.invocations().pop().unwrap();
            assert!(invocation.env_clear);
            assert_eq!(invocation.env.len(), 5);
            assert_eq!(invocation.run_as.unwrap().uid, 501);
            assert!(invocation.terminate_process_group);
            assert_eq!(invocation.redact_in_audit, vec![0]);

            runner.dispatcher().dispatch(&LifecycleFact {
                event_id: HookEventId::from_parts(1, 2),
                event: HookEvent::Connected,
                profile_id: ProfileId::new("corp"),
                display_name: "Corporate".into(),
                protocol: ProtocolKind::WireGuard,
                occurred_at_millis: 9,
            });
            tokio::task::yield_now().await;
            assert_eq!(
                mock.invocations().len(),
                1,
                "same fact is never attempted twice"
            );
        }

        #[tokio::test(flavor = "current_thread")]
        async fn bounded_shutdown_drains_jobs_already_accepted() {
            let mock = crate::process::MockRunner::with_default_success();
            let (runner, _diagnostics) = HookRunner::start(
                vec![HookSpec {
                    event: HookEvent::Disconnected,
                    executable: PathBuf::from("/usr/bin/true"),
                    args: Vec::new(),
                    timeout_secs: 5,
                }],
                VerifiedHookOwner::from_ids(501, 20),
                CommandRunner::Mock(mock.clone()),
            )
            .unwrap()
            .unwrap();
            runner.dispatcher().dispatch(&LifecycleFact {
                event_id: HookEventId::from_parts(1, 3),
                event: HookEvent::Disconnected,
                profile_id: ProfileId::new("corp"),
                display_name: "Corporate".into(),
                protocol: ProtocolKind::WireGuard,
                occurred_at_millis: 9,
            });

            runner.shutdown_bounded(Duration::from_secs(1)).await;

            assert_eq!(mock.invocations().len(), 1);
        }

        #[tokio::test(flavor = "current_thread")]
        async fn queue_saturation_is_typed_and_non_blocking() {
            let (runner, mut diagnostics) = HookRunner::start(
                vec![HookSpec {
                    event: HookEvent::Connected,
                    executable: PathBuf::from("/usr/bin/true"),
                    args: Vec::new(),
                    timeout_secs: 5,
                }],
                VerifiedHookOwner::from_ids(501, 20),
                CommandRunner::mock_default_success(),
            )
            .unwrap()
            .unwrap();
            for sequence in 1..=HOOK_QUEUE_CAPACITY + 1 {
                runner.dispatcher().dispatch(&LifecycleFact {
                    event_id: HookEventId::from_parts(1, u64::try_from(sequence).unwrap()),
                    event: HookEvent::Connected,
                    profile_id: ProfileId::new("corp"),
                    display_name: "Corporate".into(),
                    protocol: ProtocolKind::WireGuard,
                    occurred_at_millis: 9,
                });
            }
            let mut saturated = false;
            while let Ok(diagnostic) = diagnostics.try_recv() {
                saturated |= matches!(
                    diagnostic.kind,
                    HookDiagnosticKind::Failed(HookFailure::QueueSaturated)
                );
            }
            assert!(saturated);
        }

        #[tokio::test]
        async fn runner_panic_becomes_typed_failure() {
            let (runner, mut diagnostics) = HookRunner::start(
                vec![HookSpec {
                    event: HookEvent::Connected,
                    executable: PathBuf::from("/usr/bin/true"),
                    args: Vec::new(),
                    timeout_secs: 5,
                }],
                VerifiedHookOwner::from_ids(501, 20),
                CommandRunner::Mock(crate::process::MockRunner::new()),
            )
            .unwrap()
            .unwrap();
            runner.dispatcher().dispatch(&LifecycleFact {
                event_id: HookEventId::from_parts(1, 99),
                event: HookEvent::Connected,
                profile_id: ProfileId::new("corp"),
                display_name: "Corporate".into(),
                protocol: ProtocolKind::WireGuard,
                occurred_at_millis: 9,
            });
            for _ in 0..3 {
                if matches!(
                    diagnostics.recv().await.unwrap().kind,
                    HookDiagnosticKind::Failed(HookFailure::RunnerFailure)
                ) {
                    return;
                }
            }
            panic!("runner panic did not produce a typed failure");
        }

        #[tokio::test]
        async fn process_failures_are_bounded_typed_metadata() {
            use crate::process::mock::{ScriptedOutcome, SpecMatcher};

            let cases = [
                (ScriptedOutcome::Timeout, HookFailure::Timeout),
                (
                    ScriptedOutcome::Failure("sensitive stderr".into()),
                    HookFailure::NonZeroExit,
                ),
                (
                    ScriptedOutcome::Success {
                        stdout: vec![b'x'; HOOK_STREAM_LIMIT_BYTES + 1],
                        stderr: Vec::new(),
                        exit_code: 0,
                    },
                    HookFailure::OutputLimitExceeded,
                ),
            ];
            for (sequence, (outcome, expected)) in cases.into_iter().enumerate() {
                let mock = crate::process::MockRunner::new();
                mock.expect(SpecMatcher::Any, outcome);
                let (runner, mut diagnostics) = HookRunner::start(
                    vec![HookSpec {
                        event: HookEvent::Connected,
                        executable: PathBuf::from("/usr/bin/true"),
                        args: Vec::new(),
                        timeout_secs: 5,
                    }],
                    VerifiedHookOwner::from_ids(501, 20),
                    CommandRunner::Mock(mock),
                )
                .unwrap()
                .unwrap();
                runner.dispatcher().dispatch(&LifecycleFact {
                    event_id: HookEventId::from_parts(1, u64::try_from(sequence + 1).unwrap()),
                    event: HookEvent::Connected,
                    profile_id: ProfileId::new("corp"),
                    display_name: "Corporate".into(),
                    protocol: ProtocolKind::WireGuard,
                    occurred_at_millis: 9,
                });
                let mut actual = None;
                for _ in 0..3 {
                    if let HookDiagnosticKind::Failed(failure) =
                        diagnostics.recv().await.unwrap().kind
                    {
                        actual = Some(failure);
                    }
                }
                assert_eq!(actual, Some(expected));
            }
        }
    }
}

use std::path::Path;

pub use event::{HookEvent, HookEventId, LifecycleFact};
pub use runner::{
    HookAttemptId, HookDiagnostic, HookDiagnosticKind, HookDiagnostics, HookDispatcher,
    HookFailure, HookOwnerError, HookRunner, VerifiedHookOwner,
};

/// Start the configured hooks, or `None` when there are none or they cannot
/// run. Hooks never affect lifecycle correctness. Must run inside a tokio
/// runtime.
pub(crate) fn start(config_dir: &Path) -> Option<HookRunner> {
    let started = (|| {
        let settings =
            crate::config::Settings::load(config_dir, crate::config::EngineSettings::default())
                .map_err(|error| error.to_string())?;
        if settings.hooks.is_empty() {
            return Ok(None);
        }
        let owner =
            VerifiedHookOwner::for_standard_mode(config_dir).map_err(|error| error.to_string())?;
        HookRunner::start(
            settings.hooks,
            owner,
            crate::process::global_runner().clone(),
        )
        .map(|started| started.map(|(runner, _)| runner))
        .map_err(|error| error.to_string())
    })();
    started.unwrap_or_else(|error: String| {
        tracing::warn!(%error, "lifecycle hooks disabled");
        None
    })
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn invalid_hook_configuration_disables_hooks() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("settings.toml"), "hooks = [not-valid]").unwrap();
        assert!(super::start(temp.path()).is_none());
    }
}
