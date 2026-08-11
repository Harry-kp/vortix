//! State/topology characterization shared by future local and remote adapters.

#[path = "support/control_scenarios.rs"]
mod control_scenarios;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use vortix::vortix_core::cidr::Cidr;
use vortix::vortix_core::engine::state::DetailedConnectionInfo;
use vortix::vortix_core::engine::{Conflict, Engine, Role, TunnelRegistry};
use vortix::vortix_core::ports::tunnel::mock::MockTunnel;
use vortix::vortix_core::profile::ProfileId;

use vortix::cli::control::ClientControlSession;
use vortix::daemon::service::{
    RemoteControlError, RemoteControlSession, RemoteControlSubscription, RemoteControlTransport,
    RemoteControlUpdate, RemoteMutationGate,
};
use vortix::vortix_core::control::{
    AdmissionError, AuthorityEpoch, ChallengeKind, ChallengeRecord, CommandRequest, ControlHandle,
    ControlService, ControlServiceConfig, ControlSnapshot, Deadline, IdempotencyKey,
    OperationIntent, OperationRecord, OperationResult, OperationStatus, PolicyDigest,
    ProfileTopology, Secret, UserCommand,
};
use vortix::vortix_core::ipc::{IpcOp, IpcResult, RemoteSessionId};

fn cidr(address: [u8; 4], prefix: u8) -> Cidr {
    Cidr::new(IpAddr::V4(Ipv4Addr::from(address)), prefix).unwrap()
}

fn insert_connected(
    registry: &mut TunnelRegistry<MockTunnel>,
    name: &str,
    interface: &str,
    allowed_ips: Vec<Cidr>,
) {
    registry.set_connected(
        ProfileId::new(name),
        allowed_ips,
        DetailedConnectionInfo {
            interface: interface.to_string(),
            interface_authoritative: true,
            ..Default::default()
        },
        SystemTime::UNIX_EPOCH,
        || Engine::new(MockTunnel::new(), |_| None),
    );
}

#[test]
fn one_and_two_tunnel_primary_and_secondary_roles_are_stable() {
    let mut registry = TunnelRegistry::new();
    insert_connected(&mut registry, "corp", "wg0", vec![cidr([0, 0, 0, 0], 0)]);
    registry.feed_default_route_interface(Some("wg0".to_string()));
    registry.refresh_primary();

    assert_eq!(registry.primary(), Some(&ProfileId::new("corp")));
    assert!(matches!(
        registry.snapshot(&ProfileId::new("corp")).unwrap().role,
        Role::Primary { .. }
    ));

    insert_connected(&mut registry, "lab", "wg1", vec![cidr([10, 0, 0, 0], 8)]);
    let snapshots = registry.snapshot_all();
    assert_eq!(snapshots.len(), 2);
    assert!(matches!(snapshots[1].role, Role::Addressable { .. }));
}

#[test]
fn split_only_topology_keeps_no_primary_and_preserves_route_scope() {
    let mut registry = TunnelRegistry::new();
    let split = cidr([10, 0, 0, 0], 8);
    insert_connected(&mut registry, "lab", "wg1", vec![split]);
    registry.feed_default_route_interface(None);
    registry.refresh_primary();

    assert!(registry.primary().is_none());
    let snapshot = registry.snapshot(&ProfileId::new("lab")).unwrap();
    let Role::Addressable { allowed_ips } = snapshot.role else {
        panic!("split-only tunnel must remain addressable");
    };
    assert_eq!(allowed_ips, vec![split]);
    assert!(split.intersects(&cidr([10, 2, 3, 4], 32)));
    assert!(!split.intersects(&cidr([8, 8, 8, 8], 32)));
}

#[test]
fn second_default_route_is_a_typed_conflict_without_kernel_mutation() {
    let mut registry = TunnelRegistry::new();
    let default = cidr([0, 0, 0, 0], 0);
    insert_connected(&mut registry, "corp", "wg0", vec![default]);

    let conflict = registry
        .detect_conflict(&ProfileId::new("home"), &[default])
        .expect("second default route must conflict");
    assert_eq!(
        conflict,
        Conflict::DefaultRouteTakeover {
            current: ProfileId::new("corp"),
            new: ProfileId::new("home"),
        }
    );
}

#[test]
fn production_remote_mutation_gate_is_closed_until_enrollment_cutover() {
    assert_eq!(
        RemoteMutationGate::production(),
        RemoteMutationGate::Disabled
    );
    assert!(matches!(
        RemoteMutationGate::production().require_enabled(),
        Err(RemoteControlError::MutationDisabled)
    ));
    let transport: Arc<dyn RemoteControlTransport> = Arc::new(FaultTransport(
        RemoteControlError::Unavailable("must not connect".into()),
    ));
    assert_eq!(
        RemoteControlSession::connect_production(RemoteMutationGate::production(), transport)
            .unwrap_err(),
        RemoteControlError::MutationDisabled
    );
}

struct EmptyRemoteSubscription;

impl RemoteControlSubscription for EmptyRemoteSubscription {
    fn try_recv(&mut self) -> Result<Option<RemoteControlUpdate>, RemoteControlError> {
        Ok(None)
    }
}

struct FakeRemoteSubscription {
    handle: ControlHandle,
    generation: u64,
}

impl RemoteControlSubscription for FakeRemoteSubscription {
    fn try_recv(&mut self) -> Result<Option<RemoteControlUpdate>, RemoteControlError> {
        let snapshot = self.handle.snapshot();
        if snapshot.generation <= self.generation {
            return Ok(None);
        }
        self.generation = snapshot.generation;
        Ok(Some(RemoteControlUpdate {
            event: None,
            snapshot,
        }))
    }
}

struct SnapshotOnlySubscription(Option<RemoteControlUpdate>);

impl RemoteControlSubscription for SnapshotOnlySubscription {
    fn try_recv(&mut self) -> Result<Option<RemoteControlUpdate>, RemoteControlError> {
        Ok(self.0.take())
    }
}

struct SnapshotPublicationTransport;

impl RemoteControlTransport for SnapshotPublicationTransport {
    fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError> {
        match op {
            IpcOp::ControlOpen => Ok(IpcResult::ControlOpened {
                session_id: RemoteSessionId::parse(format!("session-{}", "e".repeat(32))).unwrap(),
                client_id: serde_json::from_str("\"client-0000000000000000-0000000000000001\"")
                    .unwrap(),
            }),
            other => Err(RemoteControlError::Protocol(format!(
                "unexpected snapshot transport operation: {other:?}"
            ))),
        }
    }

    fn subscribe(
        &self,
        _session_id: &RemoteSessionId,
    ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError> {
        let initial = ControlSnapshot {
            generation: 2,
            ..ControlSnapshot::default()
        };
        let published = ControlSnapshot {
            generation: 3,
            ..ControlSnapshot::default()
        };
        Ok((
            Box::new(SnapshotOnlySubscription(Some(RemoteControlUpdate {
                event: None,
                snapshot: published,
            }))),
            initial,
        ))
    }
}

#[test]
fn remote_subscription_keeps_initial_and_eventless_snapshot_publications() {
    let transport: Arc<dyn RemoteControlTransport> = Arc::new(SnapshotPublicationTransport);
    let remote = RemoteControlSession::open_for_parity(transport).unwrap();
    assert_eq!(remote.current_snapshot().generation, 2);
    assert_eq!(
        remote.take_changed_snapshot().unwrap().unwrap().generation,
        3
    );
}

struct ScriptedRemoteSubscription {
    updates: VecDeque<Result<Option<RemoteControlUpdate>, RemoteControlError>>,
}

impl RemoteControlSubscription for ScriptedRemoteSubscription {
    fn try_recv(&mut self) -> Result<Option<RemoteControlUpdate>, RemoteControlError> {
        self.updates.pop_front().unwrap_or(Ok(None))
    }
}

struct ResyncingPublicationTransport {
    subscriptions: AtomicU64,
    fail_resubscribe: bool,
}

impl RemoteControlTransport for ResyncingPublicationTransport {
    fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError> {
        match op {
            IpcOp::ControlOpen => Ok(IpcResult::ControlOpened {
                session_id: RemoteSessionId::parse(format!("session-{}", "d".repeat(32))).unwrap(),
                client_id: serde_json::from_str("\"client-0000000000000000-0000000000000001\"")
                    .unwrap(),
            }),
            other => Err(RemoteControlError::Protocol(format!(
                "unexpected resync transport operation: {other:?}"
            ))),
        }
    }

    fn subscribe(
        &self,
        _session_id: &RemoteSessionId,
    ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError> {
        let attempt = self.subscriptions.fetch_add(1, Ordering::SeqCst);
        if attempt == 1 && self.fail_resubscribe {
            return Err(RemoteControlError::Unavailable("resubscribe failed".into()));
        }
        let snapshot = ControlSnapshot {
            generation: if attempt == 0 { 1 } else { 3 },
            ..ControlSnapshot::default()
        };
        let updates = if attempt == 0 {
            VecDeque::from([
                Ok(Some(RemoteControlUpdate {
                    event: None,
                    snapshot: ControlSnapshot {
                        generation: 2,
                        ..ControlSnapshot::default()
                    },
                })),
                Err(RemoteControlError::ResyncRequired {
                    newest_generation: 3,
                }),
            ])
        } else {
            VecDeque::from([Ok(Some(RemoteControlUpdate {
                event: None,
                snapshot: ControlSnapshot {
                    generation: 4,
                    ..ControlSnapshot::default()
                },
            }))])
        };
        Ok((Box::new(ScriptedRemoteSubscription { updates }), snapshot))
    }
}

#[test]
fn remote_subscription_resynchronizes_and_continues_without_local_fallback() {
    let transport = Arc::new(ResyncingPublicationTransport {
        subscriptions: AtomicU64::new(0),
        fail_resubscribe: false,
    });
    let remote = RemoteControlSession::open_for_parity(transport.clone()).unwrap();

    assert_eq!(
        remote.take_changed_snapshot().unwrap().unwrap().generation,
        3
    );
    assert_eq!(
        remote.take_changed_snapshot().unwrap().unwrap().generation,
        4
    );
    assert_eq!(transport.subscriptions.load(Ordering::SeqCst), 2);
}

#[test]
fn failed_remote_resubscribe_preserves_the_last_drained_snapshot() {
    let transport = Arc::new(ResyncingPublicationTransport {
        subscriptions: AtomicU64::new(0),
        fail_resubscribe: true,
    });
    let remote = RemoteControlSession::open_for_parity(transport.clone()).unwrap();

    assert_eq!(
        remote.take_changed_snapshot().unwrap_err(),
        RemoteControlError::Unavailable("resubscribe failed".into())
    );
    assert_eq!(remote.current_snapshot().generation, 2);
    assert_eq!(transport.subscriptions.load(Ordering::SeqCst), 2);
}

struct FakeRemoteAuthority {
    runtime: tokio::runtime::Runtime,
    service: ControlService,
    sessions: Mutex<BTreeMap<RemoteSessionId, ControlHandle>>,
    next_session: AtomicU64,
    staged_profiles: Mutex<BTreeMap<RemoteSessionId, (String, Vec<u8>)>>,
}

impl FakeRemoteAuthority {
    fn new() -> Arc<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let profiles = ['a', 'b'].into_iter().map(profile).collect::<BTreeSet<_>>();
        let topologies = profiles
            .iter()
            .cloned()
            .map(|profile_id| (profile_id, ProfileTopology::default()))
            .collect();
        let service = {
            let _guard = runtime.enter();
            ControlService::start(ControlServiceConfig {
                known_profiles: profiles,
                profile_topologies: topologies,
                ..ControlServiceConfig::default()
            })
        };
        Arc::new(Self {
            runtime,
            service,
            sessions: Mutex::new(BTreeMap::new()),
            next_session: AtomicU64::new(0),
            staged_profiles: Mutex::new(BTreeMap::new()),
        })
    }

    fn handle(&self, session_id: &RemoteSessionId) -> Result<ControlHandle, RemoteControlError> {
        self.sessions
            .lock()
            .unwrap()
            .get(session_id)
            .cloned()
            .ok_or(RemoteControlError::SessionNotFound)
    }
}

impl RemoteControlTransport for FakeRemoteAuthority {
    #[allow(
        clippy::too_many_lines,
        reason = "one fake wire dispatcher keeps every canonical remote operation visible in the parity fixture"
    )]
    fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError> {
        match op {
            IpcOp::ControlOpen => {
                let sequence = self.next_session.fetch_add(1, Ordering::Relaxed) + 1;
                let session_id = RemoteSessionId::parse(format!("session-{sequence:032x}"))
                    .expect("fixture session id");
                let client = self
                    .service
                    .new_client()
                    .map_err(RemoteControlError::Admission)?;
                let client_id = client.client_id().clone();
                self.sessions
                    .lock()
                    .unwrap()
                    .insert(session_id.clone(), client);
                Ok(IpcResult::ControlOpened {
                    session_id,
                    client_id,
                })
            }
            IpcOp::ControlSubmit {
                session_id,
                command,
                idempotency_key,
                timeout_millis,
            } => {
                let client = self.handle(&session_id)?;
                let admitted = self
                    .runtime
                    .block_on(client.submit(CommandRequest {
                        command,
                        idempotency_key,
                        deadline: client.deadline_after(Duration::from_millis(timeout_millis)),
                    }))
                    .map_err(RemoteControlError::Admission)?;
                let deadline = std::time::Instant::now() + Duration::from_secs(1);
                while !client
                    .snapshot()
                    .operations
                    .contains_key(&admitted.operation_id)
                {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "remote publication stalled"
                    );
                    std::thread::yield_now();
                }
                Ok(IpcResult::ControlAccepted { admitted })
            }
            IpcOp::ControlSnapshot { session_id } => Ok(IpcResult::ControlSnapshot {
                snapshot: self.handle(&session_id)?.snapshot(),
            }),
            IpcOp::ControlRespondChallenge {
                session_id,
                challenge_id,
                answer,
            } => {
                let client = self.handle(&session_id)?;
                self.runtime
                    .block_on(
                        client.respond_challenge(challenge_id, Secret::new(answer.into_vec())),
                    )
                    .map_err(RemoteControlError::Challenge)?;
                Ok(IpcResult::ChallengeAccepted)
            }
            IpcOp::ControlCancelChallenge {
                session_id,
                challenge_id,
            } => {
                let client = self.handle(&session_id)?;
                self.runtime
                    .block_on(client.cancel_challenge(challenge_id))
                    .map_err(RemoteControlError::Challenge)?;
                Ok(IpcResult::ChallengeAccepted)
            }
            IpcOp::ControlStageProfileImport {
                session_id,
                file_name,
                offset,
                final_chunk,
                contents,
            } => {
                let _ = self.handle(&session_id)?;
                let bytes = contents.into_vec();
                let mut staged = self.staged_profiles.lock().unwrap();
                let upload = staged
                    .entry(session_id.clone())
                    .or_insert_with(|| (file_name.clone(), Vec::new()));
                if upload.0 != file_name || upload.1.len() as u64 != offset || bytes.is_empty() {
                    return Err(RemoteControlError::Protocol(
                        "invalid staged profile".into(),
                    ));
                }
                upload.1.extend_from_slice(&bytes);
                if !final_chunk {
                    return Ok(IpcResult::ControlProfileImportChunkAccepted {
                        next_offset: upload.1.len() as u64,
                    });
                }
                if !matches!(file_name.rsplit_once('.'), Some((_, "conf" | "ovpn"))) {
                    staged.remove(&session_id);
                    return Err(RemoteControlError::Protocol(
                        "invalid staged profile".into(),
                    ));
                }
                staged.remove(&session_id);
                Ok(IpcResult::ControlProfileImportStaged {
                    profile_id: profile('b'),
                    display_name: file_name
                        .rsplit_once('.')
                        .map_or(file_name.clone(), |(name, _)| name.to_owned()),
                })
            }
            IpcOp::ControlCancelProfileImport { session_id } => {
                self.staged_profiles.lock().unwrap().remove(&session_id);
                Ok(IpcResult::ChallengeAccepted)
            }
            other => Err(RemoteControlError::Protocol(format!(
                "fixture rejected non-control operation: {other:?}"
            ))),
        }
    }

    fn subscribe(
        &self,
        session_id: &RemoteSessionId,
    ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError> {
        let handle = self.handle(session_id)?;
        let snapshot = handle.snapshot();
        Ok((
            Box::new(FakeRemoteSubscription {
                handle,
                generation: snapshot.generation,
            }),
            snapshot,
        ))
    }
}

fn profile(label: char) -> ProfileId {
    ProfileId::parse(label.to_string().repeat(ProfileId::HEX_LEN)).unwrap()
}

fn config() -> ControlServiceConfig {
    let known_profiles = [profile('a'), profile('b')]
        .into_iter()
        .collect::<BTreeSet<_>>();
    ControlServiceConfig {
        profile_topologies: known_profiles
            .iter()
            .cloned()
            .map(|profile_id| (profile_id, ProfileTopology::default()))
            .collect(),
        known_profiles,
        ..ControlServiceConfig::default()
    }
}

fn local_admission(command: UserCommand) -> Result<AdmissionError, serde_json::Value> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let service = {
        let _guard = runtime.enter();
        ControlService::start(config())
    };
    let client = service.client();
    match runtime.block_on(client.submit(CommandRequest {
        command,
        idempotency_key: IdempotencyKey::new("parity"),
        deadline: Deadline(u64::MAX),
    })) {
        Ok(_) => Err(serde_json::to_value(client.snapshot().desired).unwrap()),
        Err(error) => Ok(error),
    }
}

fn remote_admission(command: UserCommand) -> Result<AdmissionError, serde_json::Value> {
    let authority = FakeRemoteAuthority::new();
    let transport: Arc<dyn RemoteControlTransport> = authority;
    let remote = RemoteControlSession::open_for_parity(transport).unwrap();
    match remote.submit(command, Duration::from_secs(30), "parity") {
        Ok(_) => Err(serde_json::to_value(remote.refresh_snapshot().unwrap().desired).unwrap()),
        Err(RemoteControlError::Admission(error)) => Ok(error),
        Err(error) => panic!("unexpected remote result: {error}"),
    }
}

#[test]
fn every_canonical_mutation_family_has_normalized_local_remote_parity() {
    let commands = vec![
        UserCommand::Connect {
            profile_id: profile('a'),
            conflict_acknowledgement: None,
        },
        UserCommand::ConnectExclusive {
            profile_id: profile('a'),
        },
        UserCommand::Disconnect {
            profile_id: Some(profile('a')),
        },
        UserCommand::Disconnect { profile_id: None },
        UserCommand::Reconnect {
            profile_id: Some(profile('a')),
        },
        UserCommand::ForceDisconnect {
            profile_id: Some(profile('a')),
        },
        UserCommand::SetKillSwitch {
            mode: vortix::vortix_core::state::killswitch::KillSwitchMode::Auto,
        },
        UserCommand::ImportProfile {
            profile_id: profile('b'),
        },
        UserCommand::RenameProfile {
            profile_id: profile('a'),
            new_display_name: "renamed".into(),
        },
        UserCommand::DeleteProfile {
            profile_id: profile('a'),
        },
    ];

    for command in commands {
        assert_eq!(local_admission(command.clone()), remote_admission(command));
    }
}

#[derive(Default)]
struct CliFacadeState {
    next_operation: u64,
    commands: Vec<UserCommand>,
    publications: VecDeque<ControlSnapshot>,
    current: ControlSnapshot,
    challenge_operation: Option<(vortix::vortix_core::control::OperationId, ProfileId)>,
    challenge_answers: usize,
}

#[derive(Clone)]
struct CliFacadeTransport {
    state: Arc<Mutex<CliFacadeState>>,
    challenge_next_connect: bool,
}

impl CliFacadeTransport {
    fn new(challenge_next_connect: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(CliFacadeState::default())),
            challenge_next_connect,
        }
    }

    fn operation(
        operation_id: vortix::vortix_core::control::OperationId,
        command: &UserCommand,
        status: OperationStatus,
        result: Option<OperationResult>,
    ) -> OperationRecord {
        let intent = match command {
            UserCommand::ImportProfile { profile_id }
            | UserCommand::RenameProfile { profile_id, .. }
            | UserCommand::DeleteProfile { profile_id } => OperationIntent::ProfileMutation {
                profile_id: profile_id.clone(),
            },
            _ => OperationIntent::GenerationScoped,
        };
        OperationRecord {
            id: operation_id,
            idempotency_key: IdempotencyKey::new("cli-facade"),
            client_id: serde_json::from_str("\"client-0000000000000000-0000000000000001\"")
                .unwrap(),
            command_digest: PolicyDigest("cli-facade".into()),
            authority_epoch: AuthorityEpoch(1),
            desired_generation: 1,
            admitted_at_millis: 1,
            deadline_millis: u64::MAX,
            intent,
            status,
            result,
        }
    }

    fn terminal_snapshot(
        operation_id: vortix::vortix_core::control::OperationId,
        command: &UserCommand,
    ) -> ControlSnapshot {
        let result = if matches!(
            command,
            UserCommand::ImportProfile { .. }
                | UserCommand::RenameProfile { .. }
                | UserCommand::DeleteProfile { .. }
        ) {
            OperationResult::ProfileMutationApplied
        } else {
            OperationResult::ObservedConvergence
        };
        let mut snapshot = ControlSnapshot::default();
        snapshot.operations.insert(
            operation_id.clone(),
            Self::operation(
                operation_id,
                command,
                OperationStatus::Succeeded,
                Some(result),
            ),
        );
        snapshot
    }
}

struct CliFacadeSubscription(Arc<Mutex<CliFacadeState>>);

impl RemoteControlSubscription for CliFacadeSubscription {
    fn try_recv(&mut self) -> Result<Option<RemoteControlUpdate>, RemoteControlError> {
        let mut state = self.0.lock().unwrap();
        let Some(snapshot) = state.publications.pop_front() else {
            return Ok(None);
        };
        state.current = snapshot.clone();
        Ok(Some(RemoteControlUpdate {
            event: None,
            snapshot,
        }))
    }
}

impl RemoteControlTransport for CliFacadeTransport {
    fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError> {
        match op {
            IpcOp::ControlOpen => Ok(IpcResult::ControlOpened {
                session_id: RemoteSessionId::parse(format!("session-{}", "e".repeat(32))).unwrap(),
                client_id: serde_json::from_str("\"client-0000000000000000-0000000000000001\"")
                    .unwrap(),
            }),
            IpcOp::ControlSubmit { command, .. } => {
                let mut state = self.state.lock().unwrap();
                state.next_operation += 1;
                let operation_id: vortix::vortix_core::control::OperationId = serde_json::from_str(
                    &format!("\"op-0000000000000001-{:016x}\"", state.next_operation),
                )
                .unwrap();
                state.commands.push(command.clone());
                if self.challenge_next_connect && matches!(command, UserCommand::Connect { .. }) {
                    let UserCommand::Connect { profile_id, .. } = &command else {
                        unreachable!();
                    };
                    let challenge_id = serde_json::from_str("1").unwrap();
                    let mut snapshot = ControlSnapshot::default();
                    snapshot.operations.insert(
                        operation_id.clone(),
                        Self::operation(
                            operation_id.clone(),
                            &command,
                            OperationStatus::WaitingForObservation,
                            None,
                        ),
                    );
                    snapshot.challenges.insert(
                        challenge_id,
                        ChallengeRecord {
                            id: challenge_id,
                            profile_id: profile_id.clone(),
                            operation_id: operation_id.clone(),
                            kind: ChallengeKind::TwoFactorCode,
                            label: "OTP".into(),
                            authorized_client: serde_json::from_str(
                                "\"client-0000000000000000-0000000000000001\"",
                            )
                            .unwrap(),
                            created_at_millis: 1,
                            expires_at_millis: u64::MAX,
                        },
                    );
                    state.challenge_operation = Some((operation_id.clone(), profile_id.clone()));
                    state.publications.push_back(snapshot);
                } else {
                    state
                        .publications
                        .push_back(Self::terminal_snapshot(operation_id.clone(), &command));
                }
                Ok(IpcResult::ControlAccepted {
                    admitted: vortix::vortix_core::control::AdmittedOperation { operation_id },
                })
            }
            IpcOp::ControlRespondChallenge { answer, .. } => {
                let mut state = self.state.lock().unwrap();
                assert_eq!(answer.into_vec(), b"123456");
                state.challenge_answers += 1;
                let (operation_id, profile_id) = state.challenge_operation.take().unwrap();
                let command = UserCommand::Connect {
                    profile_id,
                    conflict_acknowledgement: None,
                };
                state
                    .publications
                    .push_back(Self::terminal_snapshot(operation_id, &command));
                Ok(IpcResult::ChallengeAccepted)
            }
            IpcOp::ControlCancelChallenge { .. } => Ok(IpcResult::ChallengeAccepted),
            IpcOp::ControlStageProfileImport {
                final_chunk: true, ..
            } => Ok(IpcResult::ControlProfileImportStaged {
                profile_id: profile('b'),
                display_name: "remote-import".into(),
            }),
            IpcOp::ControlSnapshot { .. } => Ok(IpcResult::ControlSnapshot {
                snapshot: self.state.lock().unwrap().current.clone(),
            }),
            other => Err(RemoteControlError::Protocol(format!(
                "unexpected CLI facade operation: {other:?}"
            ))),
        }
    }

    fn subscribe(
        &self,
        _session_id: &RemoteSessionId,
    ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError> {
        Ok((
            Box::new(CliFacadeSubscription(Arc::clone(&self.state))),
            self.state.lock().unwrap().current.clone(),
        ))
    }
}

fn remote_cli_facade(transport: &CliFacadeTransport) -> ClientControlSession {
    ClientControlSession::remote_for_parity(
        RemoteControlSession::open_for_parity(Arc::new(transport.clone())).unwrap(),
    )
}

#[test]
fn every_cli_mutation_family_runs_through_the_remote_facade_without_local_authority() {
    let commands = [
        UserCommand::Connect {
            profile_id: profile('a'),
            conflict_acknowledgement: None,
        },
        UserCommand::Disconnect {
            profile_id: Some(profile('a')),
        },
        UserCommand::Reconnect {
            profile_id: Some(profile('a')),
        },
        UserCommand::SetKillSwitch {
            mode: vortix::vortix_core::state::killswitch::KillSwitchMode::Auto,
        },
        UserCommand::RenameProfile {
            profile_id: profile('a'),
            new_display_name: "renamed".into(),
        },
        UserCommand::DeleteProfile {
            profile_id: profile('a'),
        },
    ];

    for command in commands {
        let transport = CliFacadeTransport::new(false);
        let facade = remote_cli_facade(&transport);
        facade.validate(&command).unwrap();
        let outcome = facade
            .run(command.clone(), Duration::from_secs(1), "remote-cli")
            .unwrap();
        assert_eq!(outcome.status, OperationStatus::Succeeded);
        assert_eq!(transport.state.lock().unwrap().commands, vec![command]);
    }

    let transport = CliFacadeTransport::new(false);
    let facade = remote_cli_facade(&transport);
    let directory = tempfile::tempdir().unwrap();
    let profile_path = directory.path().join("remote-import.conf");
    std::fs::write(&profile_path, b"[Interface]\nPrivateKey = memory-only\n").unwrap();
    let (profile_id, display_name) = facade.stage_profile_import(&profile_path).unwrap();
    assert_eq!(display_name, "remote-import");
    let outcome = facade
        .run(
            UserCommand::ImportProfile { profile_id },
            Duration::from_secs(1),
            "remote-import",
        )
        .unwrap();
    assert_eq!(outcome.status, OperationStatus::Succeeded);
    assert!(matches!(
        outcome.profile_mutation,
        Some(Ok(
            vortix::cli::control::LocalProfileMutationReceipt::RemoteApplied {
                display_name: Some(name)
            }
        )) if name == "remote-import"
    ));

    let transport = CliFacadeTransport::new(true);
    let facade = remote_cli_facade(&transport);
    let outcome = facade
        .run_with_challenges(
            UserCommand::Connect {
                profile_id: profile('a'),
                conflict_acknowledgement: None,
            },
            Duration::from_secs(1),
            "remote-challenge",
            |_| Ok(Secret::new(b"123456".to_vec())),
        )
        .unwrap();
    assert_eq!(outcome.status, OperationStatus::Succeeded);
    assert_eq!(transport.state.lock().unwrap().challenge_answers, 1);
}

#[test]
fn remote_idempotency_and_challenge_are_one_shot_and_memory_only() {
    let authority = FakeRemoteAuthority::new();
    let transport: Arc<dyn RemoteControlTransport> = authority.clone();
    let owner = RemoteControlSession::open_for_parity(transport.clone()).unwrap();
    let other = RemoteControlSession::open_for_parity(transport).unwrap();
    let command = UserCommand::Connect {
        profile_id: profile('a'),
        conflict_acknowledgement: None,
    };
    let first = owner
        .submit(command.clone(), Duration::from_secs(30), "stable-retry")
        .unwrap();
    let retry = owner
        .submit(command, Duration::from_secs(60), "stable-retry")
        .unwrap();
    assert_eq!(first.operation_id, retry.operation_id);

    let issued = authority
        .runtime
        .block_on(authority.service.completer().issue_challenge(
            first.operation_id,
            profile('a'),
            ChallengeKind::TwoFactorCode,
            "OTP",
            u64::MAX,
        ))
        .unwrap();
    assert!(matches!(
        other.respond_challenge(issued.record.id, Secret::new(b"stolen".to_vec())),
        Err(RemoteControlError::Challenge(
            vortix::vortix_core::control::ChallengeError::Unauthorized
        ))
    ));
    owner
        .respond_challenge(issued.record.id, Secret::new(b"123456".to_vec()))
        .unwrap();
    assert!(matches!(
        owner.respond_challenge(issued.record.id, Secret::new(b"again".to_vec())),
        Err(RemoteControlError::Challenge(
            vortix::vortix_core::control::ChallengeError::NotFound
        ))
    ));
    assert_eq!(
        issued
            .response
            .receive_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap()
            .into_vec(),
        b"123456"
    );
    let snapshot = owner.refresh_snapshot().unwrap();
    assert!(!serde_json::to_string(&snapshot).unwrap().contains("123456"));
}

#[test]
fn remote_profile_staging_keeps_private_body_out_of_control_state() {
    let authority = FakeRemoteAuthority::new();
    let transport: Arc<dyn RemoteControlTransport> = authority;
    let remote = RemoteControlSession::open_for_parity(transport).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("new-profile.conf");
    std::fs::write(&path, b"[Interface]\nPrivateKey = private-material\n").unwrap();
    let (profile_id, display_name) = remote.stage_profile_import(&path).unwrap();
    assert_eq!(profile_id, profile('b'));
    assert_eq!(display_name, "new-profile");
    assert!(!serde_json::to_string(&remote.current_snapshot())
        .unwrap()
        .contains("private-material"));
}

struct FaultTransport(RemoteControlError);

impl RemoteControlTransport for FaultTransport {
    fn exchange(&self, _op: IpcOp) -> Result<IpcResult, RemoteControlError> {
        Err(self.0.clone())
    }

    fn subscribe(
        &self,
        _session_id: &RemoteSessionId,
    ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError> {
        Err(self.0.clone())
    }
}

struct StartingTransport;

impl RemoteControlTransport for StartingTransport {
    fn exchange(&self, op: IpcOp) -> Result<IpcResult, RemoteControlError> {
        match op {
            IpcOp::ControlOpen => Ok(IpcResult::ControlOpened {
                session_id: RemoteSessionId::parse(format!("session-{}", "f".repeat(32))).unwrap(),
                client_id: serde_json::from_str("\"client-0000000000000000-0000000000000001\"")
                    .unwrap(),
            }),
            IpcOp::ControlSubmit { .. } => {
                Err(RemoteControlError::Admission(AdmissionError::NotReady))
            }
            other => Err(RemoteControlError::Protocol(format!(
                "unexpected starting transport operation: {other:?}"
            ))),
        }
    }

    fn subscribe(
        &self,
        _session_id: &RemoteSessionId,
    ) -> Result<(Box<dyn RemoteControlSubscription>, ControlSnapshot), RemoteControlError> {
        Ok((
            Box::new(EmptyRemoteSubscription),
            ControlSnapshot::default(),
        ))
    }
}

#[test]
fn selected_remote_failures_never_construct_a_local_mutation_fallback() {
    for error in [
        RemoteControlError::Unavailable("offline".into()),
        RemoteControlError::Incompatible("schema".into()),
    ] {
        let transport: Arc<dyn RemoteControlTransport> = Arc::new(FaultTransport(error.clone()));
        assert_eq!(
            RemoteControlSession::open_for_parity(transport).unwrap_err(),
            error
        );
    }

    let transport: Arc<dyn RemoteControlTransport> = Arc::new(StartingTransport);
    let remote = RemoteControlSession::open_for_parity(transport).unwrap();
    assert_eq!(
        remote
            .submit(
                UserCommand::Disconnect { profile_id: None },
                Duration::from_secs(1),
                "starting"
            )
            .unwrap_err(),
        RemoteControlError::Admission(AdmissionError::NotReady)
    );
}
