//! Canonical control-plane vocabulary and in-process shadow service.
//!
//! U5 introduces this owner without routing existing CLI/TUI mutations through
//! it.  The service therefore changes only its in-memory model: it performs no
//! protocol, platform, process, filesystem, or network work.

pub mod command;
pub mod hooks;
pub mod model;
pub mod persistence;
pub mod reconcile;
pub mod service;
pub mod snapshot;
pub mod supervisor;
pub mod worker;

pub use command::{
    ChallengeResponse, CommandRequest, Deadline, IdempotencyKey, Secret, UserCommand,
};
pub use hooks::{HookEvent, HookEventId, LifecycleFact};
pub use model::{
    AuthorityEpoch, ChallengeId, ChallengeKind, ChallengeRecord, ClientId, CompletionOutcome,
    ControlEvent, ControlEventEnvelope, DesiredState, DriftGates, EffectiveState, EventEnvelope,
    Freshness, GateEvidence, Observation, ObservedConnectionHealth, ObservedState,
    OperationCompletion, OperationFailure, OperationId, OperationIntent, OperationRecord,
    OperationResult, OperationStatus, PolicyDigest, ProtectionEvidence, ProtectionStatus,
    RequestedTunnelState,
};
pub use persistence::{
    BootConnection, BootEligibility, ControlStateStore, ControlStateStoreError,
    DurableControlState, PersistedTombstone, RecoveredControlState, RequestedResources,
    RetentionMetadata,
};
pub use service::{
    AdmissionError, AdmittedOperation, ChallengeAnswerReceiver, ChallengeDeliveryError,
    ChallengeError, Clock, CompleterHandle, CompletionError, CompletionResult, ControlHandle,
    ControlPersistenceConfig, ControlService, ControlServiceConfig, ControlSubscription,
    EventReceiveError, ExecutionSelection, IssuedChallenge, ObservationError, ObserverHandle,
    ProfileTopology, ReadinessError, RealClock,
};
pub use snapshot::{ControlSnapshot, ServiceReadiness};
