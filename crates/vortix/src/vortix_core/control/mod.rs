//! Canonical control-plane vocabulary and in-process shadow service.
//!
//! U5 introduces this owner without routing existing CLI/TUI mutations through
//! it.  The service therefore changes only its in-memory model: it performs no
//! protocol, platform, process, filesystem, or network work.

pub mod command;
pub mod model;
pub mod service;
pub mod snapshot;

pub use command::{
    ChallengeResponse, CommandRequest, Deadline, IdempotencyKey, Secret, UserCommand,
};
pub use model::{
    AuthorityEpoch, ChallengeId, ChallengeKind, ChallengeRecord, ClientId, CompletionOutcome,
    ControlEvent, ControlEventEnvelope, DesiredState, DriftGates, EffectiveState, EventEnvelope,
    Freshness, GateEvidence, Observation, ObservedState, OperationCompletion, OperationFailure,
    OperationId, OperationRecord, OperationResult, OperationStatus, PolicyDigest,
    ProtectionEvidence, ProtectionStatus, RequestedTunnelState,
};
pub use service::{
    AdmissionError, AdmittedOperation, ChallengeAnswerReceiver, ChallengeDeliveryError,
    ChallengeError, Clock, CompleterHandle, CompletionError, CompletionResult, ControlHandle,
    ControlService, ControlServiceConfig, ControlSubscription, EventReceiveError, IssuedChallenge,
    ObservationError, ObserverHandle, ReadinessError, RealClock,
};
pub use snapshot::{ControlSnapshot, ServiceReadiness};
