//! Engine FSM, event schema, and supporting types (plan #005 U1).
//!
//! Plan #005 U1 defines the type vocabulary the FSM operates over: the
//! 5-variant `Connection` state machine, the 15-variant `EngineEvent`
//! schema, the `Input` enum, and structured `EngineError`. The actual FSM
//! implementation (`async fn handle(input)`), the JSONL journal, and the
//! `EngineHandle` actor wrapper live in subsequent units — this module
//! intentionally exports only the data shapes today.

pub mod error;
pub mod event;
pub mod fsm;
pub mod handle;
pub mod input;
pub mod registry;
pub mod state;

pub use error::EngineError;
pub use event::{EngineEvent, EventEnvelope, SCHEMA_VERSION};
pub use fsm::{Engine, EngineSettings};
pub use handle::{CommandAck, EngineHandle, EngineSubscription, LocalHandle, Snapshot};
pub use input::{Input, LinkState, ProfileChange, TunnelStatusObservation, UserCommand};
pub use registry::{
    Conflict, PrimaryTunnelChangeReason, RegistryError, Role, TunnelRegistry, TunnelSnapshot,
};
pub use state::{
    Connection, ConnectionHealth, DegradedReason, DetailedConnectionInfo, FailureReason,
};
