//! U7/U8 compatibility re-exports for the canonical control event schema.

pub use crate::vortix_core::control::model::{
    ControlEvent as EngineEvent, EventEnvelope, KillswitchEngageReason, PrimaryChangeReason,
    TunnelDownReason, SCHEMA_VERSION,
};
