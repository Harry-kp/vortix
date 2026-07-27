//! Strict, versioned daemon-to-helper wire vocabulary.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::ipc::CompatibilityRange;
use crate::vortix_core::privileged::{PrivilegedRequest, ServiceInstanceClaim};

pub const HELPER_PROTOCOL_MIN: u16 = 1;
pub const HELPER_PROTOCOL_MAX: u16 = 1;
pub const HELPER_SCHEMA_MIN: u16 = 1;
pub const HELPER_SCHEMA_MAX: u16 = 1;
pub const MAX_HELPER_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperCapability {
    Handshake,
    Observe,
    TunnelLifecycle,
    NetworkPolicy,
    CleanupOwned,
}

pub const CONTRACT_CAPABILITIES: [HelperCapability; 5] = [
    HelperCapability::Handshake,
    HelperCapability::Observe,
    HelperCapability::TunnelLifecycle,
    HelperCapability::NetworkPolicy,
    HelperCapability::CleanupOwned,
];

pub const STAGED_CAPABILITIES: [HelperCapability; 1] = [HelperCapability::Handshake];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperClientHello {
    pub product: String,
    pub product_version: String,
    pub protocol: CompatibilityRange,
    pub schema: CompatibilityRange,
    pub required_capabilities: Vec<HelperCapability>,
    pub owner_uid: u32,
    pub service: ServiceInstanceClaim,
}

impl HelperClientHello {
    #[must_use]
    pub fn current(
        owner_uid: u32,
        service: ServiceInstanceClaim,
        required_capabilities: Vec<HelperCapability>,
    ) -> Self {
        Self {
            product: "vortix".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: CompatibilityRange {
                min: HELPER_PROTOCOL_MIN,
                max: HELPER_PROTOCOL_MAX,
            },
            schema: CompatibilityRange {
                min: HELPER_SCHEMA_MIN,
                max: HELPER_SCHEMA_MAX,
            },
            required_capabilities,
            owner_uid,
            service,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperAuthorityMode {
    Staged,
    Enrolled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperServerHello {
    pub product: String,
    pub product_version: String,
    pub protocol: u16,
    pub schema: u16,
    pub authority_mode: HelperAuthorityMode,
    pub contract_capabilities: Vec<HelperCapability>,
    pub enabled_capabilities: Vec<HelperCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HelperOp {
    Handshake(HelperClientHello),
    Execute(Box<PrivilegedRequest>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRequest {
    pub id: u64,
    pub op: HelperOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperResponse {
    pub id: u64,
    pub result: Result<HelperResult, HelperError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum HelperResult {
    Handshake(HelperServerHello),
    /// U12 replaces this dormant outcome with the strict receipt wire.
    Staged,
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum HelperError {
    #[error("incompatible helper peer: {reason}")]
    Incompatible { reason: String },
    #[error("helper capability is unavailable: {capability:?}")]
    CapabilityUnavailable { capability: HelperCapability },
    #[error("helper authority is staged but not enrolled")]
    NotEnrolled,
    #[error("malformed helper request: {reason}")]
    Malformed { reason: String },
    #[error("helper frame is too large: {size} > {max}")]
    FrameTooLarge { size: usize, max: usize },
}

/// Negotiate the installed-but-unenrolled U11 helper contract.
pub fn negotiate_staged(hello: &HelperClientHello) -> Result<HelperServerHello, HelperError> {
    if hello.product != "vortix"
        || hello.product_version.is_empty()
        || hello.product_version.len() > 64
        || hello.owner_uid == 0
    {
        return Err(HelperError::Incompatible {
            reason: "product and non-root owner identity are required".into(),
        });
    }
    if hello.required_capabilities.len() > CONTRACT_CAPABILITIES.len()
        || hello
            .required_capabilities
            .iter()
            .enumerate()
            .any(|(index, capability)| hello.required_capabilities[..index].contains(capability))
    {
        return Err(HelperError::Incompatible {
            reason: "required capabilities must be unique and bounded".into(),
        });
    }
    if !hello.protocol.is_valid() || !hello.schema.is_valid() {
        return Err(HelperError::Incompatible {
            reason: "invalid compatibility range".into(),
        });
    }
    let protocol = hello
        .protocol
        .highest_common(CompatibilityRange {
            min: HELPER_PROTOCOL_MIN,
            max: HELPER_PROTOCOL_MAX,
        })
        .ok_or_else(|| HelperError::Incompatible {
            reason: "helper protocol ranges do not overlap".into(),
        })?;
    let schema = hello
        .schema
        .highest_common(CompatibilityRange {
            min: HELPER_SCHEMA_MIN,
            max: HELPER_SCHEMA_MAX,
        })
        .ok_or_else(|| HelperError::Incompatible {
            reason: "helper schema ranges do not overlap".into(),
        })?;
    for capability in &hello.required_capabilities {
        if !STAGED_CAPABILITIES.contains(capability) {
            return Err(HelperError::CapabilityUnavailable {
                capability: *capability,
            });
        }
    }
    Ok(HelperServerHello {
        product: "vortix-helper".into(),
        product_version: env!("CARGO_PKG_VERSION").into(),
        protocol,
        schema,
        authority_mode: HelperAuthorityMode::Staged,
        contract_capabilities: CONTRACT_CAPABILITIES.to_vec(),
        enabled_capabilities: STAGED_CAPABILITIES.to_vec(),
    })
}

/// Allocation-bound and strictly decode one helper request body.
pub fn parse_request(bytes: &[u8]) -> Result<HelperRequest, HelperError> {
    if bytes.len() > MAX_HELPER_FRAME_BYTES {
        return Err(HelperError::FrameTooLarge {
            size: bytes.len(),
            max: MAX_HELPER_FRAME_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|error| HelperError::Malformed {
        reason: error.to_string(),
    })
}
