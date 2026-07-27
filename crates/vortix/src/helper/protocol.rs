//! Strict, versioned daemon-to-helper wire vocabulary.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::ipc::frame::{decode_frame_bounded, encode_frame_bounded};
use crate::vortix_core::ipc::{CompatibilityRange, FrameError};
use crate::vortix_core::privileged::{
    HelperEpoch, LeaseId, PrivilegedRequest, ServiceInstanceClaim,
};

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
    pub session: Option<HelperSessionBinding>,
}

/// Authenticated incarnation expected on every enrolled receipt. The daemon
/// still treats these scalars as untrusted until the peer socket and installed
/// helper identity have been verified by the platform boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperSessionBinding {
    pub authority_epoch: AuthorityEpoch,
    pub lease_id: LeaseId,
    pub helper_epoch: HelperEpoch,
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
    /// A receipt remains an untrusted JSON value until the daemon decodes it
    /// as `UntrustedReceipt` and authenticates every binding field.
    Receipt(serde_json::Value),
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
    #[error("helper peer did not authenticate as the enrolled daemon")]
    AuthenticationFailed,
    #[error("root replay ledger is unavailable; helper session is fail-closed")]
    LedgerUnavailable,
}

/// Negotiate the installed-but-unenrolled U11 helper contract.
pub fn negotiate_staged(hello: &HelperClientHello) -> Result<HelperServerHello, HelperError> {
    negotiate_common(hello, &STAGED_CAPABILITIES)
}

#[allow(
    dead_code,
    reason = "U12 execution slice remains unreachable until U13 enrollment gates it"
)]
pub(crate) fn negotiate_enrolled(
    hello: &HelperClientHello,
    binding: HelperSessionBinding,
    enabled_capabilities: &[HelperCapability],
) -> Result<HelperServerHello, HelperError> {
    let mut negotiated = negotiate_common(hello, enabled_capabilities)?;
    negotiated.authority_mode = HelperAuthorityMode::Enrolled;
    negotiated.session = Some(binding);
    Ok(negotiated)
}

#[allow(
    dead_code,
    reason = "U12 execution slice remains unreachable until U13 enrollment gates it"
)]
fn negotiate_common(
    hello: &HelperClientHello,
    enabled_capabilities: &[HelperCapability],
) -> Result<HelperServerHello, HelperError> {
    if hello.product != "vortix"
        || hello.product_version.is_empty()
        || hello.product_version.len() > 64
        || hello.owner_uid == 0
        || enabled_capabilities.is_empty()
        || !enabled_capabilities.contains(&HelperCapability::Handshake)
        || enabled_capabilities
            .iter()
            .enumerate()
            .any(|(index, capability)| enabled_capabilities[..index].contains(capability))
        || enabled_capabilities
            .iter()
            .any(|capability| !CONTRACT_CAPABILITIES.contains(capability))
    {
        return Err(HelperError::Incompatible {
            reason: "invalid product, owner, or enabled capability set".into(),
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
        if !enabled_capabilities.contains(capability) {
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
        enabled_capabilities: enabled_capabilities.to_vec(),
        session: None,
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

/// Encode one daemon-to-helper request with the helper-specific frame cap.
pub fn encode_request_frame(request: &HelperRequest) -> Result<Vec<u8>, FrameError> {
    encode_frame_bounded::<_, MAX_HELPER_FRAME_BYTES>(request)
}

/// Decode at most one daemon-to-helper frame without allocating its declared
/// body until the 256 KiB helper limit has been checked.
pub fn decode_request_frame(bytes: &[u8]) -> Result<Option<(HelperRequest, usize)>, FrameError> {
    decode_frame_bounded::<_, MAX_HELPER_FRAME_BYTES>(bytes)
}

/// Encode one helper-to-daemon response with the same symmetric bound.
pub fn encode_response_frame(response: &HelperResponse) -> Result<Vec<u8>, FrameError> {
    encode_frame_bounded::<_, MAX_HELPER_FRAME_BYTES>(response)
}

/// Decode at most one helper-to-daemon response frame under the helper cap.
pub fn decode_response_frame(bytes: &[u8]) -> Result<Option<(HelperResponse, usize)>, FrameError> {
    decode_frame_bounded::<_, MAX_HELPER_FRAME_BYTES>(bytes)
}
