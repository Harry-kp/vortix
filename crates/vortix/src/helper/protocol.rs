//! Strict, versioned daemon-to-helper wire vocabulary.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::ipc::frame::{decode_frame_bounded, encode_frame_bounded};
use crate::vortix_core::ipc::{CompatibilityRange, FrameError};
use crate::vortix_core::privileged::{
    AuthorityBinding, HelperEpoch, LeaseId, PrivilegedOperation, PrivilegedRequest,
    RequestSequence, ServiceInstanceClaim,
};

pub const HELPER_PROTOCOL_MIN: u16 = 1;
pub const HELPER_PROTOCOL_MAX: u16 = 1;
pub const HELPER_SCHEMA_MIN: u16 = 3;
pub const HELPER_SCHEMA_MAX: u16 = 5;
pub(crate) const MANAGED_OBSERVATION_SCHEMA_MIN: u16 = 5;
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

pub(crate) const fn capability_for_operation(operation: &PrivilegedOperation) -> HelperCapability {
    operation_contract(operation).0
}

pub(crate) const fn minimum_schema_for_operation(operation: &PrivilegedOperation) -> u16 {
    operation_contract(operation).1
}

const fn operation_contract(operation: &PrivilegedOperation) -> (HelperCapability, u16) {
    match operation {
        PrivilegedOperation::StartTunnel(_) | PrivilegedOperation::StopTunnel(_) => {
            (HelperCapability::TunnelLifecycle, HELPER_SCHEMA_MIN)
        }
        PrivilegedOperation::NetworkPolicy(_) => {
            (HelperCapability::NetworkPolicy, HELPER_SCHEMA_MIN)
        }
        PrivilegedOperation::Observe(_) => (HelperCapability::Observe, HELPER_SCHEMA_MIN),
        PrivilegedOperation::ObserveManaged(_) => {
            (HelperCapability::Observe, MANAGED_OBSERVATION_SCHEMA_MIN)
        }
        PrivilegedOperation::CleanupOwned(_) => (HelperCapability::CleanupOwned, HELPER_SCHEMA_MIN),
    }
}

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
    Candidate,
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
#[serde(untagged)]
pub enum HelperSessionBinding {
    V4(HelperSessionBindingV4),
    V3(HelperSessionBindingV3),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperSessionBindingV3 {
    authority_epoch: AuthorityEpoch,
    lease_id: LeaseId,
    helper_epoch: HelperEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperSessionBindingV4 {
    authority: AuthorityBinding,
    helper_epoch: HelperEpoch,
    next_sequence: RequestSequence,
}

impl HelperSessionBinding {
    pub(crate) const fn v3(
        authority_epoch: AuthorityEpoch,
        lease_id: LeaseId,
        helper_epoch: HelperEpoch,
    ) -> Self {
        Self::V3(HelperSessionBindingV3 {
            authority_epoch,
            lease_id,
            helper_epoch,
        })
    }

    pub(crate) const fn v4(
        authority: AuthorityBinding,
        helper_epoch: HelperEpoch,
        next_sequence: RequestSequence,
    ) -> Self {
        Self::V4(HelperSessionBindingV4 {
            authority,
            helper_epoch,
            next_sequence,
        })
    }

    fn negotiated(
        schema: u16,
        authority: AuthorityBinding,
        helper_epoch: HelperEpoch,
        next_sequence: RequestSequence,
    ) -> Self {
        match schema {
            3 => Self::v3(
                authority.authority_epoch(),
                authority.lease_id(),
                helper_epoch,
            ),
            4 | 5 => Self::v4(authority, helper_epoch, next_sequence),
            _ => unreachable!("negotiation accepts only helper schemas 3 through 5"),
        }
    }

    #[must_use]
    pub const fn authority(self) -> Option<AuthorityBinding> {
        match self {
            Self::V4(binding) => Some(binding.authority),
            Self::V3(_) => None,
        }
    }

    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpoch {
        match self {
            Self::V4(binding) => binding.authority.authority_epoch(),
            Self::V3(binding) => binding.authority_epoch,
        }
    }

    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        match self {
            Self::V4(binding) => binding.authority.lease_id(),
            Self::V3(binding) => binding.lease_id,
        }
    }

    #[must_use]
    pub const fn helper_epoch(self) -> HelperEpoch {
        match self {
            Self::V4(binding) => binding.helper_epoch,
            Self::V3(binding) => binding.helper_epoch,
        }
    }

    #[must_use]
    pub const fn next_sequence(self) -> Option<RequestSequence> {
        match self {
            Self::V4(binding) => Some(binding.next_sequence),
            Self::V3(_) => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[allow(
    clippy::large_enum_variant,
    reason = "the bounded handshake occurs once per connection; boxing it would add heap churn and mechanical caller complexity"
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
    authority: AuthorityBinding,
    helper_epoch: HelperEpoch,
    next_sequence: RequestSequence,
    enabled_capabilities: &[HelperCapability],
) -> Result<HelperServerHello, HelperError> {
    let mut negotiated = negotiate_common(hello, enabled_capabilities)?;
    negotiated.authority_mode = HelperAuthorityMode::Enrolled;
    negotiated.session = Some(HelperSessionBinding::negotiated(
        negotiated.schema,
        authority,
        helper_epoch,
        next_sequence,
    ));
    Ok(negotiated)
}

pub(crate) fn negotiate_candidate(
    hello: &HelperClientHello,
    authority: AuthorityBinding,
    helper_epoch: HelperEpoch,
) -> Result<HelperServerHello, HelperError> {
    let mut negotiated = negotiate_common(hello, &STAGED_CAPABILITIES)?;
    negotiated.authority_mode = HelperAuthorityMode::Candidate;
    negotiated.session = Some(HelperSessionBinding::negotiated(
        negotiated.schema,
        authority,
        helper_epoch,
        RequestSequence::new(1).expect("one is a valid request sequence"),
    ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::{
        BootScope, LeaseId, OperationDigest, ServiceInstanceClaim,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum V3HelperCapability {
        Handshake,
        Observe,
        TunnelLifecycle,
        NetworkPolicy,
        CleanupOwned,
    }

    const V3_CONTRACT_CAPABILITIES: [V3HelperCapability; 5] = [
        V3HelperCapability::Handshake,
        V3HelperCapability::Observe,
        V3HelperCapability::TunnelLifecycle,
        V3HelperCapability::NetworkPolicy,
        V3HelperCapability::CleanupOwned,
    ];

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct V3ClientHello {
        product: String,
        product_version: String,
        protocol: CompatibilityRange,
        schema: CompatibilityRange,
        required_capabilities: Vec<V3HelperCapability>,
        owner_uid: u32,
        service: ServiceInstanceClaim,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct V3SessionBinding {
        authority_epoch: AuthorityEpoch,
        lease_id: LeaseId,
        helper_epoch: HelperEpoch,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct V3ServerHello {
        product: String,
        product_version: String,
        protocol: u16,
        schema: u16,
        authority_mode: HelperAuthorityMode,
        contract_capabilities: Vec<V3HelperCapability>,
        enabled_capabilities: Vec<V3HelperCapability>,
        session: Option<V3SessionBinding>,
    }

    fn service() -> ServiceInstanceClaim {
        ServiceInstanceClaim::systemd(42, 9, OperationDigest::of_bytes(b"daemon"), [7; 32]).unwrap()
    }

    fn authority() -> AuthorityBinding {
        AuthorityBinding::for_service(
            AuthorityEpoch(3),
            BootScope::new([4; 16]),
            LeaseId::new([5; 32]),
            &service(),
        )
        .unwrap()
    }

    #[test]
    fn new_daemon_hello_is_strictly_decodable_by_v3_helper() {
        let hello = HelperClientHello::current(501, service(), vec![HelperCapability::Handshake]);
        let encoded = serde_json::to_vec(&hello).unwrap();
        let legacy: V3ClientHello = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(legacy.schema, CompatibilityRange { min: 3, max: 5 });
        assert!(!serde_json::to_value(hello)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("expected_authority"));

        let old_response = V3ServerHello {
            product: "vortix-helper".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: 1,
            schema: 3,
            authority_mode: HelperAuthorityMode::Enrolled,
            contract_capabilities: V3_CONTRACT_CAPABILITIES.to_vec(),
            enabled_capabilities: vec![V3HelperCapability::Handshake, V3HelperCapability::Observe],
            session: Some(V3SessionBinding {
                authority_epoch: AuthorityEpoch(3),
                lease_id: LeaseId::new([5; 32]),
                helper_epoch: HelperEpoch::new(8).unwrap(),
            }),
        };
        let current: HelperServerHello =
            serde_json::from_slice(&serde_json::to_vec(&old_response).unwrap()).unwrap();
        assert!(matches!(current.session, Some(HelperSessionBinding::V3(_))));
    }

    #[test]
    fn old_daemon_and_new_helper_negotiate_exact_v3_binding_before_commands() {
        let old = V3ClientHello {
            product: "vortix".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: CompatibilityRange { min: 1, max: 1 },
            schema: CompatibilityRange { min: 3, max: 3 },
            required_capabilities: vec![V3HelperCapability::Handshake],
            owner_uid: 501,
            service: service(),
        };
        let current: HelperClientHello =
            serde_json::from_slice(&serde_json::to_vec(&old).unwrap()).unwrap();
        let response =
            negotiate_candidate(&current, authority(), HelperEpoch::new(8).unwrap()).unwrap();
        assert_eq!(response.schema, 3);
        assert!(matches!(
            response.session,
            Some(HelperSessionBinding::V3(_))
        ));
        let legacy: V3ServerHello =
            serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();
        let session = legacy.session.unwrap();
        assert_eq!(session.authority_epoch, AuthorityEpoch(3));
        assert_eq!(session.lease_id, LeaseId::new([5; 32]));
        assert_eq!(session.helper_epoch, HelperEpoch::new(8).unwrap());
    }

    #[test]
    fn new_peers_negotiate_v5_full_authority_and_replay_cursor() {
        let hello = HelperClientHello::current(501, service(), vec![HelperCapability::Handshake]);
        let response = negotiate_enrolled(
            &hello,
            authority(),
            HelperEpoch::new(9).unwrap(),
            RequestSequence::new(17).unwrap(),
            &STAGED_CAPABILITIES,
        )
        .unwrap();
        assert_eq!(response.schema, 5);
        let encoded = serde_json::to_vec(&response).unwrap();
        let decoded: HelperServerHello = serde_json::from_slice(&encoded).unwrap();
        let binding = decoded.session.unwrap();
        assert_eq!(binding.authority(), Some(authority()));
        assert_eq!(binding.helper_epoch(), HelperEpoch::new(9).unwrap());
        assert_eq!(
            binding.next_sequence(),
            Some(RequestSequence::new(17).unwrap())
        );
    }
}
