//! Daemon-side helper receipt authentication and loss classification.
//!
//! A decoded receipt is never success by itself. Only a session bound to the
//! daemon's non-serializable principal and the authenticated helper incarnation
//! can verify it. Transport loss after a request may have crossed the boundary
//! always requires observation/reconciliation before retry.

#![allow(
    dead_code,
    reason = "U12 client slice remains unreachable until U13 enrollment gates it"
)]

use thiserror::Error;

use crate::helper::validate::VerifiedHelperPeer;
use crate::helper::{
    HelperAuthorityMode, HelperCapability, HelperResponse, HelperResult, HelperServerHello,
    HELPER_PROTOCOL_MAX, HELPER_PROTOCOL_MIN, HELPER_SCHEMA_MAX, HELPER_SCHEMA_MIN,
};
use crate::vortix_core::privileged::{
    AuthenticatedReceiptVerifier, PrivilegedRequest, ReceiptError, TrustedDaemonPrincipal,
    UntrustedReceipt, VerifiedReceipt,
};

pub(crate) struct AuthenticatedHelperSession {
    verifier: AuthenticatedReceiptVerifier,
}

impl AuthenticatedHelperSession {
    pub(crate) fn from_handshake(
        principal: &TrustedDaemonPrincipal,
        _peer: &VerifiedHelperPeer,
        hello: &HelperServerHello,
    ) -> Result<Self, HelperClientError> {
        let Some(binding) = hello.session else {
            return Err(HelperClientError::NotEnrolled);
        };
        if hello.product != "vortix-helper"
            || hello.authority_mode != HelperAuthorityMode::Enrolled
            || !(HELPER_PROTOCOL_MIN..=HELPER_PROTOCOL_MAX).contains(&hello.protocol)
            || !(HELPER_SCHEMA_MIN..=HELPER_SCHEMA_MAX).contains(&hello.schema)
            || has_duplicates(&hello.contract_capabilities)
            || has_duplicates(&hello.enabled_capabilities)
            || hello
                .enabled_capabilities
                .iter()
                .any(|capability| !hello.contract_capabilities.contains(capability))
            || !hello
                .enabled_capabilities
                .contains(&HelperCapability::Handshake)
            || !hello
                .enabled_capabilities
                .contains(&HelperCapability::Observe)
            || binding.authority_epoch != principal.authority_epoch()
            || binding.lease_id != principal.lease_id()
        {
            return Err(HelperClientError::AuthorityMismatch);
        }
        Ok(Self {
            verifier: AuthenticatedReceiptVerifier::from_authenticated_helper(
                binding.authority_epoch,
                binding.lease_id,
                binding.helper_epoch,
            ),
        })
    }

    pub(crate) fn verify_receipt(
        &self,
        expected_id: u64,
        request: &PrivilegedRequest,
        response: HelperResponse,
    ) -> Result<VerifiedReceipt, HelperClientError> {
        if response.id != expected_id {
            return Err(HelperClientError::ResponseIdMismatch);
        }
        let value = match response.result.map_err(HelperClientError::Helper)? {
            HelperResult::Receipt(value) => value,
            HelperResult::Staged => return Err(HelperClientError::NotEnrolled),
            HelperResult::Handshake(_) => return Err(HelperClientError::UnexpectedResponse),
        };
        let receipt: UntrustedReceipt =
            serde_json::from_value(value).map_err(|_| HelperClientError::MalformedReceipt)?;
        self.verifier
            .verify(request, receipt)
            .map_err(HelperClientError::Receipt)
    }
}

fn has_duplicates(capabilities: &[HelperCapability]) -> bool {
    capabilities
        .iter()
        .enumerate()
        .any(|(index, capability)| capabilities[..index].contains(capability))
}

/// Delivery phase retained by the daemon until an authenticated receipt is
/// committed. This classification is intentionally independent of operation
/// type: even an apparently idempotent mutation cannot be retried blindly.
pub(crate) struct DeliveryState {
    #[allow(
        dead_code,
        reason = "retained for U12 reconciliation request construction"
    )]
    request: PrivilegedRequest,
    sent: bool,
}

impl DeliveryState {
    pub(crate) const fn prepared(request: PrivilegedRequest) -> Self {
        Self {
            request,
            sent: false,
        }
    }

    pub(crate) const fn mark_sent(&mut self) {
        self.sent = true;
    }

    pub(crate) const fn transport_lost(&self) -> RecoveryAction {
        if self.sent {
            RecoveryAction::ReconcileRequired
        } else {
            RecoveryAction::Unavailable
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryAction {
    Unavailable,
    ReconcileRequired,
}

#[derive(Debug, Error)]
pub(crate) enum HelperClientError {
    #[error("helper is staged but not enrolled")]
    NotEnrolled,
    #[error("helper session does not match daemon authority")]
    AuthorityMismatch,
    #[error("helper response ID does not match request")]
    ResponseIdMismatch,
    #[error("helper returned an unexpected response variant")]
    UnexpectedResponse,
    #[error("helper returned a malformed receipt")]
    MalformedReceipt,
    #[error("helper rejected the request: {0}")]
    Helper(crate::helper::HelperError),
    #[error("helper receipt failed authenticated validation: {0}")]
    Receipt(ReceiptError),
}
