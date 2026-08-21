//! Daemon-side helper receipt authentication and loss classification.
//!
//! A decoded receipt is never success by itself. Only a session bound to the
//! daemon's non-serializable principal and the authenticated helper incarnation
//! can verify it. Transport loss after a request may have crossed the boundary
//! always requires observation/reconciliation before retry.

#![allow(
    unsafe_code,
    reason = "absolute Unix-socket read deadlines require poll(2)"
)]
#![allow(
    dead_code,
    reason = "U12 client slice remains unreachable until U13 enrollment gates it"
)]

use std::io::Read as _;
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Instant;

use thiserror::Error;

use crate::helper::protocol::{
    capability_for_operation, minimum_schema_for_operation, RELEASE_ACK_SCHEMA_MIN,
};
use crate::helper::validate::VerifiedHelperPeer;
use crate::helper::{
    connect_verified_helper, decode_response_frame, expected_descriptor_count_for_operation,
    prepare_request, send_prepared_request, HelperAuthorityMode, HelperCapability, HelperOp,
    HelperPolicyInventory, HelperReleasedInventory, HelperRequest, HelperResponse, HelperResult,
    HelperServerHello, HelperTransportError, HELPER_PROTOCOL_MAX, HELPER_PROTOCOL_MIN,
    HELPER_SCHEMA_MAX, HELPER_SCHEMA_MIN, MAX_HELPER_FRAME_BYTES,
};
use crate::vortix_core::privileged::{
    AuthenticatedReceiptVerifier, AuthorityBinding, OperationError, PrivilegedOperation,
    PrivilegedRequest, ReceiptError, RequestSequence, ServiceInstanceClaim, TrustedDaemonPrincipal,
    UntrustedReceipt, VerifiedReceipt,
};

pub(crate) struct AuthenticatedHelperSession {
    verifier: AuthenticatedReceiptVerifier,
    principal: TrustedDaemonPrincipal,
    helper_epoch: crate::vortix_core::privileged::HelperEpoch,
    next_sequence: Option<RequestSequence>,
    negotiated_schema: u16,
    enabled_capabilities: Vec<HelperCapability>,
    policy_inventory: Option<Box<HelperPolicyInventory>>,
    released_resources: Option<Box<HelperReleasedInventory>>,
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
        let policy_capability = hello
            .enabled_capabilities
            .contains(&HelperCapability::NetworkPolicy);
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
            || binding.authority_epoch() != principal.authority_epoch()
            || binding.lease_id() != principal.lease_id()
            || (hello.schema == 3 && !matches!(binding, crate::helper::HelperSessionBinding::V3(_)))
            || ((4..=HELPER_SCHEMA_MAX).contains(&hello.schema)
                && !matches!(binding, crate::helper::HelperSessionBinding::V4(_)))
        {
            return Err(HelperClientError::AuthorityMismatch);
        }
        if (hello.schema >= 6 && policy_capability) != hello.policy_inventory.is_some()
            || (hello.schema < 6 && hello.policy_inventory.is_some())
            || hello
                .policy_inventory
                .as_ref()
                .is_some_and(|inventory| !inventory.matches_authority(binding.authority_epoch()))
        {
            return Err(HelperClientError::PolicyInventoryMismatch);
        }
        let released_inventory_expected = hello.schema >= RELEASE_ACK_SCHEMA_MIN
            && hello
                .enabled_capabilities
                .contains(&HelperCapability::Observe);
        if released_inventory_expected != hello.released_resources.is_some() {
            return Err(HelperClientError::ReleasedInventoryMismatch);
        }
        Ok(Self {
            verifier: AuthenticatedReceiptVerifier::from_authenticated_helper(
                binding.authority_epoch(),
                binding.lease_id(),
                binding.helper_epoch(),
            ),
            principal: principal.clone(),
            helper_epoch: binding.helper_epoch(),
            next_sequence: binding.next_sequence(),
            negotiated_schema: hello.schema,
            enabled_capabilities: hello.enabled_capabilities.clone(),
            policy_inventory: hello.policy_inventory.clone(),
            released_resources: hello.released_resources.clone(),
        })
    }

    fn from_authority_handshake(
        owner_uid: u32,
        service: &ServiceInstanceClaim,
        expected_authority: AuthorityBinding,
        required_capabilities: &[HelperCapability],
        peer: &VerifiedHelperPeer,
        hello: &HelperServerHello,
    ) -> Result<Self, HelperClientError> {
        let binding = hello.session.ok_or(HelperClientError::NotEnrolled)?;
        match (hello.schema, binding.authority()) {
            (4..=HELPER_SCHEMA_MAX, Some(authority)) if authority == expected_authority => {}
            (3, None)
                if binding.authority_epoch() == expected_authority.authority_epoch()
                    && binding.lease_id() == expected_authority.lease_id() => {}
            _ => return Err(HelperClientError::AuthorityMismatch),
        }
        if required_capabilities
            .iter()
            .any(|capability| !hello.enabled_capabilities.contains(capability))
        {
            return Err(HelperClientError::CapabilityMismatch);
        }
        let principal = TrustedDaemonPrincipal::from_authenticated_binding(
            owner_uid,
            expected_authority,
            service,
        )
        .map_err(HelperClientError::Principal)?;
        Self::from_handshake(&principal, peer, hello)
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

/// One authenticated daemon-to-helper connection. Construction proves the
/// fixed root helper endpoint before the handshake, then binds every request
/// to the expected enrolled authority and the returned helper incarnation.
pub(crate) struct AuthenticatedHelperTransport {
    stream: UnixStream,
    session: AuthenticatedHelperSession,
    authority_binding: AuthorityBinding,
    next_id: u64,
    next_sequence: RequestSequence,
    poisoned: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HelperConnectBudget {
    minimum_next_sequence: RequestSequence,
    deadline: Instant,
}

impl HelperConnectBudget {
    pub(crate) const fn new(minimum_next_sequence: RequestSequence, deadline: Instant) -> Self {
        Self {
            minimum_next_sequence,
            deadline,
        }
    }
}

impl AuthenticatedHelperTransport {
    pub(crate) fn connect(
        owner_uid: u32,
        expected_authority: AuthorityBinding,
        service: &ServiceInstanceClaim,
        required_capabilities: &[HelperCapability],
        budget: HelperConnectBudget,
    ) -> Result<Self, HelperClientError> {
        let (stream, peer) = connect_verified_helper(owner_uid, budget.deadline)?;
        Self::open_verified(
            stream,
            &peer,
            owner_uid,
            expected_authority,
            service,
            required_capabilities,
            budget,
        )
    }

    pub(crate) fn policy_inventory(&self) -> Option<&HelperPolicyInventory> {
        self.session.policy_inventory.as_deref()
    }

    pub(crate) fn released_resources(
        &self,
    ) -> Option<&[crate::vortix_core::privileged::ResourceTag]> {
        self.session
            .released_resources
            .as_deref()
            .map(HelperReleasedInventory::resources)
    }

    pub(crate) fn open_verified(
        mut stream: UnixStream,
        peer: &VerifiedHelperPeer,
        owner_uid: u32,
        expected_authority: AuthorityBinding,
        service: &ServiceInstanceClaim,
        required_capabilities: &[HelperCapability],
        budget: HelperConnectBudget,
    ) -> Result<Self, HelperClientError> {
        let HelperConnectBudget {
            minimum_next_sequence,
            deadline,
        } = budget;
        validate_required_capabilities(required_capabilities)?;
        set_deadline(&stream, deadline)?;
        let request = HelperRequest {
            id: 1,
            op: HelperOp::Handshake(crate::helper::HelperClientHello::current(
                owner_uid,
                service.clone(),
                required_capabilities.to_vec(),
            )),
        };
        let prepared =
            prepare_request(&request, &[]).map_err(|_| HelperClientError::RequestTransport)?;
        if Instant::now() >= deadline {
            return Err(HelperClientError::DeadlineExpired);
        }
        send_prepared_request(&mut stream, &prepared, &[])
            .map_err(|_| HelperClientError::RequestTransport)?;
        if Instant::now() >= deadline {
            return Err(HelperClientError::DeadlineExpired);
        }
        let response = read_response(&mut stream, deadline)?;
        if response.id != request.id {
            return Err(HelperClientError::ResponseIdMismatch);
        }
        let hello = match response.result.map_err(HelperClientError::Helper)? {
            HelperResult::Handshake(hello) => hello,
            HelperResult::Staged => return Err(HelperClientError::NotEnrolled),
            HelperResult::Receipt(_) => return Err(HelperClientError::UnexpectedResponse),
        };
        let session = AuthenticatedHelperSession::from_authority_handshake(
            owner_uid,
            service,
            expected_authority,
            required_capabilities,
            peer,
            &hello,
        )?;
        let next_sequence = session
            .next_sequence
            .map_or(minimum_next_sequence, |helper| {
                helper.max(minimum_next_sequence)
            });
        Ok(Self {
            stream,
            session,
            authority_binding: expected_authority,
            next_id: 2,
            next_sequence,
            poisoned: false,
        })
    }

    pub(crate) fn execute(
        &mut self,
        operation: PrivilegedOperation,
        descriptors: &[RawFd],
        deadline: Instant,
    ) -> Result<VerifiedReceipt, HelperExecutionFailure> {
        self.execute_bound(operation, descriptors, deadline)
            .map(AuthenticatedHelperOutcome::into_receipt)
    }

    pub(super) fn execute_bound(
        &mut self,
        operation: PrivilegedOperation,
        descriptors: &[RawFd],
        deadline: Instant,
    ) -> Result<AuthenticatedHelperOutcome, HelperExecutionFailure> {
        if self.poisoned {
            return Err(HelperExecutionFailure::new(
                RecoveryAction::ReconcileRequired,
                HelperClientError::SessionPoisoned,
            ));
        }
        if self.session.negotiated_schema < minimum_schema_for_operation(&operation) {
            return Err(HelperExecutionFailure::new(
                RecoveryAction::Unavailable,
                HelperClientError::SchemaMismatch,
            ));
        }
        if !self
            .session
            .enabled_capabilities
            .contains(&capability_for_operation(&operation))
        {
            return Err(HelperExecutionFailure::new(
                RecoveryAction::Unavailable,
                HelperClientError::CapabilityMismatch,
            ));
        }
        if expected_descriptor_count_for_operation(Some(&operation)) != descriptors.len() {
            return Err(HelperExecutionFailure::new(
                RecoveryAction::Unavailable,
                HelperClientError::DescriptorCountMismatch,
            ));
        }
        if let Err(error) = set_deadline(&self.stream, deadline) {
            return Err(HelperExecutionFailure::new(
                RecoveryAction::Unavailable,
                error,
            ));
        }
        let sequence = self.next_sequence;
        let request = PrivilegedRequest::new(
            &self.session.principal,
            self.session.helper_epoch,
            sequence,
            operation,
        )
        .map_err(|error| {
            HelperExecutionFailure::new(
                RecoveryAction::Unavailable,
                HelperClientError::Principal(error),
            )
        })?;
        let mut delivery = DeliveryState::prepared(request);
        let envelope = HelperRequest {
            id: self.next_id,
            op: HelperOp::Execute(Box::new(delivery.request().clone())),
        };
        let prepared = prepare_request(&envelope, descriptors).map_err(|_| {
            HelperExecutionFailure::new(
                RecoveryAction::Unavailable,
                HelperClientError::RequestTransport,
            )
        })?;
        if Instant::now() >= deadline {
            return Err(HelperExecutionFailure::new(
                RecoveryAction::Unavailable,
                HelperClientError::DeadlineExpired,
            ));
        }
        self.next_sequence = sequence
            .get()
            .checked_add(1)
            .and_then(|next| RequestSequence::new(next).ok())
            .ok_or_else(|| {
                HelperExecutionFailure::new(
                    RecoveryAction::Unavailable,
                    HelperClientError::SequenceExhausted,
                )
            })?;
        delivery.mark_sent();
        if send_prepared_request(&mut self.stream, &prepared, descriptors).is_err() {
            return Err(self.fail_after_send(&delivery, HelperClientError::RequestTransport));
        }
        if Instant::now() >= deadline {
            return Err(self.fail_after_send(&delivery, HelperClientError::DeadlineExpired));
        }
        let response = match read_response(&mut self.stream, deadline) {
            Ok(response) => response,
            Err(error) => return Err(self.fail_after_send(&delivery, error)),
        };
        if let Some(failure) = self.definitive_pre_admission_failure(envelope.id, &response) {
            return Err(failure);
        }
        let receipt = match self
            .session
            .verify_receipt(envelope.id, delivery.request(), response)
        {
            Ok(receipt) => receipt,
            Err(error) => return Err(self.fail_after_send(&delivery, error)),
        };
        self.next_id = self.next_id.checked_add(1).unwrap_or(0);
        Ok(AuthenticatedHelperOutcome {
            request: delivery.into_request(),
            receipt,
        })
    }

    pub(crate) const fn reconnect_floor(&self) -> RequestSequence {
        self.next_sequence
    }

    pub(crate) const fn authority_binding(&self) -> AuthorityBinding {
        self.authority_binding
    }

    pub(crate) fn enabled_capabilities(&self) -> &[HelperCapability] {
        &self.session.enabled_capabilities
    }

    fn definitive_pre_admission_failure(
        &mut self,
        expected_id: u64,
        response: &HelperResponse,
    ) -> Option<HelperExecutionFailure> {
        if response.id != expected_id {
            return None;
        }
        let Err(
            error @ (crate::helper::HelperError::CapabilityUnavailable { .. }
            | crate::helper::HelperError::AuthenticationFailed),
        ) = &response.result
        else {
            return None;
        };
        self.next_id = self.next_id.checked_add(1).unwrap_or(0);
        Some(HelperExecutionFailure::new(
            RecoveryAction::Unavailable,
            HelperClientError::Helper(error.clone()),
        ))
    }

    fn fail_after_send(
        &mut self,
        delivery: &DeliveryState,
        source: HelperClientError,
    ) -> HelperExecutionFailure {
        self.poisoned = true;
        HelperExecutionFailure::new(delivery.transport_lost(), source)
    }
}

/// One exact authenticated helper session shared by canonical effect workers.
///
/// The helper wire owns a single request sequence, so tunnel and policy
/// workers must serialize through this capability rather than cloning or
/// independently reconstructing authority. Mutex poisoning is classified as
/// outcome-unknown because a panic may have interrupted an in-flight request.
pub(crate) struct SharedAuthenticatedHelper {
    authority_binding: AuthorityBinding,
    enabled_capabilities: Vec<HelperCapability>,
    transport: Mutex<AuthenticatedHelperTransport>,
}

/// Immutable authority material capable of opening a fresh authenticated
/// helper session for each effect attempt or recovery operation.
///
/// A transport whose request may have crossed the helper boundary is poisoned
/// deliberately. Recovery must therefore return to this connector instead of
/// attempting reconciliation through that same transport.
pub(crate) struct AuthenticatedHelperConnector {
    owner_uid: u32,
    authority_binding: AuthorityBinding,
    service: ServiceInstanceClaim,
    required_capabilities: Vec<HelperCapability>,
}

impl AuthenticatedHelperConnector {
    pub(crate) fn new(
        owner_uid: u32,
        authority_binding: AuthorityBinding,
        service: ServiceInstanceClaim,
        required_capabilities: Vec<HelperCapability>,
    ) -> Result<Self, HelperClientError> {
        validate_required_capabilities(&required_capabilities)?;
        Ok(Self {
            owner_uid,
            authority_binding,
            service,
            required_capabilities,
        })
    }

    pub(crate) const fn authority_binding(&self) -> AuthorityBinding {
        self.authority_binding
    }

    pub(crate) fn enables(&self, capability: HelperCapability) -> bool {
        self.required_capabilities.contains(&capability)
    }

    pub(crate) fn connect(
        &self,
        deadline: Instant,
    ) -> Result<AuthenticatedHelperTransport, HelperExecutionFailure> {
        AuthenticatedHelperTransport::connect(
            self.owner_uid,
            self.authority_binding,
            &self.service,
            &self.required_capabilities,
            HelperConnectBudget::new(
                RequestSequence::new(1).expect("one is a valid request-sequence floor"),
                deadline,
            ),
        )
        .map_err(|error| HelperExecutionFailure::new(RecoveryAction::Unavailable, error))
    }
}

/// One helper result kept inseparable from the exact typed operation that the
/// authenticated transport submitted. Receipt consumers use this capability
/// instead of accepting a standalone receipt that could be paired with a
/// different same-resource plan by ordinary daemon code.
pub(super) struct AuthenticatedHelperOutcome {
    request: PrivilegedRequest,
    receipt: VerifiedReceipt,
}

impl AuthenticatedHelperOutcome {
    pub(super) const fn operation(&self) -> &PrivilegedOperation {
        self.request.operation()
    }

    pub(super) const fn receipt(&self) -> &VerifiedReceipt {
        &self.receipt
    }

    #[cfg(test)]
    pub(super) const fn from_verified_for_test(
        request: PrivilegedRequest,
        receipt: VerifiedReceipt,
    ) -> Self {
        Self { request, receipt }
    }

    fn into_receipt(self) -> VerifiedReceipt {
        self.receipt
    }
}

impl SharedAuthenticatedHelper {
    pub(crate) fn new(transport: AuthenticatedHelperTransport) -> Self {
        Self {
            authority_binding: transport.authority_binding(),
            enabled_capabilities: transport.enabled_capabilities().to_vec(),
            transport: Mutex::new(transport),
        }
    }

    pub(crate) const fn authority_binding(&self) -> AuthorityBinding {
        self.authority_binding
    }

    pub(crate) fn enables(&self, capability: HelperCapability) -> bool {
        self.enabled_capabilities.contains(&capability)
    }

    pub(crate) fn execute(
        &self,
        operation: PrivilegedOperation,
        descriptors: &[RawFd],
        deadline: Instant,
    ) -> Result<VerifiedReceipt, HelperExecutionFailure> {
        self.execute_bound(operation, descriptors, deadline)
            .map(AuthenticatedHelperOutcome::into_receipt)
    }

    pub(super) fn execute_bound(
        &self,
        operation: PrivilegedOperation,
        descriptors: &[RawFd],
        deadline: Instant,
    ) -> Result<AuthenticatedHelperOutcome, HelperExecutionFailure> {
        let mut transport = self.transport.lock().map_err(|_| {
            HelperExecutionFailure::new(
                RecoveryAction::ReconcileRequired,
                HelperClientError::SessionPoisoned,
            )
        })?;
        transport.execute_bound(operation, descriptors, deadline)
    }
}

fn validate_required_capabilities(
    required_capabilities: &[HelperCapability],
) -> Result<(), HelperClientError> {
    if required_capabilities.is_empty()
        || required_capabilities.len() > crate::helper::protocol::CONTRACT_CAPABILITIES.len()
        || has_duplicates(required_capabilities)
        || !required_capabilities.contains(&HelperCapability::Handshake)
        || !required_capabilities.contains(&HelperCapability::Observe)
    {
        return Err(HelperClientError::CapabilityMismatch);
    }
    Ok(())
}

fn set_deadline(stream: &UnixStream, deadline: Instant) -> Result<(), HelperClientError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(HelperClientError::DeadlineExpired)?;
    let socket_timeout = remaining.max(std::time::Duration::from_millis(1));
    stream
        .set_write_timeout(Some(socket_timeout))
        .map_err(HelperClientError::WriteTimeoutConfiguration)?;
    Ok(())
}

fn read_response(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<HelperResponse, HelperClientError> {
    let mut prefix = [0_u8; 4];
    read_exact_until(stream, &mut prefix, deadline)?;
    let body_len = u32::from_be_bytes(prefix) as usize;
    if body_len > MAX_HELPER_FRAME_BYTES {
        return Err(HelperClientError::OversizedResponse);
    }
    let mut frame = Vec::with_capacity(body_len + prefix.len());
    frame.extend_from_slice(&prefix);
    frame.resize(body_len + prefix.len(), 0);
    read_exact_until(stream, &mut frame[4..], deadline)?;
    decode_response_frame(&frame)
        .map_err(|_| HelperClientError::MalformedResponse)?
        .map(|(response, _)| response)
        .ok_or(HelperClientError::MalformedResponse)
}

fn read_exact_until(
    stream: &mut UnixStream,
    mut output: &mut [u8],
    deadline: Instant,
) -> Result<(), HelperClientError> {
    while !output.is_empty() {
        wait_readable(stream, deadline)?;
        match stream.read(output) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "helper response ended before its bounded frame completed",
                )
                .into());
            }
            Ok(read) => output = &mut output[read..],
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn wait_readable(stream: &UnixStream, deadline: Instant) -> Result<(), HelperClientError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(HelperClientError::DeadlineExpired)?;
        let timeout_millis = i32::try_from(
            ((remaining.as_micros().saturating_add(999)) / 1_000)
                .min(i32::MAX as u128)
                .max(1),
        )
        .expect("timeout was clamped to i32::MAX");
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout_millis) };
        if ready > 0 {
            if Instant::now() >= deadline {
                return Err(HelperClientError::DeadlineExpired);
            }
            return Ok(());
        }
        if ready == 0 {
            return Err(HelperClientError::DeadlineExpired);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(HelperClientError::Io(error));
        }
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

    pub(crate) const fn request(&self) -> &PrivilegedRequest {
        &self.request
    }

    fn into_request(self) -> PrivilegedRequest {
        self.request
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
#[error("helper execution requires {recovery:?}: {source}")]
pub(crate) struct HelperExecutionFailure {
    recovery: RecoveryAction,
    source: HelperClientError,
}

impl HelperExecutionFailure {
    const fn new(recovery: RecoveryAction, source: HelperClientError) -> Self {
        Self { recovery, source }
    }

    pub(crate) const fn recovery(&self) -> RecoveryAction {
        self.recovery
    }

    pub(crate) const fn source(&self) -> &HelperClientError {
        &self.source
    }
}

#[derive(Debug, Error)]
pub(crate) enum HelperClientError {
    #[error("helper is staged but not enrolled")]
    NotEnrolled,
    #[error("helper session does not match daemon authority")]
    AuthorityMismatch,
    #[error("helper policy inventory does not match the negotiated authority or schema")]
    PolicyInventoryMismatch,
    #[error("helper released-resource inventory does not match the negotiated schema")]
    ReleasedInventoryMismatch,
    #[error("helper capability negotiation does not satisfy the bounded request set")]
    CapabilityMismatch,
    #[error("helper schema does not support the requested operation")]
    SchemaMismatch,
    #[error("helper response ID does not match request")]
    ResponseIdMismatch,
    #[error("helper returned an unexpected response variant")]
    UnexpectedResponse,
    #[error("helper returned a malformed receipt")]
    MalformedReceipt,
    #[error("helper returned a malformed response frame")]
    MalformedResponse,
    #[error("helper response exceeds its fixed frame size")]
    OversizedResponse,
    #[error("helper operation deadline elapsed before dispatch")]
    DeadlineExpired,
    #[error("helper request descriptor count does not match its canonical plan")]
    DescriptorCountMismatch,
    #[error("helper request or response sequence is exhausted")]
    SequenceExhausted,
    #[error("helper connection is poisoned until daemon reconciliation")]
    SessionPoisoned,
    #[error("helper request transport failed")]
    RequestTransport,
    #[error("helper transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("helper write deadline could not be applied to its socket: {0}")]
    WriteTimeoutConfiguration(std::io::Error),
    #[error("fixed helper endpoint authentication failed: {0}")]
    Transport(#[from] HelperTransportError),
    #[error("daemon authority could not construct an authenticated request: {0}")]
    Principal(OperationError),
    #[error("helper rejected the request: {0}")]
    Helper(crate::helper::HelperError),
    #[error("helper receipt failed authenticated validation: {0}")]
    Receipt(ReceiptError),
}
