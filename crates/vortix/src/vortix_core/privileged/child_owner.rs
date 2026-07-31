//! Foreground protocol-child ownership and Standard-mode custodian contract.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::privileged::operation::HelperEpoch;
use crate::vortix_core::privileged::protocol_plan::ProtocolPlan;
use crate::vortix_core::privileged::resource::{ResourceKind, ResourceTag};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContainmentId([u8; 32]);

impl ContainmentId {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Serializable observation of PID, OS start token, and containment identity.
/// It is evidence to re-observe, never an ownership capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedChildIdentity {
    resource: ResourceTag,
    pid: u32,
    process_start_token: u64,
    containment: ContainmentId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedChildIdentityWire {
    resource: ResourceTag,
    pid: u32,
    process_start_token: u64,
    containment: ContainmentId,
}

impl<'de> Deserialize<'de> for ObservedChildIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ObservedChildIdentityWire::deserialize(deserializer)?;
        Self::new(
            wire.resource,
            wire.pid,
            wire.process_start_token,
            wire.containment,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ObservedChildIdentity {
    pub fn new(
        resource: ResourceTag,
        pid: u32,
        process_start_token: u64,
        containment: ContainmentId,
    ) -> Result<Self, ChildOwnershipError> {
        if resource.kind() != ResourceKind::Tunnel {
            return Err(ChildOwnershipError::NotTunnelScoped);
        }
        if pid == 0 || process_start_token == 0 || containment.0 == [0; 32] {
            return Err(ChildOwnershipError::InvalidIdentity);
        }
        Ok(Self {
            resource,
            pid,
            process_start_token,
            containment,
        })
    }

    #[must_use]
    pub(crate) const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    #[must_use]
    pub(crate) const fn pid(&self) -> u32 {
        self.pid
    }

    #[must_use]
    pub(crate) const fn process_start_token(&self) -> u64 {
        self.process_start_token
    }

    #[must_use]
    pub(crate) const fn containment(&self) -> ContainmentId {
        self.containment
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "owner", content = "scope", rename_all = "snake_case")]
pub enum ChildOwner {
    BackgroundHelper(HelperEpoch),
    StandardCustodian(ResourceTag),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedChild {
    identity: ObservedChildIdentity,
    owner: ChildOwner,
}

/// Non-serializable spawn authority held only by the helper or one scoped
/// Standard-mode custodian. U11 creates this after the OS confirms the child
/// was spawned inside the expected containment.
#[allow(dead_code, reason = "U11 platform/custodian spawn seam")]
pub(crate) struct ChildSpawnAuthority {
    owner: ChildOwner,
}

#[allow(dead_code, reason = "U11 platform/custodian spawn seam")]
impl ChildSpawnAuthority {
    pub(crate) const fn new(owner: ChildOwner) -> Self {
        Self { owner }
    }

    pub(crate) fn claim(
        &self,
        observation: ObservedChildIdentity,
    ) -> Result<OwnedChild, ChildOwnershipError> {
        if let ChildOwner::StandardCustodian(scope) = &self.owner {
            if scope != &observation.resource {
                return Err(ChildOwnershipError::OwnerScopeMismatch);
            }
        }
        Ok(OwnedChild {
            identity: observation,
            owner: self.owner.clone(),
        })
    }
}

impl OwnedChild {
    #[must_use]
    pub(crate) const fn identity(&self) -> &ObservedChildIdentity {
        &self.identity
    }

    #[must_use]
    pub fn after(&self, event: ChildExit) -> ChildOwnershipState {
        match event {
            ChildExit::NormalExit => ChildOwnershipState::Reaped,
            ChildExit::DaemonLost => ChildOwnershipState::Owned(self.owner.clone()),
            ChildExit::CustodianLost | ChildExit::HelperLost | ChildExit::OsServiceRestart => {
                ChildOwnershipState::ContainmentRequired(self.identity.containment)
            }
        }
    }
}

/// Ownership-affecting lifecycle events. Daemon loss is not helper loss: an
/// extant helper remains accountable for its child while the daemon recovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    NormalExit,
    CustodianLost,
    HelperLost,
    DaemonLost,
    OsServiceRestart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildOwnershipState {
    Owned(ChildOwner),
    Reaped,
    ContainmentRequired(ContainmentId),
    ObservationOnly,
}

impl ChildOwnershipState {
    #[must_use]
    pub const fn is_owned(&self) -> bool {
        matches!(self, Self::Owned(_))
    }

    #[must_use]
    pub const fn is_reaped(&self) -> bool {
        matches!(self, Self::Reaped)
    }

    #[must_use]
    pub const fn requires_containment(&self) -> bool {
        matches!(self, Self::ContainmentRequired(_))
    }

    #[must_use]
    pub const fn is_observation_only(&self) -> bool {
        matches!(self, Self::ObservationOnly)
    }
}

/// Scanner evidence cannot manufacture lifecycle ownership after restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildObservation {
    identity: ObservedChildIdentity,
}

impl ChildObservation {
    #[must_use]
    pub fn from_identity(identity: &ObservedChildIdentity) -> Self {
        Self {
            identity: identity.clone(),
        }
    }

    pub fn claim_after_restart(
        &self,
        _owner: ChildOwner,
    ) -> Result<OwnedChild, ChildOwnershipError> {
        Err(ChildOwnershipError::ObservationIsNotOwnership)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CustodianActionKind {
    Start,
    Status,
    Stop,
}

/// Complete Standard-mode custodian API. It can start one canonical tunnel
/// plan or inspect/stop one exact tunnel resource; global policy and desired
/// state do not exist in this vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustodianAction {
    action: CustodianActionKind,
    plan: Option<ProtocolPlan>,
    resource: Option<ResourceTag>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodianActionWire {
    action: CustodianActionKind,
    plan: Option<ProtocolPlan>,
    resource: Option<ResourceTag>,
}

impl<'de> Deserialize<'de> for CustodianAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CustodianActionWire::deserialize(deserializer)?;
        Self::validate(wire.action, wire.plan, wire.resource).map_err(serde::de::Error::custom)
    }
}

impl CustodianAction {
    pub fn start(plan: ProtocolPlan) -> Result<Self, ChildOwnershipError> {
        Self::validate(CustodianActionKind::Start, Some(plan), None)
    }

    pub fn status(resource: ResourceTag) -> Result<Self, ChildOwnershipError> {
        Self::validate(CustodianActionKind::Status, None, Some(resource))
    }

    pub fn stop(resource: ResourceTag) -> Result<Self, ChildOwnershipError> {
        Self::validate(CustodianActionKind::Stop, None, Some(resource))
    }

    fn validate(
        action: CustodianActionKind,
        plan: Option<ProtocolPlan>,
        resource: Option<ResourceTag>,
    ) -> Result<Self, ChildOwnershipError> {
        let valid = match action {
            CustodianActionKind::Start => plan.is_some() && resource.is_none(),
            CustodianActionKind::Status | CustodianActionKind::Stop => {
                plan.is_none()
                    && resource
                        .as_ref()
                        .is_some_and(|tag| tag.kind() == ResourceKind::Tunnel)
            }
        };
        if !valid {
            return Err(ChildOwnershipError::NotTunnelScoped);
        }
        Ok(Self {
            action,
            plan,
            resource,
        })
    }

    fn target(&self) -> Result<ResourceTag, ChildOwnershipError> {
        match self.action {
            CustodianActionKind::Start => {
                let plan = self
                    .plan
                    .as_ref()
                    .ok_or(ChildOwnershipError::NotTunnelScoped)?;
                ResourceTag::tunnel(plan.profile_id().clone(), plan.generation())
                    .map_err(|_| ChildOwnershipError::NotTunnelScoped)
            }
            CustodianActionKind::Status | CustodianActionKind::Stop => self
                .resource
                .clone()
                .ok_or(ChildOwnershipError::NotTunnelScoped),
        }
    }
}

/// Authorization boundary for one on-demand Standard-mode custodian. The
/// binding includes stable profile identity and attempt generation, so an
/// action for another profile or a later attempt is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardCustodianContract {
    tunnel: ResourceTag,
}

impl StandardCustodianContract {
    pub fn new(tunnel: ResourceTag) -> Result<Self, ChildOwnershipError> {
        if tunnel.kind() != ResourceKind::Tunnel {
            return Err(ChildOwnershipError::NotTunnelScoped);
        }
        Ok(Self { tunnel })
    }

    pub fn authorize(&self, action: &CustodianAction) -> Result<(), ChildOwnershipError> {
        if action.target()? == self.tunnel {
            Ok(())
        } else {
            Err(ChildOwnershipError::OwnerScopeMismatch)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ChildOwnershipError {
    #[error("child identity is invalid")]
    InvalidIdentity,
    #[error("operation is not scoped to one tunnel resource")]
    NotTunnelScoped,
    #[error("custodian scope does not match the child resource")]
    OwnerScopeMismatch,
    #[error("a process observation is not an ownership capability")]
    ObservationIsNotOwnership,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::profile::ProfileId;

    fn tunnel(byte: char, generation: u64) -> ResourceTag {
        ResourceTag::tunnel(
            ProfileId::parse(byte.to_string().repeat(ProfileId::HEX_LEN)).unwrap(),
            generation,
        )
        .unwrap()
    }

    #[test]
    fn decoded_observation_cannot_mint_ownership_and_foreign_scope_rejects() {
        let observation =
            ObservedChildIdentity::new(tunnel('a', 1), 42, 99, ContainmentId::new([1; 32]))
                .unwrap();
        let decoded: ObservedChildIdentity =
            serde_json::from_value(serde_json::to_value(&observation).unwrap()).unwrap();
        let scanner = ChildObservation::from_identity(&decoded);
        assert_eq!(
            scanner.claim_after_restart(ChildOwner::BackgroundHelper(HelperEpoch::new(1).unwrap())),
            Err(ChildOwnershipError::ObservationIsNotOwnership)
        );

        let foreign = ChildSpawnAuthority::new(ChildOwner::StandardCustodian(tunnel('b', 1)));
        assert_eq!(
            foreign.claim(decoded),
            Err(ChildOwnershipError::OwnerScopeMismatch)
        );
    }
}
