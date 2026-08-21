//! Namespaced identities for resources the helper may own or observe.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::control::AuthorityEpoch;
use crate::vortix_core::profile::{ProfileId, ProtocolKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Tunnel,
    ProcessGroup,
    Firewall,
    Dns,
    Routes,
    RuntimeSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResourceNamespace {
    Profile,
    Topology,
}

/// A resource key derived from stable control identity, never a caller-chosen
/// interface, filesystem path, route handle, DNS object, or firewall table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ResourceTag {
    namespace: ResourceNamespace,
    profile_id: Option<ProfileId>,
    authority_epoch: Option<AuthorityEpoch>,
    generation: u64,
    kind: ResourceKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceTagWire {
    namespace: ResourceNamespace,
    profile_id: Option<ProfileId>,
    authority_epoch: Option<AuthorityEpoch>,
    generation: u64,
    kind: ResourceKind,
}

impl<'de> Deserialize<'de> for ResourceTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ResourceTagWire::deserialize(deserializer)?;
        Self::validate(
            wire.namespace,
            wire.profile_id,
            wire.authority_epoch,
            wire.generation,
            wire.kind,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ResourceTag {
    pub fn tunnel(profile_id: ProfileId, generation: u64) -> Result<Self, ResourceError> {
        Self::profile(profile_id, generation, ResourceKind::Tunnel)
    }

    pub(crate) fn corresponding_tunnel(&self) -> Option<Self> {
        Self::tunnel(self.profile_id()?.clone(), self.generation).ok()
    }

    pub fn profile(
        profile_id: ProfileId,
        generation: u64,
        kind: ResourceKind,
    ) -> Result<Self, ResourceError> {
        Self::validate(
            ResourceNamespace::Profile,
            Some(profile_id),
            None,
            generation,
            kind,
        )
    }

    pub fn topology(
        authority_epoch: AuthorityEpoch,
        generation: u64,
        kind: ResourceKind,
    ) -> Result<Self, ResourceError> {
        Self::validate(
            ResourceNamespace::Topology,
            None,
            Some(authority_epoch),
            generation,
            kind,
        )
    }

    fn validate(
        namespace: ResourceNamespace,
        profile_id: Option<ProfileId>,
        authority_epoch: Option<AuthorityEpoch>,
        generation: u64,
        kind: ResourceKind,
    ) -> Result<Self, ResourceError> {
        if generation == 0 {
            return Err(ResourceError::InvalidGeneration);
        }
        let valid = match namespace {
            ResourceNamespace::Profile => {
                profile_id.is_some()
                    && authority_epoch.is_none()
                    && matches!(
                        kind,
                        ResourceKind::Tunnel
                            | ResourceKind::ProcessGroup
                            | ResourceKind::RuntimeSecret
                    )
            }
            ResourceNamespace::Topology => {
                profile_id.is_none()
                    && authority_epoch.is_some_and(|epoch| epoch.0 != 0)
                    && matches!(
                        kind,
                        ResourceKind::Firewall | ResourceKind::Dns | ResourceKind::Routes
                    )
            }
        };
        if !valid {
            return Err(ResourceError::NamespaceMismatch);
        }
        Ok(Self {
            namespace,
            profile_id,
            authority_epoch,
            generation,
            kind,
        })
    }

    #[must_use]
    pub fn profile_id(&self) -> Option<&ProfileId> {
        self.profile_id.as_ref()
    }

    #[must_use]
    pub const fn authority_epoch(&self) -> Option<AuthorityEpoch> {
        self.authority_epoch
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    #[must_use]
    pub const fn is_tunnel_scoped(&self) -> bool {
        matches!(self.namespace, ResourceNamespace::Profile)
            && matches!(self.kind, ResourceKind::Tunnel | ResourceKind::ProcessGroup)
    }
}

/// An exact resource read-back target with the protocol needed to interpret
/// tunnel-scoped OS evidence. The helper derives every physical name from the
/// resource tag; callers cannot supply an interface, path, PID, or command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceObservationTarget {
    resource: ResourceTag,
    protocol: Option<ProtocolKind>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceObservationTargetWire {
    resource: ResourceTag,
    protocol: Option<ProtocolKind>,
}

impl<'de> Deserialize<'de> for ResourceObservationTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ResourceObservationTargetWire::deserialize(deserializer)?;
        Self::new(wire.resource, wire.protocol).map_err(serde::de::Error::custom)
    }
}

impl ResourceObservationTarget {
    pub fn new(
        resource: ResourceTag,
        protocol: Option<ProtocolKind>,
    ) -> Result<Self, ResourceError> {
        let valid = match resource.kind() {
            ResourceKind::Tunnel => protocol.is_some(),
            ResourceKind::ProcessGroup => protocol == Some(ProtocolKind::OpenVpn),
            ResourceKind::Firewall
            | ResourceKind::Dns
            | ResourceKind::Routes
            | ResourceKind::RuntimeSecret => protocol.is_none(),
        };
        if !valid {
            return Err(ResourceError::ObservationProtocolMismatch);
        }
        Ok(Self { resource, protocol })
    }

    #[must_use]
    pub const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    #[must_use]
    pub const fn protocol(&self) -> Option<ProtocolKind> {
        self.protocol
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ResourceError {
    #[error("resource generation must be non-zero")]
    InvalidGeneration,
    #[error("resource kind does not belong to its namespace")]
    NamespaceMismatch,
    #[error("resource kind and observation protocol do not match")]
    ObservationProtocolMismatch,
}
