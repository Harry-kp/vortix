//! Crash-safe user-owned canonical control intent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_config::profile_store::write_atomic;
use crate::vortix_core::control::{
    BootConnection, ControlPersistenceConfig, ControlStateStore, ControlStateStoreError,
    DesiredState, DurableControlState, OperationId, OperationIntent, OperationRecord,
    OperationResult, OperationStatus, PersistedTombstone, RecoveredControlState,
    RequestedResources, RetentionMetadata,
};
use crate::vortix_core::profile::ProfileId;

const STATE_SCHEMA_VERSION: u16 = 1;
const STATE_FILE: &str = "control-state.json";
const PREVIOUS_STATE_FILE: &str = "control-state.previous.json";
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const MAX_PROFILES: usize = 512;
const MAX_OPERATIONS: usize = 512;
const MAX_ROUTES_PER_PROFILE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedControlState {
    schema_version: u16,
    boot_id: String,
    pub(crate) desired: DesiredState,
    pub(crate) operations: BTreeMap<OperationId, OperationRecord>,
    pub(crate) boot_connections: BTreeMap<ProfileId, BootConnection>,
    pub(crate) requested_resources: BTreeMap<ProfileId, RequestedResources>,
    pub(crate) tombstones: BTreeMap<ProfileId, PersistedTombstone>,
    pub(crate) retention: RetentionMetadata,
    pub(crate) reconciliation_required: bool,
}

impl PersistedControlState {
    pub(crate) fn new(boot_id: impl Into<String>, desired: DesiredState) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            boot_id: boot_id.into(),
            desired,
            operations: BTreeMap::new(),
            boot_connections: BTreeMap::new(),
            requested_resources: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            retention: RetentionMetadata::default(),
            reconciliation_required: true,
        }
    }

    fn validate(&self) -> Result<(), ControlStateError> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(ControlStateError::UnsupportedSchema(self.schema_version));
        }
        if self.boot_id.is_empty() || self.boot_id.len() > 128 {
            return Err(ControlStateError::Invalid(
                "boot ID must contain 1..=128 bytes",
            ));
        }
        if self.desired.tunnels.len() > MAX_PROFILES
            || self.boot_connections.len() > MAX_PROFILES
            || self.requested_resources.len() > MAX_PROFILES
            || self.tombstones.len() > MAX_PROFILES
            || self.operations.len() > MAX_OPERATIONS
        {
            return Err(ControlStateError::Capacity);
        }
        if !self.desired.policy_digest.is_valid()
            || self.requested_resources.values().any(|resources| {
                resources.routes.len() > MAX_ROUTES_PER_PROFILE
                    || !resources.dns_digest.is_valid()
                    || !resources.firewall_digest.is_valid()
                    || resources
                        .routes
                        .iter()
                        .any(|route| route.parse::<crate::vortix_core::Cidr>().is_err())
            })
            || self.tombstones.values().any(|tombstone| {
                !tombstone.policy_digest.is_valid()
                    || tombstone.authority_epoch != self.desired.authority_epoch
                    || tombstone.operation_id.authority_epoch() != Some(tombstone.authority_epoch)
            })
            || self.operations.iter().any(|(id, operation)| {
                id != &operation.id
                    || id.authority_epoch() != Some(operation.authority_epoch)
                    || operation.client_id.authority_epoch() != Some(operation.authority_epoch)
                    || operation.authority_epoch != self.desired.authority_epoch
                    || id.sequence() == Some(u64::MAX)
                    || operation.client_id.sequence() == Some(u64::MAX)
                    || !operation.idempotency_key.is_valid()
                    || !operation.command_digest.is_valid()
                    || operation.desired_generation > self.desired.generation
                    || operation.admitted_at_millis > operation.deadline_millis
                    || matches!(
                        &operation.intent,
                        OperationIntent::DesiredSubset { tunnels, .. }
                            if tunnels.len() > MAX_PROFILES
                    )
                    || !operation_result_matches_status(operation)
            })
        {
            return Err(ControlStateError::Invalid("invalid persisted control fact"));
        }
        Ok(())
    }
}

fn operation_result_matches_status(operation: &OperationRecord) -> bool {
    matches!(
        (operation.status, operation.result),
        (
            OperationStatus::Admitted | OperationStatus::WaitingForObservation,
            None
        ) | (
            OperationStatus::Succeeded,
            Some(OperationResult::ObservedConvergence)
        ) | (OperationStatus::Failed, Some(OperationResult::Failed(_)))
            | (OperationStatus::Cancelled, Some(OperationResult::Cancelled))
            | (OperationStatus::Expired, Some(OperationResult::Expired))
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoadedControlState {
    Missing,
    Current(PersistedControlState),
    RecoveredPrevious(PersistedControlState),
    FutureSchema(u16),
}

#[derive(Debug, Clone)]
pub struct FsControlStateStore {
    directory: PathBuf,
}

impl FsControlStateStore {
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Build the canonical persistence configuration using the current OS
    /// boot identity and this user-owned state directory.
    pub fn persistence_config(
        directory: impl Into<PathBuf>,
    ) -> Result<ControlPersistenceConfig, ControlStateStoreError> {
        let boot_id = crate::utils::boot_identity().ok_or_else(|| {
            ControlStateStoreError::Invalid("OS boot identity is unavailable".to_string())
        })?;
        Ok(ControlPersistenceConfig::new(
            boot_id,
            Arc::new(Self::new(directory)),
        ))
    }

    fn load_state(&self) -> Result<LoadedControlState, ControlStateError> {
        if !validate_directory(&self.directory)? {
            return Ok(LoadedControlState::Missing);
        }
        let current_path = self.directory.join(STATE_FILE);
        match read_state(&current_path) {
            Ok(Some(DecodedState::Current(state))) => Ok(LoadedControlState::Current(*state)),
            Ok(Some(DecodedState::Future(version))) => {
                Ok(LoadedControlState::FutureSchema(version))
            }
            Ok(None) => self.load_previous(false),
            Err(ControlStateError::Corrupt) => self.load_previous(true),
            Err(error) => Err(error),
        }
    }

    fn load_previous(
        &self,
        current_was_corrupt: bool,
    ) -> Result<LoadedControlState, ControlStateError> {
        let previous_path = self.directory.join(PREVIOUS_STATE_FILE);
        match read_state(&previous_path)? {
            Some(DecodedState::Current(state)) => Ok(LoadedControlState::RecoveredPrevious(*state)),
            Some(DecodedState::Future(version)) => Ok(LoadedControlState::FutureSchema(version)),
            None if current_was_corrupt => Err(ControlStateError::Corrupt),
            None => Ok(LoadedControlState::Missing),
        }
    }

    fn save_state(&self, state: &PersistedControlState) -> Result<(), ControlStateError> {
        ensure_directory(&self.directory)?;
        state.validate()?;
        let body = serde_json::to_vec_pretty(state)?;
        if body.len() as u64 > MAX_STATE_BYTES {
            return Err(ControlStateError::Capacity);
        }
        if !matches!(decode_state(&body)?, DecodedState::Current(_)) {
            return Err(ControlStateError::Corrupt);
        }
        let current_path = self.directory.join(STATE_FILE);
        if let Some(bytes) = read_bytes(&current_path)? {
            match decode_state(&bytes) {
                Ok(DecodedState::Current(_)) => {
                    write_atomic(&self.directory.join(PREVIOUS_STATE_FILE), &bytes)?;
                }
                Ok(DecodedState::Future(version)) => {
                    return Err(ControlStateError::UnsupportedSchema(version));
                }
                Err(ControlStateError::Corrupt) => {}
                Err(error) => return Err(error),
            }
        }
        write_atomic(&current_path, &body)?;
        Ok(())
    }
}

fn ensure_directory(path: &Path) -> Result<(), ControlStateError> {
    if !validate_directory(path)? {
        std::fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    validate_directory(path)?
        .then_some(())
        .ok_or(ControlStateError::UnsafeFile)
}

fn validate_directory(path: &Path) -> Result<bool, ControlStateError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControlStateError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let effective_uid = crate::utils::effective_user_group_ids().0;
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o022 != 0 {
            return Err(ControlStateError::UnsafeFile);
        }
    }
    Ok(true)
}

impl ControlStateStore for FsControlStateStore {
    fn load(
        &self,
        current_boot_id: &str,
    ) -> Result<Option<RecoveredControlState>, ControlStateStoreError> {
        match self.load_state().map_err(ControlStateStoreError::from)? {
            LoadedControlState::Missing => Ok(None),
            LoadedControlState::Current(state) | LoadedControlState::RecoveredPrevious(state) => {
                Ok(Some(recovered_state(state, current_boot_id)))
            }
            LoadedControlState::FutureSchema(version) => {
                Err(ControlStateStoreError::UnsupportedSchema(version))
            }
        }
    }

    fn save(
        &self,
        current_boot_id: &str,
        durable: &DurableControlState,
    ) -> Result<(), ControlStateStoreError> {
        let mut state = PersistedControlState::new(current_boot_id, durable.desired.clone());
        state.operations.clone_from(&durable.operations);
        state.boot_connections.clone_from(&durable.boot_connections);
        state
            .requested_resources
            .clone_from(&durable.requested_resources);
        state.tombstones.clone_from(&durable.tombstones);
        state.retention = durable.retention;
        state.reconciliation_required = durable.reconciliation_required;
        self.save_state(&state)
            .map_err(ControlStateStoreError::from)
    }
}

fn recovered_state(state: PersistedControlState, current_boot_id: &str) -> RecoveredControlState {
    let same_boot = state.boot_id == current_boot_id;
    RecoveredControlState {
        state: DurableControlState {
            desired: state.desired,
            operations: state.operations,
            boot_connections: state.boot_connections,
            requested_resources: state.requested_resources,
            tombstones: state.tombstones,
            retention: state.retention,
            reconciliation_required: true,
        },
        same_boot,
    }
}

enum DecodedState {
    Current(Box<PersistedControlState>),
    Future(u16),
}

fn read_state(path: &Path) -> Result<Option<DecodedState>, ControlStateError> {
    read_bytes(path)?
        .map(|bytes| decode_state(&bytes))
        .transpose()
}

fn decode_state(bytes: &[u8]) -> Result<DecodedState, ControlStateError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ControlStateError::Corrupt)?;
    let version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(ControlStateError::Corrupt)?;
    if version > STATE_SCHEMA_VERSION {
        return Ok(DecodedState::Future(version));
    }
    let state: PersistedControlState =
        serde_json::from_value(value).map_err(|_| ControlStateError::Corrupt)?;
    state.validate()?;
    Ok(DecodedState::Current(Box::new(state)))
}

fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>, ControlStateError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ControlStateError::UnsafeFile);
    }
    if metadata.len() > MAX_STATE_BYTES {
        return Err(ControlStateError::Capacity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let effective_uid = crate::utils::effective_user_group_ids().0;
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ControlStateError::UnsafeFile);
        }
    }
    Ok(Some(std::fs::read(path)?))
}

#[derive(Debug, Error)]
pub(crate) enum ControlStateError {
    #[error("control state has unsupported schema version {0}")]
    UnsupportedSchema(u16),
    #[error("control state exceeds its fixed capacity")]
    Capacity,
    #[error("control state is invalid: {0}")]
    Invalid(&'static str),
    #[error("control state is corrupt")]
    Corrupt,
    #[error("control state path is not a private owner-controlled regular file")]
    UnsafeFile,
    #[error("control state I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("control state serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<ControlStateError> for ControlStateStoreError {
    fn from(error: ControlStateError) -> Self {
        match error {
            ControlStateError::UnsupportedSchema(version) => Self::UnsupportedSchema(version),
            ControlStateError::Capacity => Self::Capacity,
            ControlStateError::Invalid(reason) => Self::Invalid(reason.to_owned()),
            ControlStateError::Corrupt => Self::Corrupt,
            ControlStateError::UnsafeFile => Self::UnsafeFile,
            ControlStateError::Io(error) => Self::Io(error.to_string()),
            ControlStateError::Json(error) => Self::Invalid(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::control::{
        AdmissionError, AuthorityEpoch, BootEligibility, ClientId, CommandRequest,
        ControlPersistenceConfig, ControlService, ControlServiceConfig, IdempotencyKey,
        PolicyDigest, ProtectionStatus, ReadinessError, RequestedTunnelState, UserCommand,
    };
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;

    fn profile(byte: char) -> ProfileId {
        ProfileId::parse(byte.to_string().repeat(ProfileId::HEX_LEN)).unwrap()
    }

    fn state(boot_id: &str) -> PersistedControlState {
        let mut desired = DesiredState {
            authority_epoch: AuthorityEpoch(7),
            policy_digest: PolicyDigest("policy".into()),
            ..DesiredState::default()
        };
        desired
            .tunnels
            .insert(profile('a'), RequestedTunnelState::Connected);
        PersistedControlState::new(boot_id, desired)
    }

    fn operation(epoch: u64, sequence: u64, client_sequence: u64) -> OperationRecord {
        let authority_epoch = AuthorityEpoch(epoch);
        let id = OperationId::from_parts(authority_epoch, sequence);
        OperationRecord {
            id,
            idempotency_key: IdempotencyKey::new("persisted-operation"),
            client_id: ClientId::from_parts(authority_epoch, client_sequence),
            command_digest: PolicyDigest("command".into()),
            authority_epoch,
            desired_generation: 0,
            admitted_at_millis: 0,
            deadline_millis: 1,
            intent: OperationIntent::GenerationScoped,
            status: OperationStatus::WaitingForObservation,
            result: None,
        }
    }

    #[test]
    fn operation_intent_defaults_to_generation_scope_for_older_state() {
        let mut persisted = state("legacy-intent");
        let operation = operation(7, 1, 1);
        persisted.operations.insert(operation.id.clone(), operation);
        let mut encoded = serde_json::to_value(&persisted).unwrap();
        encoded["operations"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .for_each(|operation| {
                operation.as_object_mut().unwrap().remove("intent");
            });

        let decoded: PersistedControlState = serde_json::from_value(encoded).unwrap();
        assert!(matches!(
            decoded.operations.values().next().unwrap().intent,
            OperationIntent::GenerationScoped
        ));
        decoded.validate().unwrap();
    }

    #[test]
    fn operation_intent_persists_canonical_kill_switch_slug() {
        let mut persisted = state("intent-slug");
        let mut operation = operation(7, 1, 1);
        operation.intent = OperationIntent::DesiredSubset {
            tunnels: BTreeMap::new(),
            kill_switch: Some(crate::vortix_core::state::killswitch::KillSwitchMode::Auto),
        };
        persisted.operations.insert(operation.id.clone(), operation);

        let encoded = serde_json::to_value(&persisted).unwrap();
        let intent = &encoded["operations"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["intent"];
        assert_eq!(intent["kill_switch"], "block-on-drop");
        let decoded: PersistedControlState = serde_json::from_value(encoded).unwrap();
        decoded.validate().unwrap();
    }

    #[test]
    fn save_is_private_atomic_and_retains_previous_generation() {
        let directory = tempdir().unwrap();
        let state_directory = directory.path().join("control");
        let store = FsControlStateStore::new(&state_directory);
        let first = state("boot-a");
        store.save_state(&first).unwrap();
        let mut second = first.clone();
        second.desired.generation = 2;
        store.save_state(&second).unwrap();

        assert_eq!(
            store.load_state().unwrap(),
            LoadedControlState::Current(second)
        );
        let previous = read_state(&state_directory.join(PREVIOUS_STATE_FILE)).unwrap();
        assert!(matches!(previous, Some(DecodedState::Current(state)) if *state == first));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(state_directory.join(STATE_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let directory_mode = std::fs::metadata(&state_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(directory_mode, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn writable_or_symlinked_state_directory_is_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempdir().unwrap();
        let writable = directory.path().join("writable");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            FsControlStateStore::new(&writable).load_state(),
            Err(ControlStateError::UnsafeFile)
        ));

        let linked = directory.path().join("linked");
        symlink(directory.path(), &linked).unwrap();
        assert!(matches!(
            FsControlStateStore::new(linked).load_state(),
            Err(ControlStateError::UnsafeFile)
        ));
    }

    #[test]
    fn corrupt_current_recovers_previous_without_claiming_current() {
        let directory = tempdir().unwrap();
        let store = FsControlStateStore::new(directory.path());
        let first = state("boot-a");
        store.save_state(&first).unwrap();
        let mut second = first.clone();
        second.desired.generation = 2;
        store.save_state(&second).unwrap();
        std::fs::write(directory.path().join(STATE_FILE), b"{").unwrap();

        assert_eq!(
            store.load_state().unwrap(),
            LoadedControlState::RecoveredPrevious(first)
        );
    }

    #[test]
    fn future_schema_is_preserved_and_never_overwritten() {
        let directory = tempdir().unwrap();
        let store = FsControlStateStore::new(directory.path());
        let path = directory.path().join(STATE_FILE);
        write_atomic(&path, br#"{"schema_version":99}"#).unwrap();

        assert!(matches!(
            store.load_state().unwrap(),
            LoadedControlState::FutureSchema(99)
        ));
        assert!(matches!(
            store.save_state(&state("boot-a")),
            Err(ControlStateError::UnsupportedSchema(99))
        ));
        assert_eq!(std::fs::read(path).unwrap(), br#"{"schema_version":99}"#);
    }

    #[test]
    fn reboot_filters_connected_intent_by_explicit_noninteractive_eligibility() {
        let mut persisted = state("old-boot");
        let interactive = profile('b');
        let disabled = profile('c');
        let unsupported = profile('d');
        persisted
            .desired
            .tunnels
            .insert(interactive.clone(), RequestedTunnelState::Connected);
        persisted
            .desired
            .tunnels
            .insert(disabled.clone(), RequestedTunnelState::Connected);
        persisted
            .desired
            .tunnels
            .insert(unsupported.clone(), RequestedTunnelState::Connected);
        persisted.boot_connections.insert(
            profile('a'),
            BootConnection {
                enabled: true,
                eligibility: BootEligibility::Eligible,
            },
        );
        persisted.boot_connections.insert(
            interactive.clone(),
            BootConnection {
                enabled: true,
                eligibility: BootEligibility::InteractiveCredentials,
            },
        );
        persisted.boot_connections.insert(
            disabled.clone(),
            BootConnection {
                enabled: false,
                eligibility: BootEligibility::Eligible,
            },
        );
        persisted.boot_connections.insert(
            unsupported.clone(),
            BootConnection {
                enabled: true,
                eligibility: BootEligibility::UnsupportedKeyProvider,
            },
        );

        let same_boot = recovered_state(persisted.clone(), "old-boot");
        assert!(same_boot.same_boot);
        assert_eq!(same_boot.state.desired, persisted.desired);
        let mut rebooted = recovered_state(persisted, "new-boot");
        assert!(!rebooted.same_boot);
        rebooted.state.prepare_for_reboot();
        assert_eq!(
            rebooted.state.desired.tunnels.get(&profile('a')),
            Some(&RequestedTunnelState::Connected)
        );
        assert_eq!(
            rebooted.state.desired.tunnels.get(&interactive),
            Some(&RequestedTunnelState::Disconnected)
        );
        assert_eq!(
            rebooted.state.desired.tunnels.get(&disabled),
            Some(&RequestedTunnelState::Disconnected)
        );
        assert_eq!(
            rebooted.state.desired.tunnels.get(&unsupported),
            Some(&RequestedTunnelState::Disconnected)
        );
    }

    #[test]
    fn persisted_operations_share_authority_and_leave_identifier_capacity() {
        let mut foreign = state("boot-a");
        let foreign_operation = operation(8, 1, 1);
        foreign
            .operations
            .insert(foreign_operation.id.clone(), foreign_operation);
        assert!(matches!(
            foreign.validate(),
            Err(ControlStateError::Invalid("invalid persisted control fact"))
        ));

        for exhausted in [operation(7, u64::MAX, 1), operation(7, 1, u64::MAX)] {
            let mut persisted = state("boot-a");
            persisted.operations.insert(exhausted.id.clone(), exhausted);
            assert!(matches!(
                persisted.validate(),
                Err(ControlStateError::Invalid("invalid persisted control fact"))
            ));
        }
    }

    #[tokio::test]
    async fn real_store_forces_scan_before_admission_and_recovers_intent() {
        let directory = tempdir().unwrap();
        let store = Arc::new(FsControlStateStore::new(directory.path()));
        let profile_id = profile('a');
        let config = ControlServiceConfig {
            authority_epoch: AuthorityEpoch(7),
            known_profiles: BTreeSet::from([profile_id.clone()]),
            persistence: Some(ControlPersistenceConfig::new("boot-a", store.clone())),
            ..ControlServiceConfig::default()
        };

        let first_operation = {
            let service = ControlService::start(config.clone());
            let client = service.client();
            assert_eq!(
                client
                    .submit(CommandRequest {
                        command: UserCommand::Connect {
                            profile_id: profile_id.clone(),
                        },
                        idempotency_key: IdempotencyKey::new("before-scan"),
                        deadline: client.deadline_after(Duration::from_secs(5)),
                    })
                    .await
                    .unwrap_err(),
                AdmissionError::NotReady
            );
            service
                .completer()
                .set_readiness(AuthorityEpoch(7), true, true)
                .await
                .unwrap();
            let admitted = client
                .submit(CommandRequest {
                    command: UserCommand::Connect {
                        profile_id: profile_id.clone(),
                    },
                    idempotency_key: IdempotencyKey::new("connect"),
                    deadline: client.deadline_after(Duration::from_secs(5)),
                })
                .await
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            while !client
                .snapshot()
                .operations
                .contains_key(&admitted.operation_id)
            {
                assert!(tokio::time::Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
            assert_eq!(
                client.snapshot().desired.tunnels.get(&profile_id),
                Some(&RequestedTunnelState::Connected)
            );
            admitted.operation_id
        };

        tokio::time::sleep(Duration::from_millis(20)).await;
        let restarted = ControlService::start(config);
        let snapshot = restarted.client().snapshot();
        assert!(!snapshot.readiness.reconciliation_complete);
        assert!(snapshot.observed.tunnels.is_empty());
        assert!(snapshot.observed.evidence.is_none());
        assert_eq!(snapshot.effective.protection, ProtectionStatus::Unknown);
        assert_eq!(
            snapshot.desired.tunnels.get(&profile_id),
            Some(&RequestedTunnelState::Connected)
        );
        assert!(snapshot.operations.contains_key(&first_operation));
    }

    #[tokio::test]
    async fn authority_mismatch_is_not_restored_or_rewritten() {
        let directory = tempdir().unwrap();
        let store = Arc::new(FsControlStateStore::new(directory.path()));
        let persisted = state("boot-a");
        store.save_state(&persisted).unwrap();
        let original = std::fs::read(directory.path().join(STATE_FILE)).unwrap();

        let service = ControlService::start(ControlServiceConfig {
            authority_epoch: AuthorityEpoch(8),
            persistence: Some(ControlPersistenceConfig::new("boot-a", store)),
            ..ControlServiceConfig::default()
        });
        let snapshot = service.client().snapshot();
        assert_eq!(snapshot.desired.authority_epoch, AuthorityEpoch(8));
        assert!(snapshot.desired.tunnels.is_empty());
        assert!(!snapshot.readiness.authority_verified);
        assert_eq!(
            service
                .completer()
                .set_readiness(AuthorityEpoch(8), true, true)
                .await
                .unwrap_err(),
            ReadinessError::Persistence
        );
        assert_eq!(
            std::fs::read(directory.path().join(STATE_FILE)).unwrap(),
            original
        );
    }
}
