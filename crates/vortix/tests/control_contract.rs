//! Frozen public control-surface inventory for the local-to-remote migration.

#[path = "support/control_scenarios.rs"]
mod control_scenarios;

use std::collections::BTreeSet;

use control_scenarios::{
    ContractArea, BACKGROUND_CAPABILITY_COPY, BOOT_INELIGIBLE_CREDENTIALS, CONTROL_SCENARIOS,
    DIAGNOSTIC_FALLBACK_LABELS, ERROR_CONTRACTS, LIFECYCLE_EVENT_HOOKS, MODE_STATUS_LABELS,
    RECOVERY_ACTIONS, TRUST_BOUNDARY_COPY,
};
use vortix::cli::output::ExitCode;

#[test]
fn shared_inventory_covers_every_control_area() {
    let areas: BTreeSet<String> = CONTROL_SCENARIOS
        .iter()
        .map(|scenario| format!("{:?}", scenario.area))
        .collect();
    for required in [
        ContractArea::Lifecycle,
        ContractArea::Status,
        ContractArea::KillSwitch,
        ContractArea::Profile,
        ContractArea::Audit,
        ContractArea::Interactive,
    ] {
        assert!(areas.contains(&format!("{required:?}")));
    }

    for scenario in CONTROL_SCENARIOS {
        assert!(!scenario.id.is_empty());
        assert_eq!(scenario.argv.first(), Some(&"vortix"));
    }
}

#[test]
fn future_background_vocabulary_is_pinned_before_ui_work_starts() {
    assert_eq!(MODE_STATUS_LABELS.len(), 6);
    assert!(MODE_STATUS_LABELS.contains(&"Standard mode: Active"));
    assert!(MODE_STATUS_LABELS.contains(&"Background mode: Recovery required"));
    assert_eq!(BACKGROUND_CAPABILITY_COPY.len(), 6);
    assert_eq!(TRUST_BOUNDARY_COPY.len(), 2);
    assert_eq!(RECOVERY_ACTIONS.len(), 4);
    assert_eq!(
        DIAGNOSTIC_FALLBACK_LABELS,
        ["stale", "unauthenticated", "advisory-only"]
    );
    assert_eq!(LIFECYCLE_EVENT_HOOKS.len(), 6);
    assert_eq!(BOOT_INELIGIBLE_CREDENTIALS.len(), 4);
}

#[test]
fn fixture_execution_is_parse_only_and_cannot_touch_real_state() {
    for scenario in CONTROL_SCENARIOS {
        assert!(
            scenario
                .argv
                .iter()
                .all(|arg| !arg.starts_with("--config-dir=")),
            "{} must not point at a real config directory",
            scenario.id
        );
    }
}

#[test]
fn semantic_error_exit_codes_are_frozen() {
    let pairs = ERROR_CONTRACTS.to_vec();
    assert_eq!(
        pairs,
        [
            ("success", 0),
            ("general_error", 1),
            ("permission_denied", 2),
            ("not_found", 3),
            ("state_conflict", 4),
            ("dependency_missing", 5),
            ("timeout", 6),
        ]
    );
    assert_eq!(
        [
            ExitCode::Success.code(),
            ExitCode::GeneralError.code(),
            ExitCode::PermissionDenied.code(),
            ExitCode::NotFound.code(),
            ExitCode::StateConflict.code(),
            ExitCode::DependencyMissing.code(),
            ExitCode::Timeout.code(),
        ],
        [0, 1, 2, 3, 4, 5, 6]
    );
}
