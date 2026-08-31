#![allow(dead_code)]

//! Shared, side-effect-free contract inventory for local and remote adapters.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputSurface {
    Human,
    Json,
    Quiet,
    JsonWatch,
    Tui,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractArea {
    Lifecycle,
    Status,
    KillSwitch,
    Profile,
    Audit,
    Interactive,
}

#[derive(Clone, Copy, Debug)]
pub struct ControlScenario {
    pub id: &'static str,
    pub area: ContractArea,
    pub argv: &'static [&'static str],
    pub command: &'static str,
    pub output: OutputSurface,
}

const fn scenario(
    id: &'static str,
    area: ContractArea,
    argv: &'static [&'static str],
    command: &'static str,
    output: OutputSurface,
) -> ControlScenario {
    ControlScenario {
        id,
        area,
        argv,
        command,
        output,
    }
}

pub const CONTROL_SCENARIOS: &[ControlScenario] = &[
    scenario(
        "up-human-default-timeout",
        ContractArea::Lifecycle,
        &["vortix", "up", "corp"],
        "up",
        OutputSurface::Human,
    ),
    scenario(
        "up-json-explicit-timeout",
        ContractArea::Lifecycle,
        &["vortix", "--json", "up", "corp", "--timeout", "60"],
        "up",
        OutputSurface::Json,
    ),
    scenario(
        "up-conflict-bypass",
        ContractArea::Lifecycle,
        &["vortix", "up", "corp", "--yes"],
        "up",
        OutputSurface::Human,
    ),
    scenario(
        "down-one-quiet",
        ContractArea::Lifecycle,
        &["vortix", "--quiet", "down", "corp"],
        "down",
        OutputSurface::Quiet,
    ),
    scenario(
        "down-all",
        ContractArea::Lifecycle,
        &["vortix", "down", "--all"],
        "down",
        OutputSurface::Human,
    ),
    scenario(
        "reconnect-all",
        ContractArea::Lifecycle,
        &["vortix", "reconnect"],
        "reconnect",
        OutputSurface::Human,
    ),
    scenario(
        "status-human",
        ContractArea::Status,
        &["vortix", "status"],
        "status",
        OutputSurface::Human,
    ),
    scenario(
        "status-json-watch",
        ContractArea::Status,
        &["vortix", "--json", "status", "--watch"],
        "status",
        OutputSurface::JsonWatch,
    ),
    scenario(
        "killswitch-show-json",
        ContractArea::KillSwitch,
        &["vortix", "--json", "killswitch"],
        "killswitch",
        OutputSurface::Json,
    ),
    scenario(
        "killswitch-vpn-only",
        ContractArea::KillSwitch,
        &["vortix", "killswitch", "vpn-only"],
        "killswitch",
        OutputSurface::Human,
    ),
    scenario(
        "killswitch-block-on-drop",
        ContractArea::KillSwitch,
        &["vortix", "killswitch", "block-on-drop"],
        "killswitch",
        OutputSurface::Human,
    ),
    scenario(
        "killswitch-off",
        ContractArea::KillSwitch,
        &["vortix", "killswitch", "off"],
        "killswitch",
        OutputSurface::Human,
    ),
    scenario(
        "killswitch-release",
        ContractArea::KillSwitch,
        &["vortix", "release-kill-switch"],
        "release-killswitch",
        OutputSurface::Human,
    ),
    scenario(
        "profile-list",
        ContractArea::Profile,
        &["vortix", "list", "--names-only"],
        "list",
        OutputSurface::Human,
    ),
    scenario(
        "profile-import",
        ContractArea::Profile,
        &["vortix", "import", "/tmp/corp.conf"],
        "import",
        OutputSurface::Human,
    ),
    scenario(
        "profile-show-json",
        ContractArea::Profile,
        &["vortix", "--json", "show", "corp"],
        "show",
        OutputSurface::Json,
    ),
    scenario(
        "profile-delete",
        ContractArea::Profile,
        &["vortix", "delete", "corp", "--yes"],
        "delete",
        OutputSurface::Human,
    ),
    scenario(
        "profile-rename",
        ContractArea::Profile,
        &["vortix", "rename", "corp", "work"],
        "rename",
        OutputSurface::Human,
    ),
    scenario(
        "audit-json-filtered",
        ContractArea::Audit,
        &["vortix", "--json", "audit", "--pid", "42", "--vpn-only"],
        "audit",
        OutputSurface::Json,
    ),
    scenario(
        "interactive-tui",
        ContractArea::Interactive,
        &["vortix"],
        "tui",
        OutputSurface::Tui,
    ),
];

pub const MODE_STATUS_LABELS: &[&str] = &[
    "Standard mode: Active",
    "Background mode: Enabling",
    "Background mode: Active",
    "Background mode: Degraded",
    "Background mode: Disabling",
    "Background mode: Recovery required",
];

pub const BACKGROUND_CAPABILITY_COPY: &[&str] = &[
    "routine CLI/TUI control without sudo after one-time setup",
    "live CLI/TUI synchronization",
    "automatic drop recovery",
    "boot connections",
    "continuous policy verification",
    "shared multi-client coordination",
];

pub const TRUST_BOUNDARY_COPY: &[&str] = &[
    "Standard mode: root-assisted full-client trust boundary",
    "Background mode: narrow privileged helper",
];

pub const DIAGNOSTIC_FALLBACK_LABELS: &[&str] = &["stale", "unauthenticated", "advisory-only"];

pub const LIFECYCLE_EVENT_HOOKS: &[&str] = &[
    "connect_started",
    "connected",
    "disconnect_started",
    "disconnected",
    "connect_failed",
    "reconnecting",
];

pub const BOOT_INELIGIBLE_CREDENTIALS: &[&str] =
    &["password", "OTP", "challenge", "private-key prompt"];

pub const RECOVERY_ACTIONS: &[&str] = &[
    "vortix setup",
    "vortix background status",
    "vortix background recover",
    "vortix background disable",
];

pub const ERROR_CONTRACTS: &[(&str, i32)] = &[
    ("success", 0),
    ("general_error", 1),
    ("permission_denied", 2),
    ("not_found", 3),
    ("state_conflict", 4),
    ("dependency_missing", 5),
    ("timeout", 6),
];
