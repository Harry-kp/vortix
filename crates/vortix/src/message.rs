//! Message system for the Vortix application.
//!
//! All state mutations flow through this centralized Message enum,
//! following the Elm Architecture (TEA) pattern. This enables:
//! - Easy debugging (log all messages)
//! - Predictable state changes
//! - Testable update logic

use crate::core::scanner::ActiveSession;
use crate::core::telemetry::TelemetryUpdate;
use crate::state::{FocusedPanel, ToastType};

/// All messages that can modify application state.
///
/// Messages are the single source of truth for state mutations.
/// They can originate from user input or programmatically.
/// Direction for list selection movement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMove {
    Next,
    Prev,
    First,
    Last,
}

/// Direction for scrolling movement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollMove {
    Up,
    Down,
    Top,
    Bottom,
}

/// All messages that can modify application state.
///
/// Messages are the single source of truth for state mutations.
/// They can originate from user input or programmatically.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some variants are handled in match but not constructed externally
pub enum Message {
    // === Navigation ===
    /// Focus next panel
    NextPanel,
    /// Focus previous panel
    PreviousPanel,
    /// Focus a specific panel
    FocusPanel(FocusedPanel),
    /// Toggle zoom on current panel
    ToggleZoom,
    /// Toggle flip (front/back view) on current panel
    ToggleFlip,

    // === Profile Management ===
    /// Move selection in profile list
    ProfileMove(SelectionMove),

    // === Connection ===
    /// Toggle connection for profile at index (None = selected)
    ToggleConnect(Option<usize>),
    /// Disconnect from current VPN (press again while disconnecting to force-kill)
    Disconnect,
    /// Reconnect to last profile
    Reconnect,
    /// Connect the currently selected sidebar profile
    ConnectSelected,
    /// Connect to quick slot (0-8)
    QuickConnect(usize),

    // === UI Overlays ===
    /// Close current overlay (Action menu, Help, Config, etc.)
    CloseOverlay,
    /// Show toast notification
    Toast(String, ToastType),
    /// View config for selected profile
    OpenConfig,
    /// Request delete for profile at index
    OpenDelete(Option<usize>),
    /// Confirm deletion
    ConfirmDelete,
    /// Confirm VPN profile switch
    ConfirmSwitch { idx: usize },

    // === Action Menu ===
    /// Open the action menu (Single actions)
    OpenActionMenu,
    /// Open the bulk action menu
    OpenBulkMenu,

    // === Scrolling ===
    /// Scroll current context
    Scroll(ScrollMove),

    // === Import ===
    /// Open import dialog
    OpenImport,

    // === System ===
    /// Log a message
    Log(String),
    /// Copy IP to clipboard
    CopyIp,
    /// Clear activity logs
    ClearLogs,
    /// Quit the application
    Quit,
    /// Background telemetry update
    Telemetry(TelemetryUpdate),
    /// Periodic system state synchronization (active profiles)
    SyncSystemState(Vec<ActiveSession>),
    /// Periodic heartbeat tick
    Tick,
    /// Connection timeout detected
    ConnectionTimeout(String),
    /// Default gateway changed (network switch, sleep/wake)
    NetworkChanged,
    /// Retry a failed connection after exponential backoff delay
    RetryConnect {
        /// Profile index to retry
        idx: usize,
        /// Which attempt this is (1-based)
        attempt: u32,
    },
    /// Result from the background connect thread
    ConnectResult {
        /// Profile name that was being connected
        profile: String,
        /// Whether the connect command succeeded
        success: bool,
        /// Error message if the command failed
        error: Option<String>,
    },
    /// Result from the background disconnect thread
    DisconnectResult {
        /// Profile name that was being disconnected
        profile: String,
        /// Whether the disconnect command succeeded
        success: bool,
        /// Error message if the command failed
        error: Option<String>,
    },
    /// Terminal resize event
    Resize(u16, u16),
    /// Import profile from path
    Import(String),

    // === Authentication ===
    /// Submit credentials from the auth prompt overlay
    AuthSubmit {
        /// Profile index to connect after saving credentials
        idx: usize,
        /// Username entered by the user
        username: String,
        /// Password entered by the user
        password: String,
        /// Whether to persist credentials for future sessions
        save: bool,
        /// Whether to auto-connect after saving (false = save-only from manage flow)
        connect_after: bool,
    },
    /// Open the auth credentials manager for the selected profile (edit/view/clear)
    ManageAuth,
    /// Clear saved credentials for the selected profile
    ClearAuth,

    // === Profile Sorting ===
    /// Cycle profile sort order (Name A-Z → Z-A → Last Used → Protocol)
    CycleSortOrder,

    // === Kill Switch ===
    /// Toggle kill switch mode (Off → Auto → `AlwaysOn` → Off)
    ToggleKillSwitch,

    // === Overlay / Inline-mode Actions (keyboard + action menus) ===
    /// Open profile rename overlay for the selected profile
    OpenRename,
    /// Open profile search/filter overlay
    OpenSearch,
    /// Open the help overlay
    OpenHelp,
    /// Cycle the activity-log level filter (All → Errors → Warn → Info → All)
    CycleLogFilter,
}

/// An item in the action menu, mapping a key to a message.
#[derive(Debug, Clone)]
pub struct ActionMenuItem {
    /// The key that triggers this action
    pub key: &'static str,
    /// Human-readable label for the action
    pub label: &'static str,
    /// The message to dispatch
    pub message: Message,
}

/// Get specific actions for the focused item/panel (triggered by 'x')
#[must_use]
pub fn get_single_actions(focused_panel: &FocusedPanel) -> Vec<ActionMenuItem> {
    let mut actions = Vec::new();

    // 1. Panel-Specific Actions
    match focused_panel {
        FocusedPanel::Sidebar => {
            actions.push(ActionMenuItem {
                key: "i",
                label: "Import Profiles",
                message: Message::OpenImport,
            });
            actions.push(ActionMenuItem {
                key: "c",
                label: "Connect / Disconnect",
                message: Message::ToggleConnect(None),
            });
            actions.push(ActionMenuItem {
                key: "r",
                label: "Reconnect",
                message: Message::ConnectSelected,
            });
            actions.push(ActionMenuItem {
                key: "v",
                label: "View Configuration",
                message: Message::OpenConfig,
            });
            actions.push(ActionMenuItem {
                key: "a",
                label: "Edit Auth Credentials",
                message: Message::ManageAuth,
            });
            actions.push(ActionMenuItem {
                key: "A",
                label: "Clear Auth Credentials",
                message: Message::ClearAuth,
            });
            actions.push(ActionMenuItem {
                key: "DEL",
                label: "Delete Profile",
                message: Message::OpenDelete(None),
            });
            actions.push(ActionMenuItem {
                key: "s",
                label: "Sort Profiles",
                message: Message::CycleSortOrder,
            });
            actions.push(ActionMenuItem {
                key: "R",
                label: "Rename Profile",
                message: Message::OpenRename,
            });
        }
        FocusedPanel::Logs => {
            actions.push(ActionMenuItem {
                key: "L",
                label: "Clear Activity Logs",
                message: Message::ClearLogs,
            });
            actions.push(ActionMenuItem {
                key: "f",
                label: "Filter Log Level",
                message: Message::CycleLogFilter,
            });
        }
        FocusedPanel::ConnectionDetails => {
            actions.push(ActionMenuItem {
                key: "y",
                label: "Copy Public IP",
                message: Message::CopyIp,
            });
        }
        FocusedPanel::Security => {
            actions.push(ActionMenuItem {
                key: "K",
                label: "Toggle Kill Switch",
                message: Message::ToggleKillSwitch,
            });
        }
        FocusedPanel::Chart => {}
    }

    // 2. Universal Contextual Utility
    if matches!(
        focused_panel,
        FocusedPanel::Chart | FocusedPanel::ConnectionDetails | FocusedPanel::Security
    ) {
        actions.push(ActionMenuItem {
            key: "f",
            label: "Flip Panel (Front/Back)",
            message: Message::ToggleFlip,
        });
    }
    actions.push(ActionMenuItem {
        key: "z",
        label: "Toggle Zoom View",
        message: Message::ToggleZoom,
    });

    actions
}

/// Get bulk/global actions (triggered by 'b')
#[must_use]
pub fn get_bulk_actions() -> Vec<ActionMenuItem> {
    vec![
        ActionMenuItem {
            key: "i",
            label: "Import Profiles",
            message: Message::OpenImport,
        },
        ActionMenuItem {
            key: "r",
            label: "Reconnect Last",
            message: Message::Reconnect,
        },
        ActionMenuItem {
            key: "D",
            label: "Disconnect All",
            message: Message::Disconnect,
        },
        ActionMenuItem {
            key: "y",
            label: "Copy Public IP",
            message: Message::CopyIp,
        },
        ActionMenuItem {
            key: "K",
            label: "Toggle Kill Switch",
            message: Message::ToggleKillSwitch,
        },
        ActionMenuItem {
            key: "/",
            label: "Search Profiles",
            message: Message::OpenSearch,
        },
        ActionMenuItem {
            key: "?",
            label: "Help",
            message: Message::OpenHelp,
        },
        ActionMenuItem {
            key: "l",
            label: "Next Panel",
            message: Message::NextPanel,
        },
        ActionMenuItem {
            key: "h",
            label: "Previous Panel",
            message: Message::PreviousPanel,
        },
        ActionMenuItem {
            key: "q",
            label: "Quit Vortix",
            message: Message::Quit,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sidebar_actions_include_connect() {
        let actions = get_single_actions(&FocusedPanel::Sidebar);
        assert!(actions.iter().any(|a| a.key == "c"));
        assert!(actions.iter().any(|a| a.key == "i"));
        assert!(actions.iter().any(|a| a.key == "v"));
        assert!(actions.iter().any(|a| a.key == "a")); // edit auth credentials
        assert!(actions.iter().any(|a| a.key == "A")); // clear auth credentials
        assert!(actions.iter().any(|a| a.key == "DEL"));
        assert!(actions.iter().any(|a| a.key == "s")); // sort
        assert!(actions.iter().any(|a| a.key == "R")); // rename
        assert!(actions.iter().any(|a| a.key == "z")); // universal zoom
    }

    #[test]
    fn test_logs_actions_include_clear_and_filter() {
        let actions = get_single_actions(&FocusedPanel::Logs);
        assert!(actions.iter().any(|a| a.key == "L"));
        assert!(actions.iter().any(|a| a.key == "f")); // log filter
        assert!(actions.iter().any(|a| a.key == "z"));
    }

    #[test]
    fn test_connection_details_actions_include_copy_ip_and_flip() {
        let actions = get_single_actions(&FocusedPanel::ConnectionDetails);
        assert!(actions.iter().any(|a| a.key == "y")); // copy IP
        assert!(actions.iter().any(|a| a.key == "f")); // flip
    }

    #[test]
    fn test_chart_actions_flip_and_zoom() {
        let actions = get_single_actions(&FocusedPanel::Chart);
        assert_eq!(actions.len(), 2);
        assert!(actions.iter().any(|a| a.key == "f")); // flip
        assert!(actions.iter().any(|a| a.key == "z")); // zoom
    }

    #[test]
    fn test_security_actions_include_killswitch_and_flip() {
        let actions = get_single_actions(&FocusedPanel::Security);
        assert!(actions.iter().any(|a| a.key == "K")); // kill switch
        assert!(actions.iter().any(|a| a.key == "f")); // flip
        assert!(actions.iter().any(|a| a.key == "z")); // zoom
    }

    #[test]
    fn test_bulk_actions_contains_essentials() {
        let actions = get_bulk_actions();
        assert!(actions.iter().any(|a| a.key == "i")); // import
        assert!(actions.iter().any(|a| a.key == "D")); // disconnect all
        assert!(actions.iter().any(|a| a.key == "q")); // quit
        assert!(actions.iter().any(|a| a.key == "y")); // copy IP
        assert!(actions.iter().any(|a| a.key == "K")); // kill switch
        assert!(actions.iter().any(|a| a.key == "/")); // search
        assert!(actions.iter().any(|a| a.key == "?")); // help
    }

    #[test]
    fn test_bulk_actions_count() {
        let actions = get_bulk_actions();
        assert_eq!(actions.len(), 10);
    }

    #[test]
    fn test_selection_move_variants() {
        assert_eq!(SelectionMove::Next, SelectionMove::Next);
        assert_ne!(SelectionMove::Next, SelectionMove::Prev);
        assert_ne!(SelectionMove::First, SelectionMove::Last);
    }

    #[test]
    fn test_scroll_move_variants() {
        assert_eq!(ScrollMove::Up, ScrollMove::Up);
        assert_ne!(ScrollMove::Up, ScrollMove::Down);
        assert_ne!(ScrollMove::Top, ScrollMove::Bottom);
    }
}
