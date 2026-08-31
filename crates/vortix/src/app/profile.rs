//! Profile CRUD and import operations.

use std::path::Path;

use super::{App, InputMode, Protocol, ToastType};
use crate::constants;
use crate::utils;
use crate::vortix_config::profile_store::{FsProfileStore, ProfileStore};
use crate::vortix_core::profile::ProfileId;

/// Bounds synchronous parsing/logging when a directory contains invalid files.
const PROFILE_IMPORT_ATTEMPTS_PER_TURN: usize = 8;

fn importable_profile_paths(dir_path: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut paths = std::fs::read_dir(dir_path)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext == "conf" || ext == "ovpn")
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

impl App {
    pub(crate) fn profile_next(&mut self) {
        let i = match self.profile_list_state.selected() {
            Some(i) => {
                if i >= self.runtime.profiles.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.profile_list_state.select(Some(i));
    }

    pub(crate) fn profile_previous(&mut self) {
        let i = match self.profile_list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.runtime.profiles.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.profile_list_state.select(Some(i));
    }

    /// Request deletion of a profile (Safety Check)
    pub(crate) fn request_delete(&mut self, idx: usize) {
        if let Some(profile) = self.runtime.profiles.get(idx) {
            if self.is_profile_active(&profile.name) {
                self.show_toast(
                    "Cannot delete active profile — disconnect first".to_string(),
                    ToastType::Warning,
                );
                return;
            }

            // 2. Switch to confirm mode
            self.input_mode = InputMode::ConfirmDelete {
                profile_id: profile.id.clone(),
                name: profile.name.clone(),
                confirm_selected: false, // Default to "No" for safety
            };
        }
    }

    /// Execute deletion after confirmation
    pub(crate) fn confirm_delete_profile(&mut self, profile_id: &ProfileId) {
        let Some(idx) = self.profile_index(profile_id) else {
            self.show_toast(
                "This profile no longer exists".to_string(),
                ToastType::Warning,
            );
            self.input_mode = InputMode::Normal;
            return;
        };

        // Safety net: state may have changed since the confirm dialog opened
        if let Some(profile) = self.runtime.profiles.get(idx) {
            if self.is_profile_active(&profile.name) {
                self.show_toast(
                    "Cannot delete — profile became active".to_string(),
                    ToastType::Warning,
                );
                self.input_mode = InputMode::Normal;
                return;
            }
        }

        // Get profile info before removing
        let profile_id = self.runtime.profiles[idx].id.clone();
        let config_path = self.runtime.profiles[idx].config_path.clone();
        let profile_name = self.runtime.profiles[idx].name.clone();
        let protocol = self.runtime.profiles[idx].protocol;

        if self.control_session.is_some() {
            if self
                .issue_control_command(crate::vortix_core::control::UserCommand::DeleteProfile {
                    profile_id,
                })
                .is_some()
            {
                self.input_mode = InputMode::Normal;
                self.show_toast(format!("Deleting '{profile_name}'…"), ToastType::Info);
            }
            return;
        }

        let Some(profiles_dir) = config_path.parent().map(Path::to_path_buf) else {
            self.show_toast(
                "Profile delete failed: invalid path".to_string(),
                ToastType::Error,
            );
            return;
        };
        if let Err(error) = FsProfileStore::new(profiles_dir).delete(&profile_id) {
            self.show_toast(format!("Profile delete failed: {error}"), ToastType::Error);
            return;
        }

        self.runtime.profiles.remove(idx);

        // The profile store owns remembered-credential cleanup as part of its
        // crash-safe delete transaction. The App only clears transient run
        // artifacts in this detached compatibility path.
        if matches!(protocol, Protocol::OpenVPN) {
            utils::cleanup_openvpn_run_files_compat(profile_id.as_str(), &profile_name);
        }

        // Adjust selection
        if self.runtime.profiles.is_empty() {
            self.profile_list_state.select(None);
        } else if let Some(selected) = self.profile_list_state.selected() {
            if selected >= self.runtime.profiles.len() {
                self.profile_list_state
                    .select(Some(self.runtime.profiles.len() - 1));
            }
        }

        self.show_toast("Profile deleted".to_string(), ToastType::Success);
        self.input_mode = InputMode::Normal;
    }

    #[cfg(test)]
    pub(crate) fn confirm_delete(&mut self, idx: usize) {
        let Some(profile_id) = self
            .runtime
            .profiles
            .get(idx)
            .map(|profile| profile.id.clone())
        else {
            return;
        };
        self.confirm_delete_profile(&profile_id);
    }

    pub(crate) fn rename_profile_by_id(&mut self, profile_id: &ProfileId, new_name: &str) {
        let Some(idx) = self.profile_index(profile_id) else {
            self.show_toast(
                "This profile no longer exists".to_string(),
                ToastType::Warning,
            );
            self.input_mode = InputMode::Normal;
            return;
        };

        let trimmed = new_name.trim();
        if trimmed.is_empty()
            || trimmed.contains('/')
            || trimmed.contains('\\')
            || trimmed.contains("..")
            || trimmed.starts_with('.')
        {
            self.show_toast(
                "Invalid name: must not contain path separators or '..'".to_string(),
                ToastType::Warning,
            );
            return;
        }

        let old_name = self.runtime.profiles[idx].name.clone();
        let old_path = self.runtime.profiles[idx].config_path.clone();
        let stable_id = self.runtime.profiles[idx].id.clone();

        if self.control_session.is_some() {
            if self.registry.snapshot(&stable_id).is_some() {
                self.show_toast(
                    "Cannot rename an active profile — disconnect first".to_string(),
                    ToastType::Warning,
                );
                return;
            }
            if self
                .issue_control_command(crate::vortix_core::control::UserCommand::RenameProfile {
                    profile_id: stable_id,
                    new_display_name: trimmed.to_string(),
                })
                .is_some()
            {
                self.input_mode = InputMode::Normal;
                self.show_toast(format!("Renaming '{old_name}'…"), ToastType::Info);
            }
            return;
        }

        if let Some(parent) = old_path.parent() {
            // The rename overlay may have been open while a connection
            // started. Re-check the stable identity at the mutation point;
            // an index or display-name check can be invalidated by sorting or
            // another rename while the dialog is open.
            use crate::vortix_core::engine::state::Connection;
            if self
                .registry
                .snapshot(&stable_id)
                .is_some_and(|snapshot| !matches!(snapshot.state, Connection::Disconnected { .. }))
            {
                self.show_toast(
                    "Cannot rename an active profile — disconnect first".to_string(),
                    ToastType::Warning,
                );
                return;
            }

            let store = FsProfileStore::new(parent.to_path_buf());
            let renamed = match store.rename(&stable_id, trimmed) {
                Ok(renamed) => renamed,
                Err(error) => {
                    self.show_toast(format!("Rename failed: {error}"), ToastType::Error);
                    return;
                }
            };

            self.runtime.profiles[idx].name = renamed.display_name;
            self.runtime.profiles[idx].config_path = renamed.config_path;

            if self.runtime.last_connected_profile.as_deref() == Some(&old_name) {
                self.runtime.last_connected_profile = Some(trimmed.to_string());
            }

            // Registry/retry state is keyed by stable ProfileId, so no
            // in-memory re-keying is required for a display-name change.

            self.runtime.save_metadata();
            self.runtime.sort_profiles();

            if let Some(new_idx) = self.runtime.profiles.iter().position(|p| p.name == trimmed) {
                self.profile_list_state.select(Some(new_idx));
            }

            self.show_toast(
                format!("Renamed '{old_name}' → '{trimmed}'"),
                ToastType::Success,
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn rename_profile(&mut self, idx: usize, new_name: &str) {
        let Some(profile_id) = self
            .runtime
            .profiles
            .get(idx)
            .map(|profile| profile.id.clone())
        else {
            return;
        };
        self.rename_profile_by_id(&profile_id, new_name);
    }

    /// Import a profile from a file path or bulk import from directory
    pub(crate) fn import_profile_from_path(&mut self, path_str: &str) {
        use crate::core::importer::{resolve_target, ImportTarget};
        use crate::message::Message;

        let mut last_imported_name: Option<String> = None;
        let mut should_close_overlay = false;

        match resolve_target(path_str) {
            Ok(ImportTarget::Url(url)) => {
                let tx = self.runtime.cmd_tx.clone();
                self.show_toast(constants::MSG_DOWNLOADING.to_string(), ToastType::Info);
                should_close_overlay = false;

                std::thread::spawn(
                    move || match crate::core::downloader::download_profile(&url) {
                        Ok(path) => {
                            let path_string = path.to_string_lossy().to_string();
                            let _ = tx.send(Message::Import(path_string));
                        }
                        Err(e) => {
                            let _ = tx.send(Message::Toast(
                                format!("{}{}", constants::MSG_DOWNLOAD_FAILED, e),
                                ToastType::Error,
                            ));
                        }
                    },
                );
            }
            Ok(ImportTarget::File(path)) => {
                last_imported_name = self.import_single_file(&path);
                should_close_overlay = last_imported_name.is_some();
                crate::core::downloader::cleanup_temp_download(&path);
            }
            Ok(ImportTarget::Directory(path)) => {
                let count = self.import_from_directory(&path);
                should_close_overlay = count > 0;
            }
            Err(e) => {
                self.show_toast(e, ToastType::Error);
            }
        }

        self.runtime.sort_profiles();

        if let Some(name) = last_imported_name {
            if let Some(idx) = self.runtime.profiles.iter().position(|p| p.name == name) {
                self.profile_list_state.select(Some(idx));
            }
        }

        if should_close_overlay {
            self.handle_message(Message::CloseOverlay);
        }
    }

    /// Import a single VPN profile file
    fn import_single_file(&mut self, path: &Path) -> Option<String> {
        if self.control_session.is_some() {
            let name = self.issue_control_import(path)?;
            self.show_toast(format!("Import queued: {name}"), ToastType::Info);
            return Some(name);
        }
        match crate::vpn::import_profile(path) {
            Ok(profile) => {
                let name = profile.name.clone();
                self.runtime.profiles.push(profile);

                self.show_toast(
                    format!("{}{}", constants::MSG_IMPORT_SUCCESS, name),
                    ToastType::Success,
                );
                Some(name)
            }
            Err(e) => {
                self.show_toast(
                    format!("{}{}", constants::MSG_IMPORT_ERROR, e),
                    ToastType::Error,
                );
                None
            }
        }
    }

    /// Import all `.conf` and `.ovpn` files from a directory.
    ///
    /// Returns the number imported synchronously in legacy mode or scheduled
    /// for bounded canonical admission.
    fn import_from_directory(&mut self, dir_path: &Path) -> usize {
        if self.control_session.is_some() {
            return self.queue_directory_import(dir_path);
        }

        let mut imported = 0;
        let mut failed = 0;

        match importable_profile_paths(dir_path) {
            Ok(paths) => {
                for path in paths {
                    if self.import_single_file(&path).is_some() {
                        imported += 1;
                    } else {
                        self.log(&format!("ERR: Failed to import {}", path.display()));
                        failed += 1;
                    }
                }

                // Show summary feedback
                if imported > 0 {
                    let msg = if failed > 0 {
                        format!("Imported {imported} profile(s), {failed} failed")
                    } else {
                        format!(
                            "{}{}{}",
                            constants::MSG_BATCH_IMPORTED,
                            imported,
                            constants::MSG_BATCH_IMPORTED_SUFFIX
                        )
                    };
                    let t_type = if failed > imported {
                        ToastType::Warning
                    } else {
                        ToastType::Success
                    };
                    self.show_toast(msg.clone(), t_type);

                    self.log(&format!(
                        "INFO: Batch imported {imported} profile(s) from {}",
                        dir_path.display()
                    ));
                } else if failed > 0 {
                    self.show_toast(
                        format!("Failed to import {failed} profiles"),
                        ToastType::Error,
                    );
                } else {
                    self.show_toast(
                        constants::MSG_NO_FILES_FOUND.to_string(),
                        ToastType::Warning,
                    );
                }
            }
            Err(e) => {
                self.log(&format!("ERR: Failed to read directory: {e}"));
                self.show_toast(format!("Error reading directory: {e}"), ToastType::Error);
            }
        }
        imported
    }

    fn queue_directory_import(&mut self, dir_path: &Path) -> usize {
        if self.pending_profile_imports.is_some() {
            self.show_toast(
                "A profile batch is already being queued".to_string(),
                ToastType::Warning,
            );
            return 0;
        }

        let paths = match importable_profile_paths(dir_path) {
            Ok(paths) => paths,
            Err(error) => {
                self.log(&format!("ERR: Failed to read directory: {error}"));
                self.show_toast(
                    format!("Error reading directory: {error}"),
                    ToastType::Error,
                );
                return 0;
            }
        };
        let count = paths.len();
        if count == 0 {
            self.show_toast(
                constants::MSG_NO_FILES_FOUND.to_string(),
                ToastType::Warning,
            );
            return 0;
        }

        self.pending_profile_imports = Some(super::PendingProfileImports {
            source: dir_path.to_path_buf(),
            remaining: paths.into(),
            queued: 0,
            failed: 0,
        });
        self.pump_pending_profile_imports();
        count
    }

    pub(crate) fn pump_pending_profile_imports(&mut self) {
        let Some(mut batch) = self.pending_profile_imports.take() else {
            return;
        };

        for _ in 0..PROFILE_IMPORT_ATTEMPTS_PER_TURN {
            let Some(path) = batch.remaining.pop_front() else {
                break;
            };
            match self.try_issue_control_import(&path) {
                Ok(_) => {
                    batch.queued += 1;
                }
                Err(crate::cli::control::LocalControlError::Busy) => {
                    batch.remaining.push_front(path);
                    break;
                }
                Err(error) => {
                    batch.failed += 1;
                    self.log(&format!(
                        "ERR: Failed to import {}: {error}",
                        path.display()
                    ));
                }
            }
        }

        if !batch.remaining.is_empty() {
            self.pending_profile_imports = Some(batch);
            return;
        }

        let summary = if batch.failed == 0 {
            format!("Queued {} profile import(s)", batch.queued)
        } else {
            format!(
                "Queued {} profile import(s), {} rejected",
                batch.queued, batch.failed
            )
        };
        self.show_toast(
            summary.clone(),
            if batch.failed == 0 {
                ToastType::Success
            } else {
                ToastType::Warning
            },
        );
        self.log(&format!("INFO: {summary} from {}", batch.source.display()));
    }
}
