//! Profile CRUD and import operations.

use std::path::Path;

use super::{App, InputMode, ToastType};
use crate::config::profile_store::FsProfileStore;
use crate::constants;
use crate::profile::ProfileId;
use crate::profile::ProtocolKind;

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
        if matches!(protocol, ProtocolKind::OpenVpn) {
            crate::openvpn::cleanup_openvpn_run_files_compat(profile_id.as_str(), &profile_name);
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

        self.sync_profiles();
        self.show_toast("Profile deleted".to_string(), ToastType::Success);
        self.input_mode = InputMode::Normal;
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

        if let Some(parent) = old_path.parent() {
            // The rename overlay may have been open while a connection
            // started. Re-check the stable identity at the mutation point;
            // an index or display-name check can be invalidated by sorting or
            // another rename while the dialog is open.
            use crate::tunnel::Connection;
            if self
                .registry
                .snapshot(&stable_id)
                .is_some_and(|snapshot| !matches!(snapshot.state, Connection::Disconnected))
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

            // Registry/retry state is keyed by stable ProfileId, so no
            // in-memory re-keying is required for a display-name change.

            self.runtime.sort_profiles();
            self.sync_profiles();

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
        use crate::config::import::{resolve_target, ImportTarget};
        use crate::message::Message;

        let mut last_imported_name: Option<String> = None;
        let mut should_close_overlay = false;

        match resolve_target(path_str) {
            Ok(ImportTarget::Url(url)) => {
                let tx = self.runtime.cmd_tx.clone();
                self.show_toast(constants::MSG_DOWNLOADING.to_string(), ToastType::Info);
                should_close_overlay = false;

                std::thread::spawn(
                    move || match crate::config::import::download_profile(&url) {
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
                crate::config::import::cleanup_temp_download(&path);
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
        match crate::config::profiles::import_profile(path) {
            Ok(profile) => {
                let name = profile.name.clone();
                self.runtime.profiles.push(profile);
                self.sync_profiles();

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

    /// Tell the engine the catalog changed.
    fn sync_profiles(&mut self) {
        let profiles = self.runtime.profiles.clone();
        if let Some(control) = &self.control {
            control.send(crate::control::Command::Profiles(profiles));
        }
    }
}
