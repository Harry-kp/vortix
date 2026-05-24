//! Profile CRUD and import operations.

use std::path::Path;

use super::{App, ConnectionState, InputMode, Protocol, ToastType};
use crate::constants;
use crate::utils;

impl App {
    pub(crate) fn profile_next(&mut self) {
        let i = match self.profile_list_state.selected() {
            Some(i) => {
                if i >= self.profiles.len().saturating_sub(1) {
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
                    self.profiles.len().saturating_sub(1)
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
        if let Some(profile) = self.profiles.get(idx) {
            let active_profile = match &self.connection_state {
                ConnectionState::Connected { profile: p, .. }
                | ConnectionState::Connecting { profile: p, .. }
                | ConnectionState::Disconnecting { profile: p, .. } => Some(p.as_str()),
                ConnectionState::Disconnected => None,
            };
            if active_profile == Some(&profile.name) {
                self.show_toast(
                    "Cannot delete active profile — disconnect first".to_string(),
                    ToastType::Warning,
                );
                return;
            }

            // 2. Switch to confirm mode
            self.input_mode = InputMode::ConfirmDelete {
                index: idx,
                name: profile.name.clone(),
                confirm_selected: false, // Default to "No" for safety
            };
        }
    }

    /// Execute deletion after confirmation
    pub(crate) fn confirm_delete(&mut self, idx: usize) {
        if idx >= self.profiles.len() {
            return;
        }

        // Safety net: state may have changed since the confirm dialog opened
        if let Some(profile) = self.profiles.get(idx) {
            let active_profile = match &self.connection_state {
                ConnectionState::Connected { profile: p, .. }
                | ConnectionState::Connecting { profile: p, .. }
                | ConnectionState::Disconnecting { profile: p, .. } => Some(p.as_str()),
                ConnectionState::Disconnected => None,
            };
            if active_profile == Some(&profile.name) {
                self.show_toast(
                    "Cannot delete — profile became active".to_string(),
                    ToastType::Warning,
                );
                self.input_mode = InputMode::Normal;
                return;
            }
        }

        // Get profile info before removing
        let config_path = self.profiles[idx].config_path.clone();
        let profile_name = self.profiles[idx].name.clone();
        let protocol = self.profiles[idx].protocol;

        // Remove from profiles
        self.profiles.remove(idx);

        // Try to delete from disk
        if config_path.exists() {
            let _ = std::fs::remove_file(&config_path);
        }

        // Clean up OpenVPN auth and runtime files
        if matches!(protocol, Protocol::OpenVPN) {
            utils::delete_openvpn_auth_file(&profile_name);
            utils::cleanup_openvpn_run_files(&profile_name);
        }

        // Adjust selection
        if self.profiles.is_empty() {
            self.profile_list_state.select(None);
        } else if let Some(selected) = self.profile_list_state.selected() {
            if selected >= self.profiles.len() {
                self.profile_list_state
                    .select(Some(self.profiles.len() - 1));
            }
        }

        self.show_toast("Profile deleted".to_string(), ToastType::Success);
        self.input_mode = InputMode::Normal;
    }

    pub(crate) fn rename_profile(&mut self, idx: usize, new_name: &str) {
        if idx >= self.profiles.len() {
            return;
        }

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

        let old_name = self.profiles[idx].name.clone();
        let old_path = self.profiles[idx].config_path.clone();

        if let Some(parent) = old_path.parent() {
            let ext = old_path
                .extension()
                .map_or("conf", |e| e.to_str().unwrap_or("conf"));
            let new_file = parent.join(format!("{new_name}.{ext}"));

            if new_file.exists() {
                self.show_toast(
                    format!("A profile named '{new_name}' already exists"),
                    ToastType::Warning,
                );
                return;
            }

            if let Err(e) = std::fs::rename(&old_path, &new_file) {
                self.show_toast(format!("Rename failed: {e}"), ToastType::Error);
                return;
            }

            self.profiles[idx].name = new_name.to_string();
            self.profiles[idx].config_path = new_file;

            if self.last_connected_profile.as_deref() == Some(&old_name) {
                self.last_connected_profile = Some(new_name.to_string());
            }

            if let ConnectionState::Connected { profile, .. } = &mut self.connection_state {
                if *profile == old_name {
                    *profile = new_name.to_string();
                }
            }

            if matches!(self.profiles[idx].protocol, Protocol::OpenVPN) {
                if let Some(auth) = utils::read_openvpn_saved_auth(&old_name) {
                    let _ = utils::write_openvpn_auth_file(new_name, &auth.0, &auth.1);
                    utils::delete_openvpn_auth_file(&old_name);
                }
            }

            self.save_metadata();
            self.sort_profiles();

            if let Some(new_idx) = self.profiles.iter().position(|p| p.name == new_name) {
                self.profile_list_state.select(Some(new_idx));
            }

            self.show_toast(
                format!("Renamed '{old_name}' → '{new_name}'"),
                ToastType::Success,
            );
        }
    }

    pub(crate) fn save_metadata(&self) {
        use std::collections::HashMap;

        let mut metadata = HashMap::new();
        for profile in &self.profiles {
            let key = profile.config_path.to_string_lossy().to_string();
            metadata.insert(
                key,
                utils::ProfileMetadata {
                    last_used: profile.last_used,
                },
            );
        }

        let _ = utils::save_profile_metadata(&metadata);
    }

    /// Sort profiles according to the current `sort_order`.
    pub(crate) fn sort_profiles(&mut self) {
        use crate::state::ProfileSortOrder;
        match self.sort_order {
            ProfileSortOrder::NameAsc => {
                self.profiles.sort_by(|a, b| a.name.cmp(&b.name));
            }
            ProfileSortOrder::NameDesc => {
                self.profiles.sort_by(|a, b| b.name.cmp(&a.name));
            }
            ProfileSortOrder::LastUsed => {
                self.profiles.sort_by(|a, b| {
                    b.last_used
                        .unwrap_or(std::time::UNIX_EPOCH)
                        .cmp(&a.last_used.unwrap_or(std::time::UNIX_EPOCH))
                });
            }
            ProfileSortOrder::Protocol => {
                fn proto_rank(p: crate::state::Protocol) -> u8 {
                    match p {
                        crate::state::Protocol::WireGuard => 0,
                        crate::state::Protocol::OpenVPN => 1,
                    }
                }
                self.profiles.sort_by(|a, b| {
                    proto_rank(a.protocol)
                        .cmp(&proto_rank(b.protocol))
                        .then_with(|| a.name.cmp(&b.name))
                });
            }
        }
    }

    /// Import a profile from a file path or bulk import from directory
    pub(crate) fn import_profile_from_path(&mut self, path_str: &str) {
        use crate::core::importer::{resolve_target, ImportTarget};
        use crate::message::Message;

        let mut last_imported_name: Option<String> = None;
        let mut should_close_overlay = false;

        match resolve_target(path_str) {
            Ok(ImportTarget::Url(url)) => {
                let tx = self.cmd_tx.clone();
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

        self.sort_profiles();

        if let Some(name) = last_imported_name {
            if let Some(idx) = self.profiles.iter().position(|p| p.name == name) {
                self.profile_list_state.select(Some(idx));
            }
        }

        if should_close_overlay {
            self.handle_message(Message::CloseOverlay);
        }
    }

    /// Import a single VPN profile file
    fn import_single_file(&mut self, path: &Path) -> Option<String> {
        match crate::vpn::import_profile(path) {
            Ok(profile) => {
                let name = profile.name.clone();
                self.profiles.push(profile);

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

    /// Bulk import all .conf and .ovpn files from a directory.
    /// Returns the number of successfully imported profiles.
    fn import_from_directory(&mut self, dir_path: &Path) -> usize {
        let mut imported = 0;
        let mut failed = 0;

        match std::fs::read_dir(dir_path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();

                    // Only process .conf and .ovpn files
                    if path.is_file()
                        && path
                            .extension()
                            .is_some_and(|ext| ext == "conf" || ext == "ovpn")
                    {
                        match crate::vpn::import_profile(&path) {
                            Ok(profile) => {
                                self.profiles.push(profile);
                                imported += 1;
                            }
                            Err(e) => {
                                self.log(&format!(
                                    "ERR: Failed to import {}: {}",
                                    path.display(),
                                    e
                                ));
                                failed += 1;
                            }
                        }
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
}
