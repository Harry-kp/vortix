//! Shared fixed-mode directory primitives for dormant helper executors.

use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectoryCreation {
    Created,
    Existing,
}

pub(crate) fn create_private_directory(
    path: &Path,
    mode: u32,
) -> std::io::Result<DirectoryCreation> {
    match std::fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(DirectoryCreation::Created),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(DirectoryCreation::Existing)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn private_directory_is_valid(
    path: &Path,
    expected_owner_uid: u32,
    mode: u32,
) -> std::io::Result<bool> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(
        metadata.is_dir()
            && metadata.uid() == expected_owner_uid
            && metadata.mode() & 0o777 == mode,
    )
}
