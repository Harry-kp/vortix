//! Credential-safe file writes with TOCTOU mitigation.
//!
//! [`write_secret_file`] creates a new file at a fixed `0o600` mode by holding
//! an open file descriptor to the parent directory and using [`libc::openat`].
//! The parent is opened with `O_NOFOLLOW | O_DIRECTORY`, which rejects
//! symlinked parents and pins the resolved directory inode for the duration
//! of the write. This closes the parent-directory TOCTOU window that exists
//! with the naive `fs::write` + `chmod` two-step pattern: between the path
//! lookup and the open, an attacker who controls a writable ancestor cannot
//! swap a directory component for a symlink that points at a sensitive
//! target.
//!
//! Combined with `O_CREAT | O_EXCL` and a `0o600` mode at creation time, the
//! file lands on disk already locked down — there is no window during which
//! the file exists with looser permissions.
//!
//! Unix only. Windows callers receive an `Unsupported` I/O error today; a
//! native Windows implementation would need different primitives (e.g.
//! `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` handling and ACL
//! tightening) and is tracked as a TODO.

use std::path::Path;

/// Errors returned by [`write_secret_file`].
#[derive(Debug, thiserror::Error)]
pub enum SecretFileError {
    /// The supplied path has no parent component.
    #[error("path has no parent directory")]
    NoParent,
    /// The supplied path has no final component (basename).
    #[error("path has no basename")]
    NoBasename,
    /// The parent directory resolved to a symlink (rejected by `O_NOFOLLOW`).
    #[error("parent directory is a symlink")]
    SymlinkParent,
    /// The target file already exists; we never overwrite.
    #[error("target file already exists")]
    FileExists,
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The basename contains an interior null byte and cannot be passed to `openat`.
    #[error("invalid filename (contains null byte)")]
    InvalidFilename,
}

/// Atomically create a credential file at `0o600` with `contents`.
///
/// Refuses to overwrite an existing file and refuses to follow a symlinked
/// parent. The fsync at the end ensures the data is durably on disk before
/// any caller (e.g. `OpenVPN`) is told to read it.
///
/// # Errors
///
/// Returns [`SecretFileError`] for invalid paths, symlinked parents,
/// pre-existing targets, or any underlying syscall failure.
#[cfg(unix)]
pub fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), SecretFileError> {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().ok_or(SecretFileError::NoParent)?;
    // `path.parent()` returns `Some("")` for bare filenames like "foo.txt".
    // Treat that as "no parent" rather than passing an empty path to open().
    if parent.as_os_str().is_empty() {
        return Err(SecretFileError::NoParent);
    }
    let basename = path.file_name().ok_or(SecretFileError::NoBasename)?;

    // 1. Open the parent directory with O_DIRECTORY | O_NOFOLLOW. This both
    //    rejects symlinked parents and holds the fd open so the inode we
    //    resolved cannot be swapped out from under us. Note: Linux surfaces
    //    a symlinked parent as ELOOP; macOS surfaces it as ENOTDIR. Either
    //    way the secret never gets written. We use an explicit
    //    `symlink_metadata` check first to deliver a clear `SymlinkParent`
    //    error — this is a UX-only optimisation, not a security boundary
    //    (the boundary is `O_NOFOLLOW` on the open call below). If the
    //    parent is swapped between the lstat and the open, the open still
    //    rejects it.
    if std::fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(SecretFileError::SymlinkParent);
    }

    let parent_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => SecretFileError::SymlinkParent,
            _ => SecretFileError::Io(e),
        })?;

    // 2. Defensive fstat: confirm we really opened a directory. O_DIRECTORY
    //    already enforces this on modern kernels, but the explicit check
    //    guards against any edge case (e.g. weird filesystem) and documents
    //    the invariant.
    #[allow(unsafe_code)]
    {
        // SAFETY: `fstat` reads metadata from a valid fd we just opened
        // and writes into our stack-local `stat` struct. No aliasing,
        // no lifetime concerns; `parent_fd` outlives the call.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // clippy::borrow_as_ptr would prefer `&raw mut stat`, which requires
        // MSRV 1.82+; the workspace MSRV is 1.75, so keep the implicit
        // coercion and silence the lint.
        #[allow(clippy::borrow_as_ptr)]
        let rc = unsafe { libc::fstat(parent_fd.as_raw_fd(), &mut stat) };
        if rc != 0 {
            return Err(SecretFileError::Io(std::io::Error::last_os_error()));
        }
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(SecretFileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "parent fd does not refer to a directory",
            )));
        }
    }

    // 3. Build a C string for the basename. CString::new rejects interior
    //    NULs, which is the only way a Rust `OsStr` can be invalid here.
    let c_name =
        CString::new(basename.as_encoded_bytes()).map_err(|_| SecretFileError::InvalidFilename)?;

    // 4. openat(parent_fd, basename, O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW|O_CLOEXEC, 0o600).
    //    - O_CREAT|O_EXCL: refuses to overwrite (EEXIST) — no race vs an
    //      attacker who might pre-create the target as a symlink.
    //    - O_NOFOLLOW: refuses to follow if the basename is itself a symlink
    //      (ELOOP).
    //    - O_CLOEXEC: prevents fd leak across exec.
    //    - 0o600 mode: file is created with restrictive perms in one step,
    //      eliminating the chmod-after-write window.
    // openat's mode argument is variadic, so it must be passed as `c_uint`
    // (not `mode_t`, which may be narrower on some platforms — e.g. `u16`
    // on macOS — and would be illegal as a variadic arg).
    let mode: std::ffi::c_uint = 0o600;
    #[allow(unsafe_code)]
    let raw_fd = {
        // SAFETY: libc::openat is FFI. We pass a valid fd, a non-null
        // C-string pointer whose lifetime exceeds the call, and standard
        // POSIX flags. The returned int is checked below before we wrap it.
        unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        }
    };

    if raw_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EEXIST) => SecretFileError::FileExists,
            _ => SecretFileError::Io(err),
        });
    }

    // SAFETY: openat returned a non-negative fd that we own exclusively;
    // wrapping it in `File` transfers ownership so the fd is closed on drop.
    #[allow(unsafe_code)]
    let mut file = unsafe { File::from_raw_fd(raw_fd) };

    // 5. Write the contents and fsync. Hold `parent_fd` alive until after
    //    the write so the inode pin remains in effect throughout.
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    drop(parent_fd);
    Ok(())
}

/// Windows stub. A TOCTOU-safe equivalent on Windows needs a different
/// primitive set; tracked for follow-up.
#[cfg(not(unix))]
pub fn write_secret_file(_path: &Path, _contents: &[u8]) -> Result<(), SecretFileError> {
    Err(SecretFileError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "write_secret_file is not yet implemented on this platform",
    )))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn happy_path_writes_at_0600_with_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("secret.auth");
        write_secret_file(&target, b"user\npass\n").expect("write should succeed");

        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "file must be created at 0o600 in one step"
        );

        let body = std::fs::read(&target).unwrap();
        assert_eq!(body, b"user\npass\n");
    }

    #[test]
    fn symlinked_parent_directory_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        // Real directory that holds the eventual target...
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        // ...and a symlink pointing to it that we use in the supplied path.
        let link_dir = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let via_symlink = link_dir.join("secret.auth");
        let result = write_secret_file(&via_symlink, b"x");
        assert!(
            matches!(result, Err(SecretFileError::SymlinkParent)),
            "expected SymlinkParent, got {result:?}"
        );

        // And nothing should have been created in the real dir either.
        assert!(!real_dir.join("secret.auth").exists());
    }

    #[test]
    fn existing_target_returns_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("already.auth");
        std::fs::write(&target, b"pre-existing").unwrap();

        let result = write_secret_file(&target, b"new");
        assert!(
            matches!(result, Err(SecretFileError::FileExists)),
            "expected FileExists, got {result:?}"
        );

        // Original content must be preserved.
        assert_eq!(std::fs::read(&target).unwrap(), b"pre-existing");
    }

    #[test]
    fn target_is_symlink_returns_io_eloop() {
        let tmp = tempfile::tempdir().unwrap();
        let decoy = tmp.path().join("decoy.txt");
        std::fs::write(&decoy, b"decoy").unwrap();
        let link = tmp.path().join("link.auth");
        std::os::unix::fs::symlink(&decoy, &link).unwrap();

        let result = write_secret_file(&link, b"payload");
        match result {
            Err(SecretFileError::FileExists) => {
                // Some kernels surface EEXIST before ELOOP when the basename
                // already exists as a symlink. Either is fine — the
                // important property is that we did not follow it.
            }
            Err(SecretFileError::Io(e)) => {
                assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "expected ELOOP");
            }
            other => panic!("expected FileExists or Io(ELOOP), got {other:?}"),
        }

        // Decoy must be untouched.
        assert_eq!(std::fs::read(&decoy).unwrap(), b"decoy");
    }

    #[test]
    fn missing_parent_returns_io_enoent() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("nope").join("secret.auth");
        let result = write_secret_file(&target, b"x");
        match result {
            Err(SecretFileError::Io(e)) => {
                assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
            }
            other => panic!("expected Io(ENOENT), got {other:?}"),
        }
    }

    #[test]
    fn basename_with_null_byte_returns_invalid_filename() {
        // We can't put a NUL in an OsStr via `Path::join` portably, so build
        // the OsString by hand from raw bytes.
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let tmp = tempfile::tempdir().unwrap();
        let bad_name = OsString::from_vec(b"bad\0name".to_vec());
        let target = tmp.path().join(bad_name);

        let result = write_secret_file(&target, b"x");
        assert!(
            matches!(result, Err(SecretFileError::InvalidFilename)),
            "expected InvalidFilename, got {result:?}"
        );
    }

    #[test]
    fn permissions_are_0600_immediately_under_loose_umask() {
        // Force a permissive umask so the naive open() would have produced
        // 0o644. Our implementation must still land at 0o600 because of the
        // explicit mode arg + O_CREAT.
        #[allow(unsafe_code)]
        // SAFETY: umask() is process-global but this single-threaded test
        // simply observes that the explicit mode arg wins over umask.
        let prev = unsafe { libc::umask(0o022) };

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("perm.auth");
        write_secret_file(&target, b"x").unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;

        // Restore umask before asserting so a failing assertion doesn't
        // leave state behind for other tests in the same process.
        #[allow(unsafe_code)]
        // SAFETY: same as above; restoring the umask we captured.
        unsafe {
            libc::umask(prev);
        }

        assert_eq!(mode, 0o600, "umask must not loosen our explicit 0o600");
    }
}
