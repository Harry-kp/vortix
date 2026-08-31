//! Anonymous regular-file descriptors for one-shot protocol material.

#![allow(
    unsafe_code,
    reason = "Linux memfd and macOS unlinked temporary descriptors require libc"
)]

use std::fs::File;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};

#[cfg(target_os = "linux")]
pub(crate) fn create(material: &[u8]) -> std::io::Result<File> {
    let descriptor = unsafe {
        libc::memfd_create(
            c"vortix-material".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    write_material(&mut file, material)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
pub(crate) fn create(material: &[u8]) -> std::io::Result<File> {
    // Unlink the empty 0600 file before writing any secret byte. A crash can
    // therefore leave at most an empty mkstemp artifact, never key material.
    let mut template = b"/tmp/vortix-material.XXXXXX\0".to_vec();
    let descriptor = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    if unsafe { libc::unlink(template.as_ptr().cast()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_close_on_exec(&file)?;
    write_material(&mut file, material)?;
    Ok(file)
}

#[cfg(target_os = "macos")]
fn set_close_on_exec(file: &File) -> std::io::Result<()> {
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn write_material(file: &mut File, material: &[u8]) -> std::io::Result<()> {
    file.write_all(material)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;

    #[test]
    fn memfd_is_anonymous_and_write_sealed_before_transport() {
        let mut descriptor = super::create(b"private-material").unwrap();

        let error = descriptor.write_all(b"mutate").unwrap_err();

        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        assert_eq!(descriptor.metadata().unwrap().nlink(), 0);
    }
}
