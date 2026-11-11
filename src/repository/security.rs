//! Implements the platform permission and publication primitives used throughout BFS.
//! Directories are private, standard metadata is owner-readable/writable, and sealed
//! payloads have no permission bits. Operations fail closed when safeguards cannot be
//! enforced; sealing is a permission boundary rather than a sandbox against owner/root.

use crate::{app::config::SecurityMode, ingest::discovery::check_path};
use anyhow::{Result, bail, ensure};
use std::{
    fs::{self, File},
    path::Path,
};

/// Fail closed unless the current platform has the supported permission backend.
pub fn supported() -> Result<()> {
    if !cfg!(unix) {
        bail!("private storage is unsupported on this platform: a Windows ACL backend is required");
    }
    Ok(())
}
/// Create or verify a private directory with owner-only permissions.
pub fn private_dir(path: &Path) -> Result<()> {
    supported()?;
    check_path(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {
                File::open(
                    path.parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or(Path::new(".")),
                )?
                .sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.permissions().mode() & 0o777 == 0o700,
            "directory must be private (0700): {}",
            path.display()
        );
    }
    Ok(())
}
/// Apply the requested final payload permissions and verify them.
pub fn seal(file: &File, mode: SecurityMode) -> Result<()> {
    supported()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bits = match mode {
            SecurityMode::Sealed => 0,
            SecurityMode::Standard => 0o600,
        };
        file.set_permissions(fs::Permissions::from_mode(bits))?;
        ensure!(
            file.metadata()?.permissions().mode() & 0o777 == bits,
            "filesystem did not enforce requested permissions"
        );
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}
/// Verify that a path is a regular file with the expected security mode.
pub fn validate_file(path: &Path, mode: SecurityMode) -> Result<()> {
    supported()?;
    check_path(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bits = match mode {
            SecurityMode::Sealed => 0,
            SecurityMode::Standard => 0o600,
        };
        ensure!(
            meta.permissions().mode() & 0o777 == bits,
            "unexpected sample permissions; refusing automatic permission changes"
        );
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}
/// Load bounded password candidates from a protected local file.
pub fn passwords(path: Option<&Path>) -> Result<Vec<String>> {
    let Some(path) = path else {
        return Ok(vec![]);
    };
    validate_file(path, SecurityMode::Standard)?;
    let meta = fs::metadata(path)?;
    ensure!(meta.len() <= 1024 * 1024, "password file exceeds 1 MiB");
    let text =
        fs::read_to_string(path).map_err(|_| anyhow::anyhow!("cannot read password file"))?;
    let passwords: Vec<_> = text
        .lines()
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    ensure!(passwords.len() <= 256, "password candidate limit exceeded");
    Ok(passwords)
}

/// Create a private temporary directory beneath a repository staging path.
pub fn private_tempdir(parent: &Path, prefix: &str) -> Result<tempfile::TempDir> {
    supported()?;
    check_path(parent)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    Ok(builder.tempdir_in(parent)?)
}

/// Publish a complete directory without replacing any existing destination.
pub fn publish_directory(source: &Path, destination: &Path) -> Result<()> {
    check_path(source)?;
    check_path(destination)?;
    #[cfg(target_os = "linux")]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    bail!("atomic no-replace directory publication is supported on Linux only")
}
