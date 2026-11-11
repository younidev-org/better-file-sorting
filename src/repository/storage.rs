//! Maintains the private content-addressed repository and its exclusive writer lock.
//! Objects are published under validated SHA-256 identities without overwriting existing
//! content. Repository security mode is persisted and cannot change automatically;
//! staging recovery and object validation keep interrupted runs recoverable.

use crate::{app::config::SecurityMode, repository::security};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

/// An open repository with a fixed security mode and an exclusive lock.
///
/// The lock lives as long as this handle. The writable catalog is opened
/// lazily and shared by workers through [Self::with_catalog].
pub struct Repository {
    root: PathBuf,
    mode: SecurityMode,
    _lock: File,
    catalog: std::sync::Mutex<Option<super::catalog::Catalog>>,
}
/// Return whether a string is a lowercase hexadecimal SHA-256 identity.
pub fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Repository {
    /// Create or open a repository while enforcing its security mode.
    pub fn open(root: &Path, mode: SecurityMode) -> Result<Self> {
        security::private_dir(root)?;
        let lock_path = root.join(".lock");
        crate::ingest::discovery::check_path(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock()
            .map_err(|_| anyhow::anyhow!("repository is in use by another process"))?;
        let mode_path = root.join("security.json");
        if mode_path.try_exists()? {
            security::validate_file(&mode_path, SecurityMode::Standard)?;
            let stored: SecurityMode = serde_json::from_slice(&fs::read(&mode_path)?)?;
            ensure!(
                stored == mode,
                "repository security mode cannot be changed automatically"
            );
            super::catalog::require(root)?;
        } else {
            super::catalog::create(root)?;
            let mut file = tempfile::NamedTempFile::new_in(root)?;
            serde_json::to_writer(&mut file, &mode)?;
            file.flush()?;
            file.as_file().sync_all()?;
            file.persist_noclobber(&mode_path)?;
            File::open(root)?.sync_all()?;
        }
        for name in ["objects", "views", "reports", ".staging"] {
            security::private_dir(&root.join(name))?;
        }
        // The exclusive repository lock proves no other writer owns these staging directories.
        for entry in fs::read_dir(root.join(".staging"))? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("run-")
                || name.to_string_lossy().starts_with("view-")
            {
                ensure!(entry.file_type()?.is_dir(), "unexpected staging entry");
                crate::ingest::discovery::check_path(&entry.path())?;
                fs::remove_dir_all(entry.path())?;
            }
        }
        Ok(Self {
            root: root.canonicalize()?,
            mode,
            _lock: lock,
            catalog: std::sync::Mutex::new(None),
        })
    }
    /// Open an existing repository without changing its recorded security mode.
    pub fn existing(root: &Path) -> Result<Self> {
        Self::existing_inner(root).with_context(|| {
            format!(
                "cannot open repository {}",
                crate::app::presentation::safe_text(&root.display().to_string())
            )
        })
    }
    fn existing_inner(root: &Path) -> Result<Self> {
        crate::ingest::discovery::check_path(root)?;
        let mode_path = root.join("security.json");
        match fs::symlink_metadata(&mode_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
                "security.json is missing; collection directories store downloads, while repository commands require ingested objects and a SQLite catalog. Ingest accessible inputs with bfsort ingest <INPUT> --extract --output <REPOSITORY>, then specify that repository explicitly. Sealed downloads require explicit authorized access first"
            ),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        security::validate_file(&mode_path, SecurityMode::Standard)?;
        let mode = serde_json::from_slice(&fs::read(mode_path)?)?;
        let lock_path = root.join(".lock");
        security::validate_file(&lock_path, SecurityMode::Standard)?;
        let lock = File::open(lock_path)?;
        lock.try_lock()
            .map_err(|_| anyhow::anyhow!("repository is in use by another process"))?;
        super::catalog::require(root)?;
        for name in ["objects", "views", "reports", ".staging"] {
            crate::ingest::discovery::check_path(&root.join(name))?;
            ensure!(root.join(name).is_dir(), "incomplete repository");
        }
        Ok(Self {
            root: root.canonicalize()?,
            mode,
            _lock: lock,
            catalog: std::sync::Mutex::new(None),
        })
    }
    /// Serialize catalog writes alongside the existing repository writer lock.
    pub fn with_catalog<T>(
        &self,
        update: impl FnOnce(&mut super::catalog::Catalog) -> Result<T>,
    ) -> Result<T> {
        let mut catalog = self
            .catalog
            .lock()
            .map_err(|_| anyhow::anyhow!("catalog lock poisoned"))?;
        if catalog.is_none() {
            *catalog = Some(super::catalog::write(&self.root)?);
        }
        update(catalog.as_mut().expect("initialized catalog"))
    }
    /// Return the canonical repository root.
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Return the repository's fixed security mode.
    pub fn mode(&self) -> SecurityMode {
        self.mode
    }
    /// Return the private staging directory path.
    pub fn staging(&self) -> PathBuf {
        self.root.join(".staging")
    }
    /// Resolve a validated SHA-256 identity to canonical object storage.
    pub fn object(&self, hash: &str) -> Result<PathBuf> {
        ensure!(valid_hash(hash), "invalid canonical hash");
        Ok(self.root.join("objects").join(&hash[..2]).join(hash))
    }
    /// Publish a staged object under the SHA-256 identity computed by the caller.
    ///
    /// Publication synchronizes the file with its final permissions, installs
    /// it without replacing an existing object, and synchronizes the parent
    /// directory. An existing object is checked for permissions and size.
    /// Callers can record the occurrence once this returns successfully.
    pub fn commit(&self, file: tempfile::NamedTempFile, hash: &str, size: u64) -> Result<()> {
        let target = self.object(hash)?;
        security::private_dir(target.parent().expect("object parent"))?;
        security::seal(file.as_file(), self.mode)?;
        file.as_file().sync_all()?;
        // Closing the writer before publication avoids retaining a writable sealed handle.
        let path = file.into_temp_path();
        match path.persist_noclobber(&target) {
            Ok(_) => (),
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        security::validate_file(&target, self.mode)?;
        ensure!(
            fs::metadata(&target)?.len() == size,
            "existing canonical object has unexpected size"
        );
        File::open(target.parent().expect("object parent"))?.sync_all()?;
        Ok(())
    }
}

impl Drop for Repository {
    fn drop(&mut self) {
        drop(
            self.catalog
                .get_mut()
                .unwrap_or_else(|p| p.into_inner())
                .take(),
        );
        // Release ownership even if a forked child briefly retains a duplicate descriptor.
        let _ = self._lock.unlock();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn dropping_repository_releases_lock_even_with_inherited_handle() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("repo");
        let repo = Repository::open(&path, SecurityMode::Standard).unwrap();
        // A concurrently forked subprocess can briefly retain the same open file description.
        let inherited = repo._lock.try_clone().unwrap();
        drop(repo);
        let reopened = Repository::existing(&path);
        assert!(reopened.is_ok());
        drop(inherited);
    }
}
