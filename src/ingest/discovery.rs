//! Finds local input files without following symlinks or entering the output repository.
//! Archive mode checks ZIP signatures; file mode retains ordinary files unchanged.
//! Shared path validation rejects unsafe ancestors, and ingest discovery excludes
//! configured password files and their hard links before payload processing.

use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};
use walkdir::WalkDir;

/// Refuse symlinks in any existing component, including input ancestors.
pub fn check_path(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for part in path.components() {
        ensure!(
            !matches!(part, Component::ParentDir),
            "parent path components are forbidden"
        );
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => ensure!(
                !meta.file_type().is_symlink(),
                "symlink path refused: {}",
                current.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
/// Discover ZIP files while excluding symlinks and the output repository.
pub fn discover(inputs: &[PathBuf], recursive: bool, output: &Path) -> Result<Vec<PathBuf>> {
    discover_inputs(inputs, recursive, output, false)
}

/// Discover ordinary files or archives without following links or entering output.
pub fn discover_inputs(
    inputs: &[PathBuf],
    recursive: bool,
    output: &Path,
    files: bool,
) -> Result<Vec<PathBuf>> {
    ensure!(!inputs.is_empty(), "provide at least one input path");
    check_path(output)?;
    let excluded = if output.exists() {
        output.canonicalize()?
    } else {
        std::env::current_dir()?.join(output)
    };
    let mut paths = BTreeSet::new();
    for input in inputs {
        check_path(input)?;
        ensure!(input.exists(), "input does not exist: {}", input.display());
        for item in WalkDir::new(input)
            .follow_links(false)
            .max_depth(if recursive { usize::MAX } else { 1 })
            .into_iter()
            .filter_entry(|e| {
                !e.path().starts_with(&excluded)
                    && e.path()
                        .canonicalize()
                        .is_ok_and(|p| !p.starts_with(&excluded))
            })
        {
            let item = item.context("archive discovery failed")?;
            if !item.file_type().is_file() {
                continue;
            }
            ensure!(
                crate::repository::security::validate_file(
                    item.path(),
                    crate::app::config::SecurityMode::Sealed
                )
                .is_err(),
                "input is sealed: {}; explicitly unlock selected payloads to 0600 before processing",
                item.path().display()
            );
            if files {
                paths.insert(item.path().canonicalize()?);
                continue;
            }
            let mut signature = [0; 4];
            let read = File::open(item.path())?.read(&mut signature)?;
            if read == 4 && matches!(&signature, b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08") {
                paths.insert(item.path().canonicalize()?);
            }
        }
    }
    Ok(paths.into_iter().collect())
}

/// Discover ingest sources, excluding protected password files in either mode.
pub fn for_ingest(config: &crate::app::config::Config) -> Result<Vec<PathBuf>> {
    let mut paths = discover_inputs(
        &config.inputs,
        config.recursive,
        &config.output,
        config.input_mode == crate::app::config::InputMode::Files,
    )?;
    let secrets = [
        config.password_file.as_deref(),
        config.output_password_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(Path::canonicalize)
    .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|p| !secrets.contains(p));
    #[cfg(unix)]
    if !secrets.is_empty() {
        use std::os::unix::fs::MetadataExt;
        let identities = secrets
            .iter()
            .map(std::fs::metadata)
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut safe = Vec::with_capacity(paths.len());
        for path in paths {
            let meta = std::fs::metadata(&path)?;
            if !identities
                .iter()
                .any(|secret| secret.dev() == meta.dev() && secret.ino() == meta.ino())
            {
                safe.push(path);
            }
        }
        paths = safe;
    }
    if config.input_mode == crate::app::config::InputMode::Files {
        ensure!(
            config
                .limits
                .max_entries
                .is_none_or(|limit| paths.len() <= limit),
            "file count limit exceeded"
        );
    }
    Ok(paths)
}
