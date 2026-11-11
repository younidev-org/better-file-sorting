//! Read-only integrity checks; sealed payload permissions are never changed.
use super::{metadata, security, storage::Repository};
use crate::{app::config::SecurityMode, ingest::discovery::check_path};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path},
    sync::atomic::{AtomicBool, Ordering},
};
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub occurrences: usize,
    pub objects: usize,
    pub verified: usize,
    pub metadata_only: usize,
    pub missing: usize,
    pub corrupt: usize,
    pub view_generations: usize,
    pub unsupported: Vec<String>,
    pub failures: Vec<String>,
    pub summary: String,
}
fn private_directory(path: &Path) -> Result<()> {
    check_path(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(meta.is_dir(), "not a directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o777 == 0o700,
            "directory must be private (0700)"
        );
    }
    Ok(())
}
fn bounded_file(path: &Path, limit: u64) -> Result<fs::File> {
    security::validate_file(path, SecurityMode::Standard)?;
    let file = fs::File::open(path)?;
    ensure!(
        file.metadata()?.len() <= limit,
        "metadata file exceeds size limit"
    );
    Ok(file)
}
fn views(
    repo: &Repository,
    records: &BTreeMap<&str, &metadata::Occurrence>,
    report: &mut Report,
    cancelled: &AtomicBool,
) -> Result<()> {
    let root = repo.root().join("views");
    let current = root.join("CURRENT");
    if current.try_exists()? {
        let mut pointer = String::new();
        bounded_file(&current, 4096)?.read_to_string(&mut pointer)?;
        let name = pointer.trim();
        ensure!(
            name.starts_with("view-") && !name.contains(['/', '\\']) && !name.contains(".."),
            "invalid current view pointer"
        );
        private_directory(&root.join(name))?;
    }
    for generation in super::catalog::read(repo.root())?.views()? {
        private_directory(&root.join(generation))?;
    }
    for entry in fs::read_dir(&root)? {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        let entry = entry?;
        if entry.file_name() == "CURRENT" {
            continue;
        }
        let generation = entry.path();
        private_directory(&generation)?;
        let rules: crate::organization::rules::Rules =
            serde_json::from_reader(bounded_file(&generation.join("rules.json"), 1024 * 1024)?)?;
        let catalog = super::catalog::read(repo.root())?;
        for view in catalog.view_plan(&entry.file_name().to_string_lossy())? {
            let path = Path::new(&view.path);
            ensure!(
                !view.path.is_empty()
                    && path.components().all(|p| matches!(p, Component::Normal(_)))
                    && !view.path.contains('\\'),
                "unsafe view path"
            );
            let record = records
                .get(view.occurrence_id.as_str())
                .ok_or_else(|| anyhow::anyhow!("view references unknown occurrence"))?;
            ensure!(
                record.sha256 == view.sha256,
                "view object reference mismatch"
            );
            if rules.organization.view_mode != crate::organization::rules::ViewMode::Manifest {
                let payload = generation.join(path);
                security::validate_file(&payload, repo.mode())?;
                ensure!(
                    fs::metadata(&payload)?.len() == record.size,
                    "view payload size mismatch"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let a = fs::metadata(&payload)?;
                    let b = fs::metadata(repo.object(&view.sha256)?)?;
                    ensure!(
                        a.dev() == b.dev() && a.ino() == b.ino(),
                        "view is not linked to canonical object"
                    );
                }
            }
        }
        report.view_generations += 1;
    }
    Ok(())
}
pub fn run(root: &Path, full: bool, cancelled: &AtomicBool) -> Result<Report> {
    let repo = Repository::existing(root)?;
    ensure!(
        !full || repo.mode() == SecurityMode::Standard,
        "full verification requires a standard repository; sealed payloads are never unlocked automatically"
    );
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    use crate::app::presentation::{Progress, byte_progress};

    let metadata_progress = Progress::new(None, "Validating repository metadata");
    let mut report = Report::default();
    for name in ["", "objects", "views", "reports", ".staging"] {
        if let Err(error) = private_directory(&repo.root().join(name)) {
            report.failures.push(format!("{name}: {error}"));
        }
    }
    let records = match metadata::load(repo.root()) {
        Ok(records) => records,
        Err(error) => {
            report.failures.push(format!("metadata: {error}"));
            report.summary = "metadata integrity failure".into();
            return Ok(report);
        }
    };
    if let Err(error) = super::catalog::read(repo.root()).and_then(|catalog| catalog.integrity()) {
        report
            .failures
            .push(format!("SQLite metadata integrity: {error}"));
    }
    report.occurrences = records.len();
    let all_records = metadata::load_all(repo.root())?;
    let identities: BTreeMap<_, _> = all_records
        .iter()
        .map(|r| (r.occurrence_id.as_str(), r))
        .collect();
    let mut objects = BTreeMap::new();
    for record in &records {
        if let Some(previous) = objects.insert(record.sha256.as_str(), record.size)
            && previous != record.size
        {
            report
                .failures
                .push(format!("{}: inconsistent object sizes", record.sha256));
        }
        if let Some(nested) = &record.nested
            && let Some(parent) = &nested.parent_occurrence_id
            && identities
                .get(parent.as_str())
                .is_none_or(|r| r.sha256 != nested.parent_sha256)
        {
            report.failures.push(format!(
                "{}: missing or inconsistent parent occurrence",
                record.occurrence_id
            ));
        }
    }
    let references = match super::cleanup::audit_metadata(&repo) {
        Ok(references) => references,
        Err(error) => {
            let message = error.to_string();
            if message.contains("unknown") || message.contains("unsupported") {
                report.unsupported.push(message);
            } else {
                report.failures.push(format!("retained metadata: {error}"));
            }
            BTreeMap::new()
        }
    };
    for (hash, size) in &references {
        // Active occurrence sizes are authoritative; metadata-only pins may use the observed size.
        objects.entry(hash.as_str()).or_insert(*size);
    }
    report.objects = objects.len();
    let mut metadata_progress = Some(metadata_progress);
    let full_progress = full.then(|| {
        drop(metadata_progress.take());
        Progress::new(Some(objects.len() as u64), "Verifying repository objects")
    });
    let total = full_progress.as_ref().and_then(|_| {
        objects
            .values()
            .try_fold(0u64, |total, size| total.checked_add(*size))
    });
    let mut read = 0u64;
    let message = |read| format!("{} read", byte_progress(read, total));
    if let Some(progress) = &full_progress {
        progress.0.set_message(message(read));
    }
    for (hash, size) in objects {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        let path = repo.object(hash)?;
        let result = (|| -> Result<()> {
            private_directory(path.parent().expect("object parent"))?;
            security::validate_file(&path, repo.mode())?;
            ensure!(
                fs::metadata(&path)?.len() == size,
                "manifest/object size mismatch"
            );
            if let Some(progress) = &full_progress {
                let actual = crate::ingest::nested::hash_file_with_progress(
                    &mut fs::File::open(&path)?,
                    cancelled,
                    |count| {
                        read = read.saturating_add(count);
                        progress.streaming_message(|| message(read));
                    },
                )?;
                ensure!(actual == hash, "object checksum mismatch");
            }
            Ok(())
        })();
        match result {
            Ok(()) if full => report.verified += 1,
            Ok(()) => report.metadata_only += 1,
            Err(error) => {
                if fs::symlink_metadata(&path)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    report.missing += 1;
                } else {
                    report.corrupt += 1;
                }
                report.failures.push(format!("{hash}: {error}"));
            }
        }
        if let Some(progress) = &full_progress {
            progress.0.inc(1);
            progress.0.set_message(message(read));
        }
    }
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    if let Some(progress) = &full_progress {
        progress.0.force_draw();
    }
    drop(full_progress);
    let _views_progress = full.then(|| Progress::new(None, "Validating repository views"));
    if let Err(error) = views(&repo, &identities, &mut report, cancelled) {
        report.failures.push(format!("views: {error}"));
    }
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    if full && !report.unsupported.is_empty() {
        report
            .failures
            .push("full verification could not validate unsupported retained metadata".into());
    }
    report.summary = format!(
        "{} objects: {} verified, {} metadata-only, {} missing, {} corrupt; {} failures; {} unsupported categories",
        report.objects,
        report.verified,
        report.metadata_only,
        report.missing,
        report.corrupt,
        report.failures.len(),
        report.unsupported.len()
    );
    Ok(report)
}
