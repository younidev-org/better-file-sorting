// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Stores and imports occurrence metadata in SQLite.
//! Content hashes identify objects; occurrence identities retain distinct source events.
//! Imports validate the entire input before publishing a batch to the catalog.

use crate::{app::config::SecurityMode, repository::security, repository::storage::valid_hash};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
/// One source event for a stored object.
///
/// Multiple occurrences can reference the same content hash. Their identities
/// preserve each source path, entry name, and archive position.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Occurrence {
    /// Retained solely to preserve archive ancestry for selected descendants.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub structural: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested: Option<NestedProvenance>,
    #[serde(default)]
    pub detection: crate::detection::classifier::Detection,
    #[serde(default)]
    pub mismatch: crate::detection::mismatch::Evaluation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional remote source context; absent in legacy and local records.
    pub provenance: Option<crate::collection::acquisition::Candidate>,
    /// Records without an input mode retain archive-sample safeguards.
    #[serde(default)]
    pub input_mode: crate::app::config::InputMode,
    /// Stable identity of this source event, independent of the object path.
    pub occurrence_id: String,
    /// Content digest used to verify integrity and identify stored objects.
    pub sha256: String,
    pub size: u64,
    pub file_type: String,
    pub original_name: String,
    pub original_entry_name: String,
    pub original_stem: String,
    pub original_extension: String,
    pub source_archive: String,
    pub source_path: String,
    pub entry_index: usize,
    pub encrypted: bool,
    /// Date of ingestion into bfsort.
    pub ingest_date: String,
    pub run_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Location of a nested member relative to its root input.
pub struct NestedProvenance {
    pub schema_version: u32,
    pub parent_sha256: String,
    /// Stored parent occurrence, if the containing archive is part of the repository.
    ///
    /// Direct members of an external root archive can have only its content hash.
    pub parent_occurrence_id: Option<String>,
    pub root_source: String,
    pub root_input_hash: String,
    pub archive_depth: usize,
    pub entry_chain: Vec<usize>,
}
/// Hash bytes as lowercase hexadecimal SHA-256.
pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
impl Occurrence {
    /// Validate identity and file-type fields loaded from a manifest.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.structural || crate::ingest::nested::is_zip(&self.detection),
            "structural occurrences must be traversable ZIP containers"
        );
        ensure!(
            valid_hash(&self.sha256) && valid_hash(&self.occurrence_id),
            "invalid manifest identity"
        );
        ensure!(
            [
                "pe", "elf", "macho", "pdf", "zip", "text", "other", "unknown"
            ]
            .contains(&self.file_type.as_str()),
            "invalid manifest file type"
        );
        if let Some(n) = &self.nested {
            ensure!(
                n.schema_version == 1
                    && valid_hash(&n.parent_sha256)
                    && valid_hash(&n.root_input_hash)
                    && n.parent_occurrence_id
                        .as_ref()
                        .is_none_or(|id| valid_hash(id))
                    && !n.entry_chain.is_empty()
                    && n.archive_depth.checked_add(1) == Some(n.entry_chain.len()),
                "invalid nested provenance"
            );
        }
        Ok(())
    }
}
pub fn store(repo: &super::storage::Repository, record: &Occurrence) -> Result<()> {
    store_many(repo, std::slice::from_ref(record))
}

/// Validate every durable object before publishing a bounded metadata batch atomically.
pub fn store_many(repo: &super::storage::Repository, records: &[Occurrence]) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    for record in records {
        record.validate()?;
        let path = repo.object(&record.sha256)?;
        security::validate_file(&path, repo.mode())?;
        ensure!(
            fs::metadata(path)?.len() == record.size,
            "manifest/object size mismatch"
        );
    }
    repo.with_catalog(|catalog| catalog.insert_many(records))
}

/// Import active occurrences, including structural ancestors, from a SQLite snapshot.
pub fn import_catalog(repo: &super::storage::Repository, input: &Path) -> Result<usize> {
    use crate::app::presentation::Progress;

    let loading = Progress::new(None, "Reading source catalog");
    let rows = super::catalog::import_rows(input)?;
    let existing: BTreeMap<_, _> = load_all(repo.root())?
        .into_iter()
        .map(|row| (row.occurrence_id.clone(), row))
        .collect();
    drop(loading);

    let progress = Progress::new(Some(rows.len() as u64), "Validating imported records");
    for row in &rows {
        let object = repo.object(&row.sha256)?;
        security::validate_file(&object, repo.mode())?;
        ensure!(
            fs::metadata(object)?.len() == row.size,
            "import references a missing or inconsistent object"
        );
        if let Some(previous) = existing.get(&row.occurrence_id) {
            ensure!(
                serde_json::to_value(previous)? == serde_json::to_value(row)?,
                "import would overwrite occurrence metadata"
            );
        }
        progress.0.inc(1);
    }
    progress.0.set_message("committing records");
    repo.with_catalog(|catalog| catalog.insert_many(&rows))?;
    Ok(rows.len())
}

/// Load visible, active occurrences in catalog order.
pub fn load(root: &Path) -> Result<Vec<Occurrence>> {
    select(root, &crate::selection::Filters::default())
}

/// Select effective metadata through bound SQL, including legacy repositories in memory.
pub fn select(root: &Path, filters: &crate::selection::Filters) -> Result<Vec<Occurrence>> {
    let _progress = crate::app::presentation::Progress::new(None, "Querying metadata");
    super::catalog::read(root)?.select(filters, false)
}

/// Load effective metadata including removed and structural occurrences.
pub fn load_all(root: &Path) -> Result<Vec<Occurrence>> {
    super::catalog::read(root)?.select(&crate::selection::Filters::default(), true)
}

/// Explicitly refresh detection metadata without changing payloads or original journals.
pub fn analyze(
    repo: &crate::repository::storage::Repository,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<usize> {
    reclassify(repo, cancelled, false)
}

pub fn reclassify(
    repo: &crate::repository::storage::Repository,
    cancelled: &std::sync::atomic::AtomicBool,
    resume: bool,
) -> Result<usize> {
    reclassify_selected(
        repo,
        cancelled,
        resume,
        &crate::selection::Filters::default(),
    )
}

pub fn reclassify_selected(
    repo: &crate::repository::storage::Repository,
    cancelled: &std::sync::atomic::AtomicBool,
    resume: bool,
    filters: &crate::selection::Filters,
) -> Result<usize> {
    use std::io::Read;
    use std::sync::atomic::Ordering;
    ensure!(
        repo.mode() == SecurityMode::Standard,
        "analysis requires a standard repository; sealed payloads are never unlocked automatically"
    );
    use crate::app::presentation::{Progress, byte_progress};

    let mut records = select(repo.root(), filters)?;
    let objects: BTreeMap<_, _> = records.iter().map(|r| (&r.sha256, r.size)).collect();
    let total = objects
        .values()
        .try_fold(0u64, |total, size| total.checked_add(*size));
    let progress = Progress::new(Some(objects.len() as u64), "Reclassifying objects");
    let mut reused = 0;
    let mut read = 0u64;
    let message = |read, reused| {
        format!(
            "{} read for verification · {reused} classifications reused",
            byte_progress(read, total)
        )
    };
    progress.0.set_message(message(read, reused));
    let mut cache = BTreeMap::new();
    let checkpoint_dir = repo.root().join("reports/reclassification");
    security::private_dir(&checkpoint_dir)?;
    for record in &mut records {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        if !cache.contains_key(&record.sha256) {
            let path = repo.object(&record.sha256)?;
            security::validate_file(&path, SecurityMode::Standard)?;
            let mut file = fs::File::open(path)?;
            ensure!(
                file.metadata()?.len() == record.size,
                "manifest/object size mismatch"
            );
            let checkpoint = checkpoint_dir.join(format!(
                "{}-{}.json",
                record.sha256,
                crate::detection::classifier::DETECTOR_VERSION
            ));
            crate::ingest::discovery::check_path(&checkpoint)?;
            let hash =
                crate::ingest::nested::hash_file_with_progress(&mut file, cancelled, |count| {
                    read = read.saturating_add(count);
                    progress.streaming_message(|| message(read, reused));
                })?;
            ensure!(
                hash == record.sha256,
                "reclassification object checksum mismatch"
            );
            if resume && checkpoint.try_exists()? {
                security::validate_file(&checkpoint, SecurityMode::Standard)?;
                ensure!(
                    fs::metadata(&checkpoint)?.len() <= 65536,
                    "oversized classification checkpoint"
                );
                let detection: crate::detection::classifier::Detection =
                    serde_json::from_reader(fs::File::open(&checkpoint)?)?;
                ensure!(
                    detection.detector_version == crate::detection::classifier::DETECTOR_VERSION,
                    "stale classification checkpoint"
                );
                cache.insert(record.sha256.clone(), detection);
                reused += 1;
            } else {
                let mut prefix = Vec::with_capacity(crate::detection::classifier::PREFIX_LIMIT);
                Read::take(&mut file, crate::detection::classifier::PREFIX_LIMIT as u64)
                    .read_to_end(&mut prefix)?;
                cache.insert(
                    record.sha256.clone(),
                    crate::detection::classifier::detect_reader(&prefix, &mut file),
                );
            }
            let mut saved = tempfile::NamedTempFile::new_in(&checkpoint_dir)?;
            serde_json::to_writer(&mut saved, &cache[&record.sha256])?;
            saved.as_file().sync_all()?;
            saved.persist(&checkpoint)?;
            fs::File::open(&checkpoint_dir)?.sync_all()?;
            progress.0.inc(1);
            progress.0.set_message(message(read, reused));
        }
        record.detection = cache[&record.sha256].clone();
        record.mismatch =
            crate::detection::mismatch::evaluate(&record.original_entry_name, &record.detection);
    }
    progress.0.force_draw();
    drop(progress);
    let publication = crate::app::presentation::Progress::new(
        Some(records.len() as u64),
        "Publishing classifications",
    );
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    repo.with_catalog(|catalog| catalog.update_classifications(&records))?;
    publication.0.inc(records.len() as u64);
    drop(publication);
    let current = repo.root().join("views/CURRENT");
    crate::ingest::discovery::check_path(&current)?;
    let rules = if current.try_exists()? {
        security::validate_file(&current, SecurityMode::Standard)?;
        ensure!(
            fs::metadata(&current)?.len() <= 4096,
            "invalid current view pointer"
        );
        let generation = fs::read_to_string(&current)?;
        let generation = generation.trim();
        ensure!(
            generation.starts_with("view-")
                && !generation.contains(['/', '\\'])
                && !generation.contains(".."),
            "invalid current view pointer"
        );
        let policy = repo
            .root()
            .join("views")
            .join(generation)
            .join("rules.json");
        crate::ingest::discovery::check_path(&policy)?;
        if policy.try_exists()? {
            security::validate_file(&policy, SecurityMode::Standard)?;
            ensure!(
                fs::metadata(&policy)?.len() <= 1024 * 1024,
                "view rules too large"
            );
            serde_json::from_reader(fs::File::open(policy)?)?
        } else {
            crate::organization::rules::Rules::load_or_preset(None, None)?
        }
    } else {
        crate::organization::rules::Rules::load_or_preset(None, None)?
    };
    let active = load(repo.root())?;
    crate::organization::organizer::organize(repo, &rules, &rules.plan(&active)?)?;
    Ok(records.len())
}
