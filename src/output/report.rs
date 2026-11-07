// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Builds repository summaries from validated occurrence metadata and storage settings.
//! Reports distinguish logical occurrences from unique content so deduplication is
//! visible without reopening payloads. Sealed repositories can therefore be summarized
//! without changing their permissions or reading their contents.

use crate::{
    app::config::SecurityMode,
    repository::metadata::Occurrence,
    repository::storage::{Repository, valid_hash},
};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Serialize)]
/// Logical counts for the selected records and physical totals for the repository.
///
/// Multiple source occurrences can share one stored object. Physical totals
/// include objects outside the selection, including unreferenced objects.
pub struct Summary {
    pub nested: crate::ingest::nested::NestedSummary,
    pub occurrences: usize,
    pub unique_samples: usize,
    pub duplicate_occurrences: usize,
    pub stored_objects: usize,
    pub orphan_objects: usize,
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub allocated_bytes: u64,
    pub per_category: BTreeMap<String, usize>,
    pub security_mode: SecurityMode,
    pub by_detected_family: BTreeMap<String, Counts>,
    pub by_detected_format: BTreeMap<String, Counts>,
    pub by_original_extension: BTreeMap<String, Counts>,
    pub by_mismatch_status: BTreeMap<String, Counts>,
    pub extension_format: Vec<CrossCount>,
    pub mismatch_pairs: Vec<CrossCount>,
}
/// Summarize selected occurrences using the catalog's repository-wide references.
pub fn summary(repo: &Repository, records: &[Occurrence]) -> Result<Summary> {
    let referenced = crate::repository::catalog::read(repo.root())?.referenced_hashes()?;
    summary_with_references(repo, records, &referenced)
}

/// Selection affects logical counts; canonical storage and orphan counts remain repository-wide.
pub fn summary_with_references(
    repo: &Repository,
    records: &[Occurrence],
    referenced: &BTreeSet<String>,
) -> Result<Summary> {
    let mut hashes = BTreeSet::new();
    let mut categories = BTreeMap::new();
    for r in records {
        *categories.entry(r.file_type.clone()).or_insert(0) += 1;
        if hashes.insert(r.sha256.clone()) {
            let path = repo.object(&r.sha256)?;
            crate::repository::security::validate_file(&path, repo.mode())?;
            ensure!(
                std::fs::metadata(path)?.len() == r.size,
                "manifest/object size mismatch"
            );
        }
    }
    let mut stored = 0;
    let mut allocated = 0;
    let mut stored_objects = 0;
    let mut orphan_objects = 0;
    for entry in walkdir::WalkDir::new(repo.root().join("objects"))
        .follow_links(false)
        .min_depth(1)
    {
        let entry = entry?;
        ensure!(
            !entry.file_type().is_symlink(),
            "symlink in canonical storage"
        );
        if entry.file_type().is_dir() {
            continue;
        }
        let hash = entry
            .file_name()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid object name"))?;
        ensure!(
            valid_hash(hash) && entry.path() == repo.object(hash)?,
            "unexpected canonical object path"
        );
        crate::repository::security::validate_file(entry.path(), repo.mode())?;
        let meta = entry.metadata()?;
        stored += meta.len();
        stored_objects += 1;
        if !referenced.contains(hash) {
            orphan_objects += 1;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            allocated += meta.blocks() * 512;
        }
        #[cfg(not(unix))]
        {
            allocated += meta.len();
        }
    }
    Ok(Summary {
        nested: crate::ingest::nested::summary(repo, records)?,
        occurrences: records.len(),
        unique_samples: hashes.len(),
        duplicate_occurrences: records.len() - hashes.len(),
        stored_objects,
        orphan_objects,
        logical_bytes: records.iter().map(|r| r.size).sum(),
        stored_bytes: stored,
        allocated_bytes: allocated,
        per_category: categories,
        security_mode: repo.mode(),
        by_detected_family: count_by(records, |r| r.detection.detected_family.as_str().into()),
        by_detected_format: count_by(records, |r| r.detection.detected_format.as_str().into()),
        by_original_extension: count_by(records, |r| {
            crate::detection::mismatch::extension(&r.original_entry_name)
        }),
        by_mismatch_status: count_by(records, |r| r.mismatch.status.as_str().into()),
        extension_format: cross_counts(records.iter()),
        mismatch_pairs: cross_counts(
            records
                .iter()
                .filter(|r| r.mismatch.status == crate::detection::mismatch::Status::Mismatch),
        ),
    })
}

#[derive(Debug, Serialize)]
pub struct Counts {
    pub occurrences: usize,
    pub unique_hashes: usize,
}
#[derive(Debug, Serialize)]
pub struct CrossCount {
    pub original_extension: String,
    pub detected_format: String,
    #[serde(flatten)]
    pub counts: Counts,
}
fn count_by(
    records: &[Occurrence],
    key: impl Fn(&Occurrence) -> String,
) -> BTreeMap<String, Counts> {
    let mut groups: BTreeMap<String, (usize, BTreeSet<&str>)> = BTreeMap::new();
    for record in records {
        let group = groups.entry(key(record)).or_default();
        group.0 += 1;
        group.1.insert(&record.sha256);
    }
    groups
        .into_iter()
        .map(|(key, (occurrences, hashes))| {
            (
                key,
                Counts {
                    occurrences,
                    unique_hashes: hashes.len(),
                },
            )
        })
        .collect()
}
fn cross_counts<'a>(records: impl Iterator<Item = &'a Occurrence>) -> Vec<CrossCount> {
    let mut groups: BTreeMap<(String, String), (usize, BTreeSet<&str>)> = BTreeMap::new();
    for r in records {
        let group = groups
            .entry((
                crate::detection::mismatch::extension(&r.original_entry_name),
                r.detection.detected_format.as_str().into(),
            ))
            .or_default();
        group.0 += 1;
        group.1.insert(&r.sha256);
    }
    groups
        .into_iter()
        .map(
            |((original_extension, detected_format), (occurrences, hashes))| CrossCount {
                original_extension,
                detected_format,
                counts: Counts {
                    occurrences,
                    unique_hashes: hashes.len(),
                },
            },
        )
        .collect()
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ReportFormat {
    #[default]
    Table,
    Json,
    Csv,
}
#[derive(Debug, Serialize)]
pub struct MismatchRow<'a> {
    pub sha256: &'a str,
    pub occurrence_id: &'a str,
    pub source_archive: &'a str,
    pub original_entry_name: &'a str,
    pub original_extension: &'a str,
    pub detected_family: &'a str,
    pub detected_format: &'a str,
    pub mime_type: Option<&'a str>,
    pub confidence: &'a str,
    pub mismatch_status: &'a str,
    pub mismatch_reason: &'a str,
    pub detector_version: &'a str,
}
#[derive(Debug, Serialize)]
pub struct MismatchReport<'a> {
    /// Counts for all occurrences, before filtering rows.
    pub counts: BTreeMap<String, usize>,
    pub rows: Vec<MismatchRow<'a>>,
}
pub fn mismatches<'a>(
    records: &'a [Occurrence],
    statuses: &[crate::detection::mismatch::Status],
    minimum: crate::detection::classifier::Confidence,
    all: bool,
) -> MismatchReport<'a> {
    let mut counts = BTreeMap::new();
    let mut rows = vec![];
    let mut sorted: Vec<_> = records.iter().collect();
    sorted.sort_by(|a, b| {
        (&a.source_path, &a.original_entry_name, &a.occurrence_id).cmp(&(
            &b.source_path,
            &b.original_entry_name,
            &b.occurrence_id,
        ))
    });
    for r in sorted {
        *counts.entry(r.mismatch.status.as_str().into()).or_insert(0) += 1;
        let included = if !statuses.is_empty() {
            statuses.contains(&r.mismatch.status)
        } else {
            all || r.mismatch.status == crate::detection::mismatch::Status::Mismatch
        };
        if !included || r.detection.confidence < minimum {
            continue;
        }
        rows.push(MismatchRow {
            sha256: &r.sha256,
            occurrence_id: &r.occurrence_id,
            source_archive: &r.source_archive,
            original_entry_name: &r.original_entry_name,
            original_extension: &r.original_extension,
            detected_family: r.detection.detected_family.as_str(),
            detected_format: r.detection.detected_format.as_str(),
            mime_type: r.detection.mime_type.as_deref(),
            confidence: r.detection.confidence.as_str(),
            mismatch_status: r.mismatch.status.as_str(),
            mismatch_reason: &r.mismatch.reason,
            detector_version: &r.detection.detector_version,
        });
    }
    MismatchReport { counts, rows }
}
impl MismatchReport<'_> {
    pub fn write(&self, mut writer: impl std::io::Write, format: ReportFormat) -> Result<()> {
        match format {
            ReportFormat::Json => {
                serde_json::to_writer_pretty(&mut writer, self)?;
                writeln!(writer)?;
            }
            ReportFormat::Csv => {
                writeln!(
                    writer,
                    "sha256,occurrence_id,source_archive,original_entry_name,original_extension,detected_family,detected_format,mime_type,confidence,mismatch_status,mismatch_reason,detector_version"
                )?;
                for row in &self.rows {
                    let fields = [
                        row.sha256,
                        row.occurrence_id,
                        row.source_archive,
                        row.original_entry_name,
                        row.original_extension,
                        row.detected_family,
                        row.detected_format,
                        row.mime_type.unwrap_or(""),
                        row.confidence,
                        row.mismatch_status,
                        row.mismatch_reason,
                        row.detector_version,
                    ];
                    for (index, field) in fields.iter().enumerate() {
                        if index > 0 {
                            write!(writer, ",")?;
                        }
                        write!(writer, "\"{}\"", field.replace('"', "\"\""))?;
                    }
                    writeln!(writer)?;
                }
            }
            ReportFormat::Table => {
                writeln!(
                    writer,
                    "Original file\tExtension\tDetected format\tConfidence\tStatus"
                )?;
                for row in &self.rows {
                    writeln!(
                        writer,
                        "{}\t{}\t{}\t{}\t{}",
                        crate::app::presentation::safe_text(row.original_entry_name),
                        crate::app::presentation::safe_text(row.original_extension),
                        row.detected_format,
                        row.confidence,
                        row.mismatch_status
                    )?;
                }
                writeln!(
                    writer,
                    "Counts (all occurrences): {}",
                    serde_json::to_string(&self.counts)?
                )?;
            }
        }
        Ok(())
    }
}
