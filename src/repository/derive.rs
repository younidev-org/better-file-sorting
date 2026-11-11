//! Build independent repositories by merging, sampling, or partitioning records.
//!
//! Each output keeps the stored archive ancestors needed by its selected
//! descendants. Additional ancestors are structural records, so they preserve
//! provenance while staying out of ordinary selection counts.
use super::{
    metadata::{self, Occurrence},
    security,
    storage::Repository,
};
use crate::{app::config::SecurityMode, selection::Filters};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

/// Source repositories, destination, and publication mode for a derived dataset.
pub struct Options {
    pub sources: Vec<PathBuf>,
    pub output: PathBuf,
    pub kind: Kind,
    pub dry_run: bool,
    pub resume: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub enum Kind {
    Merge,
    Sample(SampleOptions),
    Split { by: SplitBy },
}
#[derive(Debug, Serialize, Deserialize)]
pub enum SplitBy {
    Extension,
    Format,
}
#[derive(Debug, Serialize, Deserialize)]
/// Deterministic sampling settings applied after filtering.
///
/// Set exactly one of `count` and `percentage`. Percentage targets round down.
/// The seed orders candidates within each stratum.
pub struct SampleOptions {
    pub count: Option<usize>,
    pub percentage: Option<f64>,
    pub seed: u64,
    pub stratify: Vec<Stratum>,
    pub unit: SamplingUnit,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum Stratum {
    IngestDate,
    Family,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum SamplingUnit {
    #[default]
    UniqueHash,
    Occurrence,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Allocation {
    pub stratum: Vec<String>,
    pub eligible: usize,
    pub selected: usize,
}
#[derive(Debug, Serialize, Deserialize)]
/// Reproducibility record written to `reports/dataset.json`.
///
/// Source fingerprints identify the catalog snapshots used for selection.
/// Selected records and added archive ancestors are reported separately.
pub struct DatasetReport {
    pub schema_version: u32,
    pub algorithm_version: String,
    pub fingerprint: String,
    pub source_snapshots: BTreeMap<PathBuf, String>,
    pub filters: Filters,
    pub settings: Kind,
    pub allocations: Vec<Allocation>,
    pub selected_occurrence_ids: Vec<String>,
    pub selected_hashes: Vec<String>,
    #[serde(default)]
    pub ancestry_occurrence_ids: Vec<String>,
    #[serde(default)]
    pub ancestry_hashes: Vec<String>,
    pub detector_versions: Vec<String>,
}
const ALGORITHM: &str = "bfsort-dataset-v3";
#[derive(Debug, Serialize)]
pub struct GroupReport {
    pub name: String,
    pub occurrences: usize,
    pub unique_objects: usize,
    pub estimated_copy_bytes: u64,
    pub ancestry_additions: usize,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub requested_occurrences: usize,
    pub occurrences: usize,
    pub unique_objects: usize,
    pub estimated_copy_bytes: u64,
    pub ancestry_additions: usize,
    pub groups: Vec<GroupReport>,
    pub reused_objects: usize,
    pub report_paths: Vec<PathBuf>,
}
fn interrupted(cancelled: &AtomicBool) -> Result<()> {
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    Ok(())
}
/// Domain-separated SHA-256 ranking of the seed and selected sampling identity.
fn rank(seed: u64, identity: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ALGORITHM.as_bytes());
    hash.update([0]);
    hash.update(seed.to_be_bytes());
    hash.update(identity.as_bytes());
    hash.finalize().into()
}
fn sample(
    mut rows: Vec<Occurrence>,
    options: &SampleOptions,
) -> Result<(Vec<Occurrence>, Vec<Allocation>)> {
    ensure!(
        options.count.is_some() != options.percentage.is_some(),
        "supply exactly one of count or percentage"
    );
    ensure!(
        options
            .stratify
            .iter()
            .enumerate()
            .all(|(i, s)| !options.stratify[..i].contains(s)),
        "duplicate sampling stratum"
    );
    rows.sort_by(|a, b| a.occurrence_id.cmp(&b.occurrence_id));
    if options.unit == SamplingUnit::UniqueHash {
        let mut hashes = BTreeSet::new();
        rows.retain(|row| hashes.insert(row.sha256.clone()));
    }
    let population = rows.len();
    let count = if let Some(count) = options.count {
        count
    } else {
        let percentage = options.percentage.expect("validated percentage");
        ensure!(
            percentage.is_finite() && (0.0..=100.0).contains(&percentage),
            "percentage must be finite and between 0 and 100"
        );
        let target = (population as f64 * percentage / 100.0).floor();
        ensure!(
            target.is_finite() && target >= 0.0 && target <= population as f64,
            "percentage sample size overflow"
        );
        (target as usize).min(population)
    };
    ensure!(
        count <= population,
        "sample count exceeds eligible population"
    );
    let mut groups = BTreeMap::<Vec<String>, Vec<Occurrence>>::new();
    for row in rows {
        let key = options
            .stratify
            .iter()
            .map(|s| match s {
                Stratum::IngestDate => row.ingest_date.clone(),
                Stratum::Family => row.detection.detected_family.as_str().to_owned(),
            })
            .collect();
        groups.entry(key).or_default().push(row);
    }
    let mut allocations = Vec::new();
    let mut remainders = Vec::new();
    let mut allocated = 0;
    for (key, rows) in &groups {
        let product = (count as u128) * (rows.len() as u128);
        let share = if population == 0 {
            0
        } else {
            (product / population as u128) as usize
        };
        let remainder = if population == 0 {
            0
        } else {
            product % population as u128
        };
        allocated += share;
        allocations.push(Allocation {
            stratum: key.clone(),
            eligible: rows.len(),
            selected: share,
        });
        remainders.push((remainder, key.clone(), allocations.len() - 1));
    }
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, _, index) in remainders.into_iter().take(count - allocated) {
        allocations[index].selected += 1;
    }
    let mut selected = Vec::new();
    for allocation in &allocations {
        let rows = groups
            .get_mut(&allocation.stratum)
            .expect("allocated group");
        rows.sort_by_cached_key(|row| {
            (
                rank(
                    options.seed,
                    if options.unit == SamplingUnit::UniqueHash {
                        &row.sha256
                    } else {
                        &row.occurrence_id
                    },
                ),
                row.occurrence_id.clone(),
            )
        });
        selected.extend(rows.drain(..allocation.selected));
    }
    Ok((selected, allocations))
}
fn group(record: &Occurrence, by: &SplitBy) -> String {
    match by {
        SplitBy::Format => record.detection.detected_format.as_str().to_owned(),
        SplitBy::Extension => {
            let extension = record
                .original_extension
                .trim_start_matches('.')
                .to_ascii_lowercase();
            if extension.is_empty() {
                "unknown".to_owned()
            }
            // Encoding all bytes prevents path traversal and case/escape collisions.
            else {
                format!(
                    "ext-{}",
                    extension
                        .bytes()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                )
            }
        }
    }
}
fn object_summary(records: &[Occurrence]) -> Result<(usize, u64)> {
    let mut objects = BTreeMap::new();
    for record in records {
        if let Some(size) = objects.insert(&record.sha256, record.size) {
            ensure!(size == record.size, "conflicting object sizes");
        }
    }
    let bytes = objects.values().try_fold(0u64, |total, size| {
        total
            .checked_add(*size)
            .ok_or_else(|| anyhow::anyhow!("copy size overflow"))
    })?;
    Ok((objects.len(), bytes))
}

/// Plan or publish a derived dataset with verified copies of its objects.
///
/// Dry runs inspect source metadata and object attributes. Actual copies
/// require standard repositories. Resumable runs retain private staging
/// and verify completed work against the same source snapshots and settings.
pub fn run(options: &Options, filter: &Filters, cancelled: &AtomicBool) -> Result<Report> {
    use crate::app::presentation::{Progress, byte_progress, bytes};

    let planning = Progress::new(None, "Planning dataset objects");
    interrupted(cancelled)?;
    ensure!(
        !options.sources.is_empty(),
        "at least one source repository is required"
    );
    ensure!(
        matches!(options.kind, Kind::Merge) || options.sources.len() == 1,
        "sample and split require one source"
    );
    crate::ingest::discovery::check_path(&options.output)?;
    ensure!(
        options.resume || !options.output.try_exists()?,
        "destination already exists"
    );
    let parent = options
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let parent = parent.canonicalize()?;
    let destination = parent.join(
        options
            .output
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid destination"))?,
    );
    let mut paths = Vec::new();
    for source in &options.sources {
        crate::ingest::discovery::check_path(source)?;
        paths.push(source.canonicalize()?);
    }
    paths.sort();
    ensure!(
        paths.windows(2).all(|pair| pair[0] != pair[1]),
        "aliased source repositories"
    );
    for (index, source) in paths.iter().enumerate() {
        ensure!(
            !destination.starts_with(source) && !source.starts_with(&destination),
            "source and destination overlap"
        );
        ensure!(
            paths[index + 1..]
                .iter()
                .all(|other| !other.starts_with(source)),
            "overlapping source repositories"
        );
    }
    let sources = paths
        .iter()
        .map(|path| Repository::existing(path))
        .collect::<Result<Vec<_>>>()?;
    if !options.dry_run {
        ensure!(
            sources
                .iter()
                .all(|repo| repo.mode() == SecurityMode::Standard),
            "sealed-source transfer is unsupported; payloads are never unlocked automatically"
        );
    }
    let mut snapshots = BTreeMap::new();
    let mut records = BTreeMap::<String, Occurrence>::new();
    let mut owners = BTreeMap::new();
    let mut record_owners = BTreeMap::<String, Vec<usize>>::new();
    let mut source_records = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        super::catalog::read(source.root())?.integrity()?;
        let snapshot = metadata::load_all(source.root())?;
        snapshots.insert(
            source.root().to_path_buf(),
            metadata::digest(&serde_json::to_vec(&(
                &snapshot,
                super::cleanup::removed(source.root())?,
            ))?),
        );
        let removed = super::cleanup::removed(source.root())?;
        source_records.push(
            snapshot
                .into_iter()
                .filter(|row| !removed.contains(&row.occurrence_id))
                .map(|row| (row.occurrence_id.clone(), row))
                .collect::<BTreeMap<_, _>>(),
        );
        for record in metadata::select(source.root(), filter)? {
            interrupted(cancelled)?;
            security::validate_file(&source.object(&record.sha256)?, source.mode())?;
            ensure!(
                fs::metadata(source.object(&record.sha256)?)?.len() == record.size,
                "manifest/object size mismatch"
            );
            if let Some(previous) = records.get(&record.occurrence_id) {
                ensure!(
                    serde_json::to_value(previous)? == serde_json::to_value(&record)?,
                    "conflicting occurrence identity"
                );
                record_owners
                    .get_mut(&record.occurrence_id)
                    .expect("record owner")
                    .push(index);
            } else {
                record_owners.insert(record.occurrence_id.clone(), vec![index]);
                owners.entry(record.sha256.clone()).or_insert(index);
                records.insert(record.occurrence_id.clone(), record);
            }
        }
    }
    let selected: Vec<_> = records.into_values().collect();
    let (mut selected, allocations) = if let Kind::Sample(sample_options) = &options.kind {
        sample(selected, sample_options)?
    } else {
        (selected, Vec::new())
    };
    let fingerprint = metadata::digest(&serde_json::to_vec(&(
        ALGORITHM,
        &snapshots,
        filter,
        &options.kind,
        &destination,
    ))?);
    selected.sort_by(|a, b| a.occurrence_id.cmp(&b.occurrence_id));

    let mut groups = BTreeMap::<String, Vec<Occurrence>>::new();
    match &options.kind {
        Kind::Split { by } => {
            for record in &selected {
                groups
                    .entry(group(record, by))
                    .or_default()
                    .push(record.clone());
            }
        }
        _ => {
            groups.insert(String::new(), selected.clone());
        }
    }
    for rows in groups.values_mut() {
        *rows = ancestor_closure(rows, &source_records, &record_owners, &mut owners)?;
    }
    let mut all_rows = BTreeMap::<String, Occurrence>::new();
    for row in groups.values().flatten() {
        all_rows
            .entry(row.occurrence_id.clone())
            .and_modify(|previous| {
                if !row.structural {
                    previous.structural = false;
                }
            })
            .or_insert_with(|| row.clone());
        let source = &sources[owners[&row.sha256]];
        let path = source.object(&row.sha256)?;
        security::validate_file(&path, source.mode())?;
        ensure!(
            fs::metadata(path)?.len() == row.size,
            "manifest/object size mismatch"
        );
    }
    let all_rows: Vec<_> = all_rows.into_values().collect();
    let (unique_objects, _) = object_summary(&all_rows)?;
    let ancestry_additions = groups
        .values()
        .map(|rows| rows.iter().filter(|row| row.structural).count())
        .sum();
    let mut group_reports = Vec::new();
    let mut estimated_copy_bytes = 0u64;
    for (name, records) in &groups {
        let (unique_objects, bytes) = object_summary(records)?;
        estimated_copy_bytes = estimated_copy_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("copy size overflow"))?;
        group_reports.push(GroupReport {
            name: name.clone(),
            occurrences: records.iter().filter(|row| !row.structural).count(),
            unique_objects,
            estimated_copy_bytes: bytes,
            ancestry_additions: records.iter().filter(|row| row.structural).count(),
        });
    }
    let dataset_report = |rows: &[Occurrence]| -> Result<serde_json::Value> {
        let ids: Vec<_> = rows
            .iter()
            .filter(|row| !row.structural)
            .map(|r| r.occurrence_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let hashes: Vec<_> = rows
            .iter()
            .filter(|row| !row.structural)
            .map(|r| r.sha256.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let ancestry_ids: Vec<_> = rows
            .iter()
            .filter(|row| row.structural)
            .map(|row| row.occurrence_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let ancestry_hashes: Vec<_> = rows
            .iter()
            .filter(|row| row.structural)
            .map(|row| row.sha256.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let versions: Vec<_> = rows
            .iter()
            .map(|r| r.detection.detector_version.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(
            serde_json::json!({"schema_version":1,"algorithm_version":ALGORITHM,"fingerprint":fingerprint,"source_snapshots":snapshots,"filters":filter,"settings":options.kind,"allocations":allocations,"selected_occurrence_ids":ids,"selected_hashes":hashes,"ancestry_occurrence_ids":ancestry_ids,"ancestry_hashes":ancestry_hashes,"detector_versions":versions}),
        )
    };
    let container_report = if matches!(options.kind, Kind::Split { .. }) {
        let mut value = dataset_report(&all_rows)?;
        let ancestors: Vec<_> = groups
            .values()
            .flatten()
            .filter(|row| row.structural)
            .collect();
        value["ancestry_occurrence_ids"] = serde_json::to_value(
            ancestors
                .iter()
                .map(|row| &row.occurrence_id)
                .collect::<BTreeSet<_>>(),
        )?;
        value["ancestry_hashes"] = serde_json::to_value(
            ancestors
                .iter()
                .map(|row| &row.sha256)
                .collect::<BTreeSet<_>>(),
        )?;
        value["groups"] = serde_json::to_value(&group_reports)?;
        Some(value)
    } else {
        None
    };
    let mut report = Report {
        requested_occurrences: selected.len(),
        occurrences: selected.len(),
        unique_objects,
        estimated_copy_bytes,
        ancestry_additions,
        groups: group_reports,
        reused_objects: 0,
        report_paths: groups
            .keys()
            .map(|name| {
                if name.is_empty() {
                    destination.join("reports/dataset.json")
                } else {
                    destination.join(name).join("reports/dataset.json")
                }
            })
            .collect(),
    };
    if matches!(options.kind, Kind::Split { .. }) {
        report.report_paths.push(destination.join("dataset.json"));
    }
    interrupted(cancelled)?;
    if options.dry_run {
        return Ok(report);
    }
    drop(planning);
    let progress = Progress::new(
        Some(
            report
                .groups
                .iter()
                .map(|group| group.unique_objects as u64)
                .sum(),
        ),
        "Copying dataset objects",
    );
    let message = |copied, reused, reused_bytes| {
        format!(
            "{} processed · {} copied · {reused} reused ({})",
            byte_progress(copied + reused_bytes, Some(estimated_copy_bytes)),
            bytes(copied),
            bytes(reused_bytes)
        )
    };
    let mut copied_bytes = 0u64;
    let mut reused_bytes = 0u64;
    progress.0.set_message(message(0, 0, 0));
    // A resume stage and its lock survive cancellation; ordinary runs retain TempDir cleanup.
    let temporary;
    let stage;
    let _lock;
    let state;
    if options.resume {
        stage = parent.join(format!(
            ".bfsort-dataset-{}",
            metadata::digest(destination.as_os_str().as_encoded_bytes())
        ));
        ensure!(
            sources
                .iter()
                .all(|source| !stage.starts_with(source.root())
                    && !source.root().starts_with(&stage)),
            "resume staging overlaps a source repository"
        );
        security::private_dir(&stage)?;
        let lock_path = stage.join("lock");
        crate::ingest::discovery::check_path(&lock_path)?;
        let mut open = fs::OpenOptions::new();
        open.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let lock = open.open(&lock_path)?;
        security::validate_file(&lock_path, SecurityMode::Standard)?;
        lock.try_lock()
            .map_err(|_| anyhow::anyhow!("dataset resume is already in use"))?;
        _lock = Some(lock);
        let path = stage.join("state.sqlite3");
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let path = stage.join(format!("state.sqlite3{suffix}"));
            crate::ingest::discovery::check_path(&path)?;
            if path.try_exists()? {
                security::validate_file(&path, SecurityMode::Standard)?;
            }
        }
        if !path.try_exists()? {
            let temporary = tempfile::NamedTempFile::new_in(&stage)?;
            let connection = rusqlite::Connection::open(temporary.path())?;
            connection.pragma_update(None, "synchronous", "FULL")?;
            connection.execute_batch(
                "BEGIN;CREATE TABLE state(fingerprint TEXT NOT NULL);PRAGMA user_version=1;",
            )?;
            connection.execute("INSERT INTO state VALUES(?1)", [&fingerprint])?;
            connection.execute_batch("COMMIT;")?;
            drop(connection);
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(&path)?;
            File::open(&stage)?.sync_all()?;
        }
        let connection = rusqlite::Connection::open(&path)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "trusted_schema", false)?;
        let integrity: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        ensure!(integrity == "ok", "dataset resume database is corrupt");
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        ensure!(version == 1, "unsupported dataset resume schema");
        let rows: i64 = connection.query_row("SELECT count(*) FROM state", [], |r| r.get(0))?;
        ensure!(rows == 1, "invalid dataset resume state");
        let stored: String =
            connection.query_row("SELECT fingerprint FROM state", [], |r| r.get(0))?;
        ensure!(
            stored == fingerprint,
            "dataset source snapshot or settings changed"
        );
        state = Some(connection);
        temporary = None;
    } else {
        let directory = security::private_tempdir(&parent, ".bfsort-derived-")?;
        stage = directory.path().to_path_buf();
        temporary = Some(directory);
        _lock = None;
        state = None;
    }
    let result = stage.join("result");
    if destination.try_exists()? {
        ensure!(options.resume, "destination already exists");
        if matches!(options.kind, Kind::Split { .. }) {
            validate_report(
                &destination.join("dataset.json"),
                container_report.as_ref().expect("split report"),
            )?;
            let expected: BTreeSet<_> = groups
                .keys()
                .cloned()
                .chain(std::iter::once("dataset.json".to_owned()))
                .collect();
            let actual: BTreeSet<_> = fs::read_dir(&destination)?
                .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
                .collect::<Result<_>>()?;
            ensure!(actual == expected, "destination partitions changed");
        }
        for (name, rows) in &groups {
            let target = if name.is_empty() {
                destination.clone()
            } else {
                destination.join(name)
            };
            validate_finished(&target, rows, &dataset_report(rows)?, cancelled, |size| {
                report.reused_objects += 1;
                reused_bytes += size;
                progress.0.inc(1);
                progress
                    .0
                    .set_message(message(copied_bytes, report.reused_objects, reused_bytes));
            })?;
        }
        progress.0.force_draw();
        return Ok(report);
    }
    if matches!(options.kind, Kind::Split { .. }) {
        security::private_dir(&result)?;
    }
    for (name, rows) in &groups {
        let target = if name.is_empty() {
            result.clone()
        } else {
            result.join(name)
        };
        let repo = Repository::open(&target, SecurityMode::Standard)?;
        repo.with_catalog(|catalog| catalog.integrity())?;
        ensure!(
            super::cleanup::removed(repo.root())?.is_empty(),
            "staged dataset contains removed records"
        );
        let existing = metadata::load_all(repo.root())?;
        let expected: BTreeMap<_, _> = rows.iter().map(|r| (&r.occurrence_id, r)).collect();
        for row in &existing {
            ensure!(
                expected
                    .get(&row.occurrence_id)
                    .is_some_and(|expected| serde_json::to_value(expected).ok()
                        == serde_json::to_value(row).ok()),
                "unexpected staged metadata"
            );
        }
        let mut copied = BTreeSet::new();
        let mut pending = Vec::with_capacity(128);
        for row in parent_first(rows)? {
            interrupted(cancelled)?;
            if copied.insert(row.sha256.clone()) {
                let object = repo.object(&row.sha256)?;
                if object.try_exists()? {
                    verify_object(&repo, row, cancelled)?;
                    report.reused_objects += 1;
                    reused_bytes += row.size;
                } else {
                    let source = &sources[owners[&row.sha256]];
                    let mut input = File::open(source.object(&row.sha256)?)?;
                    let mut output = tempfile::NamedTempFile::new_in(repo.staging())?;
                    let mut hasher = Sha256::new();
                    let mut size = 0u64;
                    let mut buffer = [0u8; 65536];
                    loop {
                        interrupted(cancelled)?;
                        let count = input.read(&mut buffer)?;
                        if count == 0 {
                            break;
                        }
                        size = size
                            .checked_add(count as u64)
                            .ok_or_else(|| anyhow::anyhow!("object size overflow"))?;
                        ensure!(size <= row.size, "object exceeds recorded size");
                        hasher.update(&buffer[..count]);
                        output.write_all(&buffer[..count])?;
                        progress.streaming_message(|| {
                            message(copied_bytes + size, report.reused_objects, reused_bytes)
                        });
                    }
                    let hash: String = hasher
                        .finalize()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    ensure!(
                        size == row.size && hash == row.sha256,
                        "object checksum or size mismatch"
                    );
                    repo.commit(output, &row.sha256, size)?;
                    copied_bytes += size;
                }
                progress.0.inc(1);
                progress
                    .0
                    .set_message(message(copied_bytes, report.reused_objects, reused_bytes));
            }
            pending.push(row.clone());
            if pending.len() == 128 {
                metadata::store_many(&repo, &pending)?;
                pending.clear();
            }
        }
        metadata::store_many(&repo, &pending)?;
        let dataset = dataset_report(rows)?;
        let mut file = tempfile::NamedTempFile::new_in(&stage)?;
        serde_json::to_writer_pretty(&mut file, &dataset)?;
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        let report_path = repo.root().join("reports/dataset.json");
        crate::ingest::discovery::check_path(&report_path)?;
        if report_path.try_exists()? {
            security::validate_file(&report_path, SecurityMode::Standard)?;
        }
        file.persist(report_path)?;
        File::open(repo.root().join("reports"))?.sync_all()?;
    }
    if matches!(options.kind, Kind::Split { .. }) {
        let mut file = tempfile::NamedTempFile::new_in(&stage)?;
        serde_json::to_writer_pretty(&mut file, container_report.as_ref().expect("split report"))?;
        file.as_file().sync_all()?;
        file.persist(result.join("dataset.json"))?;
        File::open(&result)?.sync_all()?;
    }
    interrupted(cancelled)?;
    security::publish_directory(&result, &destination)?;
    File::open(&parent)?.sync_all()?;
    drop(state);
    drop(temporary);
    progress.0.force_draw();
    Ok(report)
}
fn same_provenance(left: &Occurrence, right: &Occurrence) -> Result<bool> {
    let mut left = left.clone();
    let mut right = right.clone();
    left.structural = false;
    right.structural = false;
    Ok(serde_json::to_value(left)? == serde_json::to_value(right)?)
}
fn ancestor_closure(
    selected: &[Occurrence],
    sources: &[BTreeMap<String, Occurrence>],
    record_owners: &BTreeMap<String, Vec<usize>>,
    owners: &mut BTreeMap<String, usize>,
) -> Result<Vec<Occurrence>> {
    let mut rows: BTreeMap<_, _> = selected
        .iter()
        .map(|row| (row.occurrence_id.clone(), row.clone()))
        .collect();
    let mut validated = BTreeSet::new();
    for selected in selected {
        for &index in &record_owners[&selected.occurrence_id] {
            let source = &sources[index];
            let mut row = selected;
            let mut seen = BTreeSet::new();
            loop {
                ensure!(
                    seen.insert(row.occurrence_id.clone()),
                    "nested ancestry cycle"
                );
                if validated.contains(&(index, row.occurrence_id.clone())) {
                    break;
                }
                let Some(nested) = &row.nested else { break };
                let Some(parent_id) = &nested.parent_occurrence_id else {
                    break;
                };
                let parent = source
                    .get(parent_id)
                    .ok_or_else(|| anyhow::anyhow!("missing retained nested ancestor"))?;
                ensure!(
                    parent.sha256 == nested.parent_sha256,
                    "nested ancestor hash mismatch"
                );
                ensure!(
                    crate::ingest::nested::is_zip(&parent.detection)
                        || (parent.file_type == "zip"
                            && parent.detection.detected_format
                                == crate::detection::classifier::Format::NotEvaluated),
                    "nested ancestor is not a ZIP container"
                );
                if let Some(previous) = rows.get(parent_id) {
                    ensure!(
                        same_provenance(previous, parent)?,
                        "conflicting nested ancestor identity"
                    );
                } else {
                    let mut ancestor = parent.clone();
                    ancestor.structural = true;
                    rows.insert(parent_id.clone(), ancestor);
                }
                owners.entry(parent.sha256.clone()).or_insert(index);
                row = parent;
            }
            validated.extend(seen.into_iter().map(|id| (index, id)));
        }
    }
    let rows: Vec<_> = rows.into_values().collect();
    parent_first(&rows)?;
    Ok(rows)
}
fn parent_first(rows: &[Occurrence]) -> Result<Vec<&Occurrence>> {
    let records: BTreeMap<_, _> = rows.iter().map(|row| (&row.occurrence_id, row)).collect();
    let mut children = BTreeMap::<&String, Vec<&String>>::new();
    let mut ready = BTreeSet::new();
    for row in rows {
        if let Some(parent) = row
            .nested
            .as_ref()
            .and_then(|nested| nested.parent_occurrence_id.as_ref())
        {
            let ancestor = records
                .get(parent)
                .ok_or_else(|| anyhow::anyhow!("missing nested ancestor"))?;
            ensure!(
                ancestor.sha256 == row.nested.as_ref().expect("nested").parent_sha256,
                "nested ancestor hash mismatch"
            );
            children.entry(parent).or_default().push(&row.occurrence_id);
        } else {
            ready.insert(&row.occurrence_id);
        }
    }
    let mut ordered = Vec::new();
    while let Some(id) = ready.pop_first() {
        ordered.push(records[id]);
        if let Some(children) = children.get(id) {
            ready.extend(children.iter().copied());
        }
    }
    ensure!(ordered.len() == rows.len(), "nested ancestry cycle");
    Ok(ordered)
}
fn verify_object(repo: &Repository, row: &Occurrence, cancelled: &AtomicBool) -> Result<()> {
    let path = repo.object(&row.sha256)?;
    security::validate_file(&path, repo.mode())?;
    ensure!(
        fs::metadata(&path)?.len() == row.size,
        "staged object size mismatch"
    );
    let hash = crate::ingest::nested::hash_file(&mut File::open(path)?, cancelled)?;
    ensure!(hash == row.sha256, "staged object checksum mismatch");
    Ok(())
}
fn validate_finished(
    target: &std::path::Path,
    expected: &[Occurrence],
    expected_report: &serde_json::Value,
    cancelled: &AtomicBool,
    mut on_reuse: impl FnMut(u64),
) -> Result<()> {
    let repo = Repository::existing(target)?;
    ensure!(
        repo.mode() == SecurityMode::Standard,
        "unexpected destination security mode"
    );
    validate_report(&repo.root().join("reports/dataset.json"), expected_report)?;
    super::catalog::read(repo.root())?.integrity()?;
    let mut actual = metadata::load_all(repo.root())?;
    actual.sort_by(|a, b| a.occurrence_id.cmp(&b.occurrence_id));
    ensure!(
        serde_json::to_value(&actual)? == serde_json::to_value(expected)?,
        "destination dataset metadata mismatch"
    );
    ensure!(
        super::cleanup::removed(repo.root())?.is_empty(),
        "destination contains removed records"
    );
    let mut hashes = BTreeSet::new();
    for row in &actual {
        if hashes.insert(&row.sha256) {
            verify_object(&repo, row, cancelled)?;
            on_reuse(row.size);
        }
    }
    Ok(())
}

fn validate_report(path: &std::path::Path, expected: &serde_json::Value) -> Result<()> {
    security::validate_file(path, SecurityMode::Standard)?;
    let expected_size = serde_json::to_vec_pretty(expected)?.len() as u64 + 1;
    ensure!(
        fs::metadata(path)?.len() <= expected_size,
        "oversized dataset report"
    );
    let actual: serde_json::Value = serde_json::from_reader(File::open(path)?)?;
    ensure!(actual == *expected, "destination dataset report mismatch");
    Ok(())
}
