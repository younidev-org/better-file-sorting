//! Explicit logical removal and conservative, journaled orphan reclamation.
use super::{
    metadata, security,
    storage::{Repository, valid_hash},
};
use crate::{
    app::{
        config::SecurityMode,
        presentation::{Progress, byte_progress},
    },
    ingest::discovery::check_path,
    selection::Filters,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufReader, Write},
    path::Path,
};
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub selected_occurrences: usize,
    pub candidate_objects: usize,
    pub bytes: u64,
    pub pinned: usize,
    pub dry_run: bool,
    pub occurrence_ids: Vec<String>,
    pub hashes: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    hashes: BTreeSet<String>,
}
fn read_json(path: &Path) -> Result<serde_json::Value> {
    security::validate_file(path, SecurityMode::Standard)?;
    ensure!(
        fs::metadata(path)?.len() <= 16 * 1024 * 1024,
        "cleanup metadata exceeds 16 MiB"
    );
    Ok(serde_json::from_reader(fs::File::open(path)?)?)
}
pub fn removed(root: &Path) -> Result<BTreeSet<String>> {
    super::catalog::read(root)?.removed()
}
fn publish(root: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let directory = root.join("operations");
    security::private_dir(&directory)?;
    let target = directory.join(name);
    check_path(&target)?;
    if target.try_exists()? {
        security::validate_file(&target, SecurityMode::Standard)?;
    }
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    serde_json::to_writer(&mut file, value)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist(target)?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
pub fn remove(root: &Path, filters: &Filters, dry_run: bool, confirm: bool) -> Result<Report> {
    filters.validate()?;
    ensure!(
        !filters.is_empty(),
        "remove requires an explicit nonempty selector"
    );
    ensure!(dry_run || confirm, "remove requires --confirm");
    let planning = Progress::new(None, "Loading records for removal");
    let repo = Repository::existing(root)?;
    ensure!(
        !crate::operations::status(repo.root())?
            .iter()
            .any(|r| r.state == "running"),
        "active operations prevent cleanup"
    );
    let mut rows = metadata::load_all(repo.root())?;
    let removed = removed(repo.root())?;
    rows.retain(|row| !removed.contains(&row.occurrence_id));
    let selected: BTreeSet<_> = metadata::select(repo.root(), filters)?
        .into_iter()
        .map(|r| r.occurrence_id)
        .collect();
    drop(planning);
    let progress = Progress::new(Some(rows.len() as u64), "Checking removal records");
    for row in rows.iter().filter(|r| !selected.contains(&r.occurrence_id)) {
        if let Some(nested) = &row.nested
            && let Some(parent) = &nested.parent_occurrence_id
        {
            ensure!(
                rows.iter().any(|p| &p.occurrence_id == parent
                    && p.sha256 == nested.parent_sha256
                    && !selected.contains(parent)),
                "removal would leave retained nested ancestry dangling"
            );
        }
        progress.0.inc(1);
    }
    let mut hashes = BTreeSet::new();
    let mut report = Report {
        selected_occurrences: selected.len(),
        dry_run,
        ..Default::default()
    };
    for row in rows.iter().filter(|r| selected.contains(&r.occurrence_id)) {
        if hashes.insert(&row.sha256) {
            report.bytes = report
                .bytes
                .checked_add(row.size)
                .ok_or_else(|| anyhow::anyhow!("byte count overflow"))?;
        }
        progress.0.inc(1);
    }
    report.candidate_objects = hashes.len();
    report.occurrence_ids = selected.iter().cloned().collect();
    report.hashes = hashes.into_iter().cloned().collect();
    report.pinned = rows
        .iter()
        .filter(|r| !selected.contains(&r.occurrence_id))
        .map(|r| &r.sha256)
        .collect::<BTreeSet<_>>()
        .len();
    if !dry_run && !selected.is_empty() {
        progress.0.set_message("publishing removal");
        repo.with_catalog(|catalog| catalog.remove(&selected))?;
    }
    Ok(report)
}
fn validate_extraction(value: &serde_json::Value) -> Result<()> {
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Child {
        index: usize,
        name: String,
        sha256: String,
        size: u64,
        encrypted: bool,
        file_type: String,
        detection: crate::detection::classifier::Detection,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Receipt {
        checksum: String,
        schema_version: u32,
        archive_hash: String,
        policy: String,
        entries: usize,
        bytes: u64,
        children: Vec<Child>,
    }
    let receipt: Receipt = serde_json::from_value(value.clone())?;
    ensure!(
        receipt.schema_version == 1
            && valid_hash(&receipt.archive_hash)
            && valid_hash(&receipt.checksum),
        "invalid extraction receipt identity"
    );
    let checksum = metadata::digest(&serde_json::to_vec(&(
        receipt.schema_version,
        &receipt.archive_hash,
        &receipt.policy,
        receipt.entries,
        receipt.bytes,
        &receipt.children,
    ))?);
    ensure!(
        checksum == receipt.checksum,
        "corrupt extraction receipt checksum"
    );
    let mut indices = BTreeSet::new();
    let mut bytes = 0u64;
    for child in receipt.children {
        ensure!(
            valid_hash(&child.sha256)
                && child.index < receipt.entries
                && indices.insert(child.index),
            "invalid extraction receipt child"
        );
        bytes = bytes
            .checked_add(child.size)
            .ok_or_else(|| anyhow::anyhow!("receipt size overflow"))?;
    }
    ensure!(
        bytes <= receipt.bytes,
        "invalid extraction receipt accounting"
    );
    Ok(())
}
fn collect_hashes(value: &serde_json::Value, pins: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(s) if valid_hash(s) => {
            pins.insert(s.clone());
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_hashes(value, pins)
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_hashes(value, pins)
            }
        }
        _ => {}
    }
}
pub(crate) fn audit_metadata(repo: &Repository) -> Result<std::collections::BTreeMap<String, u64>> {
    let retained_hashes = validated_pins(repo)?;
    let mut objects = std::collections::BTreeMap::new();
    for category in ["ingest", "extraction"] {
        let directory = repo.root().join("operations").join(category);
        if !directory.try_exists()? {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let value = read_json(&entry?.path())?;
            let rows = value[if category == "ingest" {
                "records"
            } else {
                "children"
            }]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("invalid object reference list"))?;
            for row in rows {
                let hash = row["sha256"]
                    .as_str()
                    .filter(|h| valid_hash(h))
                    .ok_or_else(|| anyhow::anyhow!("invalid object reference hash"))?;
                let size = row["size"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("invalid object reference size"))?;
                if let Some(old) = objects.insert(hash.to_owned(), size) {
                    ensure!(old == size, "conflicting receipt object sizes");
                }
            }
        }
    }
    let records = metadata::load_all(repo.root())?;
    let identities: std::collections::BTreeMap<_, _> = records
        .iter()
        .map(|r| (r.occurrence_id.as_str(), r))
        .collect();
    let catalog = super::catalog::read(repo.root())?;
    for generation in catalog.views()? {
        for view in catalog.view_plan(&generation)? {
            let row = identities
                .get(view.occurrence_id.as_str())
                .ok_or_else(|| anyhow::anyhow!("view references unknown occurrence"))?;
            ensure!(row.sha256 == view.sha256, "view hash reference mismatch");
            objects.insert(row.sha256.clone(), row.size);
        }
    }
    for hash in retained_hashes {
        let path = repo.object(&hash)?;
        if path.try_exists()? {
            objects.entry(hash).or_insert(fs::metadata(path)?.len());
        }
    }
    Ok(objects)
}
fn validated_pins(repo: &Repository) -> Result<BTreeSet<String>> {
    let mut pins = super::catalog::read(repo.root())?.referenced_hashes()?;
    // Unknown recovery schemas stop reclamation rather than guessing their references.
    let operations = repo.root().join("operations");
    check_path(&operations)?;
    if operations.try_exists()? {
        for entry in walkdir::WalkDir::new(&operations)
            .min_depth(1)
            .follow_links(false)
        {
            let entry = entry?;
            check_path(entry.path())?;
            let relative = entry.path().strip_prefix(&operations)?;
            if entry.file_type().is_dir() {
                ensure!(
                    relative.components().count() == 1
                        && matches!(
                            relative.to_str(),
                            Some(
                                "ingest"
                                    | "extraction"
                                    | "trees"
                                    | "analysis"
                                    | "export"
                                    | "history"
                            )
                        ),
                    "unknown operation directory prevents prune"
                );
                continue;
            }
            if relative == Path::new("removal.json") || relative == Path::new("prune.json") {
                continue;
            }
            if relative.parent() == Some(Path::new("history")) {
                if entry.path().extension().is_some_and(|e| e == "lock") {
                    security::validate_file(entry.path(), SecurityMode::Standard)?;
                    continue;
                }
                let value = read_json(entry.path())?;
                let record: crate::operations::Record = serde_json::from_value(value.clone())?;
                ensure!(
                    record.schema_version == 1,
                    "unknown history schema prevents prune"
                );
                collect_hashes(&value, &mut pins);
                continue;
            }
            ensure!(
                relative.components().count() == 2
                    && entry.path().extension().is_some_and(|e| e == "json"),
                "unknown operation metadata prevents prune"
            );
            let value = read_json(entry.path())?;
            let category = relative.parent().and_then(Path::to_str).unwrap_or("");
            let fields: &[&str] = match category {
                "ingest" => &["schema_version", "input_hash", "fingerprint", "records"],
                "extraction" => &[
                    "checksum",
                    "schema_version",
                    "archive_hash",
                    "policy",
                    "entries",
                    "bytes",
                    "children",
                ],
                "trees" => &[
                    "schema_version",
                    "root_occurrence_id",
                    "input_hash",
                    "extraction_policy",
                    "max_depth",
                    "max_total_expanded_bytes",
                    "max_total_entries",
                    "completed",
                ],
                "analysis" => &[
                    "schema_version",
                    "accepted",
                    "reused_occurrences",
                    "failures",
                    "metrics",
                    "outcomes",
                    "warnings",
                ],
                "export" => &["version", "fingerprint", "archives", "completed"],
                _ => anyhow::bail!("unknown operation schema prevents prune"),
            };
            let object = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid operation record"))?;
            ensure!(
                object.len() == fields.len() && fields.iter().all(|key| object.contains_key(*key)),
                "unknown operation schema fields prevent prune"
            );
            let version = if category == "export" {
                "version"
            } else {
                "schema_version"
            };
            ensure!(
                value[version] == 1,
                "unknown operation schema version prevents prune"
            );
            if category == "extraction" {
                validate_extraction(&value)?;
            }
            if category == "ingest" {
                let rows: Vec<metadata::Occurrence> =
                    serde_json::from_value(value["records"].clone())?;
                for row in rows {
                    row.validate()?;
                }
            }
            collect_hashes(&value, &mut pins);
        }
    }
    removed(repo.root())?;
    for entry in walkdir::WalkDir::new(repo.root().join("reports"))
        .min_depth(1)
        .follow_links(false)
    {
        let entry = entry?;
        check_path(entry.path())?;
        let relative = entry
            .path()
            .strip_prefix(repo.root().join("reports"))?
            .to_path_buf();
        if relative == Path::new("dataset.json") {
            security::validate_file(entry.path(), SecurityMode::Standard)?;
            // Dataset reports scale with catalog rows, unlike small recovery records.
            let limit = fs::metadata(repo.root().join(super::catalog::FILE_NAME))?
                .len()
                .saturating_mul(2)
                .saturating_add(16 * 1024 * 1024);
            ensure!(
                fs::metadata(entry.path())?.len() <= limit,
                "oversized dataset report"
            );
            let data: crate::repository::derive::DatasetReport =
                serde_json::from_reader(BufReader::new(fs::File::open(entry.path())?))?;
            ensure!(
                data.schema_version == 1
                    && valid_hash(&data.fingerprint)
                    && data.selected_hashes.iter().all(|h| valid_hash(h))
                    && data.selected_occurrence_ids.iter().all(|h| valid_hash(h)),
                "invalid dataset report"
            );
        } else if relative == Path::new("reclassification") && entry.file_type().is_dir() {
        } else if relative.parent() == Some(Path::new("reclassification"))
            && entry.file_type().is_file()
        {
            let value = read_json(entry.path())?;
            let _: crate::detection::classifier::Detection = serde_json::from_value(value.clone())?;
            let name = entry.file_name().to_string_lossy();
            let hash = name
                .get(..64)
                .filter(|h| valid_hash(h))
                .ok_or_else(|| anyhow::anyhow!("invalid classification checkpoint name"))?;
            pins.insert(hash.to_owned());
            collect_hashes(&value, &mut pins);
        } else if relative.components().count() == 1
            && relative.extension().is_some_and(|e| e == "json")
            && relative.file_stem().is_some_and(|stem| {
                stem.to_str()
                    .and_then(|s| s.split_once("-run-"))
                    .is_some_and(|(timestamp, suffix)| {
                        !suffix.is_empty()
                            && chrono::NaiveDateTime::parse_from_str(timestamp, "%Y%m%dT%H%M%S%.fZ")
                                .is_ok()
                    })
            })
        {
            let value = read_json(entry.path())?;
            let fields = [
                "run_id",
                "accepted",
                "skipped_files",
                "reused_occurrences",
                "failures",
                "interrupted",
                "elapsed_seconds",
                "bytes_per_second",
                "summary",
                "first_failure",
                "failure_details",
                "zip",
                "nested",
            ];
            let object = value
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("invalid run report"))?;
            ensure!(
                object.keys().all(|k| fields.contains(&k.as_str()))
                    && fields[..9].iter().all(|k| object.contains_key(*k)),
                "unknown run report schema prevents prune"
            );
            ensure!(
                value["run_id"].as_str() == relative.file_stem().and_then(|s| s.to_str()),
                "run report identity mismatch"
            );
            collect_hashes(&value, &mut pins);
        } else {
            anyhow::bail!("unsupported reports prevent prune");
        }
    }
    let views = repo.root().join("views");
    for entry in walkdir::WalkDir::new(&views)
        .min_depth(1)
        .follow_links(false)
    {
        let entry = entry?;
        check_path(entry.path())?;
        if entry.file_type().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        match name.as_ref() {
            "rules.json" => {
                let _: crate::organization::rules::Rules =
                    serde_json::from_value(read_json(entry.path())?)?;
            }
            "CURRENT" => {
                security::validate_file(entry.path(), SecurityMode::Standard)?;
                ensure!(
                    fs::metadata(entry.path())?.len() <= 4096,
                    "oversized current view pointer"
                );
                let text = fs::read_to_string(entry.path())?;
                let name = text.trim();
                ensure!(
                    name.starts_with("view-")
                        && !name.contains(['/', '\\'])
                        && !name.contains("..")
                        && repo.root().join("views").join(name).is_dir(),
                    "invalid current view pointer"
                );
            }
            _ => {
                // Payloads are under a group directory. Unknown generation metadata may hold references.
                ensure!(
                    entry.path().strip_prefix(&views)?.components().count() >= 3
                        && entry.file_type().is_file(),
                    "unsupported view metadata prevents prune"
                );
            }
        }
    }
    Ok(pins)
}
pub fn prune(root: &Path, dry_run: bool, confirm: bool) -> Result<Report> {
    ensure!(dry_run || confirm, "prune requires --confirm");
    let scanning = Progress::new(None, "Scanning retained references");
    let repo = Repository::existing(root)?;
    ensure!(
        !crate::operations::status(repo.root())?
            .iter()
            .any(|r| r.state == "running"),
        "active operations prevent cleanup"
    );
    let pins = validated_pins(&repo)?;
    let operations = repo.root().join("operations");
    let journal_path = operations.join("prune.json");
    check_path(&journal_path)?;
    if journal_path.try_exists()? {
        let previous: Journal = serde_json::from_value(read_json(&journal_path)?)?;
        ensure!(
            previous.schema_version == 1 && previous.hashes.iter().all(|h| valid_hash(h)),
            "invalid prune journal"
        );
    }
    scanning.0.set_prefix("Scanning stored objects");
    let mut scanned = 0u64;
    let mut candidates = BTreeMap::new();
    let mut report = Report {
        pinned: pins.len(),
        dry_run,
        ..Default::default()
    };
    for prefix in fs::read_dir(repo.root().join("objects"))? {
        let prefix = prefix?;
        check_path(&prefix.path())?;
        ensure!(prefix.file_type()?.is_dir(), "invalid object prefix");
        for entry in fs::read_dir(prefix.path())? {
            let entry = entry?;
            let hash = entry.file_name().to_string_lossy().into_owned();
            ensure!(
                valid_hash(&hash) && entry.path() == repo.object(&hash)?,
                "invalid canonical object path"
            );
            security::validate_file(&entry.path(), repo.mode())?;
            scanned += 1;
            scanning.streaming_message(|| format!("{scanned} objects checked"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if fs::metadata(entry.path())?.nlink() > 1 {
                    report.pinned += usize::from(!pins.contains(&hash));
                    continue;
                }
            }
            if !pins.contains(&hash) {
                let size = fs::metadata(entry.path())?.len();
                report.bytes = report
                    .bytes
                    .checked_add(size)
                    .ok_or_else(|| anyhow::anyhow!("byte count overflow"))?;
                candidates.insert(hash, size);
            }
        }
    }
    report.candidate_objects = candidates.len();
    report.hashes = candidates.keys().cloned().collect();
    drop(scanning);
    if !dry_run && (!candidates.is_empty() || journal_path.try_exists()?) {
        let progress = Progress::new(Some(candidates.len() as u64), "Pruning objects");
        let message =
            |reclaimed| format!("{} reclaimed", byte_progress(reclaimed, Some(report.bytes)));
        let mut reclaimed = 0u64;
        progress.0.set_message(message(reclaimed));
        publish(
            repo.root(),
            "prune.json",
            &Journal {
                schema_version: 1,
                hashes: candidates.keys().cloned().collect(),
            },
        )?;
        for (hash, size) in candidates {
            let path = repo.object(&hash)?;
            fs::remove_file(&path)?;
            reclaimed += size;
            progress.0.inc(1);
            progress.0.set_message(message(reclaimed));
            fs::File::open(path.parent().expect("object parent"))?.sync_all()?;
        }
        fs::remove_file(&journal_path)?;
        fs::File::open(operations)?.sync_all()?;
        progress.0.force_draw();
    }
    Ok(report)
}
