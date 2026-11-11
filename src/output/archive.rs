//! Inspects ZIP metadata and exports rule-planned layouts as ZIP archives.
//! Input opening enforces configured archive limits; output publication uses private
//! temporary storage and refuses replacement of existing destinations. Export selection
//! is shared with preview so users see the same directory choices before publication.

use crate::{app::config::Limits, ingest::discovery::check_path};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    path::{Path, PathBuf},
};
use zip::{CompressionMethod, ZipArchive};
#[derive(Debug, Serialize)]
pub struct Entry {
    pub index: usize,
    pub name: String,
    pub size: u64,
    pub compressed_size: u64,
    pub encrypted: bool,
    pub compression: String,
    pub supported_compression: bool,
    pub directory: bool,
    pub unix_mode: Option<u32>,
}
#[derive(Debug, Serialize)]
pub struct Inspection {
    pub archive: String,
    pub entries: Vec<Entry>,
}

#[derive(Serialize)]
pub struct ZipExport {
    pub reused: bool,
    pub output: PathBuf,
    pub entries: Vec<crate::organization::rules::Planned>,
}

/// Resolve exact sorted-directory selections once for previews and publication.
pub fn plan_exports(
    plan: &[crate::organization::rules::Planned],
    config: &crate::app::config::Config,
    rules: &crate::organization::rules::Rules,
) -> Result<Vec<ZipExport>> {
    config.validate()?;
    let exact_groups =
        config.zip_each_dir && config.zip_dirs.is_empty() && rules.uses_format_fallback();
    let directories: BTreeSet<String> = if config.zip_dirs.is_empty() && config.zip_each_dir {
        plan.iter()
            .filter_map(|p| {
                let split = if exact_groups {
                    p.path.rsplit_once('/')
                } else {
                    p.path.split_once('/')
                };
                split.map(|(directory, _)| directory.to_string())
            })
            .collect()
    } else {
        config.zip_dirs.iter().cloned().collect()
    };
    let matches = |entry: &crate::organization::rules::Planned, directory: &str| {
        if exact_groups {
            entry
                .path
                .rsplit_once('/')
                .is_some_and(|(parent, _)| parent == directory)
        } else {
            entry.path.starts_with(&format!("{directory}/"))
        }
    };
    for directory in &directories {
        ensure!(
            plan.iter().any(|p| matches(p, directory)),
            "sorted directory not found: {directory}"
        );
    }
    if !config.zip_each_dir {
        let entries = plan
            .iter()
            .filter(|p| directories.is_empty() || directories.iter().any(|d| matches(p, d)))
            .cloned()
            .collect();
        return Ok(vec![ZipExport {
            reused: false,
            output: config.output.clone(),
            entries,
        }]);
    }
    ensure!(!directories.is_empty(), "no sorted directories to ZIP");
    let exports: Vec<_> = directories
        .iter()
        .map(|directory| ZipExport {
            reused: false,
            output: config.output.join(format!("{directory}.zip")),
            entries: plan
                .iter()
                .filter(|p| matches(p, directory))
                .cloned()
                .collect(),
        })
        .collect();
    for (index, a) in exports.iter().enumerate() {
        for b in &exports[index + 1..] {
            ensure!(
                !a.output.starts_with(&b.output) && !b.output.starts_with(&a.output),
                "ZIP output file conflicts with an output directory"
            );
        }
    }
    Ok(exports)
}

/// Build every ZIP before publishing a new output directory as one generation.
pub fn publish_exports(
    repo: &crate::repository::storage::Repository,
    exports: &[ZipExport],
    config: &crate::app::config::Config,
    password: Option<&str>,
    cancelled: &std::sync::atomic::AtomicBool,
    records: &[crate::repository::metadata::Occurrence],
) -> Result<()> {
    if config.resume {
        return publish_resumable(repo, exports, config, password, cancelled, records)
            .context("export collection is incomplete; completed ZIPs are retained, rerun the same command with --resume");
    }
    ensure!(
        !config.output.try_exists()?,
        "ZIP output already exists; choose a fresh output path"
    );
    if !config.zip_each_dir {
        let export = exports
            .first()
            .ok_or_else(|| anyhow::anyhow!("no ZIP export planned"))?;
        return publish(
            repo,
            &export.entries,
            &export.output,
            password,
            config.compression_level,
            cancelled,
            records,
        );
    }
    let parent = config
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        crate::collection::acquisition::private_tree(parent)?;
    }
    let staging = crate::repository::security::private_tempdir(parent, ".bfs-exports-")?;
    for export in exports {
        let relative = export.output.strip_prefix(&config.output)?;
        let mut directory = staging.path().to_path_buf();
        for part in relative.parent().unwrap_or(Path::new("")).components() {
            ensure!(
                matches!(part, std::path::Component::Normal(_)),
                "unsafe ZIP output path"
            );
            directory.push(part);
            crate::repository::security::private_dir(&directory)?;
        }
        publish(
            repo,
            &export.entries,
            &staging.path().join(relative),
            password,
            config.compression_level,
            cancelled,
            records,
        )?;
    }
    ensure!(
        !cancelled.load(std::sync::atomic::Ordering::Relaxed),
        "interrupted"
    );
    check_path(&config.output)?;
    ensure!(!config.output.try_exists()?, "ZIP output already exists");
    crate::repository::security::publish_directory(staging.path(), &config.output)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
/// Open a ZIP archive after enforcing input-size and entry-count limits.
pub fn open(path: &Path, limits: &Limits) -> Result<ZipArchive<File>> {
    check_path(path)?;
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    ensure!(
        limits.max_input_bytes.is_none_or(|limit| size <= limit),
        "archive input size limit exceeded"
    );
    let archive = ZipArchive::new(file)?;
    ensure!(
        limits
            .max_entries
            .is_none_or(|limit| archive.len() <= limit),
        "archive entry count limit exceeded"
    );
    Ok(archive)
}
/// Read archive entry metadata without extracting payloads.
pub fn inspect(path: &Path, limits: &Limits) -> Result<Inspection> {
    use crate::app::presentation::Progress;

    let scanning = Progress::new(None, "Reading ZIP directory");
    let archive = open(path, limits)?;
    drop(scanning);
    let progress = Progress::new(Some(archive.len() as u64), "Inspecting ZIP entries");
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let e = archive.by_index_data(index)?;
        entries.push(Entry {
            index,
            name: e.name()?.into_owned(),
            size: e.size(),
            compressed_size: e.compressed_size(),
            encrypted: e.encrypted(),
            compression: format!("{:?}", e.compression()),
            supported_compression: matches!(
                e.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            ),
            directory: e.is_dir(),
            unix_mode: e.unix_mode(),
        });
        progress.0.inc(1);
    }
    Ok(Inspection {
        archive: path.to_string_lossy().into_owned(),
        entries,
    })
}

/// Write the logical policy layout, then atomically publish a private ZIP.
fn publish(
    repo: &crate::repository::storage::Repository,
    plan: &[crate::organization::rules::Planned],
    output: &Path,
    password: Option<&str>,
    compression_level: Option<u8>,
    cancelled: &std::sync::atomic::AtomicBool,
    records: &[crate::repository::metadata::Occurrence],
) -> Result<()> {
    use crate::app::presentation::{Progress, byte_progress, bytes};
    use std::io::{Read, Write};
    use std::sync::atomic::Ordering;

    let progress = Progress::new(Some(plan.len() as u64), "Exporting ZIP entries");
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    let (report, total) = export_report(plan, records)?;
    let message = |read, written| {
        format!(
            "{} input read · {} ZIP written",
            byte_progress(read, Some(total)),
            bytes(written)
        )
    };
    let mut read = 0u64;
    progress.0.set_message(message(read, 0));
    check_path(output)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        crate::collection::acquisition::private_tree(parent)?;
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    let mut zip = zip::ZipWriter::new(file.as_file_mut());
    let mut options = zip::write::SimpleFileOptions::default()
        .compression_method(if compression_level == Some(0) {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        })
        .compression_level(compression_level.filter(|&level| level > 0).map(i64::from))
        .unix_permissions(0o600);
    if let Some(password) = password {
        options = options.with_aes_encryption(zip::AesMode::Aes256, password);
    }
    let mut buffer = [0u8; 65536];
    for entry in plan {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        let source = repo.object(&entry.sha256)?;
        crate::repository::security::validate_file(
            &source,
            crate::app::config::SecurityMode::Standard,
        )?;
        let mut source = File::open(source)?;
        zip.start_file(&entry.path, options)?;
        loop {
            ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            read = read.saturating_add(count as u64);
            zip.write_all(&buffer[..count])?;
            progress.streaming_message(|| message(read, zip_bytes(&zip)));
        }
        progress.0.inc(1);
    }
    progress.0.set_message(message(read, zip_bytes(&zip)));
    zip.start_file("export.json", options)?;
    serde_json::to_writer(&mut zip, &report)?;
    let written = zip.finish()?.metadata().ok().map_or(0, |meta| meta.len());
    progress.0.set_message(message(read, written));
    progress.0.force_draw();
    file.as_file().sync_all()?;
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    file.persist_noclobber(output)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn zip_bytes(zip: &zip::ZipWriter<&mut File>) -> u64 {
    zip.get_ref()
        .and_then(|file| file.metadata().ok())
        .map_or(0, |meta| meta.len())
}

/// Compact report binds the payload layout and effective selected metadata without exporting records.
fn export_report(
    plan: &[crate::organization::rules::Planned],
    records: &[crate::repository::metadata::Occurrence],
) -> Result<(serde_json::Value, u64)> {
    let hashes: BTreeSet<_> = plan.iter().map(|p| p.sha256.as_str()).collect();
    let mut selected: Vec<_> = records
        .iter()
        .filter(|r| hashes.contains(r.sha256.as_str()))
        .collect();
    selected.sort_by(|a, b| a.occurrence_id.cmp(&b.occurrence_id));
    let sizes: BTreeMap<_, _> = records
        .iter()
        .map(|r| (r.occurrence_id.as_str(), r.size))
        .collect();
    let logical_bytes = selected.iter().try_fold(0u64, |total, r| {
        total
            .checked_add(r.size)
            .ok_or_else(|| anyhow::anyhow!("export size overflow"))
    })?;
    let payload_bytes = plan.iter().try_fold(0u64, |total, p| {
        let size = sizes
            .get(p.occurrence_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("export occurrence is missing"))?;
        total
            .checked_add(*size)
            .ok_or_else(|| anyhow::anyhow!("export size overflow"))
    })?;
    Ok((
        serde_json::json!({
            "schema_version": 2, "kind": "bfsort-export", "tool_version": env!("CARGO_PKG_VERSION"),
            "layout_fingerprint": crate::repository::metadata::digest(&serde_json::to_vec(plan)?),
            "snapshot_fingerprint": crate::repository::metadata::digest(&serde_json::to_vec(&selected)?),
            "payload_entries": plan.len(), "occurrences": selected.len(), "unique_objects": hashes.len(),
            "logical_bytes": logical_bytes, "payload_bytes": payload_bytes
        }),
        payload_bytes,
    ))
}

/// Plan an export from saved metadata and write ZIP output when requested.
///
/// A dry run returns the same planned entries without opening payloads.
/// Publication requires standard-mode objects. Resumable export verifies
/// completed ZIPs before reuse and publishes missing outputs independently.
pub fn export_repository(
    repo: &crate::repository::storage::Repository,
    rules: &crate::organization::rules::Rules,
    config: &crate::app::config::Config,
    dry_run: bool,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<Vec<ZipExport>> {
    let records = crate::repository::metadata::select(repo.root(), &config.filters)?;
    let planning = crate::app::presentation::Progress::new(None, "Planning ZIP exports");
    let plan = rules.plan_export(&records, config.export_naming)?;
    let mut exports = plan_exports(&plan, config, rules)?;
    drop(planning);
    let existing: BTreeSet<_> = if config.resume {
        exports
            .iter()
            .filter(|e| e.output.is_file())
            .map(|e| e.output.clone())
            .collect()
    } else {
        BTreeSet::new()
    };
    if !dry_run {
        ensure!(
            repo.mode() == crate::app::config::SecurityMode::Standard,
            "export requires a standard repository; sealed payloads are never unlocked automatically"
        );
        let password = crate::ingest::pipeline::output_password(config)?;
        publish_exports(
            repo,
            &exports,
            config,
            password.as_deref(),
            cancelled,
            &records,
        )?;
    }
    if !dry_run {
        for export in &mut exports {
            export.reused = existing.contains(&export.output);
        }
    }
    Ok(exports)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportReceipt {
    size: u64,
    sha256: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportCheckpoint {
    version: u32,
    fingerprint: String,
    archives: BTreeMap<String, ExportReceipt>,
    completed: bool,
}
fn archive_digest(path: &Path, cancelled: &std::sync::atomic::AtomicBool) -> Result<ExportReceipt> {
    let _progress = crate::app::presentation::Progress::new(None, "Verifying ZIP checksum");
    use sha2::{Digest, Sha256};
    use std::io::Read;
    crate::repository::security::validate_file(path, crate::app::config::SecurityMode::Standard)?;
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0; 65536];
    loop {
        ensure!(
            !cancelled.load(std::sync::atomic::Ordering::Relaxed),
            "interrupted"
        );
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| anyhow::anyhow!("ZIP size overflow"))?;
    }
    Ok(ExportReceipt {
        size,
        sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    })
}

/// Resume publishes independent ZIP units; the collection remains partial until all verify.
fn publish_resumable(
    repo: &crate::repository::storage::Repository,
    exports: &[ZipExport],
    config: &crate::app::config::Config,
    password: Option<&str>,
    cancelled: &std::sync::atomic::AtomicBool,
    records: &[crate::repository::metadata::Occurrence],
) -> Result<()> {
    use std::sync::atomic::Ordering;
    ensure!(
        repo.mode() == crate::app::config::SecurityMode::Standard,
        "payload export requires a standard repository"
    );
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    check_path(&config.output)?;
    let parent = config
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        crate::collection::acquisition::private_tree(parent)?;
    }
    let target = parent.canonicalize()?.join(
        config
            .output
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("output needs a filename"))?,
    );
    let operations = repo.root().join("operations");
    crate::repository::security::private_dir(&operations)?;
    let operations = operations.join("export");
    crate::repository::security::private_dir(&operations)?;
    let state_path = operations.join(format!(
        "{}.json",
        crate::repository::metadata::digest(target.as_os_str().as_encoded_bytes())
    ));
    // Passwords are never fingerprinted; verify encrypted completed archives with the supplied password.
    let fingerprint = crate::repository::metadata::digest(&serde_json::to_vec(&(
        1,
        env!("CARGO_PKG_VERSION"),
        repo.root(),
        &target,
        config.zip_each_dir,
        &config.zip_dirs,
        exports,
        records,
        password.is_some(),
        config.compression_level,
    ))?);
    let existed = state_path.try_exists()?;
    let mut state: ExportCheckpoint = if existed {
        let state: ExportCheckpoint = crate::collection::acquisition::load_json(&state_path)?;
        ensure!(
            state.version == 1,
            "unsupported export checkpoint; choose a fresh output path"
        );
        ensure!(
            state.fingerprint == fingerprint,
            "export plan or repository changed; choose a fresh output path"
        );
        state
    } else {
        ensure!(
            !config.output.try_exists()?,
            "output exists without a verified export checkpoint; choose a fresh output path"
        );
        ExportCheckpoint {
            version: 1,
            fingerprint,
            archives: BTreeMap::new(),
            completed: false,
        }
    };
    let expected: BTreeSet<_> = exports
        .iter()
        .map(|e| {
            if config.zip_each_dir {
                e.output
                    .strip_prefix(&config.output)
                    .map(|p| p.to_string_lossy().into_owned())
            } else {
                Ok("archive.zip".into())
            }
        })
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        state.archives.keys().all(|key| expected.contains(key)),
        "unexpected archive in export checkpoint"
    );
    state.completed = false;
    crate::collection::acquisition::save_json(&state_path, &state)?;
    if config.zip_each_dir {
        crate::repository::security::private_dir(&config.output)?;
    }
    for export in exports {
        ensure!(
            !cancelled.load(Ordering::Relaxed),
            "interrupted; export collection is incomplete, rerun with --resume"
        );
        let key = if config.zip_each_dir {
            export
                .output
                .strip_prefix(&config.output)?
                .to_string_lossy()
                .into_owned()
        } else {
            "archive.zip".into()
        };
        if let Some(receipt) = state.archives.get(&key)
            && export.output.try_exists()?
        {
            let actual = archive_digest(&export.output, cancelled)?;
            ensure!(
                crate::repository::storage::valid_hash(&receipt.sha256)
                    && actual.sha256 == receipt.sha256
                    && actual.size == receipt.size,
                "completed export changed: {}; refusing replacement",
                crate::app::presentation::safe_text(&export.output.display().to_string())
            );
            verify_export_password(&export.output, password)?;
            continue;
        }
        state.archives.remove(&key);
        if export.output.try_exists()? {
            // Recover a crash after publication but before checkpoint synchronization.
            verify_export_layout(
                &export.output,
                &export.entries,
                records,
                password,
                cancelled,
            )?;
        } else {
            let parent = export
                .output
                .parent()
                .ok_or_else(|| anyhow::anyhow!("output parent missing"))?;
            crate::collection::acquisition::private_tree(parent)?;
            publish(
                repo,
                &export.entries,
                &export.output,
                password,
                config.compression_level,
                cancelled,
                records,
            )?;
        }
        state
            .archives
            .insert(key, archive_digest(&export.output, cancelled)?);
        crate::collection::acquisition::save_json(&state_path, &state)?;
    }
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    state.completed = true;
    crate::collection::acquisition::save_json(&state_path, &state)?;
    Ok(())
}
fn verify_export_password(path: &Path, password: Option<&str>) -> Result<()> {
    let mut archive = ZipArchive::new(File::open(path)?)?;
    read_export_report(&mut archive, password)?;
    Ok(())
}

fn read_export_report(
    archive: &mut ZipArchive<File>,
    password: Option<&str>,
) -> Result<serde_json::Value> {
    let header = if let Some(password) = password {
        archive.by_name_decrypt("export.json", password.as_bytes())?
    } else {
        archive.by_name("export.json")?
    };
    ensure!(header.size() <= 65536, "oversized export report");
    let header: serde_json::Value = serde_json::from_reader(header)?;
    ensure!(
        header["schema_version"] == 2
            && header["kind"] == "bfsort-export"
            && header["layout_fingerprint"]
                .as_str()
                .is_some_and(crate::repository::storage::valid_hash)
            && header["snapshot_fingerprint"]
                .as_str()
                .is_some_and(crate::repository::storage::valid_hash),
        "unsupported ZIP export metadata"
    );
    Ok(header)
}
fn verify_export_layout(
    path: &Path,
    plan: &[crate::organization::rules::Planned],
    records: &[crate::repository::metadata::Occurrence],
    password: Option<&str>,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let progress =
        crate::app::presentation::Progress::new(Some(plan.len() as u64), "Verifying ZIP entries");
    let mut archive = ZipArchive::new(File::open(path)?)?;
    let header = read_export_report(&mut archive, password)?;
    ensure!(
        header == export_report(plan, records)?.0,
        "uncheckpointed export report mismatch"
    );
    ensure!(
        archive.len() == plan.len() + 1,
        "uncheckpointed export has an unexpected entry count"
    );
    let sizes: BTreeMap<_, _> = records
        .iter()
        .map(|r| (r.occurrence_id.as_str(), r.size))
        .collect();
    for entry in plan {
        let mut file = if let Some(password) = password {
            archive.by_name_decrypt(&entry.path, password.as_bytes())?
        } else {
            archive.by_name(&entry.path)?
        };
        ensure!(
            file.size() == sizes[entry.occurrence_id.as_str()],
            "uncheckpointed export size mismatch"
        );
        let mut hash = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            ensure!(
                !cancelled.load(std::sync::atomic::Ordering::Relaxed),
                "interrupted"
            );
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        let digest: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        ensure!(
            digest == entry.sha256,
            "uncheckpointed export content mismatch"
        );
        progress.0.inc(1);
    }
    Ok(())
}
