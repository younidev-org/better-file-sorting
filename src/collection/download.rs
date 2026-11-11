// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Transfers policy-selected resources into private, sealed staging with completion receipts.
//! Workers share request controls and byte budgets; files remain inaccessible by path
//! while their creation handles receive data. Only synchronized completed payloads are
//! published. Reruns validate sealed cache records, and failures never become receipts.

/// Maximum body read chunk, also bounding the speed limiter burst.
const TRANSFER_BUFFER_BYTES: usize = 16 * 1024;
/// Maximum sanitized label length, leaving room for the source hash and extension.
const MAX_FILENAME_BYTES: usize = 240;

use crate::{
    app::{
        config::SecurityMode,
        presentation::{Progress, byte_progress, byte_rate},
    },
    collection::acquisition::*,
    collection::http_source::{HttpSource, wait_until},
    repository::security,
};
use anyhow::{Result, ensure};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub fn preview(config: &DownloadConfig, inventory: &Inventory) -> Result<DownloadReport> {
    let candidates = select_candidates(inventory, config)?;
    use unicode_normalization::UnicodeNormalization;
    let mut paths = std::collections::BTreeSet::new();
    for candidate in &candidates {
        ensure!(
            crate::repository::storage::valid_hash(&candidate.source_id)
                && candidate.source_id
                    == crate::repository::metadata::digest(candidate.url.as_bytes()),
            "invalid source identity"
        );
        crate::collection::http_source::safe_url(&candidate.url)?;
        let path = payload_path(config, candidate);
        ensure!(
            paths.insert(
                path.to_string_lossy()
                    .nfc()
                    .collect::<String>()
                    .to_lowercase()
            ),
            "download destination collision for {}; choose filename = '{{name}}-{{source_id}}' or '{{source_id}}'",
            crate::app::presentation::safe_text(&candidate.name)
        );
    }
    Ok(DownloadReport {
        filtered: inventory.candidates.len() - candidates.len(),
        candidates,
        ..Default::default()
    })
}
pub(crate) fn safe_component(text: &str, limit: usize) -> String {
    let mut value = String::new();
    for c in text.chars() {
        let c = if c.is_alphanumeric()
            || (c.is_ascii_graphic()
                && !matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
            || c == ' '
        {
            c
        } else {
            '_'
        };
        if value.len() + c.len_utf8() > limit {
            break;
        }
        value.push(c);
    }
    let mut value = value.trim_matches(['.', ' ']).to_string();
    if value.is_empty() {
        value.push_str("download");
    }
    let stem = value.split('.').next().unwrap().to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        || ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].contains(&stem.as_str())
    {
        value.insert(0, '_');
    }
    value
}
pub fn payload_path(config: &DownloadConfig, candidate: &Candidate) -> PathBuf {
    let (raw_stem, raw_extension) = candidate
        .name
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or((candidate.name.as_str(), None), |(stem, ext)| {
            (stem, Some(ext))
        });
    let extension = raw_extension
        .map(|ext| format!(".{}", safe_component(ext, 80)))
        .unwrap_or_default();
    let stem = safe_component(raw_stem, MAX_FILENAME_BYTES - extension.len() - 1);
    let original = format!("{stem}{extension}");
    let id = safe_component(&candidate.source_id, 64);
    let filename = match config.filename.as_str() {
        "{source_id}" => format!("{id}{extension}"),
        "{name}-{source_id}" => {
            let stem = safe_component(
                &stem,
                MAX_FILENAME_BYTES
                    .saturating_sub(id.len() + extension.len() + 1)
                    .max(8),
            );
            format!("{stem}-{id}{extension}")
        }
        _ => original,
    };
    PathBuf::from("payloads")
        .join(&config.directory)
        .join(filename)
}
fn receipt_path(config: &DownloadConfig, id: &str) -> PathBuf {
    config
        .staging_dir
        .join("control")
        .join(format!("{id}.json"))
}
fn staged_bytes(root: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        ensure!(!entry.file_type().is_symlink(), "staging symlink refused");
        if entry.file_type().is_file() {
            total = total
                .checked_add(entry.metadata()?.len())
                .ok_or_else(|| anyhow::anyhow!("staging size overflow"))?;
        }
    }
    Ok(total)
}
struct Budget {
    transferred: u64,
    staged: u64,
    pace: Instant,
    completed: usize,
    failed: usize,
    known_sizes: usize,
    expected_bytes: Option<u64>,
}
impl Budget {
    fn record_size(&mut self, size: u64) {
        self.known_sizes += 1;
        self.expected_bytes = self.expected_bytes.and_then(|sum| sum.checked_add(size));
    }
}
pub fn run(
    config: &DownloadConfig,
    source: &SourceConfig,
    inventory: &Inventory,
    cancelled: &AtomicBool,
) -> Result<DownloadReport> {
    let mut report = preview(config, inventory)?;
    private_tree(&config.staging_dir)?;
    security::private_dir(&config.staging_dir)?;
    let control = config.staging_dir.join("control");
    private_tree(&control)?;
    security::private_dir(&control)?;
    let payloads = config.staging_dir.join("payloads");
    private_tree(&payloads)?;
    let lock_path = control.join(".lock");
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
        .map_err(|_| anyhow::anyhow!("download staging is in use"))?;
    let http = HttpSource::new(source, config)?;
    let total_limit = config.max_total_size;
    let staging_limit = config.max_staging_size;
    let file_limit = config.max_file_size;
    let speed = config.speed()?;
    let budget = Mutex::new(Budget {
        transferred: 0,
        staged: staged_bytes(&payloads)?,
        pace: Instant::now(),
        completed: 0,
        failed: 0,
        known_sizes: 0,
        expected_bytes: Some(0),
    });
    ensure!(
        staging_limit.is_none_or(|limit| budget.lock().unwrap().staged <= limit),
        "staging size limit reached"
    );
    let mut work = vec![];
    for candidate in &report.candidates {
        let receipt = receipt_path(config, &candidate.source_id);
        if receipt.try_exists()? {
            let saved = load_receipt(&receipt)?;
            ensure!(
                saved.version == 2
                    && saved.candidate.source_id == candidate.source_id
                    && saved.candidate.url == candidate.url
                    && crate::repository::storage::valid_hash(&saved.sha256)
                    && saved.path == payload_path(config, &saved.candidate),
                "invalid download receipt"
            );
            let path = config.staging_dir.join(&saved.path);
            security::validate_file(&path, SecurityMode::Sealed)?;
            ensure!(
                std::fs::metadata(path)?.len() == saved.size,
                "cached file changed"
            );
            report.cached += 1;
        } else if config.max_files.is_none_or(|limit| work.len() < limit) {
            let target = config.staging_dir.join(payload_path(config, candidate));
            crate::ingest::discovery::check_path(&target)?;
            ensure!(
                !target.try_exists()?,
                "download destination collision: {}; existing content retained",
                target.display()
            );
            work.push(candidate.clone());
        } else {
            report.not_attempted += 1;
        }
    }
    let selected = report.cached + work.len();
    let progress = Progress::new(Some(selected as u64), "Downloading files");
    let cached = report.cached;
    let transfer_message = |budget: &Budget| {
        transfer_progress(
            budget.failed,
            cached,
            budget.transferred,
            budget
                .expected_bytes
                .filter(|_| budget.known_sizes == work.len()),
            progress.0.elapsed(),
        )
    };
    {
        let mut budget = budget.lock().unwrap();
        budget.completed = cached;
        progress.0.set_position(cached as u64);
        progress.0.set_message(transfer_message(&budget));
    }
    let results = Mutex::new(vec![]);
    rayon::ThreadPoolBuilder::new()
        .num_threads(config.concurrency)
        .build()?
        .install(|| {
            work.par_iter().for_each(|candidate| {
                let result = (|| -> Result<Option<u64>> {
                    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
                    let started = Instant::now();
                    let timeout = config.timeout_seconds.map(Duration::from_secs);
                    let relative = payload_path(config, candidate);
                    let target = config.staging_dir.join(&relative);
                    private_tree(target.parent().unwrap())?;
                    crate::ingest::discovery::check_path(&target)?;
                    ensure!(!target.try_exists()?, "unreceipted target exists");
                    let mut builder = tempfile::Builder::new();
                    builder.prefix(".partial-");
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        builder.permissions(std::fs::Permissions::from_mode(0o000));
                    }
                    let mut file = builder.tempfile_in(&payloads)?;
                    security::seal(file.as_file(), SecurityMode::Sealed)?;
                    {
                        let b = budget.lock().unwrap();
                        ensure!(
                            total_limit.is_none_or(|limit| b.transferred < limit)
                                && staging_limit.is_none_or(|limit| b.staged < limit),
                            "download byte limit reached"
                        );
                    }
                    let (response, _) = http.get(&candidate.url, cancelled)?;
                    let expected = response
                        .headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());
                    if let Some(length) = expected {
                        let mut b = budget.lock().unwrap();
                        b.record_size(length);
                        if b.known_sizes == work.len() {
                            progress.0.set_message(transfer_message(&b));
                        }
                    }
                    let mut reader = crate::collection::http_source::CancellableReader::new(
                        response.into_body(),
                        cancelled,
                        timeout.and_then(|timeout| started.checked_add(timeout)),
                    );
                    let mut buffer = [0u8; TRANSFER_BUFFER_BYTES];
                    let mut size = 0u64;
                    let mut hash = Sha256::new();
                    loop {
                        if expected == Some(size) {
                            break;
                        }
                        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
                        ensure!(
                            timeout.is_none_or(|timeout| started.elapsed() < timeout),
                            "transfer timeout"
                        );
                        // Serialize read reservations so concurrent transfers cannot overshoot aggregate budgets.
                        let mut b = budget.lock().unwrap();
                        let allowance = [
                            (total_limit, b.transferred),
                            (staging_limit, b.staged),
                            (file_limit, size),
                        ]
                        .into_iter()
                        .filter_map(|(limit, used)| limit.map(|limit| limit.saturating_sub(used)))
                        .fold(buffer.len() as u64, u64::min)
                            as usize;
                        if allowance == 0
                            && file_limit == Some(size)
                            && total_limit.is_none_or(|limit| b.transferred < limit)
                        {
                            // Probe EOF without writing beyond the file cap; charge any observed byte.
                            let n = reader.read(&mut buffer[..1])?;
                            b.transferred = b
                                .transferred
                                .checked_add(n as u64)
                                .ok_or_else(|| anyhow::anyhow!("transfer size overflow"))?;
                            ensure!(n == 0, "file size limit reached");
                            break;
                        }
                        ensure!(
                            allowance > 0,
                            "download byte limit reached; EOF not verified"
                        );
                        let n = reader.read(&mut buffer[..allowance])?;
                        if n == 0 {
                            break;
                        }
                        b.transferred = b
                            .transferred
                            .checked_add(n as u64)
                            .ok_or_else(|| anyhow::anyhow!("transfer size overflow"))?;
                        b.staged = b
                            .staged
                            .checked_add(n as u64)
                            .ok_or_else(|| anyhow::anyhow!("staging size overflow"))?;
                        if let Some(rate) = speed {
                            b.pace = b.pace.max(Instant::now())
                                + Duration::from_secs_f64(n as f64 / rate as f64);
                            wait_until(
                                timeout.map_or(b.pace, |timeout| b.pace.min(started + timeout)),
                                cancelled,
                            )?;
                        }
                        progress.streaming_message(|| transfer_message(&b));
                        drop(b);
                        size = size
                            .checked_add(n as u64)
                            .ok_or_else(|| anyhow::anyhow!("file size overflow"))?;
                        hash.update(&buffer[..n]);
                        file.write_all(&buffer[..n])?;
                    }
                    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
                    ensure!(
                        timeout.is_none_or(|timeout| started.elapsed() < timeout),
                        "transfer timeout"
                    );
                    ensure!(
                        expected.is_none_or(|length| length == size),
                        "download Content-Length mismatch"
                    );
                    file.as_file().sync_all()?;
                    let path = file.into_temp_path();
                    path.persist_noclobber(&target)?;
                    File::open(target.parent().unwrap())?.sync_all()?;
                    let receipt = DownloadReceipt {
                        version: 2,
                        candidate: candidate.clone(),
                        path: relative,
                        size,
                        sha256: hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
                    };
                    save_json(&receipt_path(config, &candidate.source_id), &receipt)?;
                    Ok(expected.is_none().then_some(size))
                })();
                {
                    let mut b = budget.lock().unwrap();
                    if let Ok(size) = result {
                        if let Some(size) = size {
                            b.record_size(size);
                        }
                        b.completed += 1;
                        progress.0.set_position(b.completed as u64);
                    } else {
                        b.failed += 1;
                    }
                    progress.0.set_message(transfer_message(&b));
                }
                results.lock().unwrap().push(result.map_err(|e| {
                    format!(
                        "{}: {e:#}",
                        crate::app::presentation::safe_text(&candidate.name)
                    )
                }));
            })
        });
    for result in results.into_inner().unwrap() {
        match result {
            Ok(_) => report.downloaded += 1,
            Err(e) => {
                report.failed += 1;
                report.errors.push(e);
            }
        }
    }
    progress.0.force_draw();
    report.bytes = budget.into_inner().unwrap().transferred;
    Ok(report)
}

fn transfer_progress(
    failed: usize,
    cached: usize,
    transferred: u64,
    total: Option<u64>,
    elapsed: Duration,
) -> String {
    format!(
        "{} transferred · {} · {cached} cached · {failed} failed",
        byte_progress(transferred, total),
        byte_rate(transferred, elapsed),
    )
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    #[test]
    fn transferred_bytes_have_measured_rate_and_use_known_totals() {
        let elapsed = Duration::from_secs(2);
        let unknown = transfer_progress(0, 0, 4096, None, elapsed);
        assert!(unknown.contains("4.00 KiB transferred · 2.00 KiB/s"));
        let known = transfer_progress(0, 1, 4096, Some(8192), elapsed);
        assert!(known.contains("4.00 KiB / 8.00 KiB transferred · 2.00 KiB/s · 1 cached"));
        assert!(transfer_progress(0, 0, 0, None, Duration::ZERO).contains("0 B/s"));
    }
}
