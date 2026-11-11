// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Defines the acquisition configuration, policy selection, and durable transfer inventory.
//! Discovery records candidates in the inventory. Downloads publish completion
//! receipts that ingestion uses to identify and verify accessible inputs.
//! Metadata is bounded and published atomically, independently of sealed payload storage.

/// Maximum serialized inventory or receipt size accepted from disk.
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
/// Streaming hash buffer size; independent of user payload limits.
const HASH_BUFFER_BYTES: usize = 64 * 1024;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, Metadata},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub fn parse_bytes(value: &str) -> Result<u64> {
    let parts: Vec<_> = value.split_whitespace().collect();
    ensure!(parts.len() == 2, "expected integer and byte unit");
    ensure!(
        parts[0].bytes().all(|b| b.is_ascii_digit()),
        "invalid byte quantity"
    );
    let multiplier = match parts[1] {
        "B" => 1,
        "KB" => 1000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        "KiB" => 1024,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        _ => anyhow::bail!("invalid byte unit"),
    };
    let size = parts[0]
        .parse::<u64>()?
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("byte quantity overflow"))?;
    ensure!(size > 0, "byte quantity must be positive");
    Ok(size)
}
/// Shared TOML boundary: user quantities may be integer bytes or unit-bearing strings.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Quantity {
    Bytes(u64),
    Readable(String),
}
impl Quantity {
    pub(crate) fn bytes<E: serde::de::Error>(self) -> std::result::Result<u64, E> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Readable(value) => parse_bytes(&value).map_err(E::custom),
        }
    }
}
/// Preserve absent rule bounds and accept both representations for present bounds.
pub(crate) fn deserialize_optional_bytes<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<u64>, D::Error> {
    match Option::<Quantity>::deserialize(d)? {
        None => Ok(None),
        Some(Quantity::Readable(value)) if value == "unlimited" => Ok(None),
        Some(value) => {
            let bytes = value.bytes::<D::Error>()?;
            if bytes == 0 {
                return Err(serde::de::Error::custom(
                    "limit must be positive or unlimited",
                ));
            }
            Ok(Some(bytes))
        }
    }
}

pub(crate) fn deserialize_optional_count<'de, D: serde::Deserializer<'de>, T: TryFrom<u64>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    match Option::<Quantity>::deserialize(d)? {
        None => Ok(None),
        Some(Quantity::Readable(value)) if value == "unlimited" => Ok(None),
        Some(Quantity::Bytes(value)) if value > 0 => T::try_from(value)
            .map(Some)
            .map_err(|_| serde::de::Error::custom("limit out of range")),
        _ => Err(serde::de::Error::custom(
            "expected positive integer or unlimited",
        )),
    }
}
/// Numeric speed values mean bytes per second; readable rates retain their /s suffix.
fn deserialize_speed_text<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Ok(Option::<Quantity>::deserialize(d)?.map(|q| match q {
        Quantity::Bytes(bytes) => format!("{bytes} B/s"),
        Quantity::Readable(value) => value,
    }))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SourceConfig {
    /// HTTP(S) page whose direct resource links are discovered.
    pub page: String,
    /// Whether requests and redirects must remain on the page origin.
    pub same_origin: bool,
    /// Maximum HTML response body, expressed with a readable byte unit.
    #[serde(deserialize_with = "deserialize_optional_bytes")]
    pub max_page_size: Option<u64>,
    #[serde(deserialize_with = "deserialize_optional_count")]
    pub timeout_seconds: Option<u64>,
}
impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            page: String::new(),
            same_origin: true,
            max_page_size: None,
            timeout_seconds: None,
        }
    }
}
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OrderBy {
    #[default]
    Source,
    Name,
}
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    #[default]
    Ascending,
    Descending,
}
#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Include,
    Exclude,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name_contains: Option<String>,
    pub action: Action,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DownloadConfig {
    /// Durable discovery inventory path, relative to the working directory.
    pub inventory: PathBuf,
    /// Private storage root for sealed payloads and transfer receipts.
    pub staging_dir: PathBuf,
    /// Maximum number of uncached candidates attempted per invocation.
    #[serde(deserialize_with = "deserialize_optional_count")]
    pub max_files: Option<usize>,
    /// Maximum downloaded payload size, independent of extraction limits.
    #[serde(deserialize_with = "deserialize_optional_bytes")]
    pub max_file_size: Option<u64>,
    /// Aggregate body-byte budget, including failed transfers.
    #[serde(deserialize_with = "deserialize_optional_bytes")]
    pub max_total_size: Option<u64>,
    /// Managed payload storage budget, including existing partial files.
    #[serde(deserialize_with = "deserialize_optional_bytes")]
    pub max_staging_size: Option<u64>,
    /// Maximum number of transfer workers sharing all aggregate limits.
    pub concurrency: usize,
    /// Transfer timeout in seconds, including pacing waits.
    #[serde(deserialize_with = "deserialize_optional_count")]
    pub timeout_seconds: Option<u64>,
    /// Optional aggregate body-read rate; omission leaves speed uncapped.
    #[serde(deserialize_with = "deserialize_speed_text")]
    pub max_speed: Option<String>,
    /// Minimum spacing between request starts, including redirect hops.
    pub min_request_interval_ms: u64,
    /// Optional request-count cap for one command invocation.
    #[serde(deserialize_with = "deserialize_optional_count")]
    pub max_requests: Option<usize>,
    /// Candidate metadata field used for deterministic selection order.
    pub order_by: OrderBy,
    /// Ascending or descending candidate priority.
    pub order: Order,
    /// Safe staging directory template; does not control extracted-content rules.
    pub directory: String,
    /// Download basename policy; discovery always retains the original name.
    pub filename: String,
    /// Include/exclude filters; exclusions take precedence.
    pub policies: Vec<Policy>,
}
impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            inventory: "./collection/inventory.json".into(),
            staging_dir: "./collection/downloads".into(),
            max_files: None,
            max_file_size: None,
            max_total_size: None,
            max_staging_size: None,
            concurrency: 3,
            timeout_seconds: None,
            max_speed: None,
            min_request_interval_ms: 0,
            max_requests: None,
            order_by: OrderBy::Source,
            order: Order::Ascending,
            directory: String::new(),
            filename: "{original_name}".into(),
            policies: vec![],
        }
    }
}
impl DownloadConfig {
    pub fn speed(&self) -> Result<Option<u64>> {
        self.max_speed
            .as_deref()
            .filter(|value| *value != "unlimited")
            .map(|s| {
                parse_bytes(
                    s.strip_suffix("/s")
                        .ok_or_else(|| anyhow::anyhow!("speed requires /s"))?,
                )
            })
            .transpose()
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            [
                self.max_file_size,
                self.max_total_size,
                self.max_staging_size,
                self.timeout_seconds
            ]
            .into_iter()
            .all(|n| n != Some(0)),
            "limits must be positive or unlimited"
        );
        self.speed()?;
        ensure!(
            self.max_files != Some(0)
                && (1..=256).contains(&self.concurrency)
                && self.timeout_seconds != Some(0)
                && self.max_requests != Some(0),
            "invalid download limits"
        );
        ensure!(
            !self.inventory.as_os_str().is_empty() && !self.staging_dir.as_os_str().is_empty(),
            "empty acquisition path"
        );
        for p in &self.policies {
            ensure!(p.name_contains.is_some(), "policy requires name_contains");
        }
        ensure!(
            ["{original_name}", "{name}-{source_id}", "{source_id}"]
                .contains(&self.filename.as_str()),
            "download.filename must be {{original_name}}, {{name}}-{{source_id}}, or {{source_id}}"
        );
        ensure!(
            self.directory.is_empty()
                || self.directory.split('/').all(|c| {
                    !c.is_empty()
                        && c != "."
                        && c != ".."
                        && !c.contains(['\\', ':', '{', '}'])
                        && !c.chars().any(char::is_control)
                        && c.len() <= 200
                        && !c.ends_with(['.', ' '])
                        && crate::collection::download::safe_component(c, 200) == c
                }),
            "unsafe download.directory: use a literal relative folder"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// Stable digest of the normalized resource URL, independent of local paths.
    pub source_id: String,
    pub url: String,
    pub name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub version: u32,
    pub candidates: Vec<Candidate>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadReceipt {
    pub version: u32,
    pub candidate: Candidate,
    pub path: PathBuf,
    pub size: u64,
    /// Content digest used to verify integrity and identify stored objects.
    pub sha256: String,
}
#[derive(Debug, Default, Serialize)]
pub struct DownloadReport {
    /// Actual response body bytes read, including failed transfers.
    pub bytes: u64,
    pub downloaded: usize,
    pub cached: usize,
    pub filtered: usize,
    pub failed: usize,
    pub not_attempted: usize,
    pub candidates: Vec<Candidate>,
    pub errors: Vec<String>,
}
pub fn select_candidates(inventory: &Inventory, config: &DownloadConfig) -> Result<Vec<Candidate>> {
    config.validate()?;
    let mut rows: Vec<_> = inventory
        .candidates
        .iter()
        .filter(|c| {
            let matches = |p: &Policy| {
                c.name
                    .to_lowercase()
                    .contains(&p.name_contains.as_ref().unwrap().to_lowercase())
            };
            !config
                .policies
                .iter()
                .any(|p| p.action == Action::Exclude && matches(p))
                && (!config.policies.iter().any(|p| p.action == Action::Include)
                    || config
                        .policies
                        .iter()
                        .any(|p| p.action == Action::Include && matches(p)))
        })
        .cloned()
        .collect();
    if config.order_by == OrderBy::Name {
        rows.sort_by_key(|c| c.name.to_lowercase());
    }
    if config.order == Order::Descending {
        rows.reverse();
    }
    Ok(rows)
}
pub fn save_json(path: &Path, value: &impl Serialize) -> Result<()> {
    crate::ingest::discovery::check_path(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    crate::repository::security::validate_file(path, crate::app::config::SecurityMode::Standard)?;
    let mut bytes = vec![];
    File::open(path)?
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_METADATA_BYTES,
        "acquisition metadata exceeds 16 MiB"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn load_inventory(path: &Path) -> Result<Inventory> {
    use anyhow::Context;
    let value: serde_json::Value = load_json(path).with_context(|| format!("collection inventory could not be read: {}\nHint: run `bfsort discover -c collection.toml` or `bfsort collect -c collection.toml`; check the path and permissions.", path.display()))?;
    ensure!(
        value.get("version").and_then(serde_json::Value::as_u64) == Some(2),
        "unsupported discovery inventory; re-discover into a fresh collection (old acquisition formats are unsupported)"
    );
    let inventory: Inventory = serde_json::from_value(value)?;
    let mut ids = std::collections::BTreeSet::new();
    for c in &inventory.candidates {
        crate::collection::http_source::safe_url(&c.url)?;
        ensure!(
            c.source_id == crate::repository::metadata::digest(c.url.as_bytes())
                && ids.insert(&c.source_id),
            "invalid or duplicate source identity"
        );
    }
    Ok(inventory)
}

/// Create only missing private directories, checking all existing ancestors for links.
pub fn private_tree(path: &Path) -> Result<()> {
    crate::ingest::discovery::check_path(path)?;
    if path.is_dir() {
        return crate::repository::security::private_dir(path);
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && !parent.is_dir()
    {
        private_tree(parent)?;
    }
    crate::repository::security::private_dir(path)
}

#[derive(Debug)]
pub struct CompletedInput {
    pub path: PathBuf,
    pub receipt: DownloadReceipt,
}

/// A receipt digest tied to the file metadata observed during verification.
#[derive(Debug, Clone)]
pub struct VerifiedInput {
    pub(crate) sha256: String,
    pub(crate) metadata: Metadata,
}

impl VerifiedInput {
    pub(crate) fn unchanged(&self, path: &Path) -> Result<bool> {
        crate::ingest::discovery::check_path(path)?;
        Ok(same_file(&self.metadata, &std::fs::symlink_metadata(path)?))
    }
}

#[cfg(unix)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    after.is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && (before.mtime(), before.mtime_nsec()) == (after.mtime(), after.mtime_nsec())
        && (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec())
}

#[cfg(not(unix))]
fn same_file(_: &Metadata, _: &Metadata) -> bool {
    false
}
/// Resolve completed receipts to accessible inputs for ingestion.
///
/// Receipt identities and paths must agree with the acquisition settings.
/// Accessible payloads are checked against the recorded size and SHA-256.
/// A sealed payload requires the user to grant access before ingestion.
pub fn completed_inputs(config: &DownloadConfig) -> Result<Vec<CompletedInput>> {
    Ok(
        completed_inputs_cancellable(config, &AtomicBool::new(false))?
            .into_iter()
            .map(|(input, _)| input)
            .collect(),
    )
}

pub(crate) fn completed_inputs_cancellable(
    config: &DownloadConfig,
    cancelled: &AtomicBool,
) -> Result<Vec<(CompletedInput, Metadata)>> {
    use crate::app::presentation::{Progress, byte_progress, byte_rate};
    use sha2::{Digest, Sha256};

    config.validate()?;
    let scanning = Progress::new(None, "Reading download receipts");
    let control = config.staging_dir.join("control");
    crate::ingest::discovery::check_path(&control)?;
    let mut receipts = vec![];
    for entry in std::fs::read_dir(control)? {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        let entry = entry?;
        if entry.path().extension().is_none_or(|e| e != "json") {
            continue;
        }
        let receipt = load_receipt(&entry.path())?;
        ensure!(
            receipt.version == 2
                && crate::repository::storage::valid_hash(&receipt.sha256)
                && receipt.candidate.source_id
                    == crate::repository::metadata::digest(receipt.candidate.url.as_bytes()),
            "invalid download receipt"
        );
        crate::collection::http_source::safe_url(&receipt.candidate.url)?;
        ensure!(
            receipt.path == crate::collection::download::payload_path(config, &receipt.candidate),
            "unsafe receipt path"
        );
        receipts.push(receipt);
    }
    drop(scanning);
    ensure!(!receipts.is_empty(), "no completed downloads found");
    let total = receipts
        .iter()
        .try_fold(0u64, |sum, receipt| sum.checked_add(receipt.size));
    let progress = Progress::new(Some(receipts.len() as u64), "Verifying downloaded ZIPs");
    let message = |read| {
        format!(
            "{} ZIP bytes verified · {}",
            byte_progress(read, total),
            byte_rate(read, progress.0.elapsed())
        )
    };
    let mut read = 0u64;
    progress.0.set_message(message(read));
    progress.0.force_draw();
    let mut buffer = [0; HASH_BUFFER_BYTES];
    let mut inputs = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        let path = config.staging_dir.join(&receipt.path);
        if crate::repository::security::validate_file(
            &path,
            crate::app::config::SecurityMode::Sealed,
        )
        .is_ok()
        {
            anyhow::bail!(
                "download is sealed; explicitly unlock selected payloads to 0600 before ingest"
            );
        }
        crate::repository::security::validate_file(
            &path,
            crate::app::config::SecurityMode::Standard,
        )?;
        let mut reader = File::open(&path)?;
        let metadata = reader.metadata()?;
        ensure!(metadata.len() == receipt.size, "download size changed");
        let mut hash = Sha256::new();
        loop {
            ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
            read = read.saturating_add(n as u64);
            progress.streaming_message(|| message(read));
        }
        let actual: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        ensure!(actual == receipt.sha256, "download hash changed");
        #[cfg(unix)]
        ensure!(
            same_file(&metadata, &reader.metadata()?),
            "download changed during verification"
        );
        inputs.push((
            CompletedInput {
                path: path.canonicalize()?,
                receipt,
            },
            metadata,
        ));
        progress.0.inc(1);
        progress.0.set_message(message(read));
    }
    progress.0.force_draw();
    drop(progress);
    inputs.sort_by(|(a, _), (b, _)| {
        a.receipt
            .candidate
            .source_id
            .cmp(&b.receipt.candidate.source_id)
    });
    Ok(inputs)
}

/// Reject obsolete records before decoding their candidate schema.
pub fn load_receipt(path: &Path) -> Result<DownloadReceipt> {
    let value: serde_json::Value = load_json(path)?;
    ensure!(
        value.get("version").and_then(serde_json::Value::as_u64) == Some(2),
        "unsupported download receipt; re-download into fresh staging (old acquisition formats are unsupported; existing payloads were retained)"
    );
    Ok(serde_json::from_value(value)?)
}
