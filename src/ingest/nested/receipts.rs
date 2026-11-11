//! Validated reusable facts from one direct ZIP extraction.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Child {
    pub(super) index: usize,
    pub(super) name: String,
    pub(super) sha256: String,
    pub(super) size: u64,
    pub(super) encrypted: bool,
    pub(super) file_type: String,
    pub(super) detection: Detection,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub(super) checksum: String,
    pub(super) schema_version: u32,
    pub(super) archive_hash: String,
    pub(super) policy: String,
    pub(super) entries: usize,
    pub(super) bytes: u64,
    pub(super) children: Vec<Child>,
}
impl Receipt {
    pub(super) fn digest(&self) -> Result<String> {
        Ok(metadata::digest(&serde_json::to_vec(&(
            self.schema_version,
            &self.archive_hash,
            &self.policy,
            self.entries,
            self.bytes,
            &self.children,
        ))?))
    }
    pub(super) fn validate(&self, hash: &str, policy: &str) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.archive_hash == hash && self.policy == policy,
            "incompatible extraction receipt"
        );
        ensure!(
            self.checksum == self.digest()?,
            "extraction receipt checksum mismatch"
        );
        let mut indices = std::collections::BTreeSet::new();
        let total = self.children.iter().try_fold(0u64, |n, child| {
            ensure!(
                child.index < self.entries && indices.insert(child.index),
                "invalid receipt entry index"
            );
            ensure!(
                child.detection.detector_version == classifier::DETECTOR_VERSION,
                "stale receipt detection"
            );
            n.checked_add(child.size).context("receipt size overflow")
        })?;
        ensure!(
            total <= self.bytes && self.children.len() <= self.entries,
            "invalid receipt accounting"
        );
        Ok(())
    }
}
pub(super) struct Direct {
    pub(super) children: Vec<Child>,
    pub(super) errors: Vec<String>,
}
#[allow(clippy::too_many_arguments)]
pub(super) fn direct(
    repo: &Repository,
    source: Option<&Source>,
    hash: &str,
    config: &Config,
    passwords: &[String],
    cancelled: &AtomicBool,
    budget: &mut Budget,
    cache: &Cache,
    report: &mut TreeReport,
    on_read: &impl Fn(u64),
) -> Result<Direct> {
    let policy = policy(config);
    let path = receipt_path(repo, hash, &policy);
    let gate = cache.gate(&format!("{hash}-{policy}"))?;
    let _guard = loop {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        match gate.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(_) => anyhow::bail!("extraction lock poisoned"),
        }
    };
    ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
    if path.try_exists()? {
        security::validate_file(&path, SecurityMode::Standard)?;
        ensure!(
            fs::metadata(&path)?.len() <= 256 * 1024 * 1024,
            "extraction receipt too large"
        );
        let receipt: Receipt = serde_json::from_reader(File::open(&path)?)?;
        receipt.validate(hash, &policy)?;
        let start = Instant::now();
        for child in &receipt.children {
            verify(repo, child, cancelled)?;
        }
        report.metrics.hashing_seconds += start.elapsed().as_secs_f64();
        budget.entries(receipt.entries)?;
        budget.bytes(receipt.bytes)?;
        report.metrics.reused_archives += 1;
        return Ok(Direct {
            children: receipt.children,
            errors: vec![],
        });
    }
    let mut file = match source {
        Some(source) => source.open(repo, config, passwords, cancelled, &mut report.metrics)?,
        None => {
            ensure!(
                repo.mode() == SecurityMode::Standard,
                "sealed archive requires explicit authorized access; no automatic unsealing"
            );
            let p = repo.object(hash)?;
            security::validate_file(&p, repo.mode())?;
            File::open(p)?
        }
    };
    let hash_started = Instant::now();
    ensure!(
        hash_file(&mut file, cancelled)? == hash,
        "archive checksum mismatch"
    );
    report.metrics.hashing_seconds += hash_started.elapsed().as_secs_f64();
    let mut archive = zip::ZipArchive::new(file)?;
    ensure!(
        config.limits.max_entries.is_none_or(|n| archive.len() <= n),
        "archive entry limit exceeded"
    );
    let mut total = 0;
    let before = budget.bytes;
    let mut result = Direct {
        children: vec![],
        errors: vec![],
    };
    let started = Instant::now();
    for index in 0..archive.len() {
        if cancelled.load(Ordering::Relaxed) {
            result.errors.push("interrupted".into());
            break;
        }
        if let Err(error) = budget.entries(1) {
            result.errors.push(error.to_string());
            break;
        }
        let data = match archive.by_index_data(index) {
            Ok(data) => data,
            Err(error) => {
                result
                    .errors
                    .push(format!("invalid archive entry: {error}"));
                break;
            }
        };
        let name = match data.name() {
            Ok(name) => name.into_owned(),
            Err(error) => {
                result.errors.push(format!("invalid archive name: {error}"));
                continue;
            }
        };
        if let Err(e) = crate::ingest::extraction::validate_name(&name) {
            result.errors.push(e.to_string());
            continue;
        }
        if data.is_dir() {
            continue;
        }
        let encrypted = data.encrypted();
        let item = crate::ingest::extraction::extract_with_progress(
            &mut archive,
            index,
            passwords,
            &repo.staging(),
            &config.limits,
            &mut total,
            cancelled,
            Some(budget),
            on_read,
        );
        match item {
            Ok(mut item) => {
                report.metrics.hashing_seconds += item.hashing_seconds;
                let start = Instant::now();
                let detection = classifier::detect_reader(&item.prefix, item.file.as_file_mut());
                let file_type = classifier::classify(&item.prefix).into();
                report.metrics.detection_seconds += start.elapsed().as_secs_f64();
                let child = Child {
                    index,
                    name,
                    sha256: item.sha256,
                    size: item.size,
                    encrypted,
                    file_type,
                    detection,
                };
                if !config.filters.matches_file(
                    &child.name,
                    &child.detection,
                    &child.sha256,
                    child.size,
                ) && !is_zip(&child.detection)
                {
                    continue;
                }
                let start = Instant::now();
                if let Err(error) = repo.commit(item.file, &child.sha256, child.size) {
                    result.errors.push(format!("object I/O error: {error}"));
                    break;
                }
                report.metrics.object_publication_seconds += start.elapsed().as_secs_f64();
                result.children.push(child);
            }
            Err(e) => {
                let message = e.to_string();
                let stop = message.contains("limit")
                    || message.contains("overflow")
                    || cancelled.load(Ordering::Relaxed);
                result.errors.push(message);
                if stop {
                    break;
                }
            }
        }
    }
    report.metrics.extraction_seconds += started.elapsed().as_secs_f64();
    report.metrics.extracted_archives += 1;
    report.metrics.decompressed_bytes += budget.bytes - before;
    if result.errors.is_empty() {
        let mut receipt = Receipt {
            checksum: String::new(),
            schema_version: 1,
            archive_hash: hash.into(),
            policy,
            entries: archive.len(),
            bytes: budget.bytes - before,
            children: result.children.clone(),
        };
        receipt.checksum = receipt.digest()?;
        let start = Instant::now();
        atomic_json(&path, &receipt)?;
        report.metrics.metadata_seconds += start.elapsed().as_secs_f64();
    }
    Ok(result)
}
