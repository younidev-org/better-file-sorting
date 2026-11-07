//! Traverse ZIPs inside ZIPs while preserving each member's provenance.
//!
//! A direct-child receipt describes the extraction of one archive under a
//! particular policy. Reuse still charges the root tree's resource budget.
//! Filtering retains required ZIP containers as structural occurrences so
//! matching descendants keep their parent links.
use crate::{
    app::config::{ArchiveConfig, Config, InputMode, SecurityMode},
    detection::classifier::{self, Detection, Format},
    repository::{
        metadata::{self, NestedProvenance, Occurrence},
        security,
        storage::Repository,
    },
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

mod receipts;
mod traversal;
use receipts::{Child, Receipt, direct};
use traversal::{Source, Task, traverse};

pub struct Budget {
    bytes: u64,
    entries: usize,
    config: ArchiveConfig,
}
impl Budget {
    pub fn new(config: &ArchiveConfig) -> Self {
        Self {
            bytes: 0,
            entries: 0,
            config: config.clone(),
        }
    }
    pub fn bytes(&mut self, count: u64) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(count)
            .context("tree byte counter overflow")?;
        ensure!(
            self.config
                .max_total_expanded_bytes
                .is_none_or(|n| self.bytes <= n),
            "tree expanded byte limit exceeded"
        );
        Ok(())
    }
    fn entries(&mut self, count: usize) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(count)
            .context("tree entry counter overflow")?;
        ensure!(
            self.config
                .max_total_entries
                .is_none_or(|n| self.entries <= n),
            "tree entry limit exceeded"
        );
        Ok(())
    }
}
#[derive(Default, Serialize, Deserialize)]
pub struct Metrics {
    pub source_replay_bytes: u64,
    pub source_replay_seconds: f64,
    pub extracted_archives: usize,
    pub reused_archives: usize,
    pub decompressed_bytes: u64,
    pub extraction_seconds: f64,
    pub detection_seconds: f64,
    pub hashing_seconds: f64,
    pub object_publication_seconds: f64,
    pub metadata_seconds: f64,
}
#[derive(Serialize, Deserialize)]
pub struct Outcome {
    pub occurrence_id: String,
    pub sha256: String,
    pub depth: usize,
    pub status: String,
    pub diagnostic: Option<String>,
}
#[derive(Default, Serialize, Deserialize)]
pub struct TreeReport {
    pub schema_version: u32,
    pub accepted: usize,
    pub reused_occurrences: usize,
    pub failures: usize,
    pub metrics: Metrics,
    pub outcomes: Vec<Outcome>,
    pub warnings: Vec<String>,
}
impl TreeReport {
    pub fn merge(&mut self, other: Self) {
        self.schema_version = 1;
        self.accepted += other.accepted;
        self.reused_occurrences += other.reused_occurrences;
        self.failures += other.failures;
        self.metrics.source_replay_bytes += other.metrics.source_replay_bytes;
        self.metrics.source_replay_seconds += other.metrics.source_replay_seconds;
        self.metrics.extracted_archives += other.metrics.extracted_archives;
        self.metrics.reused_archives += other.metrics.reused_archives;
        self.metrics.decompressed_bytes += other.metrics.decompressed_bytes;
        self.metrics.extraction_seconds += other.metrics.extraction_seconds;
        self.metrics.detection_seconds += other.metrics.detection_seconds;
        self.metrics.hashing_seconds += other.metrics.hashing_seconds;
        self.metrics.object_publication_seconds += other.metrics.object_publication_seconds;
        self.metrics.metadata_seconds += other.metrics.metadata_seconds;
        self.outcomes.extend(other.outcomes);
        for warning in other.warnings {
            if !self.warnings.contains(&warning) {
                self.warnings.push(warning);
            }
        }
    }
}
struct PriorTask {
    id: String,
    parent: Option<String>,
    hash: String,
    chain: Vec<usize>,
    depth: usize,
}
#[derive(Default)]
pub struct Cache {
    published: Mutex<BTreeMap<String, bool>>,
    prior: BTreeMap<(String, String), Vec<PriorTask>>,
    locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
}
impl Cache {
    pub fn with_records<'a>(records: impl IntoIterator<Item = &'a Occurrence>) -> Self {
        let mut cache = Self::default();
        let mut ids = BTreeMap::new();
        for row in records {
            ids.insert(row.occurrence_id.clone(), row.structural);
            if let Some(n) = &row.nested
                && is_zip(&row.detection)
            {
                cache
                    .prior
                    .entry((n.root_source.clone(), n.root_input_hash.clone()))
                    .or_default()
                    .push(PriorTask {
                        id: row.occurrence_id.clone(),
                        parent: n.parent_occurrence_id.clone(),
                        hash: row.sha256.clone(),
                        chain: n.entry_chain.clone(),
                        depth: n.archive_depth + 1,
                    });
            }
        }
        cache.published = Mutex::new(ids);
        cache
    }
    fn gate(&self, key: &str) -> Result<Arc<Mutex<()>>> {
        Ok(self
            .locks
            .lock()
            .map_err(|_| anyhow::anyhow!("cache lock poisoned"))?
            .entry(key.into())
            .or_default()
            .clone())
    }
}
fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    crate::ingest::discovery::check_path(path)?;
    if path.try_exists()? {
        security::validate_file(path, SecurityMode::Standard)?;
    }
    let parent = path.parent().context("missing metadata parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut file, value)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn hash_file(file: &mut File, cancelled: &AtomicBool) -> Result<String> {
    use sha2::{Digest, Sha256};
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
fn verify(repo: &Repository, child: &Child, cancelled: &AtomicBool) -> Result<()> {
    ensure!(
        crate::repository::storage::valid_hash(&child.sha256),
        "invalid receipt hash"
    );
    crate::ingest::extraction::validate_name(&child.name)?;
    let path = repo.object(&child.sha256)?;
    security::validate_file(&path, repo.mode())?;
    ensure!(
        fs::metadata(&path)?.len() == child.size,
        "receipt object size mismatch"
    );
    if repo.mode() == SecurityMode::Standard {
        ensure!(
            hash_file(&mut File::open(path)?, cancelled)? == child.sha256,
            "receipt object checksum mismatch"
        );
    }
    Ok(())
}
fn policy(config: &Config) -> String {
    let base = format!(
        "zip-receipt-1/{}/{:?}",
        classifier::DETECTOR_VERSION,
        config.limits
    );
    if config.filters.is_empty() {
        metadata::digest(base.as_bytes())
    } else {
        metadata::digest(format!("{base}/filters={:?}", config.filters).as_bytes())
    }
}
fn receipt_path(repo: &Repository, hash: &str, policy: &str) -> std::path::PathBuf {
    repo.root()
        .join("operations/extraction")
        .join(format!("{hash}-{policy}.json"))
}
pub fn is_zip(d: &Detection) -> bool {
    matches!(
        d.detected_format,
        Format::Zip | Format::Docx | Format::Xlsx | Format::Pptx | Format::Jar | Format::Apk
    )
}
fn status(error: &str) -> &'static str {
    if error.contains("interrupted") {
        "cancelled"
    } else if error.contains("limit") || error.contains("overflow") {
        "resource_limit"
    } else if error.contains("decrypt") {
        "password_failed"
    } else if error.contains("archive") || error.contains("ZIP") {
        "invalid_archive"
    } else {
        "io_error"
    }
}
fn prepare(repo: &Repository) -> Result<()> {
    security::private_dir(&repo.root().join("operations"))?;
    for name in ["extraction", "analysis", "trees"] {
        security::private_dir(&repo.root().join("operations").join(name))?;
    }
    Ok(())
}
pub fn ingest_root(
    repo: &Repository,
    path: &Path,
    config: &Config,
    cancelled: &AtomicBool,
    cache: &Cache,
    run_id: &str,
) -> Result<TreeReport> {
    crate::ingest::discovery::check_path(path)?;
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    ensure!(
        config.limits.max_input_bytes.is_none_or(|n| size <= n),
        "input size limit exceeded"
    );
    let hash = hash_file(&mut file, cancelled)?;
    let source = path.to_str().map(str::to_owned).unwrap_or_else(|| {
        let encoded: String = path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("encoded-path:{encoded}")
    });
    let root = Occurrence {
        structural: false,
        nested: None,
        detection: Detection::default(),
        mismatch: Default::default(),
        provenance: config.remote_inputs.get(path).cloned(),
        input_mode: InputMode::Archives,
        occurrence_id: metadata::digest(&serde_json::to_vec(&(&source, &hash))?),
        sha256: hash.clone(),
        size,
        file_type: "zip".into(),
        original_name: String::new(),
        original_entry_name: String::new(),
        original_stem: String::new(),
        original_extension: String::new(),
        source_archive: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into(),
        source_path: source.clone(),
        entry_index: 0,
        encrypted: false,
        ingest_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        run_id: run_id.into(),
    };
    let expected_hash = hash.clone();
    let root_id = root.occurrence_id.clone();
    let report = traverse(
        repo,
        Task {
            parent: root,
            depth: 0,
            source: Some(Source {
                root: Arc::new(file),
                indices: vec![],
            }),
            root_hash: hash,
            root_source: source,
            chain: vec![],
            outer: true,
        },
        config,
        &security::passwords(config.password_file.as_deref())?,
        cancelled,
        cache,
    )?;
    if !cancelled.load(Ordering::Relaxed) {
        ensure!(
            hash_file(&mut File::open(path)?, cancelled)? == expected_hash,
            "input changed during ingestion"
        );
    }
    let checkpoint_path = repo
        .root()
        .join("operations/trees")
        .join(format!("{root_id}.json"));
    let mut checkpoint: traversal::TreeCheckpoint =
        serde_json::from_reader(File::open(&checkpoint_path)?)?;
    checkpoint.completed = report.failures == 0 && !cancelled.load(Ordering::Relaxed);
    atomic_json(&checkpoint_path, &checkpoint)?;
    Ok(report)
}
#[derive(Serialize)]
pub struct Preview {
    pub schema_version: u32,
    pub candidate_occurrences: usize,
    pub unique_archives: usize,
    pub reusable_archives: usize,
    pub needs_extraction: usize,
    pub inaccessible_objects: usize,
    pub max_total_expanded_bytes: Option<u64>,
    pub max_total_entries: Option<usize>,
    pub expanded_bytes: Option<u64>,
}
pub fn preview(repo: &Repository, config: &Config) -> Result<Preview> {
    ensure!(
        crate::repository::cleanup::removed(repo.root())?.is_empty(),
        "nested analysis after logical removal requires a fresh repository"
    );
    let records = metadata::load_all(repo.root())?;
    let candidates: Vec<_> = records
        .iter()
        .filter(|r| {
            is_zip(&r.detection)
                && r.nested
                    .as_ref()
                    .is_none_or(|n| n.parent_occurrence_id.is_none())
        })
        .collect();
    let hashes: std::collections::BTreeSet<_> = candidates.iter().map(|r| &r.sha256).collect();
    let mut reusable = 0;
    for hash in &hashes {
        let p = receipt_path(repo, hash, &policy(config));
        crate::ingest::discovery::check_path(&p)?;
        if p.try_exists()? {
            security::validate_file(&p, SecurityMode::Standard)?;
            ensure!(
                fs::metadata(&p)?.len() <= 256 * 1024 * 1024,
                "extraction receipt too large"
            );
            let receipt: Receipt = serde_json::from_reader(File::open(&p)?)?;
            receipt.validate(hash, &policy(config))?;
            let cancelled = AtomicBool::new(false);
            for child in &receipt.children {
                verify(repo, child, &cancelled)?;
            }
            reusable += 1;
        }
    }
    Ok(Preview {
        schema_version: 1,
        candidate_occurrences: candidates.len(),
        unique_archives: hashes.len(),
        reusable_archives: reusable,
        needs_extraction: hashes.len() - reusable,
        inaccessible_objects: if repo.mode() == SecurityMode::Sealed {
            hashes.len()
        } else {
            0
        },
        max_total_expanded_bytes: config.archive.max_total_expanded_bytes,
        max_total_entries: config.archive.max_total_entries,
        expanded_bytes: None,
    })
}
pub fn analyze(repo: &Repository, config: &Config, cancelled: &AtomicBool) -> Result<TreeReport> {
    ensure!(
        crate::repository::cleanup::removed(repo.root())?.is_empty(),
        "nested analysis after logical removal requires a fresh repository"
    );
    ensure!(
        repo.mode() == SecurityMode::Standard,
        "analysis requires a standard repository; sealed payloads are never unlocked automatically"
    );
    config.validate()?;
    ensure!(
        config.archive.nested_extraction,
        "analyze requires [archive] nested_extraction = true"
    );
    let records = metadata::load_all(repo.root())?;
    let cache = Cache::with_records(records.iter());
    let run_id = format!(
        "analysis-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ")
    );
    let mut report = TreeReport {
        schema_version: 1,
        ..Default::default()
    };
    let passwords = security::passwords(config.password_file.as_deref())?;
    let roots: Vec<_> = records
        .into_iter()
        .filter(|r| {
            r.nested
                .as_ref()
                .is_none_or(|n| n.parent_occurrence_id.is_none())
                && is_zip(&r.detection)
        })
        .collect();
    let progress =
        crate::app::presentation::Progress::new(Some(roots.len() as u64), "Analyzing root ZIPs");
    for mut parent in roots {
        parent.run_id = run_id.clone();
        let next = traverse(
            repo,
            Task {
                root_source: parent
                    .nested
                    .as_ref()
                    .map_or_else(|| parent.source_path.clone(), |n| n.root_source.clone()),
                root_hash: parent
                    .nested
                    .as_ref()
                    .map_or_else(|| parent.sha256.clone(), |n| n.root_input_hash.clone()),
                chain: parent
                    .nested
                    .as_ref()
                    .map_or_else(Vec::new, |n| n.entry_chain.clone()),
                parent,
                depth: 0,
                source: None,
                outer: false,
            },
            config,
            &passwords,
            cancelled,
            &cache,
        )?;
        report.merge(next);
        progress.0.inc(1);
        progress.0.set_message(format!(
            "archives extracted {} / reused {}; entries accepted {} / reused {}; failures {}",
            report.metrics.extracted_archives,
            report.metrics.reused_archives,
            report.accepted,
            report.reused_occurrences,
            report.failures
        ));
    }
    drop(progress);
    let rows = metadata::load(repo.root())?;
    let rules =
        crate::organization::rules::Rules::load_or_preset(config.rules.as_deref(), config.preset)?;
    crate::organization::organizer::organize(repo, &rules, &rules.plan(&rows)?)?;
    Ok(report)
}

#[derive(Debug, Default, Serialize)]
pub struct NestedSummary {
    pub analyzed_trees: usize,
    pub failed_trees: usize,
    pub occurrences_by_depth: BTreeMap<usize, usize>,
    pub unique_hashes_by_depth: BTreeMap<usize, usize>,
    pub maximum_depth: usize,
    pub parent_child_relationships: usize,
    pub archive_outcomes: BTreeMap<String, usize>,
}
pub fn summary(repo: &Repository, records: &[Occurrence]) -> Result<NestedSummary> {
    let mut summary = NestedSummary::default();
    let mut hashes: BTreeMap<usize, std::collections::BTreeSet<&str>> = BTreeMap::new();
    for row in records {
        if let Some(n) = &row.nested {
            *summary
                .occurrences_by_depth
                .entry(n.archive_depth)
                .or_default() += 1;
            hashes
                .entry(n.archive_depth)
                .or_default()
                .insert(&row.sha256);
            summary.maximum_depth = summary.maximum_depth.max(n.archive_depth);
            summary.parent_child_relationships += usize::from(n.parent_occurrence_id.is_some());
        }
    }
    summary.unique_hashes_by_depth = hashes
        .into_iter()
        .map(|(depth, hashes)| (depth, hashes.len()))
        .collect();
    let dir = repo.root().join("operations/analysis");
    crate::ingest::discovery::check_path(&dir)?;
    if dir.try_exists()? {
        let mut statuses = BTreeMap::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            security::validate_file(&path, SecurityMode::Standard)?;
            ensure!(
                fs::metadata(&path)?.len() <= 256 * 1024 * 1024,
                "analysis report too large"
            );
            let report: TreeReport = serde_json::from_reader(File::open(path)?)?;
            ensure!(
                report.schema_version == 1,
                "unsupported nested report schema"
            );
            summary.analyzed_trees += 1;
            summary.failed_trees += usize::from(report.failures > 0);
            for outcome in report.outcomes {
                statuses.insert(outcome.occurrence_id, outcome.status);
            }
        }
        for status in statuses.into_values() {
            *summary.archive_outcomes.entry(status).or_default() += 1;
        }
    }
    Ok(summary)
}
