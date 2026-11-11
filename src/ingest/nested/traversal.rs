//! Iterative archive tasks, provenance, tree checkpoints and budget preflight.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TreeCheckpoint {
    schema_version: u32,
    root_occurrence_id: String,
    input_hash: String,
    extraction_policy: String,
    max_depth: usize,
    max_total_expanded_bytes: Option<u64>,
    max_total_entries: Option<usize>,
    pub(super) completed: bool,
}
fn checkpoint(
    repo: &Repository,
    task: &Task,
    config: &Config,
) -> Result<(std::path::PathBuf, TreeCheckpoint)> {
    let path = repo
        .root()
        .join("operations/trees")
        .join(format!("{}.json", task.parent.occurrence_id));
    crate::ingest::discovery::check_path(&path)?;
    let current = TreeCheckpoint {
        schema_version: 1,
        root_occurrence_id: task.parent.occurrence_id.clone(),
        input_hash: task.parent.sha256.clone(),
        extraction_policy: policy(config),
        max_depth: config.archive.max_depth,
        max_total_expanded_bytes: config.archive.max_total_expanded_bytes,
        max_total_entries: config.archive.max_total_entries,
        completed: false,
    };
    if path.try_exists()? {
        security::validate_file(&path, SecurityMode::Standard)?;
        ensure!(
            fs::metadata(&path)?.len() <= 65536,
            "nested checkpoint too large"
        );
        let old: TreeCheckpoint = serde_json::from_reader(File::open(&path)?)?;
        ensure!(
            old.schema_version == 1
                && old.root_occurrence_id == current.root_occurrence_id
                && old.input_hash == current.input_hash
                && old.extraction_policy == current.extraction_policy
                && old.max_depth == current.max_depth,
            "incompatible nested checkpoint: depth, extraction policy or schema changed; use a fresh destination and reclassify explicitly for detector updates"
        );
    }
    Ok((path, current))
}
fn preflight(
    repo: &Repository,
    task: &Task,
    config: &Config,
    cache: &Cache,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut pending = vec![(task.parent.sha256.clone(), task.chain.clone(), task.depth)];
    if let Some(prior) = cache
        .prior
        .get(&(task.root_source.clone(), task.root_hash.clone()))
    {
        let by_id: BTreeMap<_, _> = prior.iter().map(|p| (&p.id, p)).collect();
        for prior_task in prior {
            let mut belongs = task.outer;
            let mut parent = prior_task.parent.as_ref();
            let mut seen = std::collections::BTreeSet::new();
            while !belongs {
                let Some(id) = parent else {
                    break;
                };
                ensure!(seen.insert(id), "cyclic nested provenance");
                if id == &task.parent.occurrence_id {
                    belongs = true;
                    break;
                }
                parent = by_id.get(id).and_then(|p| p.parent.as_ref());
            }
            if belongs {
                pending.push((
                    prior_task.hash.clone(),
                    prior_task.chain.clone(),
                    prior_task.depth,
                ));
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut budget = Budget::new(&config.archive);
    while let Some((hash, chain, depth)) = pending.pop() {
        ensure!(!cancelled.load(Ordering::Relaxed), "interrupted");
        if depth > config.archive.max_depth || !seen.insert(chain.clone()) {
            continue;
        }
        let path = receipt_path(repo, &hash, &policy(config));
        crate::ingest::discovery::check_path(&path)?;
        if !path.try_exists()? {
            continue;
        }
        security::validate_file(&path, SecurityMode::Standard)?;
        ensure!(
            fs::metadata(&path)?.len() <= 256 * 1024 * 1024,
            "extraction receipt too large"
        );
        let receipt: Receipt = serde_json::from_reader(File::open(path)?)?;
        receipt.validate(&hash, &policy(config))?;
        for child in &receipt.children {
            verify(repo, child, cancelled)?;
        }
        budget.entries(receipt.entries)?;
        budget.bytes(receipt.bytes)?;
        for child in receipt.children {
            if is_zip(&child.detection) {
                let mut next = chain.clone();
                next.push(child.index);
                pending.push((child.sha256, next, depth + 1));
            }
        }
    }
    Ok(())
}
#[derive(Clone)]
pub(super) struct Source {
    pub(super) root: Arc<File>,
    pub(super) indices: Vec<usize>,
}
impl Source {
    fn child(&self, index: usize) -> Self {
        let mut source = self.clone();
        source.indices.push(index);
        source
    }
    pub(super) fn open(
        &self,
        repo: &Repository,
        config: &Config,
        passwords: &[String],
        cancelled: &AtomicBool,
        metrics: &mut Metrics,
    ) -> Result<File> {
        let started = Instant::now();
        let mut file = self.root.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        // Re-read entries from an existing source handle instead of retaining an FD per sibling
        // or opening sealed stored objects. Logical expansion is charged once by receipt replay.
        for index in &self.indices {
            let mut zip = zip::ZipArchive::new(file)?;
            let mut total = 0;
            let item = crate::ingest::extraction::extract(
                &mut zip,
                *index,
                passwords,
                &repo.staging(),
                &config.limits,
                &mut total,
                cancelled,
            )?;
            metrics.source_replay_bytes = metrics
                .source_replay_bytes
                .checked_add(item.size)
                .context("source replay byte overflow")?;
            metrics.hashing_seconds += item.hashing_seconds;
            file = item.file.into_file();
            file.seek(SeekFrom::Start(0))?;
        }
        metrics.source_replay_seconds += started.elapsed().as_secs_f64();
        Ok(file)
    }
}
pub(super) struct Task {
    pub(super) parent: Occurrence,
    pub(super) depth: usize,
    pub(super) source: Option<Source>,
    pub(super) root_hash: String,
    pub(super) root_source: String,
    pub(super) chain: Vec<usize>,
    pub(super) outer: bool,
}
#[allow(clippy::too_many_arguments)]
pub(super) fn traverse(
    repo: &Repository,
    task: Task,
    config: &Config,
    passwords: &[String],
    cancelled: &AtomicBool,
    cache: &Cache,
    on_read: &impl Fn(u64),
) -> Result<TreeReport> {
    let (checkpoint_path, mut checkpoint) = checkpoint(repo, &task, config)?;
    preflight(repo, &task, config, cache, cancelled)?;
    prepare(repo)?;
    atomic_json(&checkpoint_path, &checkpoint)?;
    let outer = task.outer;
    let operation = metadata::digest(task.parent.occurrence_id.as_bytes());
    let mut queue = vec![task];
    let mut budget = Budget::new(&config.archive);
    let mut report = TreeReport {
        schema_version: 1,
        ..Default::default()
    };
    if config.archive.max_total_entries.is_none()
        || config.archive.max_total_expanded_bytes.is_none()
    {
        report
            .warnings
            .push("recursive extraction has unlimited tree budgets".into());
    }
    while let Some(task) = queue.pop() {
        let outcome = |state: &str, diagnostic| Outcome {
            occurrence_id: task.parent.occurrence_id.clone(),
            sha256: task.parent.sha256.clone(),
            depth: task.depth,
            status: state.into(),
            diagnostic,
        };
        if !task.outer && task.depth > config.archive.max_depth {
            report.outcomes.push(outcome("depth_limit", None));
            continue;
        }
        let result = direct(
            repo,
            task.source.as_ref(),
            &task.parent.sha256,
            config,
            passwords,
            cancelled,
            &mut budget,
            cache,
            &mut report,
            on_read,
        );
        match result {
            Err(error) => {
                let message = error.to_string();
                let state = status(&message);
                report.failures += 1;
                report.outcomes.push(outcome(state, Some(message)));
                if matches!(state, "resource_limit" | "io_error" | "cancelled") {
                    break;
                }
            }
            Ok(direct) => {
                let stop_tree = direct
                    .errors
                    .iter()
                    .any(|e| matches!(status(e), "resource_limit" | "io_error" | "cancelled"));
                if direct.errors.is_empty() {
                    report.outcomes.push(outcome("completed", None));
                } else {
                    report.failures += direct.errors.len();
                    for error in &direct.errors {
                        report
                            .outcomes
                            .push(outcome(status(error), Some(error.clone())));
                    }
                }
                for child in direct.children {
                    let mut chain = task.chain.clone();
                    chain.push(child.index);
                    let mut row = task.parent.clone();
                    row.occurrence_id = metadata::digest(&serde_json::to_vec(&(
                        "nested-occurrence-1",
                        &task.parent.occurrence_id,
                        child.index,
                        &child.sha256,
                    ))?);
                    row.nested = Some(NestedProvenance {
                        schema_version: 1,
                        parent_sha256: task.parent.sha256.clone(),
                        parent_occurrence_id: (!task.outer)
                            .then(|| task.parent.occurrence_id.clone()),
                        root_source: task.root_source.clone(),
                        root_input_hash: task.root_hash.clone(),
                        archive_depth: if task.outer {
                            0
                        } else {
                            task.parent
                                .nested
                                .as_ref()
                                .map_or(0, |n| n.archive_depth + 1)
                        },
                        entry_chain: chain.clone(),
                    });
                    row.sha256 = child.sha256;
                    row.size = child.size;
                    row.file_type = child.file_type;
                    row.detection = child.detection;
                    row.original_entry_name = child.name;
                    row.original_name = row
                        .original_entry_name
                        .rsplit(['/', '\\'])
                        .next()
                        .unwrap_or("")
                        .into();
                    row.original_extension = Path::new(&row.original_name)
                        .extension()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into();
                    row.original_stem = Path::new(&row.original_name)
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into();
                    row.entry_index = child.index;
                    row.encrypted = child.encrypted;
                    row.input_mode = InputMode::Archives;
                    row.mismatch =
                        crate::detection::mismatch::evaluate(&row.original_name, &row.detection);
                    row.structural = !config.filters.matches(&row);
                    let start = Instant::now();
                    {
                        let mut published = cache
                            .published
                            .lock()
                            .map_err(|_| anyhow::anyhow!("occurrence lock poisoned"))?;
                        if let Some(structural) = published.get_mut(&row.occurrence_id) {
                            if *structural && !row.structural {
                                metadata::store(repo, &row)?;
                                *structural = false;
                                report.accepted += 1;
                            } else {
                                report.reused_occurrences += usize::from(!row.structural);
                            }
                        } else {
                            metadata::store(repo, &row)?;
                            published.insert(row.occurrence_id.clone(), row.structural);
                            report.accepted += usize::from(!row.structural);
                        }
                    }
                    report.metrics.metadata_seconds += start.elapsed().as_secs_f64();
                    if is_zip(&row.detection) {
                        queue.push(Task {
                            parent: row,
                            depth: task.depth + 1,
                            source: task
                                .source
                                .as_ref()
                                .filter(|_| repo.mode() == SecurityMode::Sealed)
                                .map(|source| source.child(child.index)),
                            root_hash: task.root_hash.clone(),
                            root_source: task.root_source.clone(),
                            chain,
                            outer: false,
                        });
                    } else if row.detection.detected_family == classifier::Family::Archive {
                        report.outcomes.push(Outcome {
                            occurrence_id: row.occurrence_id,
                            sha256: row.sha256,
                            depth: task.depth + 1,
                            status: "unsupported_format".into(),
                            diagnostic: None,
                        });
                    }
                }
                if stop_tree {
                    break;
                }
            }
        }
    }
    atomic_json(
        &repo
            .root()
            .join("operations/analysis")
            .join(format!("{operation}.json")),
        &report,
    )?;
    checkpoint.completed = !outer && report.failures == 0 && !cancelled.load(Ordering::Relaxed);
    atomic_json(&checkpoint_path, &checkpoint)?;
    Ok(report)
}
