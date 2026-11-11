//! Record operation lifecycle, input outcomes, and retry arguments.
//!
//! Repository operations use the SQLite catalog. Collection operations use
//! local JSON history. The history guides retries, while each operation's
//! checkpoints determine what work can be reused.
use crate::{
    app::{cli::Cli, config::SecurityMode},
    collection::acquisition,
    ingest::discovery::check_path,
    repository::{catalog, security},
};
use anyhow::{Context, Result, ensure};
use clap::{CommandFactory, Parser};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputOutcome {
    pub source_path: String,
    pub state: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub total: Option<u64>,
    pub completed: u64,
    pub failed: u64,
    pub skipped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u32,
    pub app_version: String,
    #[serde(default)]
    pub retry_of: Option<String>,
    #[serde(default)]
    pub counts: Option<Counts>,
    #[serde(default)]
    pub checkpoints: Vec<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    pub id: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub settings_files: std::collections::BTreeMap<PathBuf, String>,
    pub state: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub exit_code: Option<u8>,
}

pub struct Guard {
    record: Record,
    root: PathBuf,
    path: PathBuf,
    lock: Option<File>,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

fn validate_arguments(command: &str, args: &[String]) -> Result<()> {
    ensure!(
        matches!(
            command,
            "ingest" | "analyze" | "reclassify" | "download" | "collect" | "export"
        ),
        "operation does not support history or retry"
    );
    ensure!(
        args.iter().any(|a| a == command),
        "operation command does not match arguments"
    );
    let parsed =
        Cli::try_parse_from(std::iter::once("bfsort".to_owned()).chain(args.iter().cloned()))
            .map_err(|_| anyhow::anyhow!("invalid operation arguments"))?;
    let actual = match parsed.command {
        crate::app::cli::Command::Ingest(_) => "ingest",
        crate::app::cli::Command::Analyze { .. } => "analyze",
        crate::app::cli::Command::Reclassify { .. } => "reclassify",
        crate::app::cli::Command::Download(_) => "download",
        crate::app::cli::Command::Collect(_) => "collect",
        crate::app::cli::Command::Export(_) => "export",
        _ => anyhow::bail!("unsupported operation command"),
    };
    ensure!(
        actual == command,
        "operation command does not match arguments"
    );
    for arg in args {
        let value = if arg.contains("://") && !arg.starts_with('-') {
            arg.as_str()
        } else {
            arg.split_once('=').map_or(arg.as_str(), |(_, v)| v)
        };
        if let Ok(url) = url::Url::parse(value)
            && url.has_host()
        {
            ensure!(
                url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "operation history cannot retain URL credentials, queries or fragments"
            );
        }
    }
    Ok(())
}

fn settings_files(
    args: &[String],
    cwd: &Path,
) -> Result<std::collections::BTreeMap<PathBuf, String>> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut paths = Vec::new();
    let mut config_path = None;
    for (i, arg) in args.iter().take_while(|a| a.as_str() != "--").enumerate() {
        if matches!(arg.as_str(), "--config" | "-c" | "--rules") {
            if let Some(path) = args.get(i + 1) {
                paths.push(cwd.join(path));
                if arg != "--rules" {
                    config_path = Some(cwd.join(path));
                }
            }
        } else if let Some(path) = arg
            .strip_prefix("--config=")
            .or_else(|| arg.strip_prefix("--rules="))
        {
            paths.push(cwd.join(path));
            if arg.starts_with("--config=") {
                config_path = Some(cwd.join(path));
            }
        } else if let Some(path) = arg.strip_prefix("-c").filter(|p| !p.is_empty()) {
            paths.push(cwd.join(path));
            config_path = Some(cwd.join(path));
        }
    }
    let implicit = cwd.join("bfs.toml");
    if implicit.try_exists()? {
        config_path.get_or_insert_with(|| implicit.clone());
        paths.push(implicit);
    }
    if !args.iter().any(|arg| {
        matches!(arg.as_str(), "--rules" | "--preset")
            || arg.starts_with("--rules=")
            || arg.starts_with("--preset=")
    }) && let Some(path) = config_path
        && let Some(rules) = crate::app::config::Config::load(Some(&path))?.rules
    {
        paths.push(cwd.join(rules));
    }
    let mut fingerprints = std::collections::BTreeMap::new();
    for path in paths {
        check_path(&path)?;
        let mut file = File::open(&path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        fingerprints.insert(
            path,
            hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        );
    }
    Ok(fingerprints)
}

fn repository_root(root: &Path) -> Result<bool> {
    let marker = root.join("security.json");
    check_path(&marker)?;
    if !marker.try_exists()? {
        ensure!(
            !catalog::exists(root)?,
            "catalog repository is missing security metadata"
        );
        return Ok(false);
    }
    security::validate_file(&marker, SecurityMode::Standard)?;
    let _: SecurityMode = acquisition::load_json(&marker)?;
    Ok(true)
}

fn save_record(root: &Path, path: &Path, record: &Record) -> Result<()> {
    if repository_root(root)? {
        catalog::write(root)?.put_operation(&record.id, &serde_json::to_string(record)?)
    } else {
        acquisition::save_json(path, record)
    }
}

/// Load collection history from its operation records.
fn load_collection_records(root: &Path) -> Result<Vec<Record>> {
    let directory = root.join("operations/history");
    check_path(&directory)?;
    if !directory.try_exists()? {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|p| p.to_str()) != Some("json") {
            continue;
        }
        let record: Record = acquisition::load_json(&path)?;
        ensure!(
            path.file_stem().and_then(|p| p.to_str()) == Some(&record.id),
            "operation identity mismatch"
        );
        validate_record(&record)?;
        records.push(record);
    }
    Ok(records)
}

fn load_records(root: &Path) -> Result<Vec<Record>> {
    if repository_root(root)? {
        catalog::read(root)?
            .operations()?
            .iter()
            .map(|record| Ok(serde_json::from_str(record)?))
            .collect()
    } else {
        load_collection_records(root)
    }
}

fn validate_record(record: &Record) -> Result<()> {
    ensure!(
        record.schema_version == 1 && valid_id(&record.id),
        "unsupported or invalid operation record"
    );
    ensure!(
        matches!(
            record.state.as_str(),
            "running" | "completed" | "failed" | "interrupted" | "cancelled"
        ),
        "invalid operation state"
    );
    Ok(())
}

impl Guard {
    pub fn id(&self) -> &str {
        &self.record.id
    }

    pub fn start(root: &Path, command: &str, args: &[String]) -> Result<Self> {
        validate_arguments(command, args)?;
        ensure!(
            !args.iter().any(|a| a == "--dry-run"),
            "dry runs do not create operation history"
        );
        acquisition::private_tree(root)?;
        let repository = repository_root(root)?;
        ensure!(
            repository || matches!(command, "ingest" | "collect" | "download"),
            "operation requires a repository root"
        );
        let directory = root.join("operations/history");
        security::private_dir(&root.join("operations"))?;
        security::private_dir(&directory)?;
        let id = format!(
            "op-{}-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%9f"),
            std::process::id()
        );
        let path = directory.join(format!("{id}.json"));
        check_path(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(directory.join(format!("{id}.lock")))?;
        lock.try_lock()
            .context("cannot own operation history lock")?;
        let cwd = std::env::current_dir()?.canonicalize()?;
        let settings_files = settings_files(args, &cwd)?;
        let record = Record {
            schema_version: 1,
            app_version: env!("CARGO_PKG_VERSION").into(),
            retry_of: None,
            counts: None,
            checkpoints: match command {
                "ingest" => vec!["operations/ingest".into(), "operations/extraction".into()],
                "analyze" => vec![
                    "operations/extraction".into(),
                    "operations/analysis".into(),
                    "operations/trees".into(),
                ],
                "reclassify" => vec!["reports/reclassification".into()],
                "export" => vec!["operations/export".into()],
                "collect" | "download" => vec!["downloads/control".into()],
                _ => Vec::new(),
            },
            last_error: None,
            id,
            command: command.into(),
            args: args.to_vec(),
            cwd,
            settings_files,
            state: "running".into(),
            started_at: chrono::Utc::now().to_rfc3339(),
            finished_at: None,
            exit_code: None,
        };
        let root = root.canonicalize()?;
        let path = root
            .join("operations/history")
            .join(format!("{}.json", record.id));
        save_record(&root, &path, &record)?;
        Ok(Self {
            record,
            root,
            path,
            lock: Some(lock),
        })
    }

    pub fn record_counts(
        &mut self,
        total: Option<u64>,
        completed: u64,
        failed: u64,
        skipped: u64,
    ) -> Result<()> {
        ensure!(self.lock.is_some(), "operation is already finished");
        self.record.counts = Some(Counts {
            total,
            completed,
            failed,
            skipped,
        });
        save_record(&self.root, &self.path, &self.record)
    }

    pub fn set_retry_of(&mut self, id: &str) -> Result<()> {
        ensure!(
            valid_id(id) && id != self.record.id,
            "invalid retry parent identity"
        );
        ensure!(self.lock.is_some(), "operation is already finished");
        self.record.retry_of = Some(id.into());
        save_record(&self.root, &self.path, &self.record)
    }

    pub fn interrupt(&mut self) -> Result<()> {
        self.finish(130)
    }

    pub fn finish(&mut self, code: u8) -> Result<()> {
        ensure!(self.lock.is_some(), "operation is already finished");
        self.record.state = match code {
            0 => "completed",
            130 => "interrupted",
            _ => "failed",
        }
        .into();
        self.record.last_error =
            (code != 0).then(|| "operation failed; inspect command reports".into());
        self.record.exit_code = Some(code);
        self.record.finished_at = Some(chrono::Utc::now().to_rfc3339());
        save_record(&self.root, &self.path, &self.record)?;
        self.lock.take();
        Ok(())
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.lock.is_some() {
            let _ = self.finish(1);
        }
    }
}

/// Inspect history without taking the repository lock or changing any files.
pub fn status(root: &Path) -> Result<Vec<Record>> {
    check_path(root)?;
    ensure!(root.is_dir(), "operation root does not exist");
    let directory = root.join("operations/history");
    check_path(&directory)?;
    let mut records = load_records(root)?;
    if records.is_empty() && !directory.try_exists()? {
        ensure!(
            repository_root(root)?
                || root.join("inventory.json").is_file()
                || root.join("downloads").is_dir(),
            "not a repository or collection root"
        );
    }
    for record in &mut records {
        validate_record(record)?;
        if record.state == "running" {
            let lock_path = directory.join(format!("{}.lock", record.id));
            check_path(&lock_path)?;
            if lock_path.try_exists()? {
                security::validate_file(&lock_path, SecurityMode::Standard)?;
                let lock = File::open(lock_path)?;
                match lock.try_lock() {
                    Ok(()) => {
                        let current = load_records(root)?
                            .into_iter()
                            .find(|r| r.id == record.id)
                            .context("operation disappeared")?;
                        validate_record(&current)?;
                        ensure!(
                            current.id == record.id && current.schema_version == 1,
                            "operation identity changed"
                        );
                        *record = current;
                        if record.state == "running" {
                            record.state = "interrupted".into();
                        }
                    }
                    Err(std::fs::TryLockError::WouldBlock) => (),
                    Err(error) => return Err(error.into()),
                }
            } else {
                record.state = "interrupted".into();
            }
        }
    }
    records.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(records)
}

/// Return arguments for the existing verified resume pipeline; run in the record's cwd.
pub fn retry_arguments(root: &Path, id: &str) -> Result<Vec<String>> {
    ensure!(valid_id(id), "invalid operation identity");
    let record = status(root)?
        .into_iter()
        .find(|r| r.id == id)
        .context("operation not found")?;
    ensure!(record.state != "running", "operation is still running");
    validate_arguments(&record.command, &record.args)?;
    ensure!(
        record.app_version == env!("CARGO_PKG_VERSION"),
        "operation application version changed; retry with the original version"
    );
    ensure!(
        record.cwd.is_absolute() && record.cwd.is_dir(),
        "operation working directory is unavailable"
    );
    ensure!(
        settings_files(&record.args, &record.cwd)? == record.settings_files,
        "operation configuration changed; retry requires the original settings"
    );
    let parsed = Cli::try_parse_from(
        std::iter::once("bfsort".to_owned()).chain(record.args.iter().cloned()),
    )?;
    let config_path = match &parsed.command {
        crate::app::cli::Command::Ingest(a) => a.config.as_ref(),
        crate::app::cli::Command::Analyze { config, .. } => config.as_ref(),
        crate::app::cli::Command::Collect(a) => a.config.as_ref(),
        crate::app::cli::Command::Download(a) => a.config.as_ref(),
        crate::app::cli::Command::Export(a) => a.config.as_ref(),
        _ => None,
    }
    .map(|p| record.cwd.join(p));
    let implicit = record.cwd.join("bfs.toml");
    let config_path = config_path.or_else(|| implicit.is_file().then_some(implicit));
    let config = config_path
        .map(|path| crate::app::config::Config::load(Some(&path)))
        .transpose()?;
    if let crate::app::cli::Command::Ingest(args) = parsed.command {
        ensure!(
            !args.zip && !args.zip_each_dir && args.zip_dirs.is_empty(),
            "direct ZIP ingestion cannot resume"
        );
        if let Some(config) = &config {
            ensure!(!config.zip_enabled(), "direct ZIP ingestion cannot resume");
        }
    }
    if let Some(config) = config {
        for path in [config.password_file, config.output_password_file]
            .into_iter()
            .flatten()
        {
            security::validate_file(&record.cwd.join(path), SecurityMode::Standard)
                .context("retry requires the protected password file again")?;
        }
    }
    for (index, arg) in record.args.iter().enumerate() {
        let password_path = if arg == "--password-file" || arg == "--output-password-file" {
            record.args.get(index + 1).map(String::as_str)
        } else {
            arg.strip_prefix("--password-file=")
                .or_else(|| arg.strip_prefix("--output-password-file="))
        };
        if let Some(path) = password_path {
            security::validate_file(&record.cwd.join(path), SecurityMode::Standard)
                .context("retry requires the protected password file again")?;
        }
    }
    let mut args: Vec<_> = record
        .args
        .into_iter()
        .filter(|a| a != "--dry-run")
        .collect();
    let options_end = args.iter().position(|a| a == "--").unwrap_or(args.len());
    if !args[..options_end].iter().any(|a| a == "--resume") {
        args.insert(options_end, "--resume".into());
    }
    Ok(args)
}

/// Rebuild a recorded ingest command for selected inputs.
///
/// Failed-only selection includes failed, interrupted, and pending inputs.
/// Explicit paths must belong to the recorded operation. The caller runs
/// the returned arguments from the recorded working directory.
pub fn retry_selected_arguments(
    root: &Path,
    id: &str,
    failed_only: bool,
    inputs: &[PathBuf],
) -> Result<Vec<String>> {
    let args = retry_arguments(root, id)?;
    if !failed_only && inputs.is_empty() {
        return Ok(args);
    }
    let record = status(root)?
        .into_iter()
        .find(|r| r.id == id)
        .context("operation not found")?;
    ensure!(
        record.command == "ingest",
        "selected input retry is supported only for ingestion"
    );
    ensure!(
        repository_root(root)? && catalog::exists(root)?,
        "input outcomes are unavailable for this operation"
    );
    let outcomes = catalog::read(root)?.inputs(id)?;
    let canonical = |path: &Path| -> Result<PathBuf> {
        let path = record.cwd.join(path);
        check_path(&path)?;
        path.canonicalize().context("retry input is unavailable")
    };
    let eligible = |row: &InputOutcome| {
        !failed_only || matches!(row.state.as_str(), "failed" | "interrupted" | "pending")
    };
    let mut selected = std::collections::BTreeSet::new();
    if inputs.is_empty() {
        for row in outcomes.iter().filter(|r| eligible(r)) {
            selected.insert(canonical(Path::new(&row.source_path))?);
        }
    } else {
        for path in inputs {
            let path = canonical(path)?;
            ensure!(
                outcomes.iter().filter(|r| eligible(r)).any(|row| {
                    canonical(Path::new(&row.source_path)).is_ok_and(|recorded| recorded == path)
                }),
                "retry input was not recorded with an eligible outcome"
            );
            selected.insert(path);
        }
    }
    ensure!(
        !selected.is_empty(),
        "no recorded inputs match the retry selection"
    );
    let mut args = ingest_options(&args)?;
    if !args.iter().any(|arg| arg == "--resume") {
        args.push("--resume".into());
    }
    args.push("--".into());
    for path in selected {
        args.push(
            path.to_str()
                .context("retry input path must be UTF-8")?
                .into(),
        );
    }
    // Reparse the actual retry, including positional overrides of configured inputs.
    Cli::try_parse_from(std::iter::once("bfsort".to_owned()).chain(args.iter().cloned()))?;
    Ok(args)
}

/// Use clap's option declarations so flag values are never mistaken for input paths.
fn ingest_options(args: &[String]) -> Result<Vec<String>> {
    let command = Cli::command();
    let ingest = command
        .find_subcommand("ingest")
        .expect("declared ingest command");
    let mut longs = std::collections::BTreeMap::new();
    let mut shorts = std::collections::BTreeMap::new();
    for arg in command.get_arguments().chain(ingest.get_arguments()) {
        if let Some(long) = arg.get_long() {
            longs.insert(long, arg.get_action().takes_values());
        }
        if let Some(aliases) = arg.get_all_aliases() {
            for alias in aliases {
                longs.insert(alias, arg.get_action().takes_values());
            }
        }
        if let Some(aliases) = arg.get_short_and_visible_aliases() {
            for alias in aliases {
                shorts.insert(alias, arg.get_action().takes_values());
            }
        }
    }
    let start = args
        .iter()
        .position(|arg| arg == "ingest")
        .context("ingest command is missing")?
        + 1;
    let mut result = args[..start].to_vec();
    let mut index = start;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            break;
        }
        let takes_value = if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, false), |(name, _)| (name, true));
            *longs.get(name).context("unknown recorded option")? && !attached
        } else if let Some(short) = arg.strip_prefix('-').filter(|s| !s.is_empty()) {
            let mut chars = short.chars().peekable();
            let mut takes_value = false;
            while let Some(name) = chars.next() {
                if *shorts.get(&name).context("unknown recorded short option")? {
                    takes_value = chars.peek().is_none();
                    break;
                }
            }
            takes_value
        } else {
            index += 1;
            continue;
        };
        result.push(arg.clone());
        if takes_value {
            index += 1;
            result.push(
                args.get(index)
                    .context("recorded option value is missing")?
                    .clone(),
            );
        }
        index += 1;
    }
    Ok(result)
}
