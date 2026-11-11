// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 Younidev. See LICENSE for license terms.

//! Loads runtime TOML settings, applies CLI overrides and validates ingest constraints.
//! Defaults preserve private storage and optional extraction budgets. Optional acquisition tables
//! leave local workflows unchanged; receipt-driven inputs are resolved only when explicit
//! local inputs are absent. Download and extraction limits remain independent.

/// Default local input directory when no explicit paths or download receipts are selected.
pub const DEFAULT_INPUT_DIRECTORY: &str = "incoming";
/// Default repository used by ingest, statistics and reorganization.
pub const DEFAULT_REPOSITORY: &str = "organized";

use crate::{app::cli::Ingest, error::Error};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum InputMode {
    #[default]
    Archives,
    Files,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    Standard,
    #[default]
    Sealed,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Security {
    pub mode: SecurityMode,
    pub restrict_directories: bool,
    pub allow_automatic_unsealing: bool,
}
impl Default for Security {
    /// Return the sealed, private security defaults.
    fn default() -> Self {
        Self {
            mode: SecurityMode::Sealed,
            restrict_directories: true,
            allow_automatic_unsealing: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum extracted entry size; integer bytes or a readable size such as 256 MiB.
    #[serde(deserialize_with = "crate::collection::acquisition::deserialize_optional_bytes")]
    pub max_entry_bytes: Option<u64>,
    /// Maximum aggregate expanded archive size; independent of compressed input size.
    #[serde(deserialize_with = "crate::collection::acquisition::deserialize_optional_bytes")]
    pub max_archive_bytes: Option<u64>,
    /// Maximum input file size; accepts the same units as download size limits.
    #[serde(deserialize_with = "crate::collection::acquisition::deserialize_optional_bytes")]
    pub max_input_bytes: Option<u64>,
    #[serde(deserialize_with = "crate::collection::acquisition::deserialize_optional_count")]
    pub max_entries: Option<usize>,
    #[serde(deserialize_with = "crate::collection::acquisition::deserialize_optional_count")]
    pub max_expansion_ratio: Option<u64>,
}
impl Default for Limits {
    /// Application budgets are opt-in; parsing and arithmetic protections remain mandatory.
    fn default() -> Self {
        Self {
            max_entry_bytes: None,
            max_archive_bytes: None,
            max_input_bytes: None,
            max_entries: None,
            max_expansion_ratio: None,
        }
    }
}
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArchiveConfig {
    pub nested_extraction: bool,
    pub max_depth: usize,
    #[serde(deserialize_with = "crate::collection::acquisition::deserialize_optional_bytes")]
    pub max_total_expanded_bytes: Option<u64>,
    #[serde(deserialize_with = "crate::collection::acquisition::deserialize_optional_count")]
    pub max_total_entries: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// CLI-only history context; never accepted from runtime TOML.
    #[serde(skip)]
    pub operation_args: Option<Vec<String>>,
    pub filters: crate::selection::Filters,
    pub compression_level: Option<u8>,
    pub export_naming: crate::organization::rules::ExportNaming,
    #[serde(skip)]
    /// Resolved receipt provenance indexed by canonical local input path.
    pub remote_inputs:
        std::collections::BTreeMap<PathBuf, crate::collection::acquisition::Candidate>,
    pub source: Option<crate::collection::acquisition::SourceConfig>,
    pub download: Option<crate::collection::acquisition::DownloadConfig>,
    pub input_mode: InputMode,
    pub zip: bool,
    pub zip_dirs: Vec<String>,
    pub zip_each_dir: bool,
    pub output_password_file: Option<PathBuf>,
    /// Private storage root for sealed payloads and transfer receipts.
    pub staging_dir: Option<PathBuf>,
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
    pub recursive: bool,
    pub workers: usize,
    pub password_file: Option<PathBuf>,
    pub rules: Option<PathBuf>,
    pub preset: Option<crate::organization::rules::Preset>,
    pub resume: bool,
    pub security: Security,
    pub limits: Limits,
    pub archive: ArchiveConfig,
}
impl Default for Config {
    /// Return configuration defaults with bounded worker parallelism.
    fn default() -> Self {
        Self {
            operation_args: None,
            filters: Default::default(),
            compression_level: None,
            export_naming: Default::default(),
            remote_inputs: Default::default(),
            source: None,
            download: None,
            input_mode: InputMode::Files,
            zip: false,
            zip_dirs: vec![],
            zip_each_dir: false,
            output_password_file: None,
            staging_dir: None,
            inputs: vec![],
            output: DEFAULT_REPOSITORY.into(),
            recursive: true,
            workers: std::thread::available_parallelism().map_or(1, |n| n.get().min(8)),
            password_file: None,
            rules: None,
            preset: None,
            resume: false,
            security: Security::default(),
            limits: Limits::default(),
            archive: ArchiveConfig::default(),
        }
    }
}
impl Config {
    /// Load TOML configuration from an optional path.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let selected = Self::active_path(path);
        let Some(path) = selected else {
            return Ok(Self::default());
        };
        let text = fs::read_to_string(&path).with_context(|| {
            if !path.exists() {
                format!("configuration file not found: {}\nHint: check the path or run without -c to use defaults.", path.display())
            } else {
                format!("cannot read configuration: {} (check permissions)", path.display())
            }
        })?;
        toml::from_str(&text)
            .map_err(|mut error: toml::de::Error| {
                error.set_input(None);
                error
            })
            .with_context(|| format!("invalid configuration: {}", path.display()))
    }

    /// Only the current directory is searched; relative paths remain relative to cwd.
    pub fn active_path(path: Option<&Path>) -> Option<PathBuf> {
        path.map(Path::to_path_buf).or_else(|| {
            Path::new("bfs.toml")
                .exists()
                .then(|| PathBuf::from("bfs.toml"))
        })
    }

    /// Merge CLI ingest overrides into file or default configuration.
    pub fn for_ingest(args: &Ingest) -> Result<Self> {
        Self::for_ingest_cancellable(args, &std::sync::atomic::AtomicBool::new(false))
    }

    pub fn for_ingest_cancellable(
        args: &Ingest,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Self> {
        let mut c = Self::load(args.config.as_deref())?;
        c.filters = args.selection.resolve(c.filters)?;
        if args.compression_level.is_some() {
            c.compression_level = args.compression_level;
        }
        if let Some(naming) = args.naming {
            c.export_naming = naming;
        }
        if let Some(mode) = args.input_mode {
            c.input_mode = mode;
        }
        if args.extract {
            c.input_mode = InputMode::Archives;
        }
        if args.zip {
            c.zip = true;
        }
        if !args.zip_dirs.is_empty() {
            c.zip_dirs.clone_from(&args.zip_dirs);
        }
        if args.zip_each_dir {
            c.zip_each_dir = true;
        }
        if let Some(path) = &args.output_password_file {
            c.output_password_file = Some(path.clone());
        }
        if let Some(path) = &args.staging_dir {
            c.staging_dir = Some(path.clone());
        }
        if !args.inputs.is_empty() {
            c.inputs.clone_from(&args.inputs);
        }
        if let Some(v) = &args.output {
            c.output.clone_from(v);
        }
        if let Some(v) = &args.rules {
            c.rules = Some(v.clone());
            c.preset = None;
        }
        if let Some(v) = args.workers {
            c.workers = v;
        }
        if let Some(v) = &args.password_file {
            c.password_file = Some(v.clone());
        }
        if let Some(v) = args.security_mode {
            c.security.mode = v;
        }
        if let Some(v) = args.recursive {
            c.recursive = v;
        }
        if c.inputs.is_empty() && c.download.is_none() {
            let download = crate::collection::acquisition::DownloadConfig::default();
            if download.staging_dir.join("control").try_exists()? {
                c.download = Some(download);
            } else {
                c.inputs.push(DEFAULT_INPUT_DIRECTORY.into());
            }
        }
        if c.inputs.is_empty()
            && let Some(download) = &c.download
        {
            for input in
                crate::collection::acquisition::completed_inputs_cancellable(download, cancelled)?
            {
                c.remote_inputs
                    .insert(input.path.clone(), input.receipt.candidate);
                c.inputs.push(input.path);
            }
        }
        c.resume |= args.resume;
        if args.preset.is_some() {
            c.preset = args.preset;
            c.rules = None;
        }
        c.validate()?;
        Ok(c)
    }
    /// Validate worker, security, output, and extraction-limit settings.
    pub fn validate(&self) -> Result<()> {
        self.filters.validate()?;
        anyhow::ensure!(
            self.compression_level.is_none_or(|level| level <= 9),
            "compression_level must be between 0 and 9"
        );
        let error = |s: &str| Error::Config(s.into());
        if let Some(source) = &self.source {
            if !source.page.is_empty() {
                crate::collection::http_source::safe_url(&source.page)?;
            }
            if source.max_page_size == Some(0) || source.timeout_seconds == Some(0) {
                return Err(error("source limits must be positive or unlimited").into());
            }
        }
        if let Some(download) = &self.download {
            download.validate()?;
        }
        if self.output_password_file.is_some() && !self.zip_enabled() {
            return Err(error("output_password_file requires ZIP output").into());
        }
        for directory in &self.zip_dirs {
            if directory.is_empty()
                || directory.contains(['\\', ':'])
                || directory.chars().any(char::is_control)
                || directory
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
            {
                return Err(
                    error("zip_dirs must contain safe relative sorted directory paths").into(),
                );
            }
        }
        if !(1..=256).contains(&self.workers) {
            return Err(error("workers must be between 1 and 256").into());
        }
        if !self.security.restrict_directories || self.security.allow_automatic_unsealing {
            return Err(error(
                "private directories are required; automatic unsealing is forbidden",
            )
            .into());
        }
        if self.limits.max_entry_bytes == Some(0)
            || self.limits.max_archive_bytes == Some(0)
            || self.limits.max_input_bytes == Some(0)
            || self.limits.max_entries == Some(0)
            || self.limits.max_expansion_ratio == Some(0)
        {
            return Err(error("extraction limits must be positive").into());
        }
        if let (Some(entry), Some(archive)) =
            (self.limits.max_entry_bytes, self.limits.max_archive_bytes)
            && entry > archive
        {
            return Err(error("entry limit exceeds archive limit").into());
        }
        if self.rules.is_some() && self.preset.is_some() {
            return Err(error("rules and preset are mutually exclusive").into());
        }
        if self.archive.nested_extraction != (self.archive.max_depth > 0) {
            return Err(error("nested_extraction requires positive max_depth; disabled extraction requires zero depth").into());
        }
        if self.archive.nested_extraction && self.input_mode != InputMode::Archives {
            return Err(error("nested_extraction requires input_mode = archives").into());
        }
        if self.archive.max_total_expanded_bytes == Some(0)
            || self.archive.max_total_entries == Some(0)
        {
            return Err(error("tree budgets must be positive or unlimited").into());
        }
        if self.output.as_os_str().is_empty() {
            return Err(error("output must not be empty").into());
        }
        if let Some(path) = &self.staging_dir {
            crate::ingest::discovery::check_path(path)?;
            if !path.is_dir() {
                return Err(error("staging_dir must be an existing directory").into());
            }
        }
        Ok(())
    }

    pub fn zip_enabled(&self) -> bool {
        self.zip || self.zip_each_dir || !self.zip_dirs.is_empty()
    }
}
